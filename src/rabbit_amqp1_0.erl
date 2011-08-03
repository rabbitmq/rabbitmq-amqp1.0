%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at http://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% The Initial Developer of the Original Code is VMware, Inc.
%% Copyright (c) 2011 VMware, Inc.  All rights reserved.
%%

-module(rabbit_amqp1_0).
-include_lib("rabbit_common/include/rabbit.hrl").
-include_lib("rabbit_common/include/rabbit_framing.hrl").
-include("rabbit_amqp1_0.hrl").

-export([accept_handshake_bytes/1, start_connection/2, handle_input/3,
         assemble_frame/3, assemble_frames/5, channel_spec/1]).

-rabbit_boot_step({?MODULE,
                   [{description, "AMQP 1-0"},
                    {mfa,         {rabbit_registry, register,
                                   [amqp, <<"1-0">>, ?MODULE]}},
                    {requires,    rabbit_registry},
                    {enables,     kernel_ready}]}).

-behaviour(rabbit_amqp).

-define(HANDSHAKE_TIMEOUT, 10).
-define(NORMAL_TIMEOUT, 3).
-define(CLOSING_TIMEOUT, 1).
-define(CHANNEL_TERMINATION_TIMEOUT, 3).
-define(SILENT_CLOSE_DELAY, 3).

-define(IS_RUNNING(State),
        (State#v1.connection_state =:= running orelse
         State#v1.connection_state =:= blocking orelse
         State#v1.connection_state =:= blocked)).

%%--------------------------------------------------------------------------

-record(v1, {parent, sock, connection, callback, recv_len, pending_recv,
             connection_state, queue_collector, heartbeater, stats_timer,
             channel_sup_sup_pid, start_heartbeat_fun, buf, buf_len,
             auth_mechanism, auth_state, module}).

-define(STATISTICS_KEYS, [pid, recv_oct, recv_cnt, send_oct, send_cnt,
                          send_pend, state, channels]).

-define(CREATION_EVENT_KEYS, [pid, address, port, peer_address, peer_port, ssl,
                              peer_cert_subject, peer_cert_issuer,
                              peer_cert_validity, auth_mechanism,
                              ssl_protocol, ssl_key_exchange,
                              ssl_cipher, ssl_hash,
                              protocol, user, vhost, timeout, frame_max,
                              client_properties]).

-define(INFO_KEYS, ?CREATION_EVENT_KEYS ++ ?STATISTICS_KEYS -- [pid]).

%%--------------------------------------------------------------------------

%% ... and finally, the 1.0 spec is crystal clear!
%% FIXME TLS and SASL use a different protocol number, and would go
%% here.
accept_handshake_bytes(<<"AMQP", 0, 1, 0, 0>>) ->
    true;

accept_handshake_bytes(_) ->
    false.

start_connection(_H,
                 State = #v1{sock = Sock, connection = Connection}) ->
    Protocol = rabbit_amqp1_0_framing,
    ok = rabbit_reader:inet_op(fun () -> rabbit_net:send(
                                           Sock, <<"AMQP", 0, 1, 0, 0>>) end),
    rabbit_reader:switch_callback(State#v1{connection = Connection#connection{
                                            timeout_sec = ?NORMAL_TIMEOUT,
                                            protocol = Protocol},
                             connection_state = starting},
                    frame_header_1_0, 8).

handle_input(frame_header_1_0, <<Size:32, DOff:8, Type:8, Channel:16>>,
             State) when DOff >= 2 andalso Type == 0 ->
    ?DEBUG("1.0 frame header: doff: ~p size: ~p~n", [DOff, Size]),
    case Size of
        8 -> % length inclusive
            {State, frame_header_1_0, 8}; %% heartbeat
        _ ->
            rabbit_reader:ensure_stats_timer(
              rabbit_reader:switch_callback(State, {frame_payload_1_0, DOff, Channel}, Size - 8))
    end;
handle_input(frame_header_1_0, Malformed, _State) ->
    throw({bad_1_0_header, Malformed});
handle_input({frame_payload_1_0, DOff, Channel},
            FrameBin, State) ->
    SkipBits = (DOff * 32 - 64), % DOff = 4-byte words, we've read 8 already
    <<Skip:SkipBits, FramePayload/binary>> = FrameBin,
    Skip = Skip, %% hide warning when debug is off
    ?DEBUG("1.0 frame: ~p (skipped ~p)~n", [FramePayload, Skip]),
    handle_1_0_frame(Channel, FramePayload,
                     rabbit_reader:switch_callback(State, frame_header_1_0, 8)).

assemble_frame(Channel, FrameRecords, rabbit_amqp1_0_framing)
  when is_list(FrameRecords) ->
    ?LOGMESSAGE(out, Channel, FrameRecords, none),
    FrameBin = [rabbit_amqp1_0_binary_generator:generate(
                  rabbit_amqp1_0_framing:encode(F)) || F <- FrameRecords],
    rabbit_amqp1_0_binary_generator:build_frame(Channel, FrameBin);
assemble_frame(Channel, FrameRecord, rabbit_amqp1_0_framing) ->
    assemble_frame(Channel, [FrameRecord], rabbit_amqp1_0_framing).

assemble_frames(_Channel, _MethodRecord, _Content, _FrameMax, _Protocol) ->
    exit(should_never_get_here).

%% Well, you know, session...
channel_spec(Args) ->
    {channel, {rabbit_amqp1_0_session, start_link, Args},
     intrinsic, ?MAX_WAIT, worker, [rabbit_amqp1_0_session]}.

%%--------------------------------------------------------------------------
%% AMQP 1.0 frame handlers

is_connection_frame(#'v1_0.open'{})  -> true;
is_connection_frame(#'v1_0.close'{}) -> true;
is_connection_frame(_)               -> false.

%% FIXME Handle depending on connection state
%% TODO It'd be nice to only decode up to the descriptor

%% Nothing specifies that connection methods have to be on a
%% particular channel.
handle_1_0_frame(_Channel, Payload,
                 State = #v1{ connection_state = CS}) when
      CS =:= closing; CS =:= closed ->
    Sections = parse_1_0_frame(Payload),
    case is_connection_frame(Sections) of
        true  -> handle_1_0_connection_frame(Sections, State);
        false -> State
    end;
handle_1_0_frame(Channel, Payload, State) ->
    Sections = parse_1_0_frame(Payload),
    case is_connection_frame(Sections) of
        true  -> handle_1_0_connection_frame(Sections, State);
        false -> handle_1_0_session_frame(Channel, Sections, State)
    end.

parse_1_0_frame(Payload) ->
    Sections = case [rabbit_amqp1_0_framing:decode(Parsed) ||
                        Parsed <- rabbit_amqp1_0_binary_parser:parse(Payload)] of
                   [Value] -> Value;
                   List    -> List
               end,
    ?DEBUG("1.0 frame(s) decoded: ~p~n", [Sections]),
    Sections.

handle_1_0_connection_frame(#'v1_0.open'{ max_frame_size = ClientFrameMax,
                                          hostname = _Hostname,
                                          properties = Props },
                            State = #v1{
                              start_heartbeat_fun = SHF,
                              stats_timer = StatsTimer,
                              connection_state = starting,
                              connection = Connection,
                              sock = Sock}) ->
    Interval = undefined, %% TODO does 1-0 really no longer have heartbeating?
    %% TODO channel_max?
    ClientProps = case Props of
                      undefined -> [];
                      {map, Ps} -> Ps
                  end,
    ClientHeartbeat = case Interval of
                          undefined -> 0;
                          {_, HB} -> HB
                      end,
    FrameMax = case ClientFrameMax of
                   undefined -> 0;
                   {_, FM} -> FM
               end,
    ServerFrameMax = rabbit_reader:server_frame_max(),
    State1 =
        if (FrameMax /= 0) and (FrameMax < ?FRAME_MIN_SIZE) ->
                rabbit_misc:protocol_error(
                  not_allowed, "frame_max=~w < ~w min size",
                  [FrameMax, ?FRAME_MIN_SIZE]);
           %% TODO Python client sets 2^32-1
           %% (ServerFrameMax /= 0) and (FrameMax > ServerFrameMax) ->
           %%      rabbit_misc:protocol_error(
           %%        not_allowed, "frame_max=~w > ~w max size",
           %%        [FrameMax, ServerFrameMax]);
           true ->
            SendFun =
                    fun() ->
                            Frame =
                                rabbit_amqp1_0_binary_generator:build_heartbeat_frame(),
                            catch rabbit_net:send(Sock, Frame)
                    end,

                Parent = self(),
                ReceiveFun =
                    fun() ->
                            Parent ! timeout
                    end,
                Heartbeater = SHF(Sock, ClientHeartbeat, SendFun,
                                  ClientHeartbeat, ReceiveFun),
                State#v1{connection_state = running,
                         connection = Connection#connection{
                                        client_properties = ClientProps,
                                        vhost = <<"/">>, %% FIXME relate to hostname
                                        timeout_sec = ClientHeartbeat,
                                        frame_max = FrameMax},
                         heartbeater = Heartbeater}
        end,
    ok = rabbit_reader:send_on_channel0(
           Sock,
           #'v1_0.open'{channel_max = {ushort, 0},
                        max_frame_size = {uint, FrameMax},
                        container_id = {utf8, list_to_binary(atom_to_list(node()))}},
           ?MODULE,
           rabbit_amqp1_0_framing),
    State2 = rabbit_reader:internal_conserve_memory(
               rabbit_alarm:register(self(), {?MODULE, conserve_memory, []}),
               State1),
    rabbit_event:notify(connection_created,
                        rabbit_reader:infos(?CREATION_EVENT_KEYS, State2)),
    rabbit_event:if_enabled(StatsTimer, fun() -> rabbit_reader:emit_stats(State2) end),
    State2;

handle_1_0_connection_frame(_Frame, State) ->
    lists:foreach(fun rabbit_channel:shutdown/1, rabbit_reader:all_channels()),
    rabbit_reader:maybe_close(State#v1{connection_state = closing}).

handle_1_0_session_frame(Channel, Frame, State) ->
    case get({channel, Channel}) of
        {ch_fr_pid, SessionPid} ->
            ok = rabbit_amqp1_0_session:process_frame(SessionPid, Frame),
            case Frame of
                #'v1_0.end'{} ->
                    erase({channel, Channel}),
                    State;
                #'v1_0.transfer'{} ->
                    case (State#v1.connection_state =:= blocking) of
                        true  -> State#v1{connection_state = blocked};
                        false -> State
                    end;
                _ ->
                    State
            end;
        closing ->
            case Frame of
                #'v1_0.end'{} ->
                    erase({channel, Channel});
                _Else ->
                    ok
            end,
            State;
        undefined ->
            case ?IS_RUNNING(State) of
                true ->
                    ok = send_to_new_1_0_session(Channel, Frame, State),
                    State;
                false ->
                    throw({channel_frame_while_starting,
                           Channel, State#v1.connection_state,
                           Frame})
            end
    end.

send_to_new_1_0_session(Channel, Frame, State) ->
    #v1{sock = Sock, queue_collector = Collector,
        channel_sup_sup_pid = ChanSupSup,
        connection = #connection{protocol  = Protocol,
                                 frame_max = FrameMax,
                                 %% FIXME SASL, TLS, etc.
                                 user      = User,
                                 vhost     = VHost,
                                 capabilities = Capabilities}} = State,
    {ok, ChSupPid, {ChPid, AState}} =
        rabbit_channel_sup_sup:start_channel(
          ChanSupSup, {tcp, Sock, Channel, FrameMax,
                       self(), ?MODULE, rabbit_amqp1_0_framing,
                       User, VHost, Capabilities, Collector}),
    erlang:monitor(process, ChSupPid),
    put({channel, Channel}, {ch_fr_pid, ChPid}),
    put({ch_sup_pid, ChSupPid}, {{channel, Channel}, {ch_fr_pid, ChPid}}),
    put({ch_fr_pid, ChPid}, {channel, Channel}),
    ok = rabbit_amqp1_0_session:process_frame(ChPid, Frame).
