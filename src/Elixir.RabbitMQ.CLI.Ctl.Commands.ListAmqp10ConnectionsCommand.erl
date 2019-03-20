%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at https://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% The Initial Developer of the Original Code is GoPivotal, Inc.
%% Copyright (c) 2007-2019 Pivotal Software, Inc.  All rights reserved.

-module('Elixir.RabbitMQ.CLI.Ctl.Commands.ListAmqp10ConnectionsCommand').

-behaviour('Elixir.RabbitMQ.CLI.CommandBehaviour').
-include("rabbit_amqp1_0.hrl").

-export([formatter/0, scopes/0, switches/0, aliases/0,
         usage/0, usage_additional/0, banner/2,
         validate/2, merge_defaults/2, run/2, output/2,
         help_section/0, description/0]).

formatter() -> 'Elixir.RabbitMQ.CLI.Formatters.Table'.
scopes() -> [ctl, diagnostics].
switches() -> [{verbose, boolean}].
aliases() -> [{'V', verbose}].

validate(Args, _) ->
    case 'Elixir.RabbitMQ.CLI.Ctl.InfoKeys':validate_info_keys(Args,
                                                               ?INFO_ITEMS) of
        {ok, _} -> ok;
        Error   -> Error
    end.

merge_defaults([], Opts) ->
    merge_defaults([<<"pid">>], Opts);
merge_defaults(Args, Opts) ->
    {Args, maps:merge(#{verbose => false}, Opts)}.

usage() ->
    <<"list_amqp10_connections [<amqp10_connectioninfoitem> ...]">>.

usage_additional() ->
      <<"<amqp10_connectioninfoitem> must be a member of the list [",
        ('Elixir.Enum':join(?INFO_ITEMS, <<", ">>))/binary,
        "].">>.

description() -> <<"Lists AMQP 1.0 connections on the target node">>.

help_section() ->
    {plugin, 'amqp1.0'}.

run(Args, #{node := NodeName,
            timeout := Timeout,
            verbose := Verbose}) ->
    InfoKeys = case Verbose of
        true  -> ?INFO_ITEMS;
        false -> 'Elixir.RabbitMQ.CLI.Ctl.InfoKeys':prepare_info_keys(Args)
    end,
    Nodes = 'Elixir.RabbitMQ.CLI.Core.Helpers':nodes_in_cluster(NodeName),

    'Elixir.RabbitMQ.CLI.Ctl.RpcStream':receive_list_items(
        NodeName,
        rabbit_amqp1_0,
        emit_connection_info_all,
        [Nodes, InfoKeys],
        Timeout,
        InfoKeys,
        length(Nodes)).

banner(_, _) -> <<"Listing AMQP 1.0 connections ...">>.

output(Result, _Opts) ->
    'Elixir.RabbitMQ.CLI.DefaultOutput':output(Result).
