%%%-------------------------------------------------------------------
%%% @doc Dynamic supervisor for per-UE FSMs.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_sup).

-behaviour(supervisor).

-export([start_link/0, start_ue_fsm/1]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

-spec start_ue_fsm(map()) -> {ok, pid()} | {error, term()}.
start_ue_fsm(InitContext) ->
    supervisor:start_child(?SERVER, [InitContext]).

init([]) ->
    SupFlags = #{strategy => simple_one_for_one,
                 intensity => 50, period => 60},

    ChildSpec = #{id => epdg_ue_fsm,
                  start => {epdg_ue_fsm, start_link, []},
                  restart => temporary, shutdown => 5000,
                  type => worker, modules => [epdg_ue_fsm]},

    {ok, {SupFlags, [ChildSpec]}}.
