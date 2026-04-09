%%%-------------------------------------------------------------------
%%% @doc ePDG top-level supervisor.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => one_for_one, intensity => 10, period => 60},

    Children = [
        #{id => epdg_ue_registry,
          start => {epdg_ue_registry, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_xfrm,
          start => {epdg_xfrm, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_gtpc_client,
          start => {epdg_gtpc_client, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_diameter_swm,
          start => {epdg_diameter_swm, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_ikev2_listener,
          start => {epdg_ikev2_listener, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_ue_sup,
          start => {epdg_ue_sup, start_link, []},
          restart => permanent, shutdown => infinity, type => supervisor},

        #{id => epdg_http,
          start => {epdg_http, start_link, []},
          restart => permanent, shutdown => 5000, type => worker}
    ],

    {ok, {SupFlags, Children}}.
