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

        %% DNS cache MUST come up before the GTP-C client so the first
        %% PGW-C resolution can hit the cache on subsequent sends.
        #{id => epdg_dns_cache,
          start => {epdg_dns_cache, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_xfrm,
          start => {epdg_xfrm, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_gtpc_client,
          start => {epdg_gtpc_client, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_gtpu_forwarder,
          start => {epdg_gtpu_forwarder, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_diameter_swm,
          start => {epdg_diameter_swm, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        %% Opt-in Redis session store (start_link returns `ignore' when
        %% EPDG_SESSION_STORE_ENABLED is false).
        #{id => epdg_session_store,
          start => {epdg_session_store, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        %% The UE FSM supervisor must be up BEFORE the session restore
        %% step (restored FSMs are its children) and before the IKE
        %% listener (which spawns FSMs for new attaches).
        #{id => epdg_ue_sup,
          start => {epdg_ue_sup, start_link, []},
          restart => permanent, shutdown => infinity, type => supervisor},

        %% Crash restore runs synchronously here — after registry / xfrm
        %% / gtpu / diameter / ue_sup, before the reconciler's first
        %% sweep and before the IKE listener accepts packets. `ignore'
        %% when the session store is disabled.
        #{id => epdg_session_restore,
          start => {epdg_session_restore, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        %% XFRM orphan reconciler (idle when EPDG_XFRM_RECONCILE_INTERVAL
        %% is 0). Started after the restore step so adopted SAs are
        %% claimed before the first sweep marks anything.
        #{id => epdg_xfrm_reconciler,
          start => {epdg_xfrm_reconciler, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_ikev2_listener,
          start => {epdg_ikev2_listener, start_link, []},
          restart => permanent, shutdown => 5000, type => worker},

        #{id => epdg_http,
          start => {epdg_http, start_link, []},
          restart => permanent, shutdown => 5000, type => worker}
    ],

    {ok, {SupFlags, Children}}.
