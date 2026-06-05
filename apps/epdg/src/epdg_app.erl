%%%-------------------------------------------------------------------
%%% @doc ePDG application module.
%%% Evolved Packet Data Gateway for VoWiFi (TS 23.402 / TS 29.273).
%%% Native Erlang IKEv2 control plane with Linux kernel XFRM data plane.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_app).

-behaviour(application).

-export([start/2, prep_stop/1, stop/1]).

start(_StartType, _StartArgs) ->
    epdg_config:init(),
    apply_log_level(),
    logger:info("Starting ePDG application"),
    epdg_metrics:init(),
    epdg_sup:start_link().

%% Apply the configured primary log level to the Erlang `logger'.
%%
%% The level arrives as a string in `EPDG_LOG_LEVEL' (chart value
%% `erlang.logLevel'). Without this call the BEAM keeps the OTP default
%% primary level `notice', so every per-attach IKE_SA_INIT proposal and
%% SWm DER/DEA line (all emitted via `logger:notice/2') reaches the logs.
%% Setting `warning' (or `error') silences that chatter while still
%% surfacing genuine problems (e.g. `pgw_unreachable'). An unrecognised
%% value falls back to `notice' rather than crashing the boot.
apply_log_level() ->
    Level = parse_log_level(epdg_config:get(log_level, "notice")),
    case logger:set_primary_config(level, Level) of
        ok -> ok;
        {error, Reason} ->
            logger:warning("Could not set log level to ~p: ~p", [Level, Reason])
    end,
    Level.

parse_log_level(L) when is_atom(L) -> parse_log_level(atom_to_list(L));
parse_log_level(L) when is_list(L) ->
    case string:lowercase(string:trim(L)) of
        "emergency" -> emergency;
        "alert"     -> alert;
        "critical"  -> critical;
        "error"     -> error;
        "warning"   -> warning;
        "notice"    -> notice;
        "info"      -> info;
        "debug"     -> debug;
        Other ->
            logger:warning("Unknown EPDG_LOG_LEVEL ~p, defaulting to notice",
                           [Other]),
            notice
    end.

%% Called BEFORE the supervisor tree is torn down. Last chance to do
%% protocol-level housekeeping while every worker is still alive.
%%
%% Each step is wrapped in `catch' so a single failure in one of the
%% housekeeping calls cannot prevent the rest of the drain from running
%% or stall the application controller's shutdown path.
prep_stop(State) ->
    logger:info("ePDG prep_stop: draining"),
    %% 1. Flip the readiness flag so kubelet probes and any LB in front
    %%    of the pod stop sending traffic immediately.
    catch epdg_http_handler:set_draining(true),
    %% 2. Stop the cowboy listener explicitly. `epdg_http:start_link/0'
    %%    returned `ignore', so the listener lives under ranch's tree
    %%    and is NOT a child of `epdg_sup'. Without this call the
    %%    listener stays up until `init:stop/0' later stops the cowboy
    %%    / ranch apps -- and `ranch_conns_sup' uses
    %%    `shutdown => infinity', so any lingering keep-alive
    %%    connection (Prometheus scrape, kubelet probe burst, the very
    %%    `/admin/drain' POST that triggered teardown) pins the BEAM
    %%    alive forever, requiring SIGKILL.
    catch cowboy:stop_listener(epdg_http_listener),
    %% 3. Close the IKEv2 UDP sockets so no new IKE_SA_INIT can spawn
    %%    a fresh UE FSM during the supervisor walk that follows.
    catch gen_server:cast(epdg_ikev2_listener, stop_accepting),
    %% 4. Broadcast a drain notification to every live UE FSM. The
    %%    preStop hook normally does this via `/admin/drain' but
    %%    direct-SIGTERM paths (eviction, node drain, dev shell)
    %%    bypass preStop entirely.
    catch epdg_ue_registry:broadcast({drain, app_stop}),
    %% 5. Give the diameter service a head start on DPR so its
    %%    transports drain in parallel with the supervisor walk that
    %%    follows. `epdg_diameter_swm:terminate/2' guards against the
    %%    service already being stopped, so the second
    %%    `diameter:stop_service/1' inside the gen_server's terminate
    %%    is a no-op.
    catch diameter:stop_service(epdg_diameter_svc),
    State.

stop(_State) ->
    logger:info("Stopping ePDG application"),
    ok.
