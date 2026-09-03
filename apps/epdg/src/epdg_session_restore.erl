%%%-------------------------------------------------------------------
%%% @doc Startup session restore (opt-in, epdg_session_store).
%%%
%%% Runs once, synchronously, inside the supervisor start sequence:
%%% AFTER the registry / XFRM / GTP-U / Diameter workers and the UE FSM
%%% supervisor are up, and BEFORE the IKEv2 listener accepts packets and
%%% before the XFRM reconciler could age out the surviving kernel SAs
%%% (the reconciler additionally protects them with its grace period).
%%%
%%% For every stored snapshot of THIS pod a UE FSM is spawned directly
%%% in `established' (see epdg_ue_fsm init({restore, ...})): it
%%% re-registers routing entries and the GTP-U bearer(s) with the
%%% persisted TEIDs, then adopts the surviving kernel XFRM state (same-node
%%% restart) or re-installs it from the persisted key material
%%% (rescheduled pod). No IKE, S2b or SWm signalling is emitted — from
%%% the UE's and the PGW's perspective the session never went away.
%%%
%%% A snapshot that fails to restore is logged and DELETED: its UE will
%%% notice via its own DPD/keepalives and re-attach normally, which is
%%% strictly better than retry-looping a corpse at every restart.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_session_restore).

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
%% The store connects to Redis asynchronously; give it a bounded head
%% start before declaring the stored sessions unreachable.
-define(LIST_RETRIES, 10).
-define(LIST_RETRY_SLEEP_MS, 500).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    case epdg_session_store:enabled() of
        true  -> gen_server:start_link({local, ?SERVER}, ?MODULE, [], []);
        false -> ignore
    end.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    Summary = restore_all(),
    %% Stays alive but idle afterwards; the summary is kept as state so
    %% it is visible in observer / sys:get_state during debugging.
    {ok, Summary}.

handle_call(_Req, _From, State) -> {reply, {error, unknown}, State}.
handle_cast(_Msg, State) -> {noreply, State}.
handle_info(_Info, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Restore
%%====================================================================

restore_all() ->
    case list_with_retry(?LIST_RETRIES) of
        {ok, []} ->
            logger:notice("Session restore: no stored sessions"),
            #{restored => 0, failed => 0};
        {ok, Snapshots} ->
            %% One kernel inventory for the whole batch; each FSM decides
            %% adopt-vs-reinstall against it.
            ExistingSAs = kernel_sa_set(),
            logger:notice("Session restore: ~B stored session(s), "
                          "~B kernel SA(s) present",
                          [length(Snapshots), sets:size(ExistingSAs)]),
            Summary = lists:foldl(
                        fun(Snap, Acc) ->
                                restore_one(Snap, ExistingSAs, Acc)
                        end,
                        #{restored => 0, failed => 0}, Snapshots),
            logger:notice("Session restore done: ~B restored, ~B failed",
                          [maps:get(restored, Summary),
                           maps:get(failed, Summary)]),
            Summary;
        {error, Reason} ->
            logger:warning("Session restore: store unreachable (~p) — "
                           "skipping restore; orphaned kernel SAs are left "
                           "to the XFRM reconciler", [Reason]),
            #{restored => 0, failed => 0}
    end.

list_with_retry(0) ->
    {error, retries_exhausted};
list_with_retry(N) ->
    case catch epdg_session_store:list_sessions() of
        {ok, Snapshots} ->
            {ok, Snapshots};
        Other ->
            case N of
                1 -> {error, Other};
                _ ->
                    timer:sleep(?LIST_RETRY_SLEEP_MS),
                    list_with_retry(N - 1)
            end
    end.

restore_one(Snapshot, ExistingSAs, #{restored := R, failed := F} = Acc) ->
    RSPI = maps:get(responder_spi, Snapshot, undefined),
    IMSI = maps:get(imsi, Snapshot, undefined),
    case catch epdg_ue_sup:start_ue_fsm({restore, Snapshot, ExistingSAs}) of
        {ok, Pid} when is_pid(Pid) ->
            epdg_metrics:inc(sessions_restored_total),
            Acc#{restored := R + 1};
        Error ->
            logger:warning("Session restore failed IMSI=~p RSPI=~p: ~p — "
                           "deleting stored entry (UE will re-attach via "
                           "DPD)", [IMSI, RSPI, Error]),
            epdg_metrics:inc(session_restore_failures_total),
            case RSPI of
                Spi when is_integer(Spi) ->
                    catch epdg_session_store:delete_session(Spi);
                _ -> ok
            end,
            Acc#{failed := F + 1}
    end.

%% {Src, Dst, Spi} of every ESP SA currently in the kernel. On a
%% same-node crash restart (hostNetwork) the previous incarnation's SAs
%% are all still here; on a reschedule this is typically empty.
kernel_sa_set() ->
    SAs = case catch epdg_xfrm:list_sas() of
        L when is_list(L) -> L;
        _                 -> []
    end,
    sets:from_list([{S, D, Spi}
                    || #{src := S, dst := D, spi := Spi} <- SAs]).
