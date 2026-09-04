%%%-------------------------------------------------------------------
%%% @doc Kernel XFRM state reconciler.
%%%
%%% Periodically compares the kernel's ESP SAs and per-UE XFRM policies
%%% against the live UE sessions (via the ESP-SPI claims in
%%% epdg_ue_registry) and deletes what nothing claims — mirroring the
%%% reconcile_interval/reconcile_grace mechanism of the IPsec-GW's
%%% OpenSIPS proto_ipsec module. Orphans arise when a UE FSM dies
%%% without terminate/3 (BEAM crash, OOM-kill) or a pod restarts on a
%%% hostNetwork node where kernel state outlives the process (and the
%%% session restore path did not re-claim it).
%%%
%%% Ownership scope: ONLY state whose outer endpoint equals this pod's
%%% IKE bind address (EPDG_IKE_BIND_ADDR, the per-ordinal VIP in
%%% manual-nlb mode). A co-located sibling ePDG pod or the IPsec-GW on
%%% the same node binds a different address and is never touched. With
%%% a wildcard bind address (0.0.0.0) ownership cannot be established
%%% and the reconciler stays idle (single warning at boot).
%%%
%%% Grace handling: instead of parsing kernel SA timestamps, an
%%% unclaimed item must stay CONTINUOUSLY unclaimed for at least
%%% EPDG_XFRM_RECONCILE_GRACE seconds (tracked across sweeps) before it
%%% is deleted. A UE mid-handshake is additionally protected by the
%%% claim-first ordering in install_child_sas (the SPI claim is
%%% registered before the kernel SA exists).
%%%
%%% EPDG_XFRM_RECONCILE_INTERVAL (seconds, default 30) is the single
%%% off-switch: 0 disables reconciliation completely, INCLUDING the
%%% startup sweep.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_xfrm_reconciler).

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
%% Pure sweep planning, exported for the EUnit suite
%% (epdg_xfrm_reconciler_tests).
-export([plan/4]).

-define(SERVER, ?MODULE).

-record(state, {
    interval_ms :: non_neg_integer(),
    grace_ms    :: non_neg_integer(),
    local_ip    :: inet:ip_address() | undefined,
    %% Unclaimed-item first-seen timestamps (monotonic ms), carried
    %% across sweeps. Keys: {sa, Src, Dst, Spi} | {pol, Src, Dst, Dir}.
    pending = #{} :: #{term() => integer()}
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    IntervalSec = epdg_config:get(xfrm_reconcile_interval, 30),
    GraceSec    = epdg_config:get(xfrm_reconcile_grace, 30),
    case IntervalSec of
        0 ->
            logger:notice("XFRM reconciler disabled "
                          "(EPDG_XFRM_RECONCILE_INTERVAL=0; no startup "
                          "sweep either)"),
            {ok, #state{interval_ms = 0, grace_ms = GraceSec * 1000,
                        local_ip = undefined}};
        _ ->
            LocalIP = local_scope_ip(),
            case LocalIP of
                undefined ->
                    logger:warning(
                        "XFRM reconciler idle: EPDG_IKE_BIND_ADDR is a "
                        "wildcard/unparseable address, so kernel-state "
                        "ownership cannot be scoped to this pod"),
                    {ok, #state{interval_ms = 0,
                                grace_ms = GraceSec * 1000,
                                local_ip = undefined}};
                _ ->
                    logger:notice("XFRM reconciler: interval=~Bs grace=~Bs "
                                  "scope=~s", [IntervalSec, GraceSec,
                                               inet:ntoa(LocalIP)]),
                    %% Startup sweep (marks; deletions happen once an item
                    %% has stayed unclaimed for the whole grace period).
                    self() ! sweep,
                    {ok, #state{interval_ms = IntervalSec * 1000,
                                grace_ms = GraceSec * 1000,
                                local_ip = LocalIP}}
            end
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(sweep, #state{interval_ms = IntervalMs} = State) ->
    State1 = try do_sweep(State)
             catch Class:Reason:Stack ->
                 logger:warning("XFRM reconciler sweep crashed ~p:~p ~P",
                                [Class, Reason, Stack, 10]),
                 State
             end,
    erlang:send_after(IntervalMs, self(), sweep),
    {noreply, State1};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Sweep
%%====================================================================

do_sweep(#state{local_ip = Local, grace_ms = GraceMs,
                pending = Pending0} = State) ->
    Now = erlang:monotonic_time(millisecond),
    epdg_metrics:inc(xfrm_reconcile_runs_total),

    %% Kernel ESP SAs scoped to our outer endpoint, keyed for pending
    %% tracking. Claimed = a live FSM registered the SPI.
    SAs = [SA || #{src := S, dst := D} = SA <- epdg_xfrm:list_sas(),
                 S =:= Local orelse D =:= Local],
    SaItems = [{{sa, S, D, Spi}, epdg_ue_registry:esp_spi_claimed(Spi)}
               || #{src := S, dst := D, spi := Spi} <- SAs],

    %% Per-UE policies scoped to our outer endpoint via the template.
    %% reqid 0 (not installed by the ePDG) is never touched; a policy is
    %% claimed when its reqid — the owning UE's inbound ESP SPI — is.
    Pols = [P || #{tmpl_src := TS, tmpl_dst := TD, reqid := R} = P
                     <- epdg_xfrm:list_policies(),
                 R > 0,
                 TS =:= Local orelse TD =:= Local],
    PolItems = [{{pol, S, D, Dir}, epdg_ue_registry:esp_spi_claimed(R)}
                || #{src := S, dst := D, dir := Dir, reqid := R} <- Pols],

    {Delete, Pending1} = plan(SaItems ++ PolItems, Pending0, Now, GraceMs),
    lists:foreach(fun(Key) -> delete_item(Key) end, Delete),
    State#state{pending = Pending1}.

%% Delete one aged-out orphan. Failures are logged by epdg_xfrm; the
%% item simply shows up again next sweep.
delete_item({sa, Src, Dst, Spi} = _Key) ->
    logger:notice("XFRM reconciler: deleting orphan SA src=~s dst=~s "
                  "spi=0x~8.16.0B (no live session claims it)",
                  [inet:ntoa(Src), inet:ntoa(Dst), Spi]),
    epdg_metrics:inc(xfrm_reconcile_orphan_sas_deleted_total),
    catch epdg_xfrm:delete_sa(#{spi => Spi, src_ip => Src, dst_ip => Dst}),
    ok;
delete_item({pol, Src, Dst, Dir} = _Key) ->
    logger:notice("XFRM reconciler: deleting orphan policy src=~s dst=~s "
                  "dir=~p (no live session claims its reqid)",
                  [Src, Dst, Dir]),
    epdg_metrics:inc(xfrm_reconcile_orphan_policies_deleted_total),
    catch epdg_xfrm:delete_policy(#{src => Src, dst => Dst, direction => Dir}),
    ok.

%%====================================================================
%% Pure sweep planning
%%====================================================================

%% @doc Decide which items to delete this sweep and carry the pending
%% (unclaimed first-seen) map forward.
%%
%%   Items    : [{Key, Claimed :: boolean()}] — current kernel state
%%   Pending  : #{Key => FirstSeenUnclaimedMs} from the previous sweep
%%   Now      : current monotonic ms
%%   GraceMs  : minimum continuous unclaimed age before deletion
%%
%% Rules:
%%   claimed                     -> keep, forget any pending mark
%%   unclaimed, first seen now   -> mark, keep
%%   unclaimed, aged >= grace    -> delete, forget mark
%%   vanished from kernel        -> forget mark
-spec plan([{term(), boolean()}], #{term() => integer()}, integer(),
           non_neg_integer()) -> {[term()], #{term() => integer()}}.
plan(Items, Pending, Now, GraceMs) ->
    lists:foldl(
      fun({Key, Claimed}, {DelAcc, PendAcc}) ->
              case Claimed of
                  true ->
                      {DelAcc, PendAcc};
                  false ->
                      FirstSeen = maps:get(Key, Pending, Now),
                      case Now - FirstSeen >= GraceMs of
                          true ->
                              {[Key | DelAcc], PendAcc};
                          false ->
                              {DelAcc, PendAcc#{Key => FirstSeen}}
                      end
              end
      end,
      %% Start from an empty pending map so items that vanished from the
      %% kernel (or became claimed) between sweeps are forgotten
      %% automatically.
      {[], #{}}, Items).

%%====================================================================
%% Internal
%%====================================================================

%% This pod's outer IKE address — the ownership scope. undefined for
%% wildcard/garbage (reconciler then stays idle).
local_scope_ip() ->
    case epdg_config:get(ike_bind_addr, "0.0.0.0") of
        Str when is_list(Str) ->
            case inet:parse_address(Str) of
                {ok, {0, 0, 0, 0}}             -> undefined;
                {ok, {0, 0, 0, 0, 0, 0, 0, 0}} -> undefined;
                {ok, IP}                       -> IP;
                _                              -> undefined
            end;
        _ -> undefined
    end.
