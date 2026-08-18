%%%-------------------------------------------------------------------
%%% @doc Userspace GTP-U forwarder for the ePDG data plane.
%%%
%%% Bridges the UEs' inner IP traffic (coming out of the kernel's ESP
%%% SAs into ONE shared TUN device, `epdg0') to the PGW-U over
%%% GTP-U/UDP 2152 and back. One process per ePDG pod owns a single
%%% UDP socket and the single shared TUN; registration of a UE is pure
%%% bookkeeping (no per-UE devices, routes or rules), so attach cost is
%%% constant and independent of the session count.
%%%
%%% Uplink packets are attributed to their bearer by the INNER SOURCE
%%% IP (IPv4: exact address; IPv6: /64 prefix — see inner_src_key/1),
%%% looked up in `by_inner_ip'. Downlink is demuxed by TEID as before,
%%% but always written to the shared TUN; the kernel XFRM OUT policy
%%% keyed on the inner destination IP selects the right SA.
%%%
%%% References:
%%%   3GPP TS 29.281 — GTP User Plane (GTPv1-U)
%%%   3GPP TS 23.402 — Non-3GPP access, S2b user-plane procedures
%%%
%%% GTP-U header (TS 29.281 §5.1, T-PDU case):
%%%   Octet 1: 0x30 = Version 1 | PT=1 (GTP) | E=0 S=0 PN=0
%%%   Octet 2: 0xFF = T-PDU message type
%%%   Octets 3-4: Length (payload bytes, not including the 8-byte header)
%%%   Octets 5-8: TEID
%%%
%%% When the PGW restarts or Recovery changes (signalled by the GTP-C
%%% client via `epdg_ue_registry:broadcast({pgw_restart, _})'), every
%%% TEID we registered is stale; the forwarder clears its tables and
%%% the UE FSMs will bring up fresh bearers.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_gtpu_forwarder).

-behaviour(gen_server).

-export([start_link/0,
         register_ue/1, unregister_ue/1,
         register_bearer/1, unregister_bearer/1,
         send/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-ifdef(TEST).
%% Internal functions plus a minimal #state{} constructor for the EUnit
%% suite (see test/epdg_gtpu_forwarder_tests.erl); the record is
%% otherwise private to this module.
-export([inner_src_key/1, ip_in_cidr/2, validate_inner_ips/3,
         new_state_for_test/1, register_ue_for_test/2,
         register_bearer_for_test/2, unregister_ue_for_test/2,
         uplink_for_test/2, classify_for_test/2]).
-endif.

-define(SERVER,     ?MODULE).
-define(GTPU_PORT,  2152).
-define(GTPU_HDR_FLAGS, 16#30).
-define(GTPU_MSG_TPDU,  16#FF).
%% The single TUN device shared by every UE bearer in this pod.
-define(SHARED_TUN, "epdg0").
%% Policy-routing table shared by all UE pools. Deliberately OUTSIDE the
%% legacy per-UE range 1000..30999 (pre-shared-TUN releases derived one
%% table per bearer in that range; cleanup_stale_tun_devices/0 may still
%% flush those tables on upgrade and must never touch ours).
-define(SHARED_TABLE, 100).
%% Priority of the shared pool / iif rules. Must sort strictly AFTER the
%% PGW-U escape rules (?PGWU_ESCAPE_PRIO) and strictly BEFORE the main
%% table (32766) — see shared_rule_selectors/2.
-define(SHARED_RULE_PRIO, 1000).
%% Priority of the PGW-U escape rules (ensure_pgwu_escape_rules/0).
%% Must sort strictly before the UE-pool rules (?SHARED_RULE_PRIO).
-define(PGWU_ESCAPE_PRIO, 900).

-record(ue_ent, {
    local_teid   :: non_neg_integer(),
    pgw_u_teid   :: non_neg_integer(),
    pgw_u_ip     :: inet:ip_address(),
    ue_inner_ip  :: inet:ip_address(),
    ue_inner_ip6 :: inet:ip_address() | undefined,
    owner_pid    :: pid() | undefined,
    %% Local TEIDs of this UE's dedicated bearers (S2b dedicated bearer
    %% activation). They share this UE's IPsec SA; kept here so the
    %% uplink classifier can enumerate them and so they are torn down with
    %% the default bearer.
    ded_teids    = [] :: [non_neg_integer()]
}).

%% A dedicated bearer. Shares the owning UE's IPsec SA (downlink rides the
%% shared TUN like everything else); uplink packets matching `filters' are
%% steered onto this bearer's PGW-U tunnel instead of the default bearer.
-record(ded_ent, {
    default_teid :: non_neg_integer(),
    pgw_u_teid   :: non_neg_integer(),
    pgw_u_ip     :: inet:ip_address(),
    filters      :: [epdg_tft:filter()],
    owner_pid    :: pid() | undefined
}).

-record(state, {
    socket     :: gen_udp:socket() | undefined,
    bind_ip    :: inet:ip_address(),
    bind_port  :: inet:port_number(),
    %% local_teid -> #ue_ent{} (default bearers)
    by_teid    :: #{non_neg_integer() => #ue_ent{}},
    %% dedicated local_teid -> #ded_ent{}
    by_ded     :: #{non_neg_integer() => #ded_ent{}},
    %% pid() -> local_teid for cleanup on owner DOWN
    by_owner   :: #{pid() => non_neg_integer()},
    %% Inner source key -> default-bearer local_teid: the uplink hot-path
    %% lookup. Keys: IPv4 = exact address tuple, IPv6 = {v6, /64 prefix}
    %% (see inner_src_key/1 for why the prefix rather than the address).
    by_inner_ip :: #{tuple() => non_neg_integer()},
    %% The shared TUN helper port (c_src/epdg_tun_port.c) and device name.
    %% `undefined' when the TUN could not be created (degraded mode, e.g.
    %% unit tests without NET_ADMIN).
    tun_port   :: port() | undefined,
    tun_name   :: string(),
    %% Configured UE inner-IP pools ({Base, PrefixLen}) from
    %% EPDG_UE_IP_POOLS; registrations outside every pool are rejected.
    pools      :: [{inet:ip_address(), 0..128}],
    next_teid  :: non_neg_integer(),
    last_rx_ts :: integer()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Register a UE bearer: allocates a local TEID and installs the inner
%% source-IP -> bearer mapping. Pure bookkeeping — no devices, routes or
%% rules are created (they are shared and set up once in init/1).
%%
%% Params:
%%   pgw_u_teid    - integer, from the Create-Session-Response F-TEID
%%   pgw_u_ip      - inet:ip_address(), from the same F-TEID
%%   ue_inner_ip   - inet:ip_address(), from PAA
%%   imsi          - binary (log correlation only)
%%   owner_pid     - pid() of the owning UE FSM (we monitor for cleanup)
%%
%% Rejects with {error, ue_ip_outside_configured_pools} when the
%% PGW-assigned inner IP falls outside every configured pool
%% (EPDG_UE_IP_POOLS): such a UE would attach fine but its uplink could
%% never be attributed to a bearer — a black hole that is very hard to
%% diagnose in the field, so fail loudly at registration instead.
%%
%% The returned `tun_name' is always the shared device (?SHARED_TUN);
%% the key is kept for API stability.
-spec register_ue(map()) ->
    {ok, #{local_teid => non_neg_integer(), tun_name => string()}}
    | {error, term()}.
register_ue(Params) ->
    gen_server:call(?SERVER, {register_ue, Params}).

-spec unregister_ue(non_neg_integer()) -> ok.
unregister_ue(LocalTeid) ->
    gen_server:call(?SERVER, {unregister_ue, LocalTeid}).

%% Register a dedicated bearer for an existing UE (S2b dedicated bearer
%% activation). The bearer shares the UE's IPsec SA — downlink GTP-U
%% arriving on `local_teid' is written to the shared TUN; uplink packets
%% matching `filters' are steered onto this bearer's PGW-U tunnel.
%%
%% Params:
%%   default_teid - local TEID of the UE's default bearer
%%   local_teid   - local TEID allocated for this dedicated bearer
%%   pgw_u_teid   - PGW-U TEID from the Create Bearer Request F-TEID
%%   pgw_u_ip     - PGW-U IP from the same F-TEID
%%   filters      - parsed uplink TFT filters (see epdg_tft:parse/1)
-spec register_bearer(map()) -> ok | {error, term()}.
register_bearer(Params) ->
    gen_server:call(?SERVER, {register_bearer, Params}).

-spec unregister_bearer(non_neg_integer()) -> ok.
unregister_bearer(LocalTeid) ->
    gen_server:call(?SERVER, {unregister_bearer, LocalTeid}).

%% Send an inner IP packet (no GTP header) to the PGW-U for a specific
%% UE bearer. Normally this is driven by the TUN reader, but exposing
%% `send/2` lets the higher-layer code inject crafted test traffic.
-spec send(non_neg_integer(), binary()) -> ok | {error, term()}.
send(LocalTeid, InnerPkt) ->
    gen_server:cast(?SERVER, {send, LocalTeid, InnerPkt}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    %% Trap exits: (a) terminate/2 must run on supervisor shutdown so the
    %% shared TUN and pool rules are removed; (b) a crash of the TUN
    %% helper port arrives as {'EXIT', Port, _} instead of killing us
    %% without cleanup.
    process_flag(trap_exit, true),
    %% An empty pool list means setup_shared_tun/1 installs no
    %% `from <pool>' rule at all: every session would attach fine but no
    %% uplink packet could ever reach the shared TUN. epdg_config:init/0
    %% refuses to boot without EPDG_UE_IP_POOLS, so hitting this means
    %% the forwarder was started without the config having run — fail
    %% loudly (CrashLoopBackOff) instead of coming up seemingly healthy.
    %% Test environments without pools must opt in explicitly via the
    %% `allow_empty_ue_pools' application env.
    Pools = epdg_config:get(ue_ip_pools, []),
    AllowEmpty = application:get_env(epdg, allow_empty_ue_pools, false),
    case {Pools, AllowEmpty} of
        {[], false} ->
            logger:error("GTP-U: no UE IP pools configured — no uplink "
                         "would ever work; check EPDG_UE_IP_POOLS. "
                         "Refusing to start."),
            {stop, no_ue_ip_pools};
        _ ->
            init_datapath(Pools)
    end.

init_datapath(Pools) ->
    cleanup_stale_tun_devices(),
    %% Node-global and idempotent; runs once per forwarder start (NOT per
    %% attach — re-running it on every TUN setup used to dump the whole
    %% rule list on each registration). ogstun devices created later
    %% (PGW-U pod restart) keep their escape because the rules match the
    %% device name, which open5gs reuses.
    ensure_pgwu_escape_rules(),
    TunPort = setup_shared_tun(Pools),
    BindIpStr = epdg_config:get(gtpu_bind_addr, "0.0.0.0"),
    BindIp    = parse_ip_or_any(BindIpStr),
    Port      = epdg_config:get(gtpu_port, ?GTPU_PORT),

    Base = #state{socket = undefined,
                  bind_ip = BindIp,
                  bind_port = Port,
                  by_teid = #{},
                  by_ded = #{},
                  by_owner = #{},
                  by_inner_ip = #{},
                  tun_port = TunPort,
                  tun_name = ?SHARED_TUN,
                  pools = Pools,
                  next_teid = 16#1000,
                  last_rx_ts = erlang:system_time(second)},
    InetFamily = case BindIp of
        {_,_,_,_,_,_,_,_} -> inet6;
        _                 -> inet
    end,
    case gen_udp:open(Port, [binary, {ip, BindIp}, {active, true},
                              {reuseaddr, true}, InetFamily]) of
        {ok, Socket} ->
            logger:info("GTP-U forwarder on ~p:~p (shared TUN ~s, ~B UE "
                        "pool(s))", [BindIp, Port, ?SHARED_TUN, length(Pools)]),
            {ok, Base#state{socket = Socket}};
        {error, eaddrinuse} ->
            %% Running outside a real ePDG pod (e.g. during unit tests)
            %% — start in a degraded mode so the supervisor comes up.
            logger:warning("GTP-U: bind ~p:~p failed (eaddrinuse); "
                           "forwarder disabled", [BindIp, Port]),
            {ok, Base};
        {error, Reason} ->
            logger:warning("GTP-U: bind ~p:~p failed: ~p; forwarder disabled",
                           [BindIp, Port, Reason]),
            {ok, Base}
    end.

handle_call({register_ue, Params}, _From, State) ->
    {Reply, NewState} = do_register_ue(Params, State),
    {reply, Reply, NewState};
handle_call({unregister_ue, LocalTeid}, _From, State) ->
    {reply, ok, do_unregister_teid(LocalTeid, State)};
handle_call({register_bearer, Params}, _From, State) ->
    {Reply, NewState} = do_register_bearer(Params, State),
    {reply, Reply, NewState};
handle_call({unregister_bearer, LocalTeid}, _From, State) ->
    {reply, ok, do_unregister_bearer(LocalTeid, State)};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast({send, Teid, Pkt}, State) ->
    {noreply, do_send_inner(Teid, Pkt, State)};
handle_cast({pgw_restart, _}, State) ->
    logger:warning("GTP-U: pgw_restart received — flushing all TEID registrations"),
    epdg_metrics:gauge_set(gtpu_dedicated_bearers_active, 0),
    %% The shared TUN and pool rules are session-independent; only the
    %% per-session bookkeeping is stale.
    {noreply, State#state{by_teid = #{}, by_ded = #{},
                          by_owner = #{}, by_inner_ip = #{}}};
handle_cast(_Msg, State) -> {noreply, State}.

handle_info({udp, _Sock, _FromIP, _FromPort, Packet}, State) ->
    case decode_gtpu(Packet) of
        {ok, Teid, Payload} ->
            epdg_metrics:inc(gtpu_rx_pkts),
            epdg_metrics:inc(gtpu_rx_bytes, byte_size(Payload)),
            %% Downlink for default and dedicated bearers alike goes out
            %% the shared TUN; the kernel XFRM OUT policy keyed on the
            %% inner destination IP selects the right SA. Unknown TEIDs
            %% (stale session, PGW misdelivery) are dropped as before.
            case known_teid(Teid, State) of
                true  -> tun_write(State#state.tun_port, Payload);
                false -> ok
            end,
            {noreply, State#state{last_rx_ts = erlang:system_time(second)}};
        _ ->
            {noreply, State}
    end;
handle_info({tun_packet, LocalTeid, Pkt}, State) ->
    {noreply, do_send_inner(LocalTeid, Pkt, State)};
%% Uplink packet read from the shared TUN by the C port helper.
handle_info({Port, {data, Pkt}}, #state{tun_port = Port} = State)
  when is_port(Port) ->
    {noreply, handle_uplink(Pkt, State)};
%% The shared TUN helper died — without it there is no datapath at all,
%% so fail loudly and let the supervisor restart us; init/1 re-creates
%% the device and rules idempotently.
handle_info({'EXIT', Port, Reason}, #state{tun_port = Port} = State)
  when is_port(Port) ->
    logger:error("GTP-U: shared TUN helper exited: ~p — restarting "
                 "forwarder", [Reason]),
    {stop, {shared_tun_exit, Reason}, State#state{tun_port = undefined}};
handle_info({Port, {exit_status, Status}}, #state{tun_port = Port} = State)
  when is_port(Port) ->
    logger:error("GTP-U: shared TUN helper exited with status ~B — "
                 "restarting forwarder", [Status]),
    {stop, {shared_tun_exit, {exit_status, Status}},
     State#state{tun_port = undefined}};
handle_info({'DOWN', _MRef, process, Pid, _Reason},
            #state{by_owner = Owners} = State) ->
    case maps:find(Pid, Owners) of
        {ok, Teid} -> {noreply, do_unregister_teid(Teid, State)};
        error      -> {noreply, State}
    end;
handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, #state{socket = S, tun_port = TP, pools = Pools}) ->
    case TP of
        TP when is_port(TP) -> catch erlang:port_close(TP);
        _                   -> ok
    end,
    teardown_shared_tun(Pools),
    case S of undefined -> ok; _ -> gen_udp:close(S) end,
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Registration
%%====================================================================

do_register_ue(#{pgw_u_teid := PgwTeid, pgw_u_ip := PgwIP,
                 ue_inner_ip := InnerIP} = P,
               #state{by_teid = Map, next_teid = N, by_owner = Owners,
                      by_inner_ip = ByIp, pools = Pools} = State) ->
    InnerIP6 = maps:get(ue_inner_ip6, P, undefined),
    case validate_inner_ips(InnerIP, InnerIP6, Pools) of
        {error, BadIps} ->
            logger:error("GTP-U: rejecting UE registration — inner IP(s) ~s "
                         "outside every configured UE pool "
                         "(EPDG_UE_IP_POOLS); check the PGW PAA ranges "
                         "against the pool config",
                         [lists:join(", ", [inet:ntoa(Ip) || Ip <- BadIps])]),
            epdg_metrics:inc(ue_ip_outside_pool_total),
            {{error, ue_ip_outside_configured_pools}, State};
        ok ->
            do_register_ue_valid(P, InnerIP, InnerIP6, PgwTeid, PgwIP,
                                 Map, N, Owners, ByIp, State)
    end.

do_register_ue_valid(P, InnerIP, InnerIP6, PgwTeid, PgwIP,
                     Map, N, Owners, ByIp, State) ->
    %% The FSM generates a 32-bit TEID in new_teid/0, advertises it to
    %% the PGW-U in the Create-Session F-TEID IE, and passes it in
    %% here as `local_teid_hint`. The PGW-U then uses THAT value as
    %% the TEID on every downlink GTP-U T-PDU. If we key the `by_teid`
    %% map on an internally-assigned counter instead, every downlink
    %% PDU misses the lookup and gets silently dropped. Always prefer
    %% the hint when present.
    LocalTeid = case maps:get(local_teid_hint, P, undefined) of
                    I when is_integer(I), I > 0 -> I;
                    _                           -> N
                end,
    Owner = maps:get(owner_pid, P, undefined),
    case is_pid(Owner) of
        true  -> erlang:monitor(process, Owner);
        false -> ok
    end,
    Ent = #ue_ent{local_teid = LocalTeid,
                  pgw_u_teid = PgwTeid,
                  pgw_u_ip = PgwIP,
                  ue_inner_ip = InnerIP,
                  ue_inner_ip6 = InnerIP6,
                  owner_pid = Owner},
    Owners1 = case Owner of
        undefined -> Owners;
        _         -> Owners#{Owner => LocalTeid}
    end,
    %% Last-writer-wins on a re-attach that reuses the same inner IP
    %% before the stale session's cleanup ran (the FSM-level IMSI
    %% supersede tears the old session down shortly after); the guarded
    %% delete in do_unregister_teid/2 keeps the fresh mapping intact.
    ByIp1 = lists:foldl(fun(K, Acc) -> Acc#{K => LocalTeid} end,
                        ByIp, inner_ip_keys(InnerIP, InnerIP6)),
    {{ok, #{local_teid => LocalTeid, tun_name => State#state.tun_name}},
     State#state{by_teid = Map#{LocalTeid => Ent},
                 by_owner = Owners1,
                 by_inner_ip = ByIp1,
                 next_teid = N + 1}}.

do_unregister_teid(Teid, #state{by_teid = Map, by_ded = Ded, by_owner = Owners,
                                 by_inner_ip = ByIp} = State) ->
    case maps:take(Teid, Map) of
        {#ue_ent{owner_pid = Owner, ded_teids = DedTeids,
                 ue_inner_ip = InnerIP, ue_inner_ip6 = InnerIP6}, Rest} ->
            %% Drop this UE's dedicated bearers along with its default bearer.
            Ded1 = lists:foldl(fun(DT, Acc) ->
                       case maps:is_key(DT, Acc) of
                           true  -> epdg_metrics:gauge_dec(gtpu_dedicated_bearers_active),
                                    maps:remove(DT, Acc);
                           false -> Acc
                       end
                   end, Ded, DedTeids),
            Owners1 = case Owner of
                undefined -> Owners;
                _         -> maps:remove(Owner, Owners)
            end,
            %% Remove the inner-IP mappings — but only those still owned
            %% by this TEID, so tearing down a superseded session cannot
            %% break the re-attached one that took over the IP.
            ByIp1 = lists:foldl(
                      fun(K, Acc) ->
                              case Acc of
                                  #{K := T} when T =:= Teid -> maps:remove(K, Acc);
                                  _                         -> Acc
                              end
                      end, ByIp, inner_ip_keys(InnerIP, InnerIP6)),
            State#state{by_teid = Rest, by_ded = Ded1,
                        by_owner = Owners1, by_inner_ip = ByIp1};
        error ->
            State
    end.

%% The by_inner_ip keys for a UE's assigned addresses: exact IPv4 address
%% (skipped for a v6-only bearer, where IPv4 is unset or the unspecified
%% address) and the /64 prefix of the IPv6 address when present.
inner_ip_keys(Ip4, Ip6) ->
    K4 = case Ip4 of
             {A, B, C, D} when {A, B, C, D} =/= {0, 0, 0, 0} -> [{A, B, C, D}];
             _                                               -> []
         end,
    K6 = case Ip6 of
             {S1, S2, S3, S4, _, _, _, _} -> [{v6, {S1, S2, S3, S4}}];
             _                            -> []
         end,
    K4 ++ K6.

%% Check the PGW-assigned inner address(es) against the configured pools.
%% Only present addresses are validated; a UE with no inner address at
%% all still registers (downlink by TEID works, uplink is impossible),
%% matching the previous behaviour.
validate_inner_ips(Ip4, Ip6, Pools) ->
    Addrs = [Ip || Ip <- [Ip4, Ip6],
                   is_tuple(Ip),
                   Ip =/= {0, 0, 0, 0}],
    case [Ip || Ip <- Addrs, not in_any_pool(Ip, Pools)] of
        []  -> ok;
        Bad -> {error, Bad}
    end.

in_any_pool(Ip, Pools) ->
    lists:any(fun(Pool) -> ip_in_cidr(Ip, Pool) end, Pools).

ip_in_cidr({_, _, _, _} = Ip, {{_, _, _, _} = Base, Len}) ->
    prefix_match(ip_to_int(Ip), ip_to_int(Base), 32, Len);
ip_in_cidr({_, _, _, _, _, _, _, _} = Ip,
           {{_, _, _, _, _, _, _, _} = Base, Len}) ->
    prefix_match(ip_to_int(Ip), ip_to_int(Base), 128, Len);
ip_in_cidr(_, _) ->
    false.

prefix_match(A, B, Bits, Len) when Len >= 0, Len =< Bits ->
    Shift = Bits - Len,
    (A bsr Shift) =:= (B bsr Shift);
prefix_match(_, _, _, _) ->
    false.

ip_to_int({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
ip_to_int({S1, S2, S3, S4, S5, S6, S7, S8}) ->
    lists:foldl(fun(S, Acc) -> (Acc bsl 16) bor S end, 0,
                [S1, S2, S3, S4, S5, S6, S7, S8]).

%%====================================================================
%% Dedicated bearer registration
%%====================================================================

do_register_bearer(#{default_teid := DefTeid, local_teid := DedTeid,
                     pgw_u_teid := PgwTeid, pgw_u_ip := PgwIP} = P,
                   #state{by_teid = Map, by_ded = Ded} = State) ->
    case maps:find(DefTeid, Map) of
        {ok, #ue_ent{owner_pid = Owner, ded_teids = DedTeids} = Ent} ->
            Filters = maps:get(filters, P, []),
            DedEnt = #ded_ent{default_teid = DefTeid,
                              pgw_u_teid   = PgwTeid,
                              pgw_u_ip     = PgwIP,
                              filters      = Filters,
                              owner_pid    = Owner},
            %% Idempotent on re-registration of the same dedicated TEID.
            WasKey = maps:is_key(DedTeid, Ded),
            case WasKey of
                false -> epdg_metrics:gauge_inc(gtpu_dedicated_bearers_active);
                true  -> ok
            end,
            Ent1 = Ent#ue_ent{ded_teids = lists:usort([DedTeid | DedTeids])},
            {ok, State#state{by_teid = Map#{DefTeid => Ent1},
                             by_ded  = Ded#{DedTeid => DedEnt}}};
        error ->
            {{error, no_default_bearer}, State}
    end;
do_register_bearer(_, State) ->
    {{error, invalid_params}, State}.

do_unregister_bearer(DedTeid, #state{by_teid = Map, by_ded = Ded} = State) ->
    case maps:take(DedTeid, Ded) of
        {#ded_ent{default_teid = DefTeid}, Ded1} ->
            epdg_metrics:gauge_dec(gtpu_dedicated_bearers_active),
            Map1 = case maps:find(DefTeid, Map) of
                {ok, #ue_ent{ded_teids = DedTeids} = Ent} ->
                    Map#{DefTeid =>
                         Ent#ue_ent{ded_teids = lists:delete(DedTeid, DedTeids)}};
                error ->
                    Map
            end,
            State#state{by_teid = Map1, by_ded = Ded1};
        error ->
            State
    end.

%% A downlink TEID is deliverable if it belongs to a registered default
%% or dedicated bearer.
known_teid(Teid, #state{by_teid = Map, by_ded = Ded}) ->
    maps:is_key(Teid, Map) orelse maps:is_key(Teid, Ded).

%%====================================================================
%% Forwarding
%%====================================================================

%% Uplink from the shared TUN: attribute the packet to its default
%% bearer via the inner source IP, then run the normal TFT
%% classification for dedicated bearers.
handle_uplink(Pkt, #state{by_inner_ip = ByIp} = State) ->
    case uplink_teid(Pkt, ByIp) of
        {ok, Teid} ->
            do_send_inner(Teid, Pkt, State);
        _NoBearer -> %% unknown_src | malformed
            epdg_metrics:inc(gtpu_uplink_unknown_src_total),
            State
    end.

uplink_teid(Pkt, ByInnerIp) ->
    case inner_src_key(Pkt) of
        {ok, Key} ->
            case ByInnerIp of
                #{Key := Teid} -> {ok, Teid};
                _              -> unknown_src
            end;
        error ->
            malformed
    end.

%% Extract the classification key from an uplink inner IP packet:
%% IPv4 -> the exact source address, IPv6 -> {v6, /64 source prefix}.
%%
%% The IPv6 key is the /64 prefix rather than the full address because
%% the PGW delegates a whole /64 per UE (open5gs carves /64s out of the
%% configured pool prefix) and the UE may source traffic from ANY
%% address it forms inside it (SLAAC, RFC 4941 privacy addresses) —
%% exact-address matching would drop everything except the single PAA
%% interface identifier.
inner_src_key(<<4:4, _IHL:4, _:11/binary, A, B, C, D, _:4/binary, _/binary>>) ->
    {ok, {A, B, C, D}};
inner_src_key(<<6:4, _:4, _:7/binary, S1:16, S2:16, S3:16, S4:16,
                _:8/binary, _:16/binary, _/binary>>) ->
    {ok, {v6, {S1, S2, S3, S4}}};
inner_src_key(_) ->
    error.

do_send_inner(_Teid, _Pkt, #state{socket = undefined} = State) -> State;
do_send_inner(Teid, Pkt,
              #state{socket = Sock, by_teid = Map} = State) ->
    case maps:find(Teid, Map) of
        {ok, #ue_ent{pgw_u_teid = DefTeid, pgw_u_ip = DefIP,
                     ded_teids = DedTeids}} ->
            %% Uplink bearer binding: a packet matching a dedicated bearer's
            %% uplink TFT rides that bearer's S2b-U tunnel; everything else
            %% stays on the default bearer.
            {PgwTeid, PgwIP} =
                classify_uplink(Pkt, DedTeids, State, {DefTeid, DefIP}),
            Packet = encode_gtpu_tpdu(PgwTeid, Pkt),
            case gen_udp:send(Sock, PgwIP, ?GTPU_PORT, Packet) of
                ok ->
                    epdg_metrics:inc(gtpu_tx_pkts),
                    epdg_metrics:inc(gtpu_tx_bytes, byte_size(Pkt)),
                    ok;
                _ -> ok
            end;
        error -> ok
    end,
    State.

%% Pick the PGW-U endpoint for an uplink packet: the first dedicated bearer
%% whose uplink TFT matches, else the default bearer.
classify_uplink(_Pkt, [], _State, Default) -> Default;
classify_uplink(Pkt, DedTeids, #state{by_ded = Ded}, Default) ->
    classify_uplink_1(DedTeids, Pkt, Ded, Default).

classify_uplink_1([], _Pkt, _Ded, Default) -> Default;
classify_uplink_1([DT | Rest], Pkt, Ded, Default) ->
    case maps:find(DT, Ded) of
        {ok, #ded_ent{pgw_u_teid = T, pgw_u_ip = IP, filters = F}} ->
            case epdg_tft:match(F, Pkt) of
                true ->
                    epdg_metrics:inc(gtpu_uplink_dedicated_pkts_total),
                    {T, IP};
                false ->
                    classify_uplink_1(Rest, Pkt, Ded, Default)
            end;
        error ->
            classify_uplink_1(Rest, Pkt, Ded, Default)
    end.

%%====================================================================
%% GTP-U codec (T-PDU only)
%%====================================================================

encode_gtpu_tpdu(Teid, Payload) ->
    Len = byte_size(Payload),
    <<?GTPU_HDR_FLAGS:8, ?GTPU_MSG_TPDU:8, Len:16, Teid:32, Payload/binary>>.

decode_gtpu(<<Ver:3, _PT:1, E:1, S:1, PN:1, _Spare:1,
              ?GTPU_MSG_TPDU:8, _Len:16, Teid:32, Rest/binary>>)
  when Ver =:= 1 ->
    %% Skip optional fields when flagged (TS 29.281 §5.1)
    Payload = skip_opt(E, S, PN, Rest),
    {ok, Teid, Payload};
decode_gtpu(_) ->
    error.

skip_opt(0, 0, 0, Bin) -> Bin;
skip_opt(E, S, PN, <<_SeqPnNext:32, Rest/binary>>)
  when (E bor S bor PN) =/= 0 ->
    case E of
        1 -> skip_ext_hdrs(Rest);
        _ -> Rest
    end;
skip_opt(_, _, _, Bin) -> Bin.

skip_ext_hdrs(<<0:8, Rest/binary>>) -> Rest;
skip_ext_hdrs(<<Len:8, Rest/binary>>) when Len > 0 ->
    Skip = Len * 4 - 1,
    case Rest of
        <<_:Skip/binary, NextType:8, More/binary>> ->
            case NextType of
                0 -> More;
                _ -> skip_ext_hdrs(<<NextType, More/binary>>)
            end;
        _ -> Rest
    end;
skip_ext_hdrs(Bin) -> Bin.

%%====================================================================
%% Shared TUN device plumbing
%%
%% One Linux TUN device (IFF_TUN | IFF_NO_PI) per ePDG pod, created once
%% in init/1. A small C helper (`epdg_tun_port', see
%% c_src/epdg_tun_port.c) owns the /dev/net/tun fd and bridges it to the
%% BEAM over stdio with {packet, 2} framing: port_command/2 writes
%% downlink GTP-U payloads into the TUN, {Port, {data, Pkt}} messages
%% carry UE-originated uplink packets.
%%
%% After the kernel XFRM subsystem decrypts inbound ESP from a UE, the
%% cleartext packet (src = UE inner IP, inside one of the configured
%% pools) matches the per-pool `from <pool> lookup ?SHARED_TABLE' rule
%% and rides the shared table's default route out the TUN, where the
%% helper reads it. The reverse path (PGW T-PDU written into the TUN)
%% re-enters routing via the `iif epdg0' rule; the shared table's
%% default route satisfies the FIB lookup and the kernel's outbound
%% XFRM policy for `dst UE_IP' encrypts and emits ESP-in-UDP toward the
%% UE. The rule/route count is constant in the number of configured
%% pools — nothing here scales with the session count.
%%
%% CRITICAL: the shared table's default route must NOT live in MAIN.
%% The ePDG runs on hostNetwork and shares the node routing table with
%% a co-located PGW-U; polluting MAIN would shadow the PGW-U's ogstun
%% pool routes and black-hole its traffic. Conversely, PGW-U-decapped
%% uplink (src inside the same pools, iif ogstun*) must escape the
%% `from <pool>' rules — see ensure_pgwu_escape_rules/0.
%%
%% Scaling note: the single helper process serialises all uplink reads.
%% If it ever becomes the bottleneck, open the device with
%% IFF_MULTI_QUEUE and spawn one helper (one queue fd) per BEAM
%% scheduler; by_inner_ip classification is stateless per packet, so
%% queues can be consumed concurrently.
%%====================================================================

setup_shared_tun(Pools) ->
    Name = ?SHARED_TUN,
    WantV6 = lists:any(fun({Base, _}) -> tuple_size(Base) =:= 8 end, Pools),
    ensure_forwarding_sysctls(WantV6),
    %% Idempotent: "File exists" from a device that survived a previous
    %% run (hostNetwork persists devices across pod restarts) is fine —
    %% the helper re-attaches to the existing device by name.
    run_quiet(io_lib:format("ip tuntap add dev ~s mode tun", [Name])),
    case filelib:is_dir("/sys/class/net/" ++ Name) of
        false ->
            logger:error("TUN: cannot create shared device ~s (missing "
                         "NET_ADMIN / /dev/net/tun?) — datapath disabled",
                         [Name]),
            undefined;
        true ->
            %% Delete-then-add so a crashed previous run cannot leave
            %% duplicate rules behind (there is no `ip rule replace').
            Selectors = shared_rule_selectors(Name, Pools),
            lists:foreach(fun({Fam, Sel}) ->
                run_quiet(rule_cmd(Fam, "del", Sel))
            end, Selectors),
            BaseCmds = [
                io_lib:format("ip link set dev ~s up", [Name]),
                %% Loose rp_filter on the TUN so decrypted uplink with
                %% src=UE_IP isn't dropped as a martian (asymmetric path).
                %% Values 0 (none) and 2 (loose) are both safe; only 1
                %% (strict) drops asymmetric-path packets. The host or
                %% pod-level sysctls may already set default.rp_filter
                %% to 0 or 2, in which case new interfaces inherit it.
                io_lib:format(
                    "val=$(cat /proc/sys/net/ipv4/conf/~s/rp_filter "
                    "2>/dev/null); [ \"$val\" != 1 ] || "
                    "sysctl -wq net.ipv4.conf.~s.rp_filter=2", [Name, Name])
            ],
            V6Cmds = case WantV6 of
                true ->
                    %% Make sure IPv6 is enabled on the TUN even if the
                    %% host disables it by default.
                    [io_lib:format("sysctl -wq net.ipv6.conf.~s.disable_ipv6=0",
                                   [Name]),
                     io_lib:format("ip -6 route replace default dev ~s table ~B",
                                   [Name, ?SHARED_TABLE])];
                false ->
                    []
            end,
            RouteCmds = [
                %% The shared table's only route: any destination goes out
                %% the shared TUN. Satisfies both the uplink lookup (dst =
                %% arbitrary IMS/internet address, selected by the
                %% `from <pool>' rules) and the downlink lookup (dst =
                %% UE IP, selected by the `iif' rule), where the XFRM OUT
                %% policy then intercepts the packet.
                io_lib:format("ip route replace default dev ~s table ~B",
                              [Name, ?SHARED_TABLE])
            ],
            RuleCmds = [rule_cmd(Fam, "add", Sel) || {Fam, Sel} <- Selectors],
            run_cmds_or_warn(Name, BaseCmds ++ RouteCmds ++ V6Cmds ++ RuleCmds),
            open_tun_port(Name)
    end.

teardown_shared_tun(Pools) ->
    Name = ?SHARED_TUN,
    lists:foreach(fun({Fam, Sel}) ->
        run_quiet(rule_cmd(Fam, "del", Sel))
    end, shared_rule_selectors(Name, Pools)),
    run_quiet(io_lib:format("ip route flush table ~B", [?SHARED_TABLE])),
    run_quiet(io_lib:format("ip -6 route flush table ~B", [?SHARED_TABLE])),
    delete_tun_dev(Name).

%% The constant set of policy-routing rules for the shared datapath:
%%
%%   - one `iif <tun>' rule per address family (downlink: packets the
%%     forwarder injects into the TUN re-enter routing here and must
%%     resolve via the shared table, NOT via MAIN);
%%   - one `from <pool>' rule per configured UE pool (uplink:
%%     XFRM-decrypted SWu packets carry src = UE inner IP and must be
%%     steered into the TUN for GTP-U encapsulation).
%%
%% All rules share ?SHARED_RULE_PRIO: they sort strictly after the
%% PGW-U escape rules (?PGWU_ESCAPE_PRIO) and strictly before the main
%% table (32766).
shared_rule_selectors(Name, Pools) ->
    Iif = "iif " ++ Name,
    WantV6 = lists:any(fun({Base, _}) -> tuple_size(Base) =:= 8 end, Pools),
    IifRules = [{"ip", Iif}] ++ [{"ip -6", Iif} || WantV6],
    PoolRules = [{family_cmd(Base), "from " ++ cidr_str(Pool)}
                 || {Base, _} = Pool <- Pools],
    IifRules ++ PoolRules.

rule_cmd(Fam, Op, Selector) ->
    io_lib:format("~s rule ~s ~s lookup ~B priority ~B",
                  [Fam, Op, Selector, ?SHARED_TABLE, ?SHARED_RULE_PRIO]).

family_cmd(Base) when tuple_size(Base) =:= 8 -> "ip -6";
family_cmd(_)                                -> "ip".

cidr_str({Base, Len}) ->
    lists:flatten(io_lib:format("~s/~B", [inet:ntoa(Base), Len])).

run_quiet(Cmd) ->
    _ = os:cmd(lists:flatten(Cmd) ++ " 2>/dev/null"),
    ok.

run_cmds_or_warn(Name, Cmds) ->
    lists:foldl(
      fun(C, Acc) ->
              Out = os:cmd(lists:flatten(C) ++ " 2>&1"),
              case string:trim(Out) of
                  "" -> Acc;
                  _  ->
                      logger:warning("TUN ~s: cmd=~s out=~s",
                                     [Name, lists:flatten(C), Out]),
                      Acc
              end
      end, ok, Cmds).

%% Verify forwarding sysctls are in effect. When set via pod-level
%% securityContext.sysctls or host-level /etc/sysctl.d/ the values
%% are already correct and the write attempts are harmless no-ops
%% (or fail on a read-only /proc/sys).
ensure_forwarding_sysctls(WantV6) ->
    _ = os:cmd("sysctl -wq net.ipv4.ip_forward=1 2>&1"),
    verify_sysctl_exact("net.ipv4.ip_forward", "1"),
    verify_rp_filter("net.ipv4.conf.all.rp_filter"),
    case WantV6 of
        true ->
            _ = os:cmd("sysctl -wq net.ipv6.conf.all.forwarding=1 2>&1"),
            verify_sysctl_exact("net.ipv6.conf.all.forwarding", "1");
        false ->
            ok
    end,
    ok.

%% Escape rules for a co-located PGW-U.
%%
%% The ePDG runs on hostNetwork and shares the node routing table with a
%% co-located PGW-U. When the PGW-U decapsulates GTP-U uplink it injects
%% the inner packet (src=UE_IP) through its ogstun device for normal
%% forwarding toward the IMS core. Without an escape rule that packet
%% matches the shared `from <pool>' rule (shared_rule_selectors/2) —
%% which is meant for XFRM-decrypted SWu uplink only — and is looped
%% back into the ePDG's TUN instead of reaching the network: a total
%% uplink black-hole for every UE whose anchoring PGW-U sits on the
%% ePDG's own node.
%%
%% Fix: anything entering through an ogstun device is routed via the
%% main table, at a priority strictly below the pool rules. The rules
%% are node-global, idempotent, and intentionally never torn down.
%% XFRM-decrypted SWu uplink is unaffected (iif = the underlay NIC), as
%% is downlink the forwarder injects into the shared TUN (iif = epdg0).
ensure_pgwu_escape_rules() ->
    Prio = ?PGWU_ESCAPE_PRIO,
    Sh = io_lib:format(
        "for d in /sys/class/net/ogstun*; do "
          "[ -e \"$d\" ] || continue; dev=${d##*/}; "
          "ip rule list | grep -q \"^~B:.*iif $dev \" || "
            "ip rule add iif \"$dev\" lookup main priority ~B; "
          "ip -6 rule list | grep -q \"^~B:.*iif $dev \" || "
            "ip -6 rule add iif \"$dev\" lookup main priority ~B; "
        "done 2>&1",
        [Prio, Prio, Prio, Prio]),
    case string:trim(os:cmd(lists:flatten(Sh))) of
        ""  -> ok;
        Out -> logger:warning("PGW-U escape rules: ~s", [Out]), ok
    end.

verify_sysctl_exact(Key, Expected) ->
    case read_sysctl(Key) of
        Expected -> ok;
        {error, Reason} ->
            logger:warning("sysctl ~s: ~s", [Key, Reason]);
        Actual ->
            logger:error("sysctl ~s=~s (need ~s); add to pod "
                         "securityContext.sysctls or run in "
                         "privileged mode", [Key, Actual, Expected])
    end.

%% rp_filter: 0 (none) and 2 (loose) are both safe for the ePDG's
%% asymmetric TUN path. Only 1 (strict) drops uplink packets.
verify_rp_filter(Key) ->
    case read_sysctl(Key) of
        "1" ->
            logger:error("sysctl ~s=1 (strict); uplink will be dropped "
                         "— set to 0 or 2 via host sysctl or pod "
                         "securityContext.sysctls", [Key]);
        {error, Reason} ->
            logger:warning("sysctl ~s: ~s", [Key, Reason]);
        _ -> ok
    end.

read_sysctl(Key) ->
    Path = "/proc/sys/" ++ re:replace(Key, "\\.", "/", [global, {return, list}]),
    case file:read_file(list_to_binary(Path)) of
        {ok, Bin} -> string:trim(binary_to_list(Bin));
        {error, _} -> {error, "cannot read " ++ Path}
    end.

open_tun_port(Name) ->
    case locate_tun_helper() of
        {ok, Exec} ->
            try
                Port = erlang:open_port(
                    {spawn_executable, Exec},
                    [{args, [Name]}, {packet, 2}, binary, exit_status, use_stdio]),
                Port
            catch
                error:Reason ->
                    logger:error("TUN: failed to spawn port helper for ~s: ~p",
                                 [Name, Reason]),
                    undefined
            end;
        error ->
            logger:error("TUN: helper binary epdg_tun_port not found for ~s "
                         "— uplink/downlink forwarding will be inactive",
                         [Name]),
            undefined
    end.

%% Prefer the binary shipped alongside the release (see Dockerfile); fall
%% back to PATH so local dev builds that put the helper on $PATH keep
%% working without rebuilding the whole image.
locate_tun_helper() ->
    Release = filename:join([code:root_dir(), "bin", "epdg_tun_port"]),
    case filelib:is_regular(Release) of
        true  -> {ok, Release};
        false ->
            case os:find_executable("epdg_tun_port") of
                false -> error;
                Path  -> {ok, Path}
            end
    end.

delete_tun_dev(undefined) -> ok;
delete_tun_dev(Name) ->
    run_quiet(io_lib:format("ip tuntap del dev ~s mode tun", [Name])).

tun_write(undefined, _Pkt) -> ok;
tun_write(Port, Pkt) when is_port(Port), is_binary(Pkt) ->
    try erlang:port_command(Port, Pkt, [nosuspend]) of
        true  -> ok;
        false -> ok  %% busy / hi-watermark — drop; UE will retransmit
    catch
        error:_ -> ok
    end.

%%====================================================================
%% Startup cleanup of legacy per-UE TUN devices
%%
%% Releases before the shared-TUN datapath created one TUN device
%% ("ue<teid>"), one routing table and two-to-four ip rules PER default
%% bearer. On hostNetwork those survive pod restarts, so the first
%% start after an upgrade must sweep them or they linger forever. This
%% whole section exists only for that migration path.
%%====================================================================

cleanup_stale_tun_devices() ->
    Raw = os:cmd("ip -o link show type tun 2>/dev/null"),
    Lines = string:split(Raw, "\n", all),
    Stale = [Name || L <- Lines,
                     Name <- [extract_ue_tun_name(L)],
                     Name =/= undefined],
    lists:foreach(fun(Name) ->
        Ip = tun_ip_from_route(Name),
        Teid = teid_from_tun_name(Name),
        teardown_legacy_ue_routing(Ip, Teid),
        delete_tun_dev(Name),
        epdg_metrics:inc(tun_startup_cleaned_total)
    end, Stale),
    case length(Stale) of
        0 -> ok;
        N -> logger:notice("Startup cleanup: removed ~B stale per-UE TUN "
                           "device(s) from a pre-shared-TUN release", [N])
    end.

extract_ue_tun_name(Line) ->
    case re:run(Line, "\\b(ue[0-9]+):", [{capture, [1], list}]) of
        {match, [Name]} -> Name;
        _               -> undefined
    end.

teid_from_tun_name("ue" ++ Digits) ->
    try list_to_integer(Digits)
    catch _:_ -> 0
    end;
teid_from_tun_name(_) -> 0.

%% Route-table / rule-priority id the LEGACY per-UE datapath derived from
%% the local TEID. Kept solely so the startup sweep can address the
%% tables and rules a pre-shared-TUN release left behind.
legacy_ue_route_table(LocalTeid) ->
    1000 + (LocalTeid rem 30000).

tun_ip_from_route(Name) ->
    %% The legacy datapath kept the UE's /32 in the per-UE policy table
    %% (not in main), so query that table (id derived from the TEID) and
    %% ignore its default route.
    Table = legacy_ue_route_table(teid_from_tun_name(Name)),
    Cmd = lists:flatten(io_lib:format(
        "ip route show table ~B dev ~s 2>/dev/null "
        "| grep -v default | head -1 | awk '{print $1}'", [Table, Name])),
    Raw = string:trim(os:cmd(Cmd)),
    case parse_route_ip(Raw) of
        {ok, Ip} -> Ip;
        _        -> undefined
    end.

parse_route_ip(Str) ->
    %% Strip /32 suffix if present
    Bare = case string:split(Str, "/") of
        [H | _] -> H;
        _       -> Str
    end,
    case inet:parse_ipv4_address(Bare) of
        {ok, Ip} -> {ok, Ip};
        _        -> error
    end.

teardown_legacy_ue_routing(Ip, Teid) ->
    Table = legacy_ue_route_table(Teid),
    %% The legacy downlink iif rule is keyed on the TUN device name,
    %% which is derived purely from the TEID — so it can always be
    %% removed, even when the UE IP is unknown.
    Name = lists:flatten(io_lib:format("ue~B", [Teid])),
    case Ip of
        {A,B,C,D} when {A,B,C,D} =/= {0,0,0,0} ->
            UeIp = io_lib:format("~B.~B.~B.~B", [A,B,C,D]),
            run_quiet(io_lib:format("ip rule del from ~s/32 lookup ~B priority ~B",
                                    [UeIp, Table, Table]));
        _ -> ok
    end,
    run_quiet(io_lib:format("ip rule del iif ~s lookup ~B priority ~B",
                            [Name, Table, Table])),
    run_quiet(io_lib:format("ip route flush table ~B", [Table])),
    %% IPv6: remove the downlink iif rule by selector, the uplink
    %% from-rule by priority (works even though the UE's IPv6 is
    %% unknown here), and flush the per-UE v6 table.
    run_quiet(io_lib:format("ip -6 rule del iif ~s lookup ~B priority ~B",
                            [Name, Table, Table])),
    run_quiet(io_lib:format("ip -6 rule del priority ~B", [Table])),
    run_quiet(io_lib:format("ip -6 route flush table ~B", [Table])),
    ok.

%%====================================================================
%% Helpers
%%====================================================================

parse_ip_or_any(undefined) -> {0,0,0,0};
parse_ip_or_any(Str) when is_list(Str) ->
    case inet:parse_address(Str) of
        {ok, IP} -> IP;
        _        -> {0,0,0,0}
    end;
parse_ip_or_any(T) when is_tuple(T) -> T.

%%====================================================================
%% Test helpers
%%====================================================================

-ifdef(TEST).
%% Minimal #state{} constructor for the EUnit suite: socket-less and
%% TUN-less, so tests exercise the pure bookkeeping/classification code
%% without NET_ADMIN.
new_state_for_test(Pools) ->
    #state{socket = undefined, bind_ip = {0,0,0,0}, bind_port = 0,
           by_teid = #{}, by_ded = #{}, by_owner = #{}, by_inner_ip = #{},
           tun_port = undefined, tun_name = ?SHARED_TUN, pools = Pools,
           next_teid = 16#1000, last_rx_ts = 0}.

register_ue_for_test(Params, State) -> do_register_ue(Params, State).

register_bearer_for_test(Params, State) -> do_register_bearer(Params, State).

unregister_ue_for_test(Teid, State) -> do_unregister_teid(Teid, State).

%% Runs the real uplink entry point (metric side effects included) and
%% returns the possibly-updated state.
uplink_for_test(Pkt, State) -> handle_uplink(Pkt, State).

%% Returns the uplink classification decision without sending anything:
%% {ok, DefaultTeid, {PgwTeid, PgwIP}} | unknown_src | malformed.
classify_for_test(Pkt, #state{by_teid = Map, by_inner_ip = ByIp} = State) ->
    case uplink_teid(Pkt, ByIp) of
        {ok, Teid} ->
            case maps:find(Teid, Map) of
                {ok, #ue_ent{pgw_u_teid = DT, pgw_u_ip = DIP,
                             ded_teids = Ded}} ->
                    {ok, Teid, classify_uplink(Pkt, Ded, State, {DT, DIP})};
                error ->
                    unknown_src
            end;
        Other ->
            Other
    end.
-endif.
