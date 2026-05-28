%%%-------------------------------------------------------------------
%%% @doc Userspace GTP-U forwarder for the ePDG data plane.
%%%
%%% Bridges the UE's inner IP traffic (coming out of the kernel's ESP
%%% SAs into a per-UE TUN device) to the PGW-U over GTP-U/UDP 2152 and
%%% back. One process per ePDG pod owns a single UDP socket shared
%%% across every active UE; per-UE TUN devices handle the "inside"
%%% plumbing.
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
         send/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER,     ?MODULE).
-define(GTPU_PORT,  2152).
-define(GTPU_HDR_FLAGS, 16#30).
-define(GTPU_MSG_TPDU,  16#FF).

-record(ue_ent, {
    local_teid   :: non_neg_integer(),
    pgw_u_teid   :: non_neg_integer(),
    pgw_u_ip     :: inet:ip_address(),
    tun_name     :: string(),
    tun_port     :: port() | undefined,
    ue_inner_ip  :: inet:ip_address(),
    owner_pid    :: pid() | undefined
}).

-record(state, {
    socket     :: gen_udp:socket() | undefined,
    bind_ip    :: inet:ip_address(),
    bind_port  :: inet:port_number(),
    %% local_teid -> #ue_ent{}
    by_teid    :: #{non_neg_integer() => #ue_ent{}},
    %% pid() -> local_teid for cleanup on owner DOWN
    by_owner   :: #{pid() => non_neg_integer()},
    %% port() -> local_teid so we can route TUN-read packets to their
    %% bearer without scanning by_teid on the hot path.
    by_port    :: #{port() => non_neg_integer()},
    next_teid  :: non_neg_integer(),
    last_rx_ts :: integer()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Register a UE bearer: allocates a local TEID, optionally spawns a
%% TUN device, and returns the allocated TEID + TUN name.
%%
%% Params:
%%   pgw_u_teid    - integer, from the Create-Session-Response F-TEID
%%   pgw_u_ip      - inet:ip_address(), from the same F-TEID
%%   ue_inner_ip   - inet:ip_address(), from PAA
%%   imsi          - binary (used only in TUN name suffix)
%%   owner_pid     - pid() of the owning UE FSM (we monitor for cleanup)
-spec register_ue(map()) ->
    {ok, #{local_teid => non_neg_integer(), tun_name => string()}}
    | {error, term()}.
register_ue(Params) ->
    gen_server:call(?SERVER, {register_ue, Params}).

-spec unregister_ue(non_neg_integer()) -> ok.
unregister_ue(LocalTeid) ->
    gen_server:call(?SERVER, {unregister_ue, LocalTeid}).

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
    cleanup_stale_tun_devices(),
    BindIpStr = epdg_config:get(gtpu_bind_addr, "0.0.0.0"),
    BindIp    = parse_ip_or_any(BindIpStr),
    Port      = epdg_config:get(gtpu_port, ?GTPU_PORT),

    InetFamily = case BindIp of
        {_,_,_,_,_,_,_,_} -> inet6;
        _                 -> inet
    end,
    case gen_udp:open(Port, [binary, {ip, BindIp}, {active, true},
                              {reuseaddr, true}, InetFamily]) of
        {ok, Socket} ->
            logger:info("GTP-U forwarder on ~p:~p", [BindIp, Port]),
            schedule_gc(),
            {ok, #state{socket = Socket,
                        bind_ip = BindIp,
                        bind_port = Port,
                        by_teid = #{},
                        by_owner = #{},
                        by_port = #{},
                        next_teid = 16#1000,
                        last_rx_ts = erlang:system_time(second)}};
        {error, eaddrinuse} ->
            %% Running outside a real ePDG pod (e.g. during unit tests)
            %% — start in a degraded mode so the supervisor comes up.
            logger:warning("GTP-U: bind ~p:~p failed (eaddrinuse); "
                           "forwarder disabled", [BindIp, Port]),
            schedule_gc(),
            {ok, #state{socket = undefined, bind_ip = BindIp,
                        bind_port = Port, by_teid = #{}, by_owner = #{},
                        by_port = #{}, next_teid = 16#1000,
                        last_rx_ts = erlang:system_time(second)}};
        {error, Reason} ->
            logger:warning("GTP-U: bind ~p:~p failed: ~p; forwarder disabled",
                           [BindIp, Port, Reason]),
            schedule_gc(),
            {ok, #state{socket = undefined, bind_ip = BindIp,
                        bind_port = Port, by_teid = #{}, by_owner = #{},
                        by_port = #{}, next_teid = 16#1000,
                        last_rx_ts = erlang:system_time(second)}}
    end.

handle_call({register_ue, Params}, _From, State) ->
    {Reply, NewState} = do_register_ue(Params, State),
    {reply, Reply, NewState};
handle_call({unregister_ue, LocalTeid}, _From, State) ->
    {reply, ok, do_unregister_teid(LocalTeid, State)};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast({send, Teid, Pkt}, State) ->
    {noreply, do_send_inner(Teid, Pkt, State)};
handle_cast({pgw_restart, _}, State) ->
    logger:warning("GTP-U: pgw_restart received — flushing all TEID registrations"),
    maps:fold(fun(_, Ent, _) -> close_tun_ent(Ent), ok end,
              ok, State#state.by_teid),
    {noreply, State#state{by_teid = #{}, by_owner = #{}, by_port = #{}}};
handle_cast(_Msg, State) -> {noreply, State}.

handle_info({udp, _Sock, _FromIP, _FromPort, Packet},
            #state{by_teid = Map} = State) ->
    case decode_gtpu(Packet) of
        {ok, Teid, Payload} ->
            epdg_metrics:inc(gtpu_rx_pkts),
            epdg_metrics:inc(gtpu_rx_bytes, byte_size(Payload)),
            case maps:find(Teid, Map) of
                {ok, #ue_ent{tun_port = TP}} ->
                    tun_write(TP, Payload);
                _ ->
                    ok
            end,
            {noreply, State#state{last_rx_ts = erlang:system_time(second)}};
        _ ->
            {noreply, State}
    end;
handle_info({tun_packet, LocalTeid, Pkt}, State) ->
    {noreply, do_send_inner(LocalTeid, Pkt, State)};
%% Packet read from a per-UE TUN by the C port helper — forward uplink.
handle_info({Port, {data, Pkt}}, #state{by_port = PMap} = State)
  when is_port(Port) ->
    case maps:find(Port, PMap) of
        {ok, Teid} -> {noreply, do_send_inner(Teid, Pkt, State)};
        error      -> {noreply, State}
    end;
%% Port helper exited — treat as TUN loss for the bearer.
handle_info({'EXIT', Port, Reason}, #state{by_port = PMap} = State)
  when is_port(Port) ->
    case maps:find(Port, PMap) of
        {ok, Teid} ->
            logger:warning("GTP-U: tun port exited teid=~B reason=~p",
                           [Teid, Reason]),
            {noreply, do_unregister_teid(Teid, State)};
        error ->
            {noreply, State}
    end;
handle_info({'DOWN', _MRef, process, Pid, _Reason},
            #state{by_owner = Owners} = State) ->
    case maps:find(Pid, Owners) of
        {ok, Teid} -> {noreply, do_unregister_teid(Teid, State)};
        error      -> {noreply, State}
    end;
handle_info(gc_tun, #state{by_teid = Map} = State) ->
    Stale = find_orphaned_tuns(Map),
    lists:foreach(fun({Name, Ip, Teid}) ->
        teardown_ue_routing(Ip, Teid),
        delete_tun_dev(Name),
        epdg_metrics:inc(tun_gc_cleaned_total),
        logger:info("GC: removed orphaned TUN ~s (teid=~B)", [Name, Teid])
    end, Stale),
    schedule_gc(),
    {noreply, State};
handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, #state{socket = S, by_teid = Map}) ->
    maps:fold(fun(_, Ent, _) -> close_tun_ent(Ent), ok end, ok, Map),
    case S of undefined -> ok; _ -> gen_udp:close(S) end,
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Registration
%%====================================================================

do_register_ue(#{pgw_u_teid := PgwTeid, pgw_u_ip := PgwIP,
                 ue_inner_ip := InnerIP} = P,
               #state{by_teid = Map, next_teid = N,
                      by_owner = Owners, by_port = PMap} = State) ->
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
    TunName   = tun_name_for(P),
    TunPort   = maybe_open_tun(TunName, InnerIP, LocalTeid),
    Owner     = maps:get(owner_pid, P, undefined),
    case is_pid(Owner) of
        true  -> erlang:monitor(process, Owner);
        false -> ok
    end,
    Ent = #ue_ent{local_teid = LocalTeid,
                  pgw_u_teid = PgwTeid,
                  pgw_u_ip = PgwIP,
                  tun_name = TunName,
                  tun_port = TunPort,
                  ue_inner_ip = InnerIP,
                  owner_pid = Owner},
    Owners1 = case Owner of
        undefined -> Owners;
        _         -> Owners#{Owner => LocalTeid}
    end,
    PMap1 = case is_port(TunPort) of
        true  -> PMap#{TunPort => LocalTeid};
        false -> PMap
    end,
    {{ok, #{local_teid => LocalTeid, tun_name => TunName}},
     State#state{by_teid = Map#{LocalTeid => Ent},
                 by_owner = Owners1,
                 by_port = PMap1,
                 next_teid = N + 1}}.

do_unregister_teid(Teid, #state{by_teid = Map, by_owner = Owners,
                                 by_port = PMap} = State) ->
    case maps:take(Teid, Map) of
        {#ue_ent{tun_port = TP, owner_pid = Owner} = Ent, Rest} ->
            close_tun_ent(Ent),
            Owners1 = case Owner of
                undefined -> Owners;
                _         -> maps:remove(Owner, Owners)
            end,
            PMap1 = case is_port(TP) of
                true  -> maps:remove(TP, PMap);
                false -> PMap
            end,
            State#state{by_teid = Rest, by_owner = Owners1, by_port = PMap1};
        error ->
            State
    end.

%%====================================================================
%% Forwarding
%%====================================================================

do_send_inner(_Teid, _Pkt, #state{socket = undefined} = State) -> State;
do_send_inner(Teid, Pkt,
              #state{socket = Sock, by_teid = Map} = State) ->
    case maps:find(Teid, Map) of
        {ok, #ue_ent{pgw_u_teid = PgwTeid, pgw_u_ip = PgwIP}} ->
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
%% TUN device plumbing
%%
%% Each per-UE bearer owns one Linux TUN device (IFF_TUN | IFF_NO_PI).
%% The device is created via `ip tuntap add`, addressed with the UE's
%% inner IP, and brought up. A small C helper (`epdg_tun_port`, see
%% c_src/epdg_tun_port.c) is spawned to own the /dev/net/tun fd and
%% bridge it to the BEAM over stdio using the standard `{packet, 2}`
%% framing. We talk to it via `port_command/2` (downlink: GTP-U payload
%% → TUN) and receive `{Port, {data, Pkt}}` messages (uplink: UE-originated
%% IP packet → GTP-U to PGW).
%%
%% With this plumbing in place, after the kernel XFRM subsystem
%% decrypts inbound ESP from the UE, the cleartext packet is routed
%% toward `dst = ue_inner_ip` — which lives on our TUN — so the C
%% helper reads it on /dev/net/tun and hands it up. The reverse path
%% (PGW T-PDU → TUN write) triggers the kernel's outbound XFRM policy
%% for `src 0.0.0.0/0 dst UE_IP/32`, which encrypts and emits ESP-in-UDP
%% toward the UE.
%%====================================================================

maybe_open_tun(Name, {A,B,C,D} = _Ip, LocalTeid) ->
    %% Linux IFNAMSIZ = 16 bytes incl. trailing NUL: interface names
    %% must be <= 15 chars. Guard here so that upstream generation
    %% mistakes surface as explicit log warnings instead of silent
    %% "ip tuntap add" failures ("dev not a valid ifname") that used
    %% to leave the pod without a TUN.
    case length(Name) =< 15 of
        false ->
            logger:warning("TUN: refusing to create device with name ~s "
                           "(~B chars > IFNAMSIZ-1=15)",
                           [Name, length(Name)]),
            undefined;
        true ->
            ensure_forwarding_sysctls(),
            UeIp = io_lib:format("~B.~B.~B.~B", [A,B,C,D]),
            Table = ue_route_table(LocalTeid),
            %% NOTE: we intentionally do NOT assign the UE's inner IP to
            %% the TUN — that would make the kernel treat UE_IP as local
            %% and deliver downlink packets to us instead of forwarding
            %% them through the XFRM OUT policy back out to the UE.
            Cmds = [
                io_lib:format("ip tuntap add dev ~s mode tun", [Name]),
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
                    "sysctl -wq net.ipv4.conf.~s.rp_filter=2", [Name, Name]),
                %% Main table downlink route: lets FIB lookup for dst=UE_IP
                %% succeed; the XFRM OUT bundle (dst=UE_IP/32 tmpl tunnel esp)
                %% overrides and actually emits ESP via eth0.
                io_lib:format("ip route add ~s/32 dev ~s", [UeIp, Name]),
                %% Uplink policy table: after XFRM decrypt, packets with
                %% src=UE_IP are sent out the UE's own TUN for the BEAM
                %% to pick up and wrap into GTP-U.
                io_lib:format("ip rule add from ~s/32 lookup ~B priority ~B",
                              [UeIp, Table, Table]),
                io_lib:format("ip route add default dev ~s table ~B",
                              [Name, Table])
            ],
            case run_cmds_or_warn(Name, Cmds) of
                ok    -> open_tun_port(Name);
                error -> undefined
            end
    end;
maybe_open_tun(_Name, _, _) ->
    undefined.

%% Route-table / rule priority derived from the per-pod local TEID.
%%
%% CRITICAL: the returned value is used for BOTH the table id and the
%% `ip rule ... priority` value. iproute2 orders rules by priority
%% (lowest first). The main table is consulted at priority 32766, and
%% since the pod's main table has a default route (`default via
%% eth0`), any rule with priority >= 32766 is never reached for
%% uplink traffic — the main lookup wins first. We therefore clamp to
%% the 1000..31000 range so every per-UE rule sits strictly before
%% main, regardless of which 32-bit TEID the FSM hands us.
ue_route_table(LocalTeid) ->
    1000 + (LocalTeid rem 30000).

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
ensure_forwarding_sysctls() ->
    _ = os:cmd("sysctl -wq net.ipv4.ip_forward=1 2>&1"),
    verify_sysctl_exact("net.ipv4.ip_forward", "1"),
    verify_rp_filter("net.ipv4.conf.all.rp_filter"),
    ok.

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

close_tun_ent(#ue_ent{tun_port = TP, tun_name = Name,
                      local_teid = Teid, ue_inner_ip = Ip}) ->
    case TP of
        undefined -> ok;
        Port when is_port(Port) -> catch erlang:port_close(Port), ok
    end,
    teardown_ue_routing(Ip, Teid),
    delete_tun_dev(Name).

teardown_ue_routing(undefined, _Teid) -> ok;
teardown_ue_routing({A,B,C,D}, Teid) ->
    UeIp = io_lib:format("~B.~B.~B.~B", [A,B,C,D]),
    Table = ue_route_table(Teid),
    _ = os:cmd(lists:flatten(
        io_lib:format("ip rule del from ~s/32 lookup ~B priority ~B 2>&1",
                      [UeIp, Table, Table]))),
    _ = os:cmd(lists:flatten(
        io_lib:format("ip route flush table ~B 2>&1", [Table]))),
    ok.

delete_tun_dev(undefined) -> ok;
delete_tun_dev(Name) ->
    _ = os:cmd(lists:flatten(
                 io_lib:format("ip tuntap del dev ~s mode tun 2>&1", [Name]))),
    ok.

tun_write(undefined, _Pkt) -> ok;
tun_write(Port, Pkt) when is_port(Port), is_binary(Pkt) ->
    try erlang:port_command(Port, Pkt, [nosuspend]) of
        true  -> ok;
        false -> ok  %% busy / hi-watermark — drop; UE will retransmit
    catch
        error:_ -> ok
    end.

%% Build a Linux interface name for a UE's TUN device.
%% IFNAMSIZ limits us to 15 usable chars; a 15-digit IMSI would make
%% "ue" ++ IMSI = 17 chars and `ip tuntap add` silently rejects it. We
%% instead use the 32-bit local GTP-U TEID (<= 10 decimal digits) with
%% an "ue" prefix, giving at most 12 chars and guaranteeing uniqueness
%% per session within this pod. IMSI stays available in logs for
%% correlation.
tun_name_for(P) ->
    Teid = maps:get(local_teid_hint, P, 0),
    lists:flatten(io_lib:format("ue~B", [Teid])).

%%====================================================================
%% Startup orphan cleanup
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
        teardown_ue_routing(Ip, Teid),
        delete_tun_dev(Name),
        epdg_metrics:inc(tun_startup_cleaned_total)
    end, Stale),
    case length(Stale) of
        0 -> ok;
        N -> logger:notice("Startup cleanup: removed ~B stale TUN device(s)", [N])
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

tun_ip_from_route(Name) ->
    Cmd = lists:flatten(io_lib:format(
        "ip route show dev ~s 2>/dev/null | head -1 | awk '{print $1}'", [Name])),
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

%%====================================================================
%% Periodic GC reconciliation
%%====================================================================

schedule_gc() ->
    Interval = epdg_config:get(tun_gc_interval, 300000),
    erlang:send_after(Interval, self(), gc_tun).

find_orphaned_tuns(ByTeid) ->
    Raw = os:cmd("ip -o link show type tun 2>/dev/null"),
    Lines = string:split(Raw, "\n", all),
    AllNames = [Name || L <- Lines,
                        Name <- [extract_ue_tun_name(L)],
                        Name =/= undefined],
    [{Name, tun_ip_from_route(Name), Teid}
     || Name <- AllNames,
        Teid <- [teid_from_tun_name(Name)],
        not maps:is_key(Teid, ByTeid)].

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
