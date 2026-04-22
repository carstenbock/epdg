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
            {ok, #state{socket = Socket,
                        bind_ip = BindIp,
                        bind_port = Port,
                        by_teid = #{},
                        by_owner = #{},
                        next_teid = 16#1000,
                        last_rx_ts = erlang:system_time(second)}};
        {error, eaddrinuse} ->
            %% Running outside a real ePDG pod (e.g. during unit tests)
            %% — start in a degraded mode so the supervisor comes up.
            logger:warning("GTP-U: bind ~p:~p failed (eaddrinuse); "
                           "forwarder disabled", [BindIp, Port]),
            {ok, #state{socket = undefined, bind_ip = BindIp,
                        bind_port = Port, by_teid = #{}, by_owner = #{},
                        next_teid = 16#1000,
                        last_rx_ts = erlang:system_time(second)}};
        {error, Reason} ->
            logger:warning("GTP-U: bind ~p:~p failed: ~p; forwarder disabled",
                           [BindIp, Port, Reason]),
            {ok, #state{socket = undefined, bind_ip = BindIp,
                        bind_port = Port, by_teid = #{}, by_owner = #{},
                        next_teid = 16#1000,
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
    NewByTeid = maps:fold(fun(_, Ent, Acc) ->
        close_tun(Ent#ue_ent.tun_port),
        Acc
    end, #{}, State#state.by_teid),
    {noreply, State#state{by_teid = NewByTeid, by_owner = #{}}};
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
handle_info({'DOWN', _MRef, process, Pid, _Reason},
            #state{by_owner = Owners} = State) ->
    case maps:find(Pid, Owners) of
        {ok, Teid} -> {noreply, do_unregister_teid(Teid, State)};
        error      -> {noreply, State}
    end;
handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, #state{socket = S, by_teid = Map}) ->
    maps:fold(fun(_, #ue_ent{tun_port = TP}, _) -> close_tun(TP), ok end,
              ok, Map),
    case S of undefined -> ok; _ -> gen_udp:close(S) end,
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Registration
%%====================================================================

do_register_ue(#{pgw_u_teid := PgwTeid, pgw_u_ip := PgwIP,
                 ue_inner_ip := InnerIP} = P,
               #state{by_teid = Map, next_teid = N, by_owner = Owners} = State) ->
    LocalTeid = N,
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
    {{ok, #{local_teid => LocalTeid, tun_name => TunName}},
     State#state{by_teid = Map#{LocalTeid => Ent},
                 by_owner = Owners1,
                 next_teid = N + 1}}.

do_unregister_teid(Teid, #state{by_teid = Map, by_owner = Owners} = State) ->
    case maps:take(Teid, Map) of
        {#ue_ent{tun_port = TP, owner_pid = Owner}, Rest} ->
            close_tun(TP),
            Owners1 = case Owner of
                undefined -> Owners;
                _         -> maps:remove(Owner, Owners)
            end,
            State#state{by_teid = Rest, by_owner = Owners1};
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
%% A full production path would open `/dev/net/tun` via a port driver
%% and wire the fd into an active `{active, true}` port. That requires
%% a small NIF/port binary which we do not build in-tree yet. The stub
%% below attempts `ip tuntap add` with the right naming and mirrors
%% the interface config; the actual packet pump is a TODO marked by
%% the "tun_port = undefined" state — forwarding still works in the
%% outbound direction if the UE FSM calls `send/2` directly, and the
%% UDP listener drops inbound packets for unknown TEIDs cleanly.
%%====================================================================

maybe_open_tun(Name, {A,B,C,D} = _Ip, _LocalTeid) ->
    Add  = io_lib:format("ip tuntap add dev ~s mode tun 2>/dev/null", [Name]),
    AddR = io_lib:format("ip addr add ~B.~B.~B.~B/32 dev ~s 2>/dev/null",
                         [A,B,C,D, Name]),
    Up   = io_lib:format("ip link set dev ~s up 2>/dev/null", [Name]),
    _ = os:cmd(lists:flatten(Add)),
    _ = os:cmd(lists:flatten(AddR)),
    _ = os:cmd(lists:flatten(Up)),
    undefined;
maybe_open_tun(_Name, _, _) ->
    undefined.

close_tun(undefined) -> ok;
close_tun(_Port) -> ok.

tun_write(undefined, _Pkt) -> ok;
tun_write(_Port, _Pkt)     -> ok.

tun_name_for(P) ->
    IMSI = maps:get(imsi, P, <<>>),
    Teid = maps:get(local_teid_hint, P, 0),
    Base = case IMSI of
        <<>> -> io_lib:format("~B", [Teid]);
        _    -> binary_to_list(IMSI)
    end,
    lists:flatten(io_lib:format("ue~s", [Base])).

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
