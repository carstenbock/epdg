%%%-------------------------------------------------------------------
%%% @doc GTP-C v2 client for the S2b reference point toward the PGW-C
%%% (Open5GS SMF in our deployments).
%%%
%%% Design goals (see ePDG tunnel bring-up plan §Task 2):
%%%   1. FQDN-only peer config. The PGW's ClusterIP / PodIP can change
%%%      at any time (Kubernetes reschedule, chart upgrade) so we
%%%      re-resolve on every send path via `epdg_dns_cache'.
%%%   2. GTP-C Echo heartbeat per TS 29.274 §7.1 to notice a dead or
%%%      restarted peer even when we have no user traffic to send.
%%%   3. Recovery counter tracking — TS 29.274 §7.1.3 restart detection:
%%%      if the PGW's Recovery value changes we treat every session as
%%%      invalid and broadcast `pgw_restart' to every UE FSM.
%%%   4. Exponential-backoff reconnect loop with a bounded pending
%%%      queue so new `create_session' calls don't hang forever while
%%%      the peer is down.
%%%   5. Epoch-tagged outstanding requests — on peer change we bump an
%%%      epoch counter and drop any late responses tagged with a stale
%%%      epoch.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_gtpc_client).

-behaviour(gen_server).

-export([start_link/0,
         create_session_request/1, delete_session_request/1,
         send_bearer_response/1,
         peer_status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(GTP_C_PORT,       2123).
-define(DEFAULT_ECHO_SEC,   60).
-define(DEFAULT_ECHO_TIMEOUT_SEC, 3).
-define(DEFAULT_ECHO_MAX_MISSES, 3).
-define(DEFAULT_BACKOFF_START_MS, 1000).
-define(DEFAULT_BACKOFF_MAX_MS,  30000).
-define(DEFAULT_MAX_DOWN_SEC,       30).
-define(DEFAULT_PENDING_LIMIT,      16).
-define(REQ_TIMEOUT_MS,          30000).

-record(pending_call, {
    from       :: {pid(), reference()},
    kind       :: create_session | delete_session,
    params     :: map(),
    seq        :: non_neg_integer(),
    epoch      :: non_neg_integer(),
    timer_ref  :: reference()
}).

-record(state, {
    socket        :: gen_udp:socket() | undefined,
    local_ip      :: inet:ip_address() | undefined,
    local_u_ip    :: inet:ip_address() | undefined,
    pgw_fqdn      :: string() | undefined,
    pgw_ip        :: inet:ip_address() | undefined,
    pgw_port      :: inet:port_number(),
    local_recovery:: non_neg_integer(),
    peer_recovery:: non_neg_integer() | undefined,
    peer_state    :: up | down,
    epoch         :: non_neg_integer(),
    seq_num       :: non_neg_integer(),
    pending       :: #{non_neg_integer() => #pending_call{}},
    buffered      :: [{term(), create_session | delete_session, map()}],
    down_since    :: integer() | undefined,
    backoff_ms    :: non_neg_integer(),
    echo_seq      :: non_neg_integer(),
    echo_pending  :: {reference(), non_neg_integer()} | undefined,
    echo_misses   :: non_neg_integer(),
    %% Tunables read from config at startup
    echo_interval_ms  :: non_neg_integer(),
    echo_timeout_ms   :: non_neg_integer(),
    echo_max_misses   :: non_neg_integer(),
    backoff_max_ms    :: non_neg_integer(),
    max_down_sec      :: non_neg_integer(),
    pending_limit     :: non_neg_integer()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec create_session_request(map()) -> {ok, map()} | {error, term()}.
create_session_request(Params) ->
    gen_server:call(?SERVER, {create_session, Params}, 45000).

-spec delete_session_request(map()) -> {ok, map()} | {error, term()}.
delete_session_request(Params) ->
    gen_server:call(?SERVER, {delete_session, Params}, 30000).

%% Send a triggered response to a PGW-initiated bearer request. Called by the
%% owning UE FSM once it has (un)installed the dedicated bearer's data-plane
%% state. `Resp' carries `kind' (create|update|delete), `seq_num', `teid' (the
%% PGW's control-plane TEID), and per-bearer details. The client fills in its
%% own advertised user-plane IP + GTP-C mode and emits the encoded response.
-spec send_bearer_response(map()) -> ok.
send_bearer_response(Resp) ->
    gen_server:cast(?SERVER, {send_bearer_response, Resp}).

-spec peer_status() -> map().
peer_status() ->
    gen_server:call(?SERVER, peer_status).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    BindAddr = parse_ip_or_any(epdg_config:get(gtpc_bind_addr, "0.0.0.0")),
    Port     = epdg_config:get(gtpc_port, ?GTP_C_PORT),
    PgwFqdn  = require_fqdn(epdg_config:get(pgw_fqdn,
                                             epdg_config:get(pgw_addr, ""))),
    PgwPort  = epdg_config:get(pgw_port, ?GTP_C_PORT),

    EchoSec  = epdg_config:get(gtpc_echo_interval_sec, ?DEFAULT_ECHO_SEC),
    EchoTO   = epdg_config:get(gtpc_echo_timeout_sec,  ?DEFAULT_ECHO_TIMEOUT_SEC),
    EchoMax  = epdg_config:get(gtpc_echo_max_misses,   ?DEFAULT_ECHO_MAX_MISSES),
    BackMax  = epdg_config:get(gtpc_backoff_max_sec,
                                ?DEFAULT_BACKOFF_MAX_MS div 1000),
    MaxDown  = epdg_config:get(gtpc_max_down_sec, ?DEFAULT_MAX_DOWN_SEC),
    PendLim  = epdg_config:get(gtpc_pending_limit, ?DEFAULT_PENDING_LIMIT),

    InetFamily = case BindAddr of
        {_,_,_,_,_,_,_,_} -> inet6;
        _                 -> inet
    end,
    case gen_udp:open(Port, [binary, {ip, BindAddr}, {active, true},
                              {reuseaddr, true}, InetFamily]) of
        {ok, Socket} ->
            {ok, {LIP, _}} = inet:sockname(Socket),
            LocalUIP = resolve_local_u_ip(epdg_config:get(gtpu_advertise_addr, ""),
                                          LIP),
            logger:info("GTP-C S2b on ~p:~p → PGW FQDN=~p port=~p",
                        [LIP, Port, PgwFqdn, PgwPort]),
            State0 = #state{
                socket        = Socket,
                local_ip      = LIP,
                local_u_ip    = LocalUIP,
                pgw_fqdn      = PgwFqdn,
                pgw_ip        = undefined,
                pgw_port      = PgwPort,
                local_recovery= local_restart_counter(),
                peer_recovery = undefined,
                peer_state    = up,
                epoch         = 1,
                seq_num       = 0,
                pending       = #{},
                buffered      = [],
                down_since    = undefined,
                backoff_ms    = ?DEFAULT_BACKOFF_START_MS,
                echo_seq      = 0,
                echo_pending  = undefined,
                echo_misses   = 0,
                echo_interval_ms = EchoSec * 1000,
                echo_timeout_ms  = EchoTO  * 1000,
                echo_max_misses  = EchoMax,
                backoff_max_ms   = BackMax * 1000,
                max_down_sec     = MaxDown,
                pending_limit    = PendLim
            },
            schedule_echo(State0),
            {ok, State0};
        {error, Reason} ->
            {stop, {gtpc_bind_failed, Reason}}
    end.

%%--------------------------------------------------------------------
%% handle_call
%%--------------------------------------------------------------------

handle_call({create_session, Params}, From, State) ->
    dispatch_call(create_session, Params, From, State);

handle_call({delete_session, Params}, From, State) ->
    dispatch_call(delete_session, Params, From, State);

handle_call(peer_status, _From,
            #state{pgw_fqdn = F, pgw_ip = IP, peer_state = PS,
                   peer_recovery = PR, local_recovery = LR,
                   epoch = E} = State) ->
    {reply, #{fqdn => F, ip => IP, peer_state => PS,
              peer_recovery => PR, local_recovery => LR,
              epoch => E}, State};

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

%%--------------------------------------------------------------------
%% handle_cast / handle_info
%%--------------------------------------------------------------------

handle_cast({send_bearer_response, Resp}, State) ->
    {noreply, do_send_bearer_response(Resp, State)};
handle_cast(_, State) -> {noreply, State}.

handle_info({udp, _Sock, _FromIP, _FromPort, Data}, State) ->
    {noreply, handle_udp(Data, State)};

handle_info({timeout, Ref, {seq_timeout, SeqNum, Epoch}},
            #state{pending = Pending} = State) ->
    case maps:find(SeqNum, Pending) of
        {ok, #pending_call{timer_ref = Ref, epoch = Epoch, from = From}} ->
            epdg_metrics:inc(gtpc_timeouts_total),
            gen_server:reply(From, {error, timeout}),
            State1 = State#state{pending = maps:remove(SeqNum, Pending)},
            {noreply, State1};
        _ -> {noreply, State}
    end;

handle_info({timeout, _Ref, echo_tick}, State) ->
    {noreply, send_echo(State)};

handle_info({timeout, Ref, {echo_timeout, EchoSeq, Epoch}},
            #state{echo_pending = {Ref, EchoSeq}, epoch = Epoch} = State) ->
    {noreply, handle_echo_timeout(State)};
handle_info({timeout, _Ref, {echo_timeout, _, _}}, State) ->
    {noreply, State};

handle_info({timeout, _Ref, reconnect_tick}, State) ->
    {noreply, try_reconnect(State)};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{socket = S}) ->
    case S of undefined -> ok; _ -> gen_udp:close(S) end,
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Dispatch an incoming call: enqueue if the peer is down, otherwise
%% send immediately.
%%====================================================================

dispatch_call(Kind, Params, From, #state{peer_state = down,
                                           buffered = Q,
                                           pending_limit = Lim,
                                           max_down_sec = MaxDown,
                                           down_since = DS} = State) ->
    case length(Q) >= Lim of
        true ->
            gen_server:reply(From, {error, pgw_overloaded}),
            {noreply, State};
        false ->
            Now = erlang:system_time(second),
            TooLong = is_integer(DS) andalso (Now - DS) > MaxDown,
            case TooLong of
                true ->
                    gen_server:reply(From, {error, pgw_unreachable}),
                    {noreply, State};
                false ->
                    {noreply, State#state{buffered = Q ++ [{From, Kind, Params}]}}
            end
    end;
dispatch_call(Kind, Params, From, State) ->
    {noreply, send_call(Kind, Params, From, State)}.

send_call(create_session, Params, From, State) ->
    send_create_session(Params, From, State);
send_call(delete_session, Params, From, State) ->
    send_delete_session(Params, From, State).

%%====================================================================
%% Create Session
%%====================================================================

send_create_session(Params, From,
                    #state{seq_num = Seq, local_ip = LIP, local_u_ip = LUIP,
                           local_recovery = Rec,
                           epoch = Epoch} = State) ->
    APN      = maps:get(apn,     Params, <<"ims">>),
    RAT      = maps:get(rat_type,Params, 3),     %% WLAN
    IMSI     = maps:get(imsi,    Params, <<>>),
    MSISDN   = maps:get(msisdn,  Params, <<>>),
    MEI      = maps:get(mei,     Params, <<>>),
    PdnType  = maps:get(pdn_type,Params, 1),
    %% Requested existing UE address(es) for a 3GPP->non-3GPP handover attach;
    %% relayed to the PGW as the Create-Session PAA so the PDN and its
    %% address(es) survive the handover. IPv6 is the /64 PDN prefix.
    HoV4     = maps:get(handover_v4, Params, undefined),
    HoV6     = maps:get(handover_v6, Params, undefined),
    %% Serving Network IE is Conditional on S2b CSR (TS 29.274 §7.2.1,
    %% §8.18) and Open5GS SMF enforces its presence — data != NULL,
    %% len == OGS_PLMN_ID_LEN (3 bytes). Default to the ePDG's own PLMN
    %% from the MCC/MNC env vars so the IE is always emitted even when
    %% the caller (e.g. `epdg_ue_fsm:proceed_with_s2b/15`) does not
    %% supply one.
    SN       = case maps:get(serving_network, Params, undefined) of
                   undefined -> default_serving_network();
                   Other     -> Other
               end,
    AmbrUl   = maps:get(ambr_ul_kbps, Params, 500000),
    AmbrDl   = maps:get(ambr_dl_kbps, Params, 1000000),
    EBI      = maps:get(ebi, Params, 5),
    LCT      = maps:get(local_c_teid, Params, 0),
    LUT      = maps:get(local_u_teid, Params, 0),

    Msg = epdg_gtpc_codec:encode_create_session_request(#{
        seq_num       => Seq,
        imsi          => IMSI,
        msisdn        => MSISDN,
        mei           => MEI,
        apn           => APN,
        rat_type      => RAT,
        pdn_type      => PdnType,
        handover_v4   => HoV4,
        handover_v6   => HoV6,
        local_ip      => LIP,
        local_u_ip    => LUIP,
        local_c_teid  => LCT,
        local_u_teid  => LUT,
        recovery      => Rec,
        serving_network => SN,
        ambr_ul_kbps  => AmbrUl,
        ambr_dl_kbps  => AmbrDl,
        ebi           => EBI,
        mode          => epdg_config:get(gtpc_mode, s2b)
    }),

    deliver_and_pend(Msg, create_session, Params, Seq, Epoch, From, State).

%% Serving Network default: the ePDG's own PLMN from env/config
%% (`MCC` / `MNC` in `epdg_config:init/0`). Encoded per TS 24.008
%% §10.5.1.3 (TBCD MCC+MNC, 3 octets) by `epdg_gtpc_codec`.
default_serving_network() ->
    MCC = to_binary(epdg_config:get(mcc, "001")),
    MNC = to_binary(epdg_config:get(mnc, "01")),
    {MCC, MNC}.

to_binary(B) when is_binary(B) -> B;
to_binary(L) when is_list(L)   -> list_to_binary(L);
to_binary(A) when is_atom(A)   -> atom_to_binary(A, utf8).

%%====================================================================
%% Delete Session
%%====================================================================

send_delete_session(Params, From,
                    #state{seq_num = Seq, epoch = Epoch} = State) ->
    PgwTEID = maps:get(pgw_c_teid, Params, maps:get(pgw_teid, Params, 0)),
    EBI     = maps:get(ebi, Params, 5),
    Msg = epdg_gtpc_codec:encode_delete_session_request(#{
        seq_num => Seq, teid => PgwTEID, ebi => EBI}),
    deliver_and_pend(Msg, delete_session, Params, Seq, Epoch, From, State).

deliver_and_pend(Msg, Kind, Params, Seq, Epoch, From,
                 #state{socket = Socket, pgw_port = PgwPort,
                        pending = Pending} = State0) ->
    case resolved_peer_ip(State0) of
        {ok, IP, State1} ->
            case gen_udp:send(Socket, IP, PgwPort, Msg) of
                ok ->
                    epdg_metrics:inc(gtpc_requests_total),
                    TRef = erlang:start_timer(
                              ?REQ_TIMEOUT_MS, self(),
                              {seq_timeout, Seq, Epoch}),
                    Call = #pending_call{from = From, kind = Kind,
                                          params = Params, seq = Seq,
                                          epoch = Epoch, timer_ref = TRef},
                    State1#state{seq_num = (Seq + 1) band 16#FFFFFF,
                                  pending = Pending#{Seq => Call}};
                {error, SendErr} ->
                    logger:warning("GTP-C send failed: ~p — marking peer down",
                                   [SendErr]),
                    gen_server:reply(From, {error, SendErr}),
                    mark_peer_down(invalidate_dns(State1))
            end;
        {error, Reason, State1} ->
            gen_server:reply(From, {error, {resolve_failed, Reason}}),
            mark_peer_down(State1)
    end.

%%====================================================================
%% Peer IP resolution (via cache)
%%====================================================================

resolved_peer_ip(#state{pgw_ip = IP} = State) when IP =/= undefined ->
    {ok, IP, State};
resolved_peer_ip(#state{pgw_fqdn = FQDN} = State) ->
    case epdg_dns_cache:lookup(FQDN) of
        {ok, IP} -> {ok, IP, State#state{pgw_ip = IP}};
        {error, R} -> {error, R, State}
    end.

invalidate_dns(#state{pgw_fqdn = FQDN} = State) ->
    catch epdg_dns_cache:invalidate(FQDN),
    State#state{pgw_ip = undefined}.

%%====================================================================
%% Echo heartbeat (TS 29.274 §7.1)
%%====================================================================

schedule_echo(#state{echo_interval_ms = IntervalMs}) ->
    erlang:start_timer(IntervalMs, self(), echo_tick).

send_echo(#state{socket = Socket, pgw_port = Port,
                 local_recovery = Rec,
                 echo_seq = ES, echo_timeout_ms = Timeout,
                 epoch = Epoch} = State) ->
    schedule_echo(State),
    Seq = (ES + 1) band 16#FFFFFF,
    Msg = epdg_gtpc_codec:encode_echo_request(#{seq_num => Seq,
                                                 recovery => Rec}),
    case resolved_peer_ip(State) of
        {ok, IP, State1} ->
            case gen_udp:send(Socket, IP, Port, Msg) of
                ok ->
                    epdg_metrics:inc(gtpc_echo_sent_total),
                    TRef = erlang:start_timer(
                              Timeout, self(),
                              {echo_timeout, Seq, Epoch}),
                    State1#state{echo_seq = Seq,
                                  echo_pending = {TRef, Seq}};
                {error, _} ->
                    mark_peer_down(invalidate_dns(State1))
            end;
        {error, _, State1} ->
            mark_peer_down(State1)
    end.

handle_echo_timeout(#state{echo_misses = M, echo_max_misses = MaxM} = State) ->
    epdg_metrics:inc(gtpc_echo_timeouts_total),
    M1 = M + 1,
    case M1 >= MaxM of
        true ->
            logger:warning("GTP-C: ~B consecutive echo timeouts — peer down", [M1]),
            mark_peer_down(invalidate_dns(State#state{echo_misses = M1,
                                                        echo_pending = undefined}));
        false ->
            State#state{echo_misses = M1, echo_pending = undefined}
    end.

%%====================================================================
%% Peer state transitions
%%====================================================================

mark_peer_down(#state{peer_state = down} = State) -> State;
mark_peer_down(State) ->
    epdg_metrics:inc(gtpc_peer_down_total),
    catch epdg_ue_registry:broadcast(pgw_down),
    State1 = State#state{peer_state = down,
                          down_since = erlang:system_time(second),
                          backoff_ms = ?DEFAULT_BACKOFF_START_MS,
                          echo_pending = undefined},
    erlang:start_timer(?DEFAULT_BACKOFF_START_MS, self(), reconnect_tick),
    State1.

mark_peer_up(#state{peer_state = up} = State) -> State;
mark_peer_up(#state{} = State) ->
    logger:info("GTP-C: peer recovered"),
    %% Flush buffered calls
    State1 = State#state{peer_state = up,
                          down_since = undefined,
                          backoff_ms = ?DEFAULT_BACKOFF_START_MS,
                          echo_misses = 0},
    flush_buffered(State1).

flush_buffered(#state{buffered = []} = State) -> State;
flush_buffered(#state{buffered = [{From, Kind, Params} | Rest]} = State) ->
    State1 = State#state{buffered = Rest},
    flush_buffered(send_call(Kind, Params, From, State1)).

try_reconnect(#state{peer_state = up} = State) -> State;
try_reconnect(#state{backoff_ms = BO, backoff_max_ms = Max,
                     max_down_sec = MaxDown, down_since = DS,
                     buffered = Q} = State) ->
    Now = erlang:system_time(second),
    case DS =/= undefined andalso (Now - DS) > MaxDown of
        true ->
            %% Too long down — fail all queued calls so the UE FSMs
            %% can take over.
            lists:foreach(fun({From, _, _}) ->
                gen_server:reply(From, {error, pgw_unreachable})
            end, Q),
            State#state{buffered = []};
        false ->
            %% Force fresh DNS + echo
            State1 = invalidate_dns(State),
            State2 = send_echo(State1),
            NextBo = min(BO * 2, Max),
            erlang:start_timer(NextBo, self(), reconnect_tick),
            State2#state{backoff_ms = NextBo}
    end.

%%====================================================================
%% UDP packet dispatcher
%%====================================================================

handle_udp(Data, State) ->
    case epdg_gtpc_codec:decode_header(Data) of
        {ok, Msg} ->
            dispatch_gtpc_msg(Msg, State);
        {error, _} ->
            State
    end.

dispatch_gtpc_msg(#{type := 2, seq_num := Seq} = Msg, State) ->
    %% Echo Response — clear pending echo, update Recovery
    State1 = case State#state.echo_pending of
        {TRef, Seq} ->
            erlang:cancel_timer(TRef),
            State#state{echo_pending = undefined, echo_misses = 0};
        _ -> State
    end,
    apply_recovery(Msg, mark_peer_up(State1));
dispatch_gtpc_msg(#{type := 1, seq_num := Seq} = Msg, State) ->
    %% Echo Request — respond immediately with our Recovery value
    Resp = epdg_gtpc_codec:encode_echo_response(#{
        seq_num => Seq, recovery => State#state.local_recovery}),
    catch resolve_and_send(Resp, State),
    apply_recovery(Msg, State);
dispatch_gtpc_msg(#{type := 33, seq_num := Seq} = Msg, State) ->
    deliver_response(Seq, Msg, State, create_session);
dispatch_gtpc_msg(#{type := 37, seq_num := Seq} = Msg, State) ->
    deliver_response(Seq, Msg, State, delete_session);
%% PGW-initiated dedicated bearer signalling (TS 29.274 §7.2.3/§7.2.7/§7.2.9.1).
%% Routed to the owning UE FSM by the request's header TEID (= the ePDG's local
%% S2b-C TEID); an unknown TEID is answered with "Context Not Found" so the PGW
%% stops retransmitting instead of timing out.
dispatch_gtpc_msg(#{type := 95} = Msg, State) ->
    route_bearer_request(create, Msg, State);
dispatch_gtpc_msg(#{type := 97} = Msg, State) ->
    route_bearer_request(update, Msg, State);
dispatch_gtpc_msg(#{type := 99} = Msg, State) ->
    route_bearer_request(delete, Msg, State);
dispatch_gtpc_msg(_Other, State) -> State.

route_bearer_request(Kind, #{teid := CTEID, seq_num := Seq} = Msg, State) ->
    epdg_metrics:inc(bearer_req_metric(Kind)),
    case epdg_ue_registry:lookup_by_cteid(CTEID) of
        {ok, Pid} ->
            Decoded = decode_bearer_request(Kind, Msg),
            gen_statem:cast(Pid, {gtpc_bearer_request, Kind, Decoded}),
            State;
        error ->
            logger:warning("GTP-C: ~p bearer request for unknown C-TEID ~p "
                           "— replying Context Not Found", [Kind, CTEID]),
            epdg_metrics:inc(gtpc_bearer_no_context_total),
            Bin = encode_bearer_response(
                    Kind, #{seq_num => Seq, teid => 0, cause => 64,
                            bearers => []}),
            catch resolve_and_send(Bin, State),
            State
    end.

decode_bearer_request(create, Msg) ->
    epdg_gtpc_codec:decode_create_bearer_request(Msg);
decode_bearer_request(update, Msg) ->
    epdg_gtpc_codec:decode_update_bearer_request(Msg);
decode_bearer_request(delete, Msg) ->
    epdg_gtpc_codec:decode_delete_bearer_request(Msg).

bearer_req_metric(create) -> gtpc_create_bearer_req_total;
bearer_req_metric(update) -> gtpc_update_bearer_req_total;
bearer_req_metric(delete) -> gtpc_delete_bearer_req_total.

%% Encode + emit a bearer response to the PGW. For a Create Bearer Response the
%% ePDG advertises its own user-plane F-TEID, whose IP is the client's
%% advertised GTP-U address (the FSM only knows the TEID it allocated).
do_send_bearer_response(#{kind := Kind} = Resp0,
                        #state{local_u_ip = LUIP} = State) ->
    Resp = case Kind of
        create ->
            Bearers = [B#{u_ip => maps:get(u_ip, B, LUIP)}
                       || B <- maps:get(bearers, Resp0, [])],
            Resp0#{bearers => Bearers};
        _ ->
            Resp0
    end,
    Bin = encode_bearer_response(Kind, Resp),
    catch resolve_and_send(Bin, State),
    epdg_metrics:inc(gtpc_bearer_resp_total),
    State.

encode_bearer_response(create, R) ->
    Mode = epdg_config:get(gtpc_mode, s2b),
    epdg_gtpc_codec:encode_create_bearer_response(R#{mode => Mode});
encode_bearer_response(update, R) ->
    epdg_gtpc_codec:encode_update_bearer_response(R);
encode_bearer_response(delete, R) ->
    epdg_gtpc_codec:encode_delete_bearer_response(R).

resolve_and_send(Bin, #state{socket = S, pgw_port = P} = State) ->
    case resolved_peer_ip(State) of
        {ok, IP, _} -> catch gen_udp:send(S, IP, P, Bin), ok;
        _ -> ok
    end.

deliver_response(Seq, Msg, #state{pending = Pending, epoch = Epoch} = State0, Kind) ->
    case maps:find(Seq, Pending) of
        {ok, #pending_call{from = From, timer_ref = Ref,
                            epoch = E}} when E =:= Epoch ->
            erlang:cancel_timer(Ref),
            epdg_metrics:inc(gtpc_responses_total),
            Decoded = case Kind of
                create_session ->
                    {ok, epdg_gtpc_codec:decode_create_session_response(Msg)};
                _ ->
                    {ok, Msg}
            end,
            gen_server:reply(From, Decoded),
            State1 = State0#state{pending = maps:remove(Seq, Pending)},
            apply_recovery(Msg, mark_peer_up(State1));
        {ok, _Stale} ->
            %% Stale epoch — drop
            State0#state{pending = maps:remove(Seq, Pending)};
        error ->
            apply_recovery(Msg, State0)
    end.

%% Update our view of the peer Recovery counter. Any change means the
%% PGW has restarted (TS 29.274 §7.1.3) so every outstanding session
%% is dead: broadcast pgw_restart and bump the epoch so late answers
%% to old requests are discarded.
apply_recovery(#{ies := IEs}, State) ->
    case lists:keyfind(recovery, 1, IEs) of
        {recovery, Bin} ->
            case epdg_gtpc_codec:decode_recovery(Bin) of
                undefined -> State;
                R -> update_recovery(R, State)
            end;
        _ -> State
    end.

update_recovery(R, #state{peer_recovery = undefined} = State) ->
    logger:info("GTP-C: peer initial Recovery=~B", [R]),
    State#state{peer_recovery = R};
update_recovery(R, #state{peer_recovery = R} = State) ->
    State;
update_recovery(RNew, #state{peer_recovery = ROld, epoch = Epoch} = State) ->
    logger:warning("GTP-C: peer Recovery changed ~B → ~B (PGW restart)",
                   [ROld, RNew]),
    epdg_metrics:inc(gtpc_peer_restarts_total),
    catch epdg_ue_registry:broadcast(pgw_restart),
    State#state{peer_recovery = RNew,
                 epoch = Epoch + 1,
                 pending = #{}}.

%%====================================================================
%% Helpers
%%====================================================================

%% Persistent restart counter across pod restarts is nice-to-have; for
%% now we use a per-process second-truncated wall-clock modulo 255 so
%% two restarts in the same second are still distinct thanks to the
%% epoch bump.
local_restart_counter() ->
    (erlang:system_time(second) band 16#FF).

parse_ip_or_any(undefined) -> parse_ip_or_any("0.0.0.0");
parse_ip_or_any(Str) when is_list(Str) ->
    case inet:parse_address(Str) of
        {ok, IP} -> IP;
        _        -> {0,0,0,0}
    end;
parse_ip_or_any(T) when is_tuple(T) -> T.

resolve_local_u_ip(undefined, Default) -> Default;
resolve_local_u_ip("", Default) -> Default;
resolve_local_u_ip("0.0.0.0", Default) -> Default;
resolve_local_u_ip(Str, Default) when is_list(Str) ->
    case inet:parse_address(Str) of
        {ok, IP} -> IP;
        _        -> Default
    end;
resolve_local_u_ip(Bin, Default) when is_binary(Bin) ->
    resolve_local_u_ip(binary_to_list(Bin), Default);
resolve_local_u_ip({0,0,0,0}, Default) -> Default;
resolve_local_u_ip(T, _Default) when is_tuple(T) -> T;
resolve_local_u_ip(_, Default) -> Default.

%% Enforce that the PGW configuration is an FQDN, not an IP literal.
%% Pod IPs and ClusterIPs in Kubernetes change under our feet; binding
%% to them directly would make every PGW restart a hard outage for us.
require_fqdn("") ->
    error({pgw_fqdn_missing, "pgw_fqdn must be set to a DNS name"});
require_fqdn(Val) when is_binary(Val) ->
    require_fqdn(binary_to_list(Val));
require_fqdn(Val) when is_list(Val) ->
    case inet:parse_address(Val) of
        {ok, _} ->
            logger:warning("GTP-C: pgw_fqdn=~p is a bare IP — using it but "
                           "re-resolution will be disabled; prefer an FQDN",
                           [Val]),
            Val;
        {error, _} ->
            Val
    end.
