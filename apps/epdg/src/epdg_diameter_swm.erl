%%%-------------------------------------------------------------------
%%% @doc Diameter SWm client (ePDG → 3GPP AAA Server).
%%% Application-ID 16777264 (TS 29.273).
%%% Sends DER/DEA for EAP relay, AAR/AAA for authorization.
%%% Connects to AAA Server via all configured DRA replicas.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_diameter_swm).

-behaviour(gen_server).

-include_lib("diameter/include/diameter.hrl").

-export([start_link/0,
         diameter_eap_request/2,
         aa_request/2,
         session_termination_request/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% Diameter application callbacks
-export([peer_up/3, peer_down/3, pick_peer/4,
         prepare_request/3, prepare_retransmit/3,
         handle_answer/4, handle_error/4, handle_request/3]).

-define(SERVER, ?MODULE).
-define(SVC_NAME, epdg_diameter_svc).
-define(SWM_APP_ID, 16777264).
-define(VENDOR_3GPP, 10415).

-define(DNS_RETRY_INITIAL, 5000).
-define(DNS_RETRY_MAX,    60000).
-define(HEALTH_CHECK_INTERVAL, 30000).

-record(state, {
    service_started :: boolean(),
    dra_port        :: non_neg_integer() | undefined,
    transport_mod   :: module() | undefined,
    %% Per-host transport state: #{Host => {Ref | undefined, Retries}}
    transports      :: #{string() => {term() | undefined, non_neg_integer()}}
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Send Diameter-EAP-Request (DER) — relay EAP payload to AAA Server.
-spec diameter_eap_request(binary(), map()) -> {ok, map()} | {error, term()}.
diameter_eap_request(IMSI, Opts) ->
    gen_server:call(?SERVER, {der, IMSI, Opts}, 15000).

%% @doc Send AA-Request (AAR) — authorize session after successful EAP.
-spec aa_request(binary(), map()) -> {ok, map()} | {error, term()}.
aa_request(IMSI, Opts) ->
    gen_server:call(?SERVER, {aar, IMSI, Opts}, 15000).

%% @doc Send Session-Termination-Request (STR).
-spec session_termination_request(binary(), map()) -> {ok, map()} | {error, term()}.
session_termination_request(SessionId, Opts) ->
    gen_server:call(?SERVER, {str, SessionId, Opts}, 15000).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    OriginHost  = epdg_config:get(origin_host, "epdg.localdomain"),
    OriginRealm = epdg_config:get(origin_realm, "localdomain"),
    DiamPort    = epdg_config:get(diameter_port, 3868),
    DRAHosts    = epdg_config:get(dra_hosts, ["dra-diameter"]),
    DRAPort     = epdg_config:get(dra_port, 3868),
    Transport   = epdg_config:get(dra_transport, "tcp"),

    diameter:start(),

    SvcOpts = [
        {'Origin-Host',  list_to_binary(OriginHost)},
        {'Origin-Realm', list_to_binary(OriginRealm)},
        {'Vendor-Id', ?VENDOR_3GPP},
        {'Product-Name', "volte.io ePDG"},
        {'Auth-Application-Id', [?SWM_APP_ID]},
        {'Supported-Vendor-Id', [?VENDOR_3GPP]},
        {string_decode, false},
        {application, [{alias, swm},
                       {dictionary, diameter_dict_swm},
                       {module, ?MODULE}]}
    ],

    case diameter:start_service(?SVC_NAME, SvcOpts) of
        ok ->
            TransMod = transport_module(Transport),
            diameter:add_transport(?SVC_NAME, {listen, [
                {transport_module, TransMod},
                {transport_config, [{reuseaddr, true},
                                    {ip, {0,0,0,0}},
                                    {port, DiamPort}]}
            ]}),

            InitTransports = maps:from_list(
                [{H, {undefined, 0}} || H <- DRAHosts]),
            State0 = #state{service_started = true,
                            dra_port        = DRAPort,
                            transport_mod   = TransMod,
                            transports      = InitTransports},
            logger:notice("SWm client: connecting to ~B DRA host(s): ~p",
                          [length(DRAHosts), DRAHosts]),
            erlang:send_after(?HEALTH_CHECK_INTERVAL, self(), health_check),
            {ok, connect_all(State0)};
        {error, Reason} ->
            logger:error("Failed to start SWm Diameter service: ~p", [Reason]),
            {ok, #state{service_started = false,
                        transports      = #{}}}
    end.

handle_call({der, IMSI, Opts}, _From, #state{service_started = true} = State) ->
    EAPPayload = maps:get(eap_payload, Opts, <<>>),
    SessionId  = generate_session_id(),

    Msg = ['ASR',
           {'Session-Id', SessionId},
           {'User-Name', IMSI},
           {'Auth-Request-Type', 3}],

    Result = case diameter:call(?SVC_NAME, swm, Msg, []) of
        {ok, Answer} ->
            {ok, #{session_id => SessionId,
                   eap_payload => EAPPayload,
                   answer => Answer}};
        {error, R} ->
            {error, R}
    end,
    epdg_metrics:inc(diameter_swm_requests_total),
    {reply, Result, State};

handle_call({aar, IMSI, Opts}, _From, #state{service_started = true} = State) ->
    APN = maps:get(apn, Opts, <<"ims">>),
    SessionId = generate_session_id(),
    Msg = ['ASR',
           {'Session-Id', SessionId},
           {'User-Name', IMSI},
           {'Auth-Request-Type', 1}],
    Result = case diameter:call(?SVC_NAME, swm, Msg, []) of
        {ok, Answer} -> {ok, #{session_id => SessionId, apn => APN, answer => Answer}};
        {error, R}   -> {error, R}
    end,
    epdg_metrics:inc(diameter_swm_requests_total),
    {reply, Result, State};

handle_call({str, SessionId, _Opts}, _From, #state{service_started = true} = State) ->
    Msg = ['STR',
           {'Session-Id', SessionId},
           {'Termination-Cause', 1}],
    Result = case diameter:call(?SVC_NAME, swm, Msg, []) of
        {ok, Answer} -> {ok, #{answer => Answer}};
        {error, R}   -> {error, R}
    end,
    {reply, Result, State};

handle_call(_, _From, #state{service_started = false} = State) ->
    {reply, {error, diameter_not_started}, State};

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) -> {noreply, State}.

handle_info({retry_dra_dns, Host}, State) ->
    {noreply, try_connect_host(Host, State)};
handle_info({diameter_peer_down, PeerRef}, #state{transports = Ts} = State) ->
    Host = host_for_peer_ref(PeerRef, Ts),
    case Host of
        "unknown" ->
            logger:warning("SWm peer down: could not map PeerRef to host"),
            {noreply, State};
        _ ->
            erlang:send_after(15000, self(), {re_resolve_dra, Host}),
            {noreply, State}
    end;
handle_info({re_resolve_dra, Host}, #state{transports = Ts} = State) ->
    case maps:find(Host, Ts) of
        {ok, {OldRef, _}} when OldRef =/= undefined ->
            logger:notice("SWm: re-resolving DRA ~s after peer down", [Host]),
            catch diameter:remove_transport(?SVC_NAME, OldRef),
            NewTs = Ts#{Host => {undefined, 0}},
            {noreply, try_connect_host(Host, State#state{transports = NewTs})};
        _ ->
            {noreply, try_connect_host(Host, State)}
    end;
handle_info({force_reconnect, Host}, #state{transports = Ts} = State) ->
    case maps:find(Host, Ts) of
        {ok, {OldRef, _}} when OldRef =/= undefined ->
            logger:warning("SWm: forcing reconnect to DRA ~s (stale IP detected)", [Host]),
            catch diameter:remove_transport(?SVC_NAME, OldRef),
            NewTs = Ts#{Host => {undefined, 0}},
            {noreply, try_connect_host(Host, State#state{transports = NewTs})};
        _ ->
            {noreply, try_connect_host(Host, State)}
    end;
handle_info(health_check, #state{service_started = true} = State) ->
    check_transport_health(State),
    erlang:send_after(?HEALTH_CHECK_INTERVAL, self(), health_check),
    {noreply, State};
handle_info(health_check, State) ->
    erlang:send_after(?HEALTH_CHECK_INTERVAL, self(), health_check),
    {noreply, State};
handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, #state{service_started = true}) ->
    diameter:stop_service(?SVC_NAME),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Diameter callbacks
%%====================================================================

peer_up(_SvcName, {_PeerRef, Caps}, State) ->
    RemoteHost = case Caps of
        #diameter_caps{origin_host = {_, RH}} -> RH;
        _ -> <<"unknown">>
    end,
    logger:notice("SWm peer up: ~s (DRA reachable)", [RemoteHost]),
    epdg_metrics:gauge_inc(diameter_swm_peers),
    State.

peer_down(_SvcName, {PeerRef, Caps}, State) ->
    RemoteHost = case Caps of
        #diameter_caps{origin_host = {_, RH}} -> RH;
        _ -> <<"unknown">>
    end,
    logger:notice("SWm peer down: ~s", [RemoteHost]),
    epdg_metrics:gauge_dec(diameter_swm_peers),
    ?SERVER ! {diameter_peer_down, PeerRef},
    State.

pick_peer([Peer | _], _, _SvcName, _State) ->
    {ok, Peer}.

prepare_request(#diameter_packet{msg = Msg} = Pkt, _SvcName, {_, Caps}) ->
    #diameter_caps{origin_host = {OH, _}, origin_realm = {OR, _}} = Caps,
    NewMsg = setelement(2, Msg, [{'Origin-Host', OH}, {'Origin-Realm', OR}
                                  | element(2, Msg)]),
    {send, Pkt#diameter_packet{msg = NewMsg}}.

prepare_retransmit(Pkt, SvcName, Peer) ->
    prepare_request(Pkt, SvcName, Peer).

handle_answer(#diameter_packet{msg = Msg}, _Req, _SvcName, _Peer) ->
    {ok, Msg}.

handle_error(Reason, _Req, _SvcName, _Peer) ->
    {error, Reason}.

handle_request(_Pkt, _SvcName, _Peer) ->
    discard.

%%====================================================================
%% Internal
%%====================================================================

check_transport_health(#state{transports = Ts}) ->
    TInfos = diameter:service_info(?SVC_NAME, transport),
    lists:foreach(fun(Info) when is_list(Info) ->
        check_single_transport(Info, Ts);
    (_) -> ok
    end, TInfos).

check_single_transport(Info, Transports) ->
    Type = proplists:get_value(type, Info),
    case Type of
        connect -> check_connect_transport(Info, Transports);
        _ -> ok
    end.

check_connect_transport(Info, Transports) ->
    Ref = proplists:get_value(ref, Info),
    Options = proplists:get_value(options, Info, []),
    TransConfig = proplists:get_value(transport_config, Options, []),
    RAddr = proplists:get_value(raddr, TransConfig),
    WatchdogState = case proplists:get_value(watchdog, Info) of
        {_, _, S} -> S;
        _ -> unknown
    end,
    case WatchdogState of
        okay -> ok;
        _ ->
            check_cer_result(Info, Ref),
            check_stale_ip(RAddr, Ref, Transports)
    end.

check_cer_result(Info, Ref) ->
    case proplists:get_value(peer, Info) of
        {_, _} -> ok;
        undefined ->
            case proplists:get_value(watchdog, Info) of
                {_, _, initial} ->
                    logger:warning("SWm transport ~p: stuck in initial state "
                                   "(no CER exchanged yet)", [Ref]);
                _ -> ok
            end
    end,
    case proplists:get_value(close, Info) of
        {ResultCode, _, _} when ResultCode =:= 4003 ->
            logger:warning("SWm transport ~p: CER rejected with Result-Code "
                           "4003 (DIAMETER_ELECTION_LOST) -- check "
                           "Origin-Host uniqueness", [Ref]);
        {ResultCode, _, _} when ResultCode =/= 2001 ->
            logger:warning("SWm transport ~p: CER rejected with "
                           "Result-Code ~B", [Ref, ResultCode]);
        _ -> ok
    end.

check_stale_ip(undefined, _Ref, _Transports) -> ok;
check_stale_ip(RAddr, Ref, Transports) ->
    Host = host_for_ref(Ref, Transports),
    case Host of
        undefined -> ok;
        _ ->
            case resolve_host(Host) of
                {ok, CurrentIP} when CurrentIP =/= RAddr ->
                    logger:warning("SWm transport ~p: stale IP ~p for host ~s "
                                   "(current DNS: ~p), forcing reconnect",
                                   [Ref, RAddr, Host, CurrentIP]),
                    self() ! {force_reconnect, Host};
                _ -> ok
            end
    end.

host_for_ref(Ref, Transports) ->
    case [H || {H, {R, _}} <- maps:to_list(Transports), R =:= Ref] of
        [Host | _] -> Host;
        [] -> undefined
    end.

connect_all(State) ->
    Hosts = maps:keys(State#state.transports),
    lists:foldl(fun(H, S) -> try_connect_host(H, S) end, State, Hosts).

try_connect_host(Host, #state{dra_port = DRAPort, transport_mod = TransMod,
                               transports = Ts} = State) ->
    {_OldRef, Retries} = maps:get(Host, Ts, {undefined, 0}),
    case resolve_host(Host) of
        {ok, DRAIP} ->
            case diameter:add_transport(?SVC_NAME, {connect, [
                {transport_module, TransMod},
                {transport_config, [{raddr, DRAIP},
                                    {rport, DRAPort},
                                    {ip, {0,0,0,0}}]},
                {reconnect_timer, 5000}
            ]}) of
                {ok, Ref} ->
                    logger:notice("SWm transport added -> DRA ~s:~B", [Host, DRAPort]),
                    State#state{transports = Ts#{Host => {Ref, 0}}};
                {error, TErr} ->
                    Delay = retry_delay(Retries),
                    logger:error("SWm transport to DRA ~s:~p failed: ~p, "
                                 "retrying in ~Bms",
                                 [Host, DRAPort, TErr, Delay]),
                    erlang:send_after(Delay, self(), {retry_dra_dns, Host}),
                    State#state{transports = Ts#{Host => {undefined, Retries + 1}}}
            end;
        {error, _} ->
            Delay = retry_delay(Retries),
            logger:warning("Cannot resolve DRA host ~s, retrying in ~Bms "
                           "(attempt ~B)",
                           [Host, Delay, Retries + 1]),
            erlang:send_after(Delay, self(), {retry_dra_dns, Host}),
            State#state{transports = Ts#{Host => {undefined, Retries + 1}}}
    end.

%% Map a Diameter PeerRef (from peer_down callback) to the configured
%% DRA hostname via diameter:service_info transport introspection.
host_for_peer_ref(PeerRef, Transports) ->
    TInfos = diameter:service_info(?SVC_NAME, transport),
    case find_transport_ref(TInfos, PeerRef) of
        {ok, TransRef} ->
            case [H || {H, {R, _}} <- maps:to_list(Transports),
                       R =:= TransRef] of
                [Host | _] -> Host;
                [] -> "unknown"
            end;
        error -> "unknown"
    end.

find_transport_ref(TInfos, PeerRef) ->
    Matches = [proplists:get_value(ref, Info)
               || Info <- TInfos,
                  is_list(Info),
                  match_peer_ref(Info, PeerRef)],
    case Matches of
        [Ref | _] -> {ok, Ref};
        [] -> error
    end.

match_peer_ref(Info, PeerRef) ->
    case proplists:get_value(peer, Info) of
        {_, PRef} when PRef =:= PeerRef -> true;
        _ ->
            case proplists:get_value(accept, Info) of
                Accept when is_list(Accept) ->
                    lists:any(fun(A) ->
                        case proplists:get_value(peer, A) of
                            {_, PR} when PR =:= PeerRef -> true;
                            _ -> false
                        end
                    end, Accept);
                _ -> false
            end
    end.

retry_delay(Retries) ->
    min(?DNS_RETRY_INITIAL bsl min(Retries, 4), ?DNS_RETRY_MAX).

generate_session_id() ->
    TS = erlang:system_time(microsecond),
    Host = epdg_config:get(origin_host, "epdg"),
    list_to_binary(io_lib:format("~s;~B;epdg", [Host, TS])).

transport_module("sctp") -> diameter_sctp;
transport_module("tcp")  -> diameter_tcp;
transport_module(_)      -> diameter_tcp.

resolve_host(Host) ->
    case inet:getaddr(Host, inet) of
        {ok, IP} -> {ok, IP};
        {error, _} ->
            case inet:getaddr(list_to_atom(Host), inet) of
                {ok, IP} -> {ok, IP};
                Err -> Err
            end
    end.
