%%%-------------------------------------------------------------------
%%% @doc Diameter SWm client (ePDG → 3GPP AAA Server via DRA).
%%%
%%% Application-ID 16777264 (TS 29.273 clause 7). This module owns a
%%% single Diameter service (`epdg_diameter_svc') advertising SWm, and
%%% maintains one connect-transport per configured DRA replica. It
%%% exposes three synchronous APIs that the per-UE FSM calls:
%%%
%%%   new_session_id/0              — allocate a fresh Session-Id
%%%   diameter_eap_request/1        — DER (code 268) relaying an EAP
%%%                                    packet between UE and AAA
%%%   aa_request/1                  — AAR (code 265) post-EAP
%%%                                    authorization (not wired to
%%%                                    FSM yet; reserved for CP phase)
%%%   session_termination_request/1 — STR (code 275) on tunnel teardown
%%%
%%% The wire format uses the generated `diameter_gen_swm' dictionary
%%% (compiled from priv/dict/swm.dia by scripts/compile-diameter-dicts.sh),
%%% so all 3GPP AVPs (EAP-Payload, EAP-Master-Session-Key, RAT-Type,
%%% Visited-Network-Identifier, Service-Selection, Non-3GPP-User-Data,
%%% APN-Configuration, MIP6-Feature-Vector, 3GPP-AAA-Server-Name, …)
%%% encode and decode correctly against the AAA server.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_diameter_swm).

-behaviour(gen_server).

-include_lib("diameter/include/diameter.hrl").
-include_lib("diameter/include/diameter_gen_base_rfc6733.hrl").

-export([start_link/0,
         new_session_id/0,
         diameter_eap_request/1,
         aa_request/1,
         session_termination_request/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% Diameter application callbacks
-export([peer_up/3, peer_down/3, pick_peer/4,
         prepare_request/3, prepare_retransmit/3,
         handle_answer/4, handle_error/4, handle_request/3]).

-define(SERVER, ?MODULE).
-define(SVC_NAME, epdg_diameter_svc).
-define(APP_ALIAS, swm).
-define(SWM_APP_ID, 16777264).
-define(VENDOR_3GPP, 10415).
-define(DIAM_CALL_TIMEOUT, 10000).

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

%% @doc Allocate a stable Diameter Session-Id for a single EAP-AKA'
%% conversation (one UE, one ePDG attach). RFC 6733 §8.8 format.
-spec new_session_id() -> binary().
new_session_id() ->
    OriginHost = to_list(epdg_config:get(origin_host, "epdg.localdomain")),
    <<High:32, Low:32>> = crypto:strong_rand_bytes(8),
    Now = erlang:system_time(second),
    list_to_binary(
      io_lib:format("~s;~B;~B;~8.16.0B~8.16.0B",
                    [OriginHost, Now, erlang:unique_integer([positive]),
                     High, Low])).

%% @doc Send a Diameter-EAP-Request (DER, command 268) relaying an EAP
%% packet from the UE to the AAA server. Opts must include:
%%   session_id    :: binary()        — stable per-UE, allocated once
%%   user_name     :: binary()        — NAI the UE sent (IDi)
%%   eap_payload   :: binary()        — raw RFC 3748 EAP packet bytes
%% Opts may include:
%%   apn                :: binary()   — Service-Selection, default "ims"
%%   rat_type           :: integer()  — default WLAN (0)
%%   visited_plmn       :: binary()   — Visited-Network-Identifier
%%   auth_request_type  :: integer()  — default 3 (AUTHORIZE_AUTHENTICATE)
%%   destination_realm  :: binary()   — override Destination-Realm
%%
%% Returns on success a map:
%%   result_code    :: integer()      — 2001 | 1001 | 4xxx | 5xxx
%%   eap_payload    :: binary()       — next EAP packet for the UE
%%   msk            :: binary()       — on 2001 only
%%   session_timeout:: integer()      — when present
%%   non_3gpp_user_data :: term() | undefined
%%   apn_configurations :: [term()]
-spec diameter_eap_request(map()) -> {ok, map()} | {error, term()}.
diameter_eap_request(Opts) when is_map(Opts) ->
    gen_server:call(?SERVER, {der, Opts}, ?DIAM_CALL_TIMEOUT + 1000).

%% @doc Send an AA-Request (AAR, command 265) to authorize the session
%% after successful EAP authentication. Not used by the FSM in this
%% revision; reserved for the CP/child-SA phase.
-spec aa_request(map()) -> {ok, map()} | {error, term()}.
aa_request(Opts) when is_map(Opts) ->
    gen_server:call(?SERVER, {aar, Opts}, ?DIAM_CALL_TIMEOUT + 1000).

%% @doc Send a Session-Termination-Request (STR, command 275).
-spec session_termination_request(map()) -> {ok, map()} | {error, term()}.
session_termination_request(Opts) when is_map(Opts) ->
    gen_server:call(?SERVER, {str, Opts}, ?DIAM_CALL_TIMEOUT + 1000).

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
    %% Make sure the generated codec module is loaded before the
    %% service references it as `dictionary'.
    _ = code:ensure_loaded(diameter_gen_swm),

    OriginStateId = erlang:system_time(second),
    SvcOpts = [
        {'Origin-Host',  to_bin(OriginHost)},
        {'Origin-Realm', to_bin(OriginRealm)},
        {'Vendor-Id', ?VENDOR_3GPP},
        {'Product-Name', "volte.io ePDG"},
        {'Origin-State-Id', OriginStateId},
        {'Firmware-Revision', 1},
        {'Auth-Application-Id', [?SWM_APP_ID]},
        {'Supported-Vendor-Id', [?VENDOR_3GPP]},
        {'Vendor-Specific-Application-Id',
           [#'diameter_base_Vendor-Specific-Application-Id'{
              'Vendor-Id' = ?VENDOR_3GPP,
              'Auth-Application-Id' = [?SWM_APP_ID]}]},
        {string_decode, false},
        %% parse_swm_dea/1 pattern-matches the list form
        %% `['DEA' | AVPs]' returned by OTP when `decode_format=list'.
        %% The default is `record', which would deliver a
        %% `#diameter_swm_DEA{}' tuple and make our parser default
        %% Result-Code to 0.
        {decode_format, list},
        {application, [{alias, ?APP_ALIAS},
                       {dictionary, diameter_gen_swm},
                       {module, ?MODULE},
                       {answer_errors, callback},
                       {request_errors, answer_3xxx}]}
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

handle_call({der, Opts}, _From, #state{service_started = true} = State) ->
    Result = send_der(Opts),
    epdg_metrics:inc(diameter_swm_requests_total),
    {reply, Result, State};

handle_call({aar, Opts}, _From, #state{service_started = true} = State) ->
    Result = send_aar(Opts),
    epdg_metrics:inc(diameter_swm_requests_total),
    {reply, Result, State};

handle_call({str, Opts}, _From, #state{service_started = true} = State) ->
    Result = send_str(Opts),
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
    %% `epdg_app:prep_stop/1' already calls `diameter:stop_service/1'
    %% before the supervisor walks the tree, so by the time this
    %% gen_server's `terminate/2' fires the service is normally gone.
    %% Probe `diameter:services/0' first so we only invoke
    %% `stop_service/1' once -- the second call against an
    %% already-stopped service can block on stale transport state and
    %% blow past the 5 s supervisor shutdown window, leaving diameter
    %% app state half-cleaned for the later `application:stop(diameter)'
    %% in `init:stop/0' to hang on.
    case lists:member(?SVC_NAME, diameter:services()) of
        true  -> catch diameter:stop_service(?SVC_NAME);
        false -> ok
    end,
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Message builders (list form, OTP diameter encodes via diameter_gen_swm)
%%====================================================================

send_der(#{session_id := SessionId, eap_payload := EAPPayload} = Opts) ->
    UserName = maps:get(user_name, Opts, undefined),
    APN      = to_bin(maps:get(apn, Opts, epdg_config:get(default_apn, "ims"))),
    RATType  = maps:get(rat_type, Opts, epdg_config:get(swm_rat_type, 0)),
    AuthReqT = maps:get(auth_request_type, Opts, 3),   % AUTHORIZE_AUTHENTICATE
    DestRealm = to_bin(maps:get(destination_realm, Opts,
                                epdg_config:get(swm_dest_realm,
                                    epdg_config:get(origin_realm, "localdomain")))),
    DestHost  = maps:get(destination_host, Opts, undefined),
    Base = ['DER',
            {'Session-Id', SessionId},
            {'Auth-Application-Id', ?SWM_APP_ID},
            {'Auth-Request-Type', AuthReqT},
            {'Destination-Realm', DestRealm},
            {'EAP-Payload', EAPPayload},
            {'Service-Selection', APN},
            {'RAT-Type', RATType}],
    Msg0 = maybe_add(Base, 'User-Name', UserName),
    Msg1 = maybe_add(Msg0, 'Visited-Network-Identifier',
                      maps:get(visited_plmn, Opts, undefined)),
    %% RFC 6733 §6.8 / 3GPP TS 29.273: pin follow-up DERs of a session to
    %% the AAA that anchored the first DEA. The DRA honours Destination-Host
    %% over load-balancing realm-based routing.
    Msg  = maybe_add(Msg1, 'Destination-Host', DestHost),
    do_call(Msg, fun parse_dea/1);

send_der(_Opts) ->
    {error, {missing, [session_id, eap_payload]}}.

send_aar(#{session_id := SessionId,
           user_name  := UserName} = Opts) ->
    APN      = to_bin(maps:get(apn, Opts, epdg_config:get(default_apn, "ims"))),
    RATType  = maps:get(rat_type, Opts, epdg_config:get(swm_rat_type, 0)),
    AuthReqT = maps:get(auth_request_type, Opts, 1),   % AUTHORIZE_ONLY
    DestRealm = to_bin(maps:get(destination_realm, Opts,
                                epdg_config:get(swm_dest_realm,
                                    epdg_config:get(origin_realm, "localdomain")))),
    DestHost  = maps:get(destination_host, Opts, undefined),
    Base = ['AAR',
            {'Session-Id', SessionId},
            {'Auth-Application-Id', ?SWM_APP_ID},
            {'Auth-Request-Type', AuthReqT},
            {'Destination-Realm', DestRealm},
            {'User-Name', UserName},
            {'Service-Selection', APN},
            {'RAT-Type', RATType}],
    Msg = maybe_add(Base, 'Destination-Host', DestHost),
    do_call(Msg, fun parse_aaa/1);

send_aar(_Opts) ->
    {error, {missing, [session_id, user_name]}}.

send_str(#{session_id := SessionId} = Opts) ->
    UserName  = maps:get(user_name, Opts, undefined),
    Cause     = maps:get(termination_cause, Opts, 1),  % LOGOUT
    DestRealm = to_bin(maps:get(destination_realm, Opts,
                                epdg_config:get(swm_dest_realm,
                                    epdg_config:get(origin_realm, "localdomain")))),
    DestHost  = maps:get(destination_host, Opts, undefined),
    Base = ['STR',
            {'Session-Id', SessionId},
            {'Destination-Realm', DestRealm},
            {'Auth-Application-Id', ?SWM_APP_ID},
            {'Termination-Cause', Cause}],
    Msg0 = maybe_add(Base, 'User-Name', UserName),
    Msg  = maybe_add(Msg0, 'Destination-Host', DestHost),
    do_call(Msg, fun parse_sta/1);

send_str(_Opts) ->
    {error, missing_session_id}.

do_call(Msg, ParseFun) ->
    case diameter:call(?SVC_NAME, ?APP_ALIAS, Msg, [{timeout, ?DIAM_CALL_TIMEOUT}]) of
        {ok, Answer} ->
            {ok, ParseFun(Answer)};
        {error, Reason} = Err ->
            logger:warning("SWm do_call: error ~p", [Reason]),
            Err;
        Other ->
            logger:warning("SWm do_call: unexpected return ~P", [Other, 10]),
            {error, Other}
    end.

%%====================================================================
%% Answer parsers — tolerant of both the generated record form and the
%% fallback list form returned by OTP diameter depending on how the
%% codec decoded the answer.
%%====================================================================

parse_dea(Answer) ->
    %% OTP diameter returns a `diameter_base_answer-message' record when
    %% the remote peer synthesises an RFC 6733 base error answer (e.g.
    %% the AAA server's OTP stack auto-answering with 3001 because the
    %% app-id was not negotiated on that transport). Extract Result-Code
    %% directly from that tuple shape so we surface the real error.
    case is_tuple(Answer)
         andalso element(1, Answer) =:= 'diameter_base_answer-message' of
        true  -> parse_base_answer(Answer);
        false -> parse_swm_dea(Answer)
    end.

parse_base_answer(Ans) ->
    %% Record layout (from diameter_gen_base_rfc6733):
    %%   {_tag, Session-Id, Origin-Host, Origin-Realm, Result-Code,
    %%    Origin-State-Id, Error-Reporting-Host, Proxy-Info, AVP}
    SId = first_binary(element(2, Ans)),
    OH  = first_binary(element(3, Ans)),
    RC  = element(5, Ans),
    #{session_id         => SId,
      origin_host        => OH,
      result_code        => RC,
      eap_payload        => <<>>,
      msk                => undefined,
      session_timeout    => undefined,
      non_3gpp_user_data => undefined,
      apn_configurations => [],
      mip6_feature_vector => undefined}.

parse_swm_dea(Answer) ->
    RC       = avp_value('Result-Code', Answer, 0),
    EapPl    = first_binary(avp_value('EAP-Payload', Answer, <<>>)),
    MSK      = first_binary(avp_value('EAP-Master-Session-Key', Answer, undefined)),
    Timeout  = avp_value('Session-Timeout', Answer, undefined),
    UserData = avp_value('Non-3GPP-User-Data', Answer, undefined),
    APNCfg   = avp_value('APN-Configuration', Answer, []),
    MIP6FV   = avp_value('MIP6-Feature-Vector', Answer, undefined),
    SId      = avp_value('Session-Id', Answer, <<>>),
    %% Origin-Host anchors the Diameter session to a specific AAA instance
    %% (RFC 6733 §6.8, 3GPP TS 29.273). Subsequent DERs for the same
    %% session must carry this as Destination-Host so the DRA routes
    %% them back to the AAA that holds the EAP state.
    OriginHost = first_binary(avp_value('Origin-Host', Answer, undefined)),
    #{session_id         => SId,
      result_code        => RC,
      origin_host        => OriginHost,
      eap_payload        => EapPl,
      msk                => MSK,
      session_timeout    => Timeout,
      non_3gpp_user_data => UserData,
      apn_configurations => ensure_list(APNCfg),
      mip6_feature_vector => MIP6FV}.

parse_aaa(Answer) ->
    RC       = avp_value('Result-Code', Answer, 0),
    Timeout  = avp_value('Session-Timeout', Answer, undefined),
    UserData = avp_value('Non-3GPP-User-Data', Answer, undefined),
    APNCfg   = avp_value('APN-Configuration', Answer, []),
    SId      = avp_value('Session-Id', Answer, <<>>),
    #{session_id         => SId,
      result_code        => RC,
      session_timeout    => Timeout,
      non_3gpp_user_data => UserData,
      apn_configurations => ensure_list(APNCfg)}.

parse_sta(Answer) ->
    RC  = avp_value('Result-Code', Answer, 0),
    SId = avp_value('Session-Id', Answer, <<>>),
    #{session_id => SId, result_code => RC}.

%%====================================================================
%% Diameter callbacks
%%====================================================================

peer_up(_SvcName, {_PeerRef, Caps}, State) ->
    RemoteHost = case Caps of
        #diameter_caps{origin_host = {_, RH}} -> RH;
        _ -> <<"unknown">>
    end,
    logger:notice("SWm peer up: ~s", [RemoteHost]),
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

pick_peer(LocalCandidates, RemoteCandidates, _SvcName, _State) ->
    case LocalCandidates of
        [Peer | _] -> {ok, Peer};
        _ ->
            case RemoteCandidates of
                [RPeer | _] -> {ok, RPeer};
                _ ->
                    logger:warning("SWm pick_peer: no peers available"),
                    false
            end
    end.

%% Inject Origin-Host / Origin-Realm from service Caps right before send.
%% Works on the list form of Msg (['DER', {AVP,V}, ...]).
prepare_request(#diameter_packet{msg = Msg} = Pkt, _SvcName, {_, Caps}) ->
    {send, Pkt#diameter_packet{msg = inject_origin(Msg, Caps)}}.

prepare_retransmit(Pkt, SvcName, Peer) ->
    prepare_request(Pkt, SvcName, Peer).

handle_answer(#diameter_packet{msg = Msg}, _Req, _SvcName, _Peer) ->
    {ok, Msg}.

handle_error(Reason, _Req, _SvcName, _Peer) ->
    logger:warning("SWm handle_error: ~P", [Reason, 10]),
    {error, Reason}.

handle_request(_Pkt, _SvcName, _Peer) ->
    %% ePDG is not expected to serve SWm requests; AAA → ePDG ASR/RAR
    %% arrive as this callback — answer with a 3001 for now.
    {answer_message, 3001}.

%%====================================================================
%% Origin injection (list form)
%%====================================================================

inject_origin(Msg, Caps) when is_list(Msg) ->
    #diameter_caps{origin_host = {OH, _}, origin_realm = {OR, _}} = Caps,
    case Msg of
        [Cmd | Rest] when is_atom(Cmd); is_binary(Cmd) ->
            Stripped = [AVP || AVP <- Rest, not is_origin(AVP)],
            [Cmd, {'Origin-Host', OH}, {'Origin-Realm', OR} | Stripped];
        _ -> Msg
    end.

is_origin({'Origin-Host', _})  -> true;
is_origin({'Origin-Realm', _}) -> true;
is_origin(_)                   -> false.

%%====================================================================
%% Transport health (unchanged from 0.0.16)
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
                {reconnect_timer, 5000},
                {capabilities,
                    [{'Auth-Application-Id', [?SWM_APP_ID]}]}
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

%%====================================================================
%% Answer helpers
%%====================================================================

%% Retrieve an AVP value from an Answer that might be:
%%   * a record (tuple with first element = command atom e.g. 'diameter_gen_swm_DEA')
%%   * a list ['DEA' | AVPs]
%%   * a plain list of AVPs (legacy)
avp_value(Key, Answer, Default) when is_tuple(Answer) ->
    %% Record form: tag, Session-Id, then AVPs — fall back to list form
    %% by searching recursively through the tuple fields.
    case tuple_to_list(Answer) of
        [_Tag | Fields] -> find_in_fields(Key, Fields, Default);
        _ -> Default
    end;
avp_value(Key, [_Cmd | AVPs], Default) when is_atom(_Cmd); is_binary(_Cmd) ->
    proplists:get_value(Key, AVPs, Default);
avp_value(Key, AVPs, Default) when is_list(AVPs) ->
    proplists:get_value(Key, AVPs, Default);
avp_value(_, _, Default) ->
    Default.

find_in_fields(_Key, [], Default) -> Default;
find_in_fields(Key, [V | Rest], Default) ->
    case lookup_here(Key, V) of
        {ok, Found} -> Found;
        not_found -> find_in_fields(Key, Rest, Default)
    end.

lookup_here(Key, L) when is_list(L) ->
    case proplists:get_value(Key, L) of
        undefined -> not_found;
        V -> {ok, V}
    end;
lookup_here(_, _) -> not_found.

first_binary([H | _]) when is_binary(H) -> H;
first_binary(B) when is_binary(B) -> B;
first_binary(_) -> undefined.

ensure_list(L) when is_list(L) -> L;
ensure_list(undefined) -> [];
ensure_list(V) -> [V].

%%====================================================================
%% Misc helpers
%%====================================================================

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L)   -> list_to_binary(L).

to_list(L) when is_list(L)   -> L;
to_list(B) when is_binary(B) -> binary_to_list(B).

maybe_add(Msg, _K, undefined) -> Msg;
maybe_add(Msg, K, V) -> Msg ++ [{K, V}].
