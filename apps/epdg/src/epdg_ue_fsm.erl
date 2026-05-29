%%%-------------------------------------------------------------------
%%% @doc Per-UE state machine (gen_statem).
%%% Manages IKEv2/IPsec tunnel lifecycle for a single UE.
%%%
%%% States: idle → ike_sa_init → ike_auth → established
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_fsm).

-behaviour(gen_statem).

-export([start_link/1, handle_ikev2/4, get_state/1, disconnect/1]).
-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([idle/3, ike_sa_init/3, ike_auth/3, established/3]).

-define(IKE_SA_INIT_TIMEOUT, 30000).
-define(IKE_AUTH_TIMEOUT,    60000).
-define(DPD_INTERVAL,        30000).
-define(DPD_TIMEOUT,         10000).
-define(DPD_RETRIES,             3).

%% Maximum jitter for graceful-drain teardown. Broadcast {drain, _} fans
%% out to every live UE FSM simultaneously; each FSM picks a random delay
%% in [0, ?DRAIN_MAX_JITTER_MS) before tearing its tunnel down so N UEs
%% don't all reconnect to a sibling pod in the same millisecond.
-define(DRAIN_MAX_JITTER_MS, 30000).

-record(data, {
    peer_ip          :: inet:ip_address() | undefined,
    peer_port        :: inet:port_number() | undefined,
    initiator_spi    :: non_neg_integer() | undefined,
    responder_spi    :: non_neg_integer() | undefined,
    imsi             :: binary() | undefined,
    apn              :: binary() | undefined,
    ike_sa           :: map() | undefined,
    child_sa         :: map() | undefined,
    eap_state        :: map() | undefined,
    pgw_session      :: map() | undefined,
    ue_inner_ip      :: inet:ip_address() | undefined,
    ue_inner_ip6     :: inet:ip_address() | undefined,
    message_id       :: non_neg_integer(),
    nonce_i          :: binary() | undefined,
    nonce_r          :: binary() | undefined,
    dh_group         :: non_neg_integer() | undefined,
    dh_public        :: binary() | undefined,
    dh_private       :: binary() | undefined,
    %% DH shared secret (g^ir mod p) used to derive SKEYSEED
    shared_secret    :: binary() | undefined,
    %% Negotiated IKE crypto suite as returned by epdg_ikev2_codec:select_proposal/1
    crypto_suite     :: map() | undefined,
    %% Key-derivation parameters from keys_params_for_suite/1
    keys_params      :: map() | undefined,
    %% SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
    ike_keys         :: map() | undefined,
    %% IDr payload body (bytes after 4-byte reserved hdr) cached for AUTH signature
    idr_body         :: binary() | undefined,
    %% UE NAI (IDi payload data) for SWm user-name etc.
    ue_nai           :: binary() | undefined,
    %% DPD consecutive failure counter (RFC 7296 §2.4)
    dpd_failures     :: non_neg_integer(),
    %% EAP identifier counter (monotonic per RFC 3748)
    eap_next_id      :: non_neg_integer(),
    %% X.509 certificate for IKEv2 responder auth (TS 33.402 §7.2.1)
    cert_der         :: binary() | undefined,
    private_key      :: term() | undefined,
    %% Stored IKE_SA_INIT request bytes (as received from the UE) for use
    %% when verifying the UE's AUTH payload (RFC 7296 §2.15 "InitiatorSigned
    %% Octets" = RealMessage1).
    ike_sa_init_req  :: binary() | undefined,
    %% Stored IKE_SA_INIT response bytes for AUTH signature (RFC 7296 §2.15)
    %% and retransmission (RFC 7296 §2.1).
    ike_sa_init_resp :: binary() | undefined,
    %% IDi payload body (IDType | reserved(3) | identity data) cached from
    %% the first IKE_AUTH request so we can recompute prf(SK_pi, IDi')
    %% when verifying the UE's MSK-AUTH after EAP-Success.
    idi_body         :: binary() | undefined,
    %% SWm (Diameter) session tying this UE to the AAA server; allocated
    %% on the first EAP-Response/Identity from the UE and reused across
    %% every DER/DEA round until teardown.
    swm_session_id   :: binary() | undefined,
    %% Origin-Host of the AAA that answered the first DEA. Per RFC 6733
    %% §6.8 and 3GPP TS 29.273, every follow-up DER for this session
    %% must carry this as Destination-Host so the DRA pins the route
    %% to the AAA instance that holds the EAP/session state.
    swm_dest_host    :: binary() | undefined,
    %% EAP Master Session Key delivered by the AAA via the success DEA
    %% (TS 33.402 §7.2.2). Used to compute the IKE_AUTH AUTH payload
    %% per RFC 7296 §2.16 (prf-PSK form of §2.15 with MSK as shared key).
    eap_msk          :: binary() | undefined,
    %% True once EAP-AKA' has completed successfully and we have sent
    %% EAP-Success to the UE; we then wait for the UE's final AUTH.
    eap_done         :: boolean(),
    %% S2b session metadata returned by the PGW, cached so FSM
    %% terminate/3 can issue a Delete-Session-Request with the right
    %% TEID + EBI.
    gtpu_teid_local  :: non_neg_integer() | undefined,
    gtpu_teid_pgw    :: non_neg_integer() | undefined,
    %% RFC 7296 §2.16 (IKE_AUTH with EAP): SAi2 / TSi / TSr are carried in
    %% the *first* IKE_AUTH message (alongside IDi) — the post-EAP-Success
    %% AUTH message only contains AUTH. We cache the raw payload bodies
    %% here when we decrypt that first message so finalize_ike_auth/N can
    %% pick the child-SA proposal + TS selectors from them once the AUTH
    %% round completes. If these stay `undefined` we end up falling back
    %% to default_child_suite() with peer_spi=0, which installs an
    %% outbound XFRM SA with SPI 0 and silently kills the downlink.
    sai2_body        :: binary() | undefined,
    tsi_body         :: binary() | undefined,
    tsr_body         :: binary() | undefined,
    %% Cached final IKE_AUTH response bytes for retransmission (RFC 7296
    %% §2.1: "If a request is retransmitted, the responder MUST send back
    %% its last response to that request").
    ike_auth_last_resp :: binary() | undefined,
    %% Message ID of the last IKE_AUTH request we responded to; used to
    %% detect retransmissions across all EAP round-trip stages.
    ike_auth_last_msg_id :: non_neg_integer() | undefined
}).

%%====================================================================
%% API
%%====================================================================

start_link(InitContext) ->
    gen_statem:start_link(?MODULE, InitContext, []).

-spec handle_ikev2(pid(), map(), binary(), inet:port_number() | undefined) -> ok.
handle_ikev2(Pid, Header, RawData, FromPort) ->
    gen_statem:cast(Pid, {ikev2, Header, RawData, FromPort}).

-spec get_state(pid()) -> {ok, atom()}.
get_state(Pid) ->
    gen_statem:call(Pid, get_state).

-spec disconnect(pid()) -> ok.
disconnect(Pid) ->
    gen_statem:cast(Pid, disconnect).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

callback_mode() -> [state_functions, state_enter].

init(#{peer_ip := PeerIP, peer_port := PeerPort} = _Ctx) ->
    RSPI = epdg_ikev2_crypto:generate_spi(),
    epdg_metrics:inc(ue_sessions_total),
    epdg_metrics:gauge_inc(ue_sessions_active),
    {CertDer, PrivKey} = load_ike_certificate(),
    {ok, idle, #data{
        peer_ip       = PeerIP,
        peer_port     = PeerPort,
        responder_spi = RSPI,
        message_id    = 0,
        dpd_failures  = 0,
        eap_next_id   = 1,
        cert_der      = CertDer,
        private_key   = PrivKey,
        eap_done      = false,
        ike_auth_last_resp = undefined,
        ike_auth_last_msg_id = undefined
    }}.

terminate(_Reason, _State, #data{responder_spi = RSPI, imsi = IMSI,
                                  peer_ip = PeerIP, initiator_spi = ISPI,
                                  child_sa = ChildSA, pgw_session = PGW,
                                  ue_nai = UeNai,
                                  swm_session_id = SwmSessionId,
                                  swm_dest_host  = SwmDestHost}) ->
    case ChildSA of
        #{spi_in := SPIIn, spi_out := SPIOut} ->
            catch epdg_xfrm:delete_sa(#{spi => SPIIn}),
            catch epdg_xfrm:delete_sa(#{spi => SPIOut});
        _ -> ok
    end,
    case PGW of
        #{pgw_c_teid := CTEID, ebi := EBI} ->
            catch epdg_gtpc_client:delete_session_request(
                    #{pgw_c_teid => CTEID, ebi => EBI});
        #{pgw_teid := TEID} ->
            catch epdg_gtpc_client:delete_session_request(#{pgw_teid => TEID});
        _ -> ok
    end,
    %% Release the SWm Diameter session toward the 3GPP AAA Server
    %% (TS 29.273 clause 7 session-termination procedure). Fire-and-forget
    %% from a detached process: session_termination_request/1 is a blocking
    %% gen_server:call with a 10 s+ timeout, while the UE FSM only gets a
    %% 5 s supervisor shutdown budget — blocking here would risk a brutal
    %% kill. During a full pod drain epdg_app:prep_stop/1 has already
    %% stopped the diameter service, so this is a harmless no-op then; it
    %% matters for per-UE detach (UE DELETE, DPD timeout).
    maybe_send_swm_str(SwmSessionId, SwmDestHost, IMSI, UeNai),
    case PGW of
        #{local_u_teid := LocalUTEID} ->
            catch epdg_gtpu_forwarder:unregister_ue(LocalUTEID);
        _ -> ok
    end,
    catch epdg_ue_registry:unregister(RSPI),
    case {PeerIP, ISPI} of
        {IP, I} when IP =/= undefined, I =/= undefined ->
            catch epdg_ue_registry:unregister_initiator(IP, I);
        _ -> ok
    end,
    epdg_metrics:gauge_dec(ue_sessions_active),
    logger:info("UE FSM terminated IMSI=~p RSPI=~.16B", [IMSI, value_or_zero(RSPI)]),
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%% Best-effort SWm Session-Termination-Request (STR, TS 29.273 clause 7).
%% Only meaningful once the UE was anchored to an AAA (swm_session_id set
%% on the first DER). Spawned so the blocking Diameter call never holds up
%% the FSM's terminate/3.
maybe_send_swm_str(undefined, _DestHost, _IMSI, _UeNai) ->
    ok;
maybe_send_swm_str(SessionId, DestHost, IMSI, UeNai) ->
    UserName = pick_user_name(UeNai, IMSI),
    Base = #{session_id => SessionId, termination_cause => 1},  %% DIAMETER_LOGOUT
    Args0 = case UserName of
        UN when is_binary(UN), byte_size(UN) > 0 -> Base#{user_name => UN};
        _                                        -> Base
    end,
    Args = case DestHost of
        DH when is_binary(DH), byte_size(DH) > 0 -> Args0#{destination_host => DH};
        _                                        -> Args0
    end,
    spawn(fun() ->
        case catch epdg_diameter_swm:session_termination_request(Args) of
            {ok, #{result_code := RC}} ->
                logger:info("SWm STR sent session_id=~s IMSI=~p result_code=~p",
                            [SessionId, IMSI, RC]);
            Other ->
                logger:info("SWm STR best-effort send result session_id=~s "
                            "IMSI=~p: ~p", [SessionId, IMSI, Other])
        end
    end),
    ok.

%%====================================================================
%% State: idle
%%====================================================================

idle(enter, _OldState, Data) ->
    {keep_state, Data, [{state_timeout, ?IKE_SA_INIT_TIMEOUT, timeout}]};

idle(cast, {ikev2, #{exchange_type := ike_sa_init} = Header, RawData, FromPort}, Data) ->
    handle_ike_sa_init_request(Header, RawData,
                               (refresh_peer_port(Data, FromPort))
                                   #data{ike_sa_init_req = RawData});

idle(cast, {ikev2, _, _, _}, Data) ->
    {keep_state, Data};

idle(cast, {drain, Reason}, Data) ->
    handle_drain(idle, Reason, Data);
idle(info, drain_stop, _Data) ->
    {stop, {shutdown, drained}};

idle(state_timeout, timeout, #data{peer_ip = PeerIP} = _Data) ->
    logger:warning("UE FSM idle timeout (no IKE_SA_INIT received) peer=~p", [PeerIP]),
    {stop, normal};

idle({call, From}, get_state, Data) ->
    {keep_state, Data, [{reply, From, {ok, idle}}]}.

%%====================================================================
%% State: ike_sa_init
%%====================================================================

ike_sa_init(enter, _OldState, Data) ->
    {keep_state, Data, [{state_timeout, ?IKE_AUTH_TIMEOUT, timeout}]};

ike_sa_init(cast, {ikev2, #{exchange_type := ike_auth} = Header, RawData, FromPort}, Data) ->
    handle_ike_auth_request(Header, RawData, refresh_peer_port(Data, FromPort));

%% IKE_SA_INIT retransmit from the initiator: re-send our cached response bytes
%% (RFC 7296 §2.1 - responder MUST retransmit the same response, not regenerate).
ike_sa_init(cast, {ikev2, #{exchange_type := ike_sa_init}, _RawData, FromPort},
            #data{peer_ip = PeerIP,
                  ike_sa_init_resp = Resp} = Data0)
  when is_binary(Resp), byte_size(Resp) > 0 ->
    Data = refresh_peer_port(Data0, FromPort),
    #data{peer_port = PeerPort} = Data,
    logger:info("IKE_SA_INIT retransmit detected, re-sending cached response "
                "(~p bytes) to ~p:~p", [byte_size(Resp), PeerIP, PeerPort]),
    catch epdg_ikev2_listener:send(PeerIP, PeerPort, 500, Resp),
    {keep_state, Data};

ike_sa_init(cast, {ikev2, _, _, _}, Data) ->
    {keep_state, Data};

ike_sa_init(cast, {drain, Reason}, Data) ->
    handle_drain(ike_sa_init, Reason, Data);
ike_sa_init(info, drain_stop, _Data) ->
    {stop, {shutdown, drained}};

ike_sa_init(state_timeout, timeout,
            #data{peer_ip = PeerIP, initiator_spi = ISPI} = _Data) ->
    logger:warning("UE FSM ike_sa_init timeout (no IKE_AUTH received) "
                   "peer=~p ISPI=~.16B", [PeerIP, value_or_zero(ISPI)]),
    {stop, normal};

ike_sa_init({call, From}, get_state, Data) ->
    {keep_state, Data, [{reply, From, {ok, ike_sa_init}}]}.

%%====================================================================
%% State: ike_auth (EAP exchange in progress)
%%====================================================================

ike_auth(enter, _OldState, Data) ->
    {keep_state, Data, [{state_timeout, ?IKE_AUTH_TIMEOUT, timeout}]};

%% RFC 7296 §2.1 retransmission: if we already responded to this MsgId,
%% retransmit the cached response instead of re-processing.
ike_auth(cast, {ikev2, #{exchange_type := ike_auth, message_id := MsgId} = _Header,
                _RawData, FromPort},
         #data{ike_auth_last_msg_id = MsgId, ike_auth_last_resp = LastResp,
               imsi = IMSI} = Data)
  when is_binary(LastResp), byte_size(LastResp) > 0 ->
    Data1 = refresh_peer_port(Data, FromPort),
    #data{peer_ip = PIP, peer_port = PP} = Data1,
    catch epdg_ikev2_listener:send(PIP, PP, LastResp),
    logger:notice("ike_auth: retransmitting cached response (~B bytes) "
                  "msg_id=~B IMSI=~p", [byte_size(LastResp), MsgId, IMSI]),
    {keep_state, Data1};

ike_auth(cast, {ikev2, #{exchange_type := ike_auth} = Header, RawData, FromPort}, Data) ->
    handle_ike_auth_eap(Header, RawData, refresh_peer_port(Data, FromPort));

%% A UE may abandon the half-open IKE SA mid-auth with an INFORMATIONAL
%% DELETE (RFC 7296 §1.4.1). Handle it the same way as in `established`
%% so we ack and tear down rather than crashing on an unmatched event.
ike_auth(cast, {ikev2, #{exchange_type := informational} = Header, RawData, FromPort}, Data) ->
    handle_informational(Header, RawData, refresh_peer_port(Data, FromPort));

ike_auth(cast, disconnect, _Data) ->
    {stop, normal};

%% The GTP-C client saw the PGW restart (Recovery IE change) or lost
%% its Echo heartbeat — every ongoing session is invalid, so tear down
%% cleanly and the UE will redial.
ike_auth(cast, pgw_restart, _Data) -> {stop, {shutdown, pgw_restart}};
ike_auth(cast, pgw_down,    _Data) -> {stop, {shutdown, pgw_unreachable}};

ike_auth(cast, {drain, Reason}, Data) ->
    handle_drain(ike_auth, Reason, Data);
ike_auth(info, drain_stop, _Data) ->
    {stop, {shutdown, drained}};

ike_auth(state_timeout, timeout, #data{peer_ip = PeerIP, imsi = IMSI} = _Data) ->
    logger:warning("UE FSM ike_auth timeout (EAP exchange abandoned) "
                   "peer=~p IMSI=~p", [PeerIP, IMSI]),
    {stop, normal};

ike_auth({call, From}, get_state, Data) ->
    {keep_state, Data, [{reply, From, {ok, ike_auth}}]}.

%%====================================================================
%% State: established (IPsec tunnel active)
%%====================================================================

established(enter, _OldState, #data{responder_spi = RSPI, imsi = IMSI} = Data) ->
    epdg_ue_registry:register(RSPI, self(), IMSI),
    logger:info("Tunnel established IMSI=~p RSPI=~.16B", [IMSI, RSPI]),
    epdg_metrics:inc(ike_tunnels_established_total),
    Interval = epdg_config:get(dpd_interval, ?DPD_INTERVAL),
    {keep_state, Data, [{state_timeout, Interval, dpd}]};

established(cast, {ikev2, #{exchange_type := informational, flags := Flags} = _Header,
                   _RawData, FromPort}, Data)
  when (Flags band 16#20) =/= 0 ->
    %% INFORMATIONAL response — this is the UE's reply to our DPD probe.
    Interval = epdg_config:get(dpd_interval, ?DPD_INTERVAL),
    {keep_state, (refresh_peer_port(Data, FromPort))#data{dpd_failures = 0},
     [{state_timeout, Interval, dpd}]};

established(cast, {ikev2, #{exchange_type := informational} = Header, RawData, FromPort}, Data) ->
    handle_informational(Header, RawData, refresh_peer_port(Data, FromPort));

established(cast, {ikev2, #{exchange_type := create_child_sa} = _Header, _RawData, FromPort}, Data) ->
    %% MOBIKE or rekey
    {keep_state, refresh_peer_port(Data, FromPort)};

established(cast, {ikev2, #{exchange_type := ike_auth, message_id := MsgId} = _Header,
                   _RawData, FromPort},
            #data{imsi = IMSI, ike_auth_last_resp = LastResp} = Data) ->
    %% RFC 7296 §2.1: retransmit our cached response to a retransmitted
    %% request. Without this, a single UDP packet loss on the final
    %% IKE_AUTH response leaves the UE stuck (never receives tunnel params).
    Data1 = refresh_peer_port(Data, FromPort),
    case LastResp of
        Bin when is_binary(Bin), byte_size(Bin) > 0 ->
            #data{peer_ip = PIP, peer_port = PP} = Data1,
            catch epdg_ikev2_listener:send(PIP, PP, Bin),
            logger:notice("established: retransmitting IKE_AUTH response "
                          "(~B bytes) msg_id=~B IMSI=~p",
                          [byte_size(Bin), MsgId, IMSI]);
        _ ->
            logger:warning("established: ignoring unexpected ike_auth msg_id=~B "
                           "IMSI=~p (no cached response)", [MsgId, IMSI])
    end,
    %% UE is alive (it sent us a packet) — reset DPD.
    Interval = epdg_config:get(dpd_interval, ?DPD_INTERVAL),
    {keep_state, Data1#data{dpd_failures = 0},
     [{state_timeout, Interval, dpd}]};

established(cast, disconnect, _Data) ->
    {stop, normal};

established(cast, pgw_restart, _Data) -> {stop, {shutdown, pgw_restart}};
established(cast, pgw_down,    _Data) -> {stop, {shutdown, pgw_unreachable}};

established(cast, {drain, Reason}, Data) ->
    handle_drain(established, Reason, Data);
established(info, drain_stop, Data) ->
    %% Best-effort: tell the UE to abandon this IKE SA so it can redial
    %% a sibling pod immediately rather than waiting for DPD. Any failure
    %% (missing keys, listener down) is logged and swallowed — we still
    %% tear the FSM down so the preStop deadline is honoured.
    _ = try_send_delete_informational(Data),
    {stop, {shutdown, drained}};

established(state_timeout, dpd, #data{dpd_failures = F, imsi = IMSI} = Data) ->
    MaxRetries = epdg_config:get(dpd_retries, ?DPD_RETRIES),
    case F >= MaxRetries of
        true ->
            logger:warning("DPD: peer unreachable after ~B probes, "
                           "terminating IMSI=~p", [F, IMSI]),
            epdg_metrics:inc(dpd_timeout_total),
            {stop, {shutdown, dpd_timeout}};
        false ->
            Data1 = send_dpd_probe(Data),
            Timeout = epdg_config:get(dpd_timeout, ?DPD_TIMEOUT),
            {keep_state, Data1#data{dpd_failures = F + 1},
             [{state_timeout, Timeout, dpd}]}
    end;

established({call, From}, get_state, Data) ->
    {keep_state, Data, [{reply, From, {ok, established}}]}.

%%====================================================================
%% IKE_SA_INIT handler
%%====================================================================

handle_ike_sa_init_request(#{initiator_spi := ISPI, next_payload := NextPL,
                              payload_data := PayloadBin,
                              message_id   := MsgId} = _Header,
                            _RawData,
                            #data{responder_spi = RSPI,
                                  peer_ip = PeerIP, peer_port = PeerPort} = Data) ->
    case epdg_ikev2_codec:decode_payloads(NextPL, PayloadBin) of
        {ok, Payloads} ->
            case process_sa_init_payloads(Payloads) of
                {ok, Parsed} ->
                    send_sa_init_response(ISPI, MsgId, Parsed, Data);
                {error, Reason} ->
                    logger:warning("IKE_SA_INIT from ~p:~p rejected: ~p "
                                   "(ISPI=~.16B RSPI=~.16B)",
                                   [PeerIP, PeerPort, Reason, ISPI, RSPI]),
                    send_notify_and_stop(ISPI, MsgId, Reason, Data)
            end;
        {error, DecodeErr} ->
            logger:warning("IKE_SA_INIT from ~p:~p payload decode error: ~p",
                           [PeerIP, PeerPort, DecodeErr]),
            send_notify_and_stop(ISPI, MsgId, invalid_syntax, Data)
    end.

%% Extract and validate SA / KE / Nonce payloads.
process_sa_init_payloads(Payloads) ->
    case epdg_ikev2_codec:find_payload(sa, Payloads) of
        {ok, #{data := SAData}} ->
            case epdg_ikev2_codec:decode_sa_payload(SAData) of
                {ok, Proposals} ->
                    log_sa_proposals(Proposals),
                    KEPeek = case epdg_ikev2_codec:find_payload(ke, Payloads) of
                        {ok, #{data := <<DHGrp:16, _Rsv:16, _/binary>>}} ->
                            DHGrp;
                        _ -> undefined
                    end,
                    logger:notice("IKE_SA_INIT KE DH group advertised=~p", [KEPeek]),
                    case epdg_ikev2_codec:select_proposal(Proposals) of
                        {ok, Suite} ->
                            #{encr := #{id := EId, attrs := EA},
                              prf  := #{id := PId},
                              integ := Ig,
                              dh   := #{id := DId}} = Suite,
                            IntegDesc = case Ig of
                                none -> none;
                                #{id := IId} -> IId
                            end,
                            logger:notice("IKE_SA_INIT chose suite encr=~p(~p) "
                                          "prf=~p integ=~p dh=~p",
                                          [EId, EA, PId, IntegDesc, DId]),
                            with_ke_and_nonce(Suite, Payloads);
                        {error, SelErr} ->
                            logger:warning("IKE_SA_INIT select_proposal rejected: ~p",
                                           [SelErr]),
                            {error, no_proposal_chosen}
                    end;
                {error, DErr} ->
                    logger:warning("IKE_SA_INIT decode_sa_payload failed: ~p",
                                   [DErr]),
                    {error, invalid_syntax}
            end;
        error ->
            {error, invalid_syntax}
    end.

%% Dump every transform in every proposal the UE sent so we can tell, from
%% runtime evidence, which algorithm/keylen/DH combo was offered and which
%% of our predicates (is_supported_encr/prf/integ/dh) is rejecting it.
log_sa_proposals(Proposals) ->
    logger:notice("IKE_SA_INIT peer offered ~B proposal(s)", [length(Proposals)]),
    lists:foreach(fun(#{number := N, protocol_id := Proto,
                        transforms_data := TData} = _Prop) ->
        case epdg_ikev2_codec:decode_transforms(TData) of
            {ok, Transforms} ->
                Summary = [format_transform(T) || T <- Transforms],
                logger:notice("  proposal #~B proto=~B transforms=~s",
                              [N, Proto, lists:join(", ", Summary)]);
            {error, TErr} ->
                logger:warning("  proposal #~B transforms decode failed: ~p",
                               [N, TErr])
        end
    end, Proposals).

format_transform(#{type := Type, id := Id, attrs := Attrs}) ->
    AttrStr = case maps:get(key_length, Attrs, undefined) of
        undefined -> "";
        KL -> io_lib:format("/keylen=~B", [KL])
    end,
    io_lib:format("~s:~B~s", [atom_to_list(Type), Id, AttrStr]).

with_ke_and_nonce(Suite, Payloads) ->
    case epdg_ikev2_codec:find_payload(ke, Payloads) of
        {ok, #{data := KEData}} ->
            case epdg_ikev2_codec:decode_ke_payload(KEData) of
                {ok, {PeerDHGroup, PeerPub}} ->
                    #{dh := #{id := SelectedDH}} = Suite,
                    case PeerDHGroup =:= SelectedDH of
                        true ->
                            with_nonce(Suite, PeerPub, Payloads);
                        false ->
                            {error, invalid_ke_payload}
                    end;
                {error, _} -> {error, invalid_syntax}
            end;
        error ->
            {error, invalid_syntax}
    end.

with_nonce(Suite, PeerPub, Payloads) ->
    case epdg_ikev2_codec:find_payload(nonce, Payloads) of
        {ok, #{data := NonceI}} when byte_size(NonceI) >= 16,
                                      byte_size(NonceI) =< 256 ->
            {ok, #{suite => Suite, peer_dh_pub => PeerPub, nonce_i => NonceI}};
        _ ->
            {error, invalid_syntax}
    end.

%% Build and transmit the IKE_SA_INIT response; transition to ike_sa_init state.
send_sa_init_response(ISPI, MsgId,
                       #{suite := Suite, peer_dh_pub := PeerPub, nonce_i := NonceI},
                       #data{responder_spi = RSPI, peer_ip = PeerIP,
                             peer_port = PeerPort, cert_der = CertDer} = Data) ->
    #{dh := #{id := DHGroupId}} = Suite,
    {DHPub, DHPriv} = epdg_ikev2_crypto:dh_generate(DHGroupId),

    %% DH shared secret for later SKEYSEED computation in IKE_AUTH.
    SharedSecret =
        try epdg_ikev2_crypto:dh_compute(DHGroupId, PeerPub, DHPriv)
        catch _:Err ->
            logger:warning("DH compute failed: ~p", [Err]),
            <<>>
        end,

    NonceR = epdg_ikev2_crypto:generate_nonce(),

    %% Encode response payloads: SA_r | KE_r | Nonce_r | [CERTREQ]
    SAPayload    = epdg_ikev2_codec:encode_sa_response(Suite#{spi => <<>>}),
    KEPayload    = epdg_ikev2_codec:encode_ke_payload(DHGroupId, DHPub),
    NoncePayload = epdg_ikev2_codec:encode_nonce_payload(NonceR),

    %% RFC 7296 §2.23: responder MUST include NAT_DETECTION_SOURCE_IP and
    %% NAT_DETECTION_DESTINATION_IP notifies in the IKE_SA_INIT response.
    %% Each hash = SHA1(SPIi || SPIr || IP || Port), with SPIs as 8-byte
    %% values and port as 2 bytes. The UE compares our
    %% NAT_DETECTION_DESTINATION_IP against SHA1(SPIi||SPIr||dst_it_sent_to
    %% || port) — in a K8s pod we hash our internal pod IP (e.g.
    %% 10.0.4.49), while the UE sends to our public/NATed IP, so the
    %% hashes inevitably differ and the UE recognises the ePDG is behind
    %% a NAT and switches subsequent IKE + ESP to UDP/4500. Without these
    %% notifies strongSwan/iOS/Android stay on port 500 and emit pure
    %% ESP (IP proto 50), which Kubernetes CNIs/LBs drop, so no ESP ever
    %% reaches the pod's XFRM.
    %% Per RFC 7296 §2.23: SOURCE hash = hash of IP/port the packet is
    %% SENT FROM (us, the responder); DESTINATION hash = hash of IP/port
    %% the packet is SENT TO (the UE). An earlier iteration had these
    %% swapped — correct now.
    OurIpBin = ip_bytes(local_hash_ip()),
    UeIpBin  = ip_bytes(PeerIP),
    OurPort  = 500,
    UePort   = PeerPort,
    NatSourceHash =
        crypto:hash(sha, <<ISPI:64, RSPI:64, OurIpBin/binary, OurPort:16>>),
    NatDestHash =
        crypto:hash(sha, <<ISPI:64, RSPI:64, UeIpBin/binary,  UePort:16>>),
    NatSourceNotify = epdg_ikev2_codec:encode_notify_payload(0, 16388, <<>>, NatSourceHash),
    NatDestNotify   = epdg_ikev2_codec:encode_notify_payload(0, 16389, <<>>, NatDestHash),

    %% Standard ordering (matches strongSwan / cisco / RFC §1.2 example):
    %% SA, KE, Nonce, [CERTREQ], N(NAT_SOURCE), N(NAT_DESTINATION).
    Payloads1 = [{sa, SAPayload}, {ke, KEPayload}, {nonce, NoncePayload}],
    Payloads2 = case CertDer of
        undefined -> Payloads1;
        _ ->
            CertReq = epdg_ikev2_codec:encode_certreq_payload(<<>>),
            Payloads1 ++ [{certreq, CertReq}]
    end,
    Payloads = Payloads2 ++ [{notify, NatSourceNotify},
                             {notify, NatDestNotify}],

    {FirstPL, PayloadBin} = epdg_ikev2_codec:encode_payloads(Payloads),

    %% Flags: Response (0x20), not Initiator (we are responder).
    RespBytes = epdg_ikev2_codec:encode_header(
        #{initiator_spi     => ISPI,
          responder_spi     => RSPI,
          next_payload      => FirstPL,
          exchange_type_raw => 34,  %% IKE_SA_INIT
          flags             => 16#20,
          message_id        => MsgId,
          payload_bin       => PayloadBin}),

    case epdg_ikev2_listener:send(PeerIP, PeerPort, 500, RespBytes) of
        ok -> ok;
        {error, SendErr} ->
            logger:warning("Failed to send IKE_SA_INIT response to ~p:~p: ~p",
                           [PeerIP, PeerPort, SendErr])
    end,

    %% Register SPI and (peer_ip, ispi) so subsequent messages + retransmits
    %% reach this FSM.
    epdg_ue_registry:register(RSPI, self(), undefined),
    epdg_ue_registry:register_initiator(PeerIP, ISPI, self()),

    NewData = Data#data{
        initiator_spi    = ISPI,
        nonce_i          = NonceI,
        nonce_r          = NonceR,
        dh_group         = DHGroupId,
        dh_public        = DHPub,
        dh_private       = DHPriv,
        shared_secret    = SharedSecret,
        crypto_suite     = Suite,
        ike_sa_init_resp = RespBytes
    },
    {next_state, ike_sa_init, NewData}.

%% Send a NOTIFY response and terminate cleanly — avoids log-noisy crash reports.
send_notify_and_stop(ISPI, MsgId, Reason,
                      #data{responder_spi = RSPI, peer_ip = PeerIP,
                            peer_port = PeerPort} = Data) ->
    NotifyType = notify_type_for_reason(Reason),
    NotifyPayload = epdg_ikev2_codec:encode_notify_payload(0, NotifyType,
                                                            <<>>, <<>>),
    {FirstPL, PayloadBin} = epdg_ikev2_codec:encode_payloads(
        [{notify, NotifyPayload}]),
    RespBytes = epdg_ikev2_codec:encode_header(
        #{initiator_spi     => ISPI,
          responder_spi     => RSPI,
          next_payload      => FirstPL,
          exchange_type_raw => 34,
          flags             => 16#20,
          message_id        => MsgId,
          payload_bin       => PayloadBin}),
    catch epdg_ikev2_listener:send(PeerIP, PeerPort, 500, RespBytes),
    {stop, normal, Data}.

notify_type_for_reason(no_proposal_chosen) -> 14;
notify_type_for_reason(invalid_ke_payload) -> 17;
notify_type_for_reason(invalid_syntax)     -> 7;
notify_type_for_reason(_)                  -> 7.

value_or_zero(undefined) -> 0;
value_or_zero(N)         -> N.

%%====================================================================
%% IKE_AUTH handler (initial, first UE → ePDG encrypted exchange)
%%
%% Flow per RFC 7296 §1.2 / TS 33.402 §7.2.2:
%%   1. Derive SK_d/SK_a{i,r}/SK_e{i,r}/SK_p{i,r} from SKEYSEED.
%%   2. Decrypt the SK payload (RFC 5282 AEAD wire format).
%%   3. Parse inner chain: IDi (NAI), [CERT], [CERTREQ], [IDr], [SAi2,
%%      TSi, TSr, CP, etc.]. For EAP-AKA' the UE sends no AUTH.
%%   4. Build responder IDr (FQDN from config).
%%   5. Compute AUTH signature = sign(IKE_SA_INIT_resp | Nonce_i |
%%      prf(SK_pr, IDr')). Body of IDr (type + reserved + data) is used.
%%   6. Encode inner response chain: IDr | CERT | AUTH | EAP-Req/Identity.
%%      (Real EAP-AKA'/Challenge arrives via SWm in the next patch.)
%%   7. Encrypt inside SK + send. Transition to ike_auth.
%%====================================================================

handle_ike_auth_request(Header, RawData,
                        #data{shared_secret = SharedSecret,
                              nonce_i = NonceI, nonce_r = NonceR,
                              crypto_suite = Suite,
                              initiator_spi = ISPI, responder_spi = RSPI,
                              cert_der = CertDer, private_key = PrivKey,
                              ike_sa_init_resp = IkeSaInitRespBytes,
                              peer_ip = PeerIP, peer_port = PeerPort,
                              eap_next_id = EapId} = Data) ->
    #{message_id := MsgId, flags := InFlags} = Header,

    case prerequisites_ok(Data) of
        {error, Reason} ->
            logger:warning("IKE_AUTH rejected: ~p peer=~p:~p", [Reason, PeerIP, PeerPort]),
            {stop, normal, Data};
        ok ->
            case epdg_ikev2_codec:keys_params_for_suite(Suite) of
                {error, KPErr} ->
                    logger:warning("IKE_AUTH: unsupported crypto suite: ~p", [KPErr]),
                    {stop, normal, Data};
                {ok, KeyParams} ->
                    %% Derive IKE SA keys (SKEYSEED + SK_*) now that we have
                    %% NonceI/NonceR/SharedSecret and a ready params map.
                    %% RFC 7296 §2.14 seeds prf+ with Ni|Nr|SPIi|SPIr; pass
                    %% both SPIs as 8-byte big-endian binaries.
                    KeyParams2 = KeyParams#{spi_i => <<ISPI:64>>,
                                             spi_r => <<RSPI:64>>},
                    Keys = epdg_ikev2_crypto:derive_ike_keys(
                             SharedSecret, NonceI, NonceR, KeyParams2),
                    logger:info("IKE_AUTH keys derived ISPI=~.16B RSPI=~.16B "
                                "prf=~p aead=~p enc_key_len=~p integ_key_len=~p",
                                [ISPI, RSPI,
                                 maps:get(prf, KeyParams),
                                 maps:get(is_aead, KeyParams),
                                 maps:get(enc_key_len, KeyParams),
                                 maps:get(integ_key_len, KeyParams)]),

                    %% Decrypt the SK payload. The peer is the initiator so
                    %% they used SK_ei / SK_ai.
                    case epdg_ikev2_crypto:decode_encrypted_message(
                           KeyParams, Keys, initiator, RawData) of
                        {error, DErr} ->
                            logger:warning("IKE_AUTH: decrypt failed: ~p "
                                           "peer=~p:~p", [DErr, PeerIP, PeerPort]),
                            {stop, normal, Data};
                        {ok, #{payloads := InnerPayloads}} ->
                            logger:info("IKE_AUTH decrypted: ~p inner payloads",
                                        [length(InnerPayloads)]),
                            {IDiType, UeNai, IDiBody} = extract_idi(InnerPayloads),
                            %% RFC 7296 §2.16: SAi2 / TSi / TSr arrive in
                            %% this first IKE_AUTH request together with IDi
                            %% (not in the post-EAP-Success AUTH message),
                            %% so capture them now for finalize_ike_auth/N.
                            Sai2Body = stash_payload_body(sa,  InnerPayloads),
                            TsiBody  = stash_payload_body(tsi, InnerPayloads),
                            TsrBody  = stash_payload_body(tsr, InnerPayloads),
                            IMSI = parse_imsi_from_nai(UeNai),
                            logger:info("IKE_AUTH IDi type=~p data=~p IMSI=~p",
                                        [IDiType, UeNai, IMSI]),

                            %% Build IDr = FQDN of ePDG (RFC 7296 §3.5 ID_FQDN=2).
                            IDrFqdn = list_to_binary(
                                epdg_config:get(ike_id_fqdn,
                                                "epdg.localdomain")),
                            IDrPayload = epdg_ikev2_codec:encode_id_payload(2, IDrFqdn),

                            %% Compute AUTH over (IKE_SA_INIT_resp | Nonce_i
                            %% | prf(SK_pr, IDr')). IDr' = ID payload body.
                            #{prf := PRF} = KeyParams,
                            {AuthMethod, Signature} =
                                epdg_ikev2_crypto:sign_auth_data(
                                    PRF, IkeSaInitRespBytes, NonceI,
                                    #{sk_pr => maps:get(sk_pr, Keys),
                                      id_payload => IDrPayload},
                                    PrivKey),

                            CertBin = epdg_ikev2_codec:encode_cert_payload(CertDer),
                            AuthBin = epdg_ikev2_codec:encode_auth_payload(
                                          AuthMethod, Signature),
                            %% First EAP message: Request/Identity. Replaced
                            %% once SWm DER/DEA is wired in.
                            EapReq  = epdg_ikev2_codec:encode_eap_request_identity(EapId),
                            EapBin  = epdg_ikev2_codec:encode_eap_payload(EapReq),

                            InnerChain = [
                                {idr,  IDrPayload},
                                {cert, CertBin},
                                {auth, AuthBin},
                                {eap,  EapBin}
                            ],

                            %% Preserve peer's flag set except we flip Response
                            %% and clear Initiator (we are responder).
                            RespFlags = (InFlags band (bnot 16#08)) bor 16#20,

                            Hdr = #{initiator_spi     => ISPI,
                                    responder_spi     => RSPI,
                                    exchange_type_raw => 35,  %% IKE_AUTH
                                    flags             => RespFlags,
                                    message_id        => MsgId},

                            case epdg_ikev2_crypto:encode_encrypted_message(
                                   KeyParams, Keys, responder, Hdr, InnerChain) of
                                {ok, RespBytes} ->
                                    catch epdg_ikev2_listener:send(
                                            PeerIP, PeerPort, RespBytes),
                                    logger:info(
                                      "IKE_AUTH response sent (~p bytes) "
                                      "IMSI=~p MsgId=~B",
                                      [byte_size(RespBytes), IMSI, MsgId]),
                                    NewData = Data#data{
                                        keys_params  = KeyParams,
                                        ike_keys     = Keys,
                                        idr_body     = IDrPayload,
                                        idi_body     = IDiBody,
                                        imsi         = IMSI,
                                        ue_nai       = UeNai,
                                        eap_next_id  = (EapId + 1) rem 256,
                                        sai2_body    = Sai2Body,
                                        tsi_body     = TsiBody,
                                        tsr_body     = TsrBody,
                                        ike_auth_last_resp = RespBytes,
                                        ike_auth_last_msg_id = MsgId
                                    },
                                    {next_state, ike_auth, NewData};
                                {error, EErr} ->
                                    logger:warning(
                                      "IKE_AUTH response encrypt failed: ~p",
                                      [EErr]),
                                    {stop, normal, Data}
                            end
                    end
            end
    end.

prerequisites_ok(#data{shared_secret = <<>>}) -> {error, no_shared_secret};
prerequisites_ok(#data{shared_secret = undefined}) -> {error, no_shared_secret};
prerequisites_ok(#data{nonce_i = undefined}) -> {error, no_nonce_i};
prerequisites_ok(#data{nonce_r = undefined}) -> {error, no_nonce_r};
prerequisites_ok(#data{crypto_suite = undefined}) -> {error, no_suite};
prerequisites_ok(#data{cert_der = undefined}) -> {error, no_cert};
prerequisites_ok(#data{private_key = undefined}) -> {error, no_priv_key};
prerequisites_ok(#data{ike_sa_init_resp = undefined}) -> {error, no_ike_sa_init_resp};
prerequisites_ok(_) -> ok.

%% Locate the IDi payload in the decrypted inner chain and normalise it to
%% {IdType, IdData, IdBody} where IdBody = IDType(1) | reserved(3) |
%% IdData, i.e. the full payload body (RFC 7296 §2.15 "IDi'"). Returns
%% {undefined, <<>>, <<>>} if absent/unparseable.
extract_idi(Payloads) ->
    case epdg_ikev2_codec:find_payload(idi, Payloads) of
        {ok, #{data := D}} ->
            case epdg_ikev2_codec:decode_id_payload(D) of
                {ok, {T, Raw}} -> {T, Raw, D};
                _              -> {undefined, <<>>, <<>>}
            end;
        _ -> {undefined, <<>>, <<>>}
    end.

%% Extract IMSI from a 3GPP permanent identity NAI of the form
%%   0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
%% (TS 23.003 §19.3.2). Tolerates pseudonym / re-auth forms by returning
%% undefined if the user-part doesn't match an IMSI pattern.
parse_imsi_from_nai(<<>>) -> undefined;
parse_imsi_from_nai(Nai) when is_binary(Nai) ->
    case binary:split(Nai, <<"@">>) of
        [Username, _Realm] ->
            case Username of
                <<"0", Digits/binary>> ->
                    case is_all_digits(Digits) of
                        true  -> Digits;
                        false -> undefined
                    end;
                _ -> undefined
            end;
        _ -> undefined
    end.

is_all_digits(<<>>) -> false;
is_all_digits(B)    -> is_all_digits_acc(B).
is_all_digits_acc(<<>>) -> true;
is_all_digits_acc(<<C, Rest/binary>>) when C >= $0, C =< $9 ->
    is_all_digits_acc(Rest);
is_all_digits_acc(_) -> false.

%%====================================================================
%% IKE_AUTH EAP continuation
%%====================================================================

%% Continuation IKE_AUTH exchanges carry the UE's EAP response inside an
%% SK payload (RFC 7296 §2.16). We decrypt, extract the EAP packet, and
%% relay it via Diameter-EAP-Request (SWm, TS 29.273 clause 7) toward the
%% 3GPP AAA server. The DEA brings back the next EAP packet — typically
%% EAP-Request/AKA'-Challenge on the first round, then Success/Failure —
%% which we wrap into a fresh SK and send back to the UE.
%%
%% The IKE FSM stays in state `ike_auth' across every EAP round, only
%% transitioning once the UE sends its final AUTH (handled in the
%% post-EAP-Success branch, currently logged and awaiting the CP/SAr2
%% phase of the tunnel bring-up).
handle_ike_auth_eap(Header, RawData,
                    #data{keys_params = KeyParams, ike_keys = Keys,
                          initiator_spi = ISPI, responder_spi = RSPI,
                          peer_ip = PeerIP, peer_port = PeerPort} = Data) ->
    #{message_id := MsgId, flags := InFlags} = Header,

    case {KeyParams, Keys} of
        {undefined, _} ->
            logger:warning("IKE_AUTH(cont): no key params, dropping "
                           "peer=~p:~p MsgId=~B", [PeerIP, PeerPort, MsgId]),
            {stop, normal, Data};
        {_, undefined} ->
            logger:warning("IKE_AUTH(cont): no IKE keys, dropping "
                           "peer=~p:~p MsgId=~B", [PeerIP, PeerPort, MsgId]),
            {stop, normal, Data};
        {_, _} ->
            case epdg_ikev2_crypto:decode_encrypted_message(
                   KeyParams, Keys, initiator, RawData) of
                {error, DErr} ->
                    logger:warning("IKE_AUTH(cont): decrypt failed: ~p "
                                   "peer=~p:~p MsgId=~B",
                                   [DErr, PeerIP, PeerPort, MsgId]),
                    {stop, normal, Data};
                {ok, #{payloads := InnerPayloads}} ->
                    dispatch_ike_auth_cont(MsgId, InFlags, InnerPayloads,
                                           ISPI, RSPI, Data)
            end
    end.

%% Branch on whether this inner chain carries an AUTH payload (UE proving
%% MSK knowledge after EAP-Success, RFC 7296 §2.16) or an EAP response
%% (another round of EAP-AKA' being relayed via SWm).
dispatch_ike_auth_cont(MsgId, InFlags, InnerPayloads, ISPI, RSPI,
                       #data{eap_done = true} = Data) ->
    case epdg_ikev2_codec:find_payload(auth, InnerPayloads) of
        {ok, #{data := AuthRaw}} ->
            handle_post_eap_auth(MsgId, InFlags, AuthRaw, InnerPayloads,
                                 ISPI, RSPI, Data);
        _ ->
            logger:warning("IKE_AUTH(cont): post-EAP-Success message without "
                           "AUTH payload; ignoring MsgId=~B", [MsgId]),
            {keep_state, Data}
    end;
dispatch_ike_auth_cont(MsgId, InFlags, InnerPayloads, ISPI, RSPI,
                       #data{} = Data) ->
    PayloadTypes = [maps:get(type, P) || P <- InnerPayloads],
    logger:info("IKE_AUTH(cont) decrypted MsgId=~B payloads=~p",
                [MsgId, PayloadTypes]),
    EapBytes = case epdg_ikev2_codec:find_payload(eap, InnerPayloads) of
        {ok, #{data := EB}} -> EB;
        _ -> <<>>
    end,
    log_eap_packet(EapBytes),
    case EapBytes of
        <<>> ->
            logger:warning("IKE_AUTH(cont): no EAP payload in inner chain; "
                           "ignoring MsgId=~B", [MsgId]),
            {keep_state, Data};
        _ ->
            relay_eap_via_swm(MsgId, InFlags, EapBytes, ISPI, RSPI, Data)
    end.

%% Relay an EAP packet through SWm (DER/DEA) and act on the AAA server's
%% response. Returns a gen_statem transition tuple.
relay_eap_via_swm(MsgId, InFlags, EapBytes, ISPI, RSPI,
                  #data{imsi = IMSI, ue_nai = UeNai,
                        peer_ip = PeerIP, peer_port = _PeerPort,
                        swm_session_id = SessionId0,
                        swm_dest_host  = DestHost0} = Data) ->
    SessionId = case SessionId0 of
        undefined -> epdg_diameter_swm:new_session_id();
        S         -> S
    end,
    Base = #{session_id  => SessionId,
             user_name   => pick_user_name(UeNai, IMSI),
             eap_payload => EapBytes,
             apn         => to_bin(epdg_config:get(default_apn, "ims"))},
    DERArgs = case DestHost0 of
        undefined -> Base;
        DH        -> Base#{destination_host => DH}
    end,
    logger:notice("SWm DER send session_id=~s eap_len=~B IMSI=~p dest_host=~p",
                  [SessionId, byte_size(EapBytes), IMSI, DestHost0]),
    case epdg_diameter_swm:diameter_eap_request(DERArgs) of
        {ok, #{result_code := RC} = Dea} ->
            DestHost1 = pick_dest_host(DestHost0, Dea),
            logger:notice("SWm DEA recv session_id=~s result_code=~B "
                          "eap_out_len=~B msk_len=~B origin_host=~p",
                          [SessionId, RC,
                           iolist_size(maps:get(eap_payload, Dea, <<>>)),
                           msk_len(maps:get(msk, Dea, undefined)),
                           maps:get(origin_host, Dea, undefined)]),
            handle_dea(RC, Dea, MsgId, InFlags, ISPI, RSPI,
                       Data#data{swm_session_id = SessionId,
                                 swm_dest_host  = DestHost1});
        {error, Reason} ->
            logger:warning("SWm DER failed: ~p session_id=~s IMSI=~p",
                           [Reason, SessionId, IMSI]),
            send_eap_failure_and_stop(MsgId, InFlags, ISPI, RSPI,
                                      Data#data{swm_session_id = SessionId})
    end.

%% Once we have anchored the session to an AAA, keep that Origin-Host
%% even if a later DEA omits it. If we have none yet, take the first
%% non-empty Origin-Host we see (RFC 6733 §6.8).
pick_dest_host(Current, Dea) ->
    case maps:get(origin_host, Dea, undefined) of
        OH when is_binary(OH), byte_size(OH) > 0 -> OH;
        _ -> Current
    end.

%% DIAMETER_MULTI_ROUND_AUTH (1001): another EAP round.
handle_dea(1001, #{eap_payload := EapOut}, MsgId, InFlags, ISPI, RSPI, Data)
  when is_binary(EapOut), byte_size(EapOut) >= 4 ->
    Data1 = send_eap_to_ue(EapOut, MsgId, InFlags, ISPI, RSPI, Data),
    {keep_state, Data1};
%% DIAMETER_SUCCESS (2001): EAP has completed; DEA carries EAP-Success and
%% the MSK for computing the final IKE AUTH.
handle_dea(2001, #{eap_payload := EapOut, msk := MSK}, MsgId, InFlags,
           ISPI, RSPI, Data)
  when is_binary(EapOut), byte_size(EapOut) >= 4,
       is_binary(MSK),    byte_size(MSK)    >= 32 ->
    logger:notice("SWm auth SUCCESS: MSK=~B bytes delivered", [byte_size(MSK)]),
    Data1 = send_eap_to_ue(EapOut, MsgId, InFlags, ISPI, RSPI, Data),
    {keep_state, Data1#data{eap_msk = MSK, eap_done = true}};
%% Failure codes or missing/short AVPs in the DEA.
handle_dea(RC, Dea, MsgId, InFlags, ISPI, RSPI, Data) ->
    EapOut = case maps:get(eap_payload, Dea, <<>>) of
        B when is_binary(B), byte_size(B) >= 4 -> B;
        _ -> build_eap_failure_for(Data)
    end,
    logger:warning("SWm auth FAILURE result_code=~B - sending EAP-Failure", [RC]),
    Data1 = send_eap_to_ue(EapOut, MsgId, InFlags, ISPI, RSPI, Data),
    {stop, normal, Data1}.

%% Final IKE_AUTH message post-EAP-Success (TS 33.402 §7.2.2 steps
%% 14-17): the UE sends its own AUTH over the MSK. We verify it,
%% request an S2b PDN connection from the PGW, install the kernel
%% ESP SAs for the negotiated child SA, then answer with
%%   IDr | AUTH | CFG_REPLY | SAr2 | TSi | TSr
%% and transition to `established`.
handle_post_eap_auth(MsgId, InFlags, AuthRaw, InnerPayloads,
                     ISPI, RSPI,
                     #data{eap_msk = MSK,
                           keys_params = KeyParams,
                           ike_keys = Keys,
                           nonce_r = NonceR, nonce_i = NonceI,
                           ike_sa_init_req = IkeSaInitReqBytes,
                           ike_sa_init_resp = IkeSaInitRespBytes,
                           idi_body = IDiBody,
                           idr_body = IDrBody,
                           imsi = IMSI, ue_nai = UeNai,
                           peer_ip = PeerIP, peer_port = PeerPort,
                           apn = Apn0} = Data0) ->
    logger:notice("IKE_AUTH(cont) post-EAP-Success AUTH received "
                  "(~B bytes) IMSI=~p", [byte_size(AuthRaw), IMSI]),

    #{prf := PRF} = KeyParams,
    {_AuthMethod, PeerAuth} = case epdg_ikev2_codec:decode_auth_payload(AuthRaw) of
        {ok, Pair} -> Pair;
        _ -> {0, <<>>}
    end,

    case epdg_ikev2_crypto:verify_initiator_psk_auth(
           PRF, MSK, IkeSaInitReqBytes, NonceR,
           maps:get(sk_pi, Keys), IDiBody, PeerAuth) of
        false ->
            logger:warning("IKE_AUTH AUTH verify failed IMSI=~p "
                           "auth_len=~B", [IMSI, byte_size(PeerAuth)]),
            send_ike_notify_and_stop(MsgId, InFlags, ISPI, RSPI,
                                     24, Data0);  %% AUTHENTICATION_FAILED
        true ->
            logger:info("IKE_AUTH AUTH verified (MSK-based, RFC 5998)"),
            Apn = case Apn0 of undefined -> default_apn(); A -> A end,
            proceed_with_s2b(MsgId, InFlags, ISPI, RSPI,
                              InnerPayloads, UeNai, IMSI, IDrBody,
                              NonceI, NonceR,
                              IkeSaInitRespBytes, Apn,
                              PeerIP, PeerPort, Data0#data{apn = Apn})
    end.

default_apn() ->
    list_to_binary(epdg_config:get(default_apn, "ims")).

%%--------------------------------------------------------------------
%% Request an S2b PDN connection, set up the child SA, then send the
%% final IKE_AUTH response.
%%--------------------------------------------------------------------

proceed_with_s2b(MsgId, InFlags, ISPI, RSPI,
                 InnerPayloads, _UeNai, IMSI, IDrBody,
                 NonceI, NonceR,
                 IkeSaInitRespBytes, Apn,
                 PeerIP, PeerPort,
                 #data{keys_params = KeyParams, ike_keys = Keys,
                       eap_msk = MSK} = Data0) ->
    LocalCTeid = new_teid(),
    LocalUTeid = new_teid(),
    case epdg_gtpc_client:create_session_request(#{
            imsi         => IMSI,
            apn          => Apn,
            rat_type     => 3,           %% WLAN
            pdn_type     => 1,           %% IPv4
            ebi          => 5,
            local_c_teid => LocalCTeid,
            local_u_teid => LocalUTeid
        }) of
        {ok, #{cause := Cause} = Resp} when Cause =:= 16 orelse Cause =:= undefined ->
            finalize_ike_auth(MsgId, InFlags, ISPI, RSPI, InnerPayloads,
                               IDrBody, NonceI, NonceR,
                               IkeSaInitRespBytes, MSK,
                               KeyParams, Keys,
                               LocalCTeid, LocalUTeid, Resp,
                               PeerIP, PeerPort, Data0);
        {ok, #{cause := Cause}} ->
            logger:warning("S2b Create-Session rejected cause=~B IMSI=~p",
                           [Cause, IMSI]),
            send_ike_notify_and_stop(MsgId, InFlags, ISPI, RSPI,
                                     37, Data0); %% NO_ADDITIONAL_SAS
        {error, Reason} ->
            logger:warning("S2b Create-Session failed: ~p IMSI=~p",
                           [Reason, IMSI]),
            send_ike_notify_and_stop(MsgId, InFlags, ISPI, RSPI,
                                     37, Data0)
    end.

finalize_ike_auth(MsgId, InFlags, ISPI, RSPI, InnerPayloads,
                   IDrBody, NonceI, NonceR,
                   IkeSaInitRespBytes, MSK, KeyParams, Keys,
                   LocalCTeid, LocalUTeid, GtpcResp,
                   PeerIP, PeerPort, Data0) ->
    #{prf := PRF} = KeyParams,

    %% RFC 7296 §2.16: in the EAP flow, SAi2 / TSi / TSr arrive in the
    %% FIRST IKE_AUTH message together with IDi — the post-EAP-Success
    %% AUTH message only carries AUTH. We stashed those payload bodies
    %% into #data{} in handle_ike_auth_request/3; prefer them here, and
    %% only fall back to the current (post-EAP) InnerPayloads for the
    %% corner case where a non-EAP UE sent SAi2 alongside AUTH.
    SaiBin = case Data0#data.sai2_body of
                 undefined ->
                     case epdg_ikev2_codec:find_payload(sa, InnerPayloads) of
                         {ok, #{data := SB}} -> SB;
                         _                   -> undefined
                     end;
                 SB2 -> SB2
             end,
    ChildSuite = case SaiBin of
        undefined -> default_child_suite();
        _ ->
            case epdg_ikev2_codec:decode_child_sa_payload(SaiBin) of
                {ok, S} -> S;
                _       -> default_child_suite()
            end
    end,

    EncKeyLen   = epdg_ikev2_codec:child_enc_key_len(maps:get(encr, ChildSuite)),
    IntegKeyLen = epdg_ikev2_codec:child_integ_key_len(maps:get(integ, ChildSuite, none)),
    Needed      = 2 * (EncKeyLen + IntegKeyLen),

    %% RFC 7296 §2.17: KEYMAT = prf+(SK_d, Ni|Nr). Split into:
    %%   SK_ei_child | SK_ai_child | SK_er_child | SK_ar_child
    #{key_material := KeyMat} =
        epdg_ikev2_crypto:derive_child_keys(PRF, maps:get(sk_d, Keys),
                                             NonceI, NonceR, Needed),
    {SkEiChild, SkAiChild, SkErChild, SkArChild} =
        split_child_keymat(KeyMat, EncKeyLen, IntegKeyLen),

    %% Allocate our (responder) ESP SPI.
    <<ResponderSPIInt:32>> = crypto:strong_rand_bytes(4),
    ResponderSPI = <<ResponderSPIInt:32>>,

    %% Peer SPI (initiator) from the UE's SA payload
    PeerSPI = maps:get(peer_spi, ChildSuite, <<0:32>>),

    %% CP/TS from UE
    {UeInnerIp, PdnDns, PdnPcscf, _CpAttrsIn} =
        extract_pdn_attrs(GtpcResp),
    %% Same reasoning as SAi2 above — TSi/TSr were stashed from the
    %% first IKE_AUTH. Fall back to whatever the post-EAP AUTH message
    %% happens to carry only if the stash is empty (defensive).
    {UeTsi, UeTsr} = extract_ts_stashed_or(Data0, InnerPayloads),

    install_child_sas(PeerIP, PeerPort, PeerSPI, ResponderSPI,
                       ChildSuite,
                       SkEiChild, SkAiChild, SkErChild, SkArChild,
                       UeInnerIp),

    %% Register this UE's bearer with the GTP-U forwarder so the
    %% inbound GTP-U packets from PGW-U can be demuxed to the right
    %% TUN device.
    {PgwUIp, PgwUTeid} = pgw_u_from_resp(GtpcResp),
    catch epdg_gtpu_forwarder:register_ue(#{
        pgw_u_teid   => PgwUTeid,
        pgw_u_ip     => PgwUIp,
        ue_inner_ip  => UeInnerIp,
        imsi         => Data0#data.imsi,
        owner_pid    => self(),
        local_teid_hint => LocalUTeid}),

    %% Responder AUTH (MSK-based, method 2 = Shared Key MIC)
    AuthSig = epdg_ikev2_crypto:build_responder_psk_auth(
                PRF, MSK, IkeSaInitRespBytes, NonceI,
                maps:get(sk_pr, Keys), IDrBody),
    AuthBin = epdg_ikev2_codec:encode_auth_payload(2, AuthSig),

    %% CFG_REPLY from the PGW's PAA + PCO
    CpReplyBin = build_cfg_reply(UeInnerIp, PdnDns, PdnPcscf),

    %% SAr2: advertise chosen child suite with our SPI
    ChildRespSuite = ChildSuite#{responder_spi => ResponderSPI},
    SaBin = epdg_ikev2_codec:encode_child_sa_response(ChildRespSuite),
    %% TSi/TSr mirror what the UE proposed.
    TsiBin = encode_ts_or_default(UeTsi),
    TsrBin = encode_ts_or_default(UeTsr),

    %% IDrBody is already the RFC 7296 §3.5 ID payload body (IDType |
    %% reserved | IDdata) we encoded in the first IKE_AUTH response;
    %% encode_payloads_chain/1 re-wraps it with the generic 4-byte
    %% payload header on its way out.
    InnerChain = [
        {idr,  IDrBody},
        {auth, AuthBin},
        {cp,   CpReplyBin},
        {sa,   SaBin},
        {tsi,  TsiBin},
        {tsr,  TsrBin}
    ],

    RespFlags = (InFlags band (bnot 16#08)) bor 16#20,
    Hdr = #{initiator_spi     => ISPI,
            responder_spi     => RSPI,
            exchange_type_raw => 35,
            flags             => RespFlags,
            message_id        => MsgId},

    case epdg_ikev2_crypto:encode_encrypted_message(
           KeyParams, Keys, responder, Hdr, InnerChain) of
        {ok, RespBytes} ->
            catch epdg_ikev2_listener:send(PeerIP, PeerPort, RespBytes),
            logger:info("IKE_AUTH final response sent (~B bytes) IMSI=~p "
                        "ue_inner_ip=~p pcscf=~p dns=~p",
                        [byte_size(RespBytes), Data0#data.imsi,
                         UeInnerIp, PdnPcscf, PdnDns]),
            epdg_metrics:inc(ike_auth_success_total),
            Data1 = Data0#data{
                child_sa = #{spi_in  => ResponderSPIInt,
                             spi_out => binary_to_int(PeerSPI),
                             suite   => ChildRespSuite},
                pgw_session = GtpcResp#{ue_inner_ip => UeInnerIp,
                                          local_c_teid => LocalCTeid,
                                          local_u_teid => LocalUTeid},
                ue_inner_ip = UeInnerIp,
                gtpu_teid_local = LocalUTeid,
                gtpu_teid_pgw = PgwUTeid,
                ike_auth_last_resp = RespBytes,
                ike_auth_last_msg_id = MsgId
            },
            {next_state, established, Data1};
        {error, EErr} ->
            logger:warning("IKE_AUTH final response encrypt failed: ~p",
                           [EErr]),
            epdg_metrics:inc(ike_auth_failure_total),
            {stop, normal, Data0}
    end.

%% Default transforms fallback if the UE didn't send an SAi2 we can
%% understand — stick to the same IKE suite we already agreed on.
default_child_suite() ->
    #{encr   => #{type => encr, type_raw => 1, id => 12,
                  attrs => #{key_length => 128}},
      integ  => #{type => integ, type_raw => 3, id => 12, attrs => #{}},
      esn    => #{type => esn, type_raw => 5, id => 0, attrs => #{}},
      proposal_number => 1,
      protocol_id => 3,
      peer_spi    => <<0:32>>}.

split_child_keymat(Mat, E, I) ->
    <<SKei:E/binary, Rest1/binary>> = Mat,
    <<SKai:I/binary, Rest2/binary>> = Rest1,
    <<SKer:E/binary, Rest3/binary>> = Rest2,
    <<SKar:I/binary, _/binary>> = Rest3,
    {SKei, SKai, SKer, SKar}.

%% Pull UE inner IP / DNS / P-CSCF out of the GTP-C Create-Session-Resp
%% map that our codec returns.
extract_pdn_attrs(#{paa := #{ipv4 := Ip4}, pco := Pco}) ->
    {Ip4, maps:get(dns_v4, Pco, []), maps:get(pcscf_v4, Pco, []), Pco};
extract_pdn_attrs(#{paa := #{ipv4 := Ip4}}) ->
    {Ip4, [], [], #{}};
extract_pdn_attrs(_) ->
    {{0,0,0,0}, [], [], #{}}.

pgw_u_from_resp(#{pgw_u_fteid := #{ip := IP, teid := T}}) -> {IP, T};
pgw_u_from_resp(_) -> {{0,0,0,0}, 0}.

extract_ts_in(InnerPayloads) ->
    Tsi = case epdg_ikev2_codec:find_payload(tsi, InnerPayloads) of
        {ok, #{data := D1}} ->
            case epdg_ikev2_codec:decode_ts_payload(D1) of
                {ok, Ts} -> Ts;
                _ -> []
            end;
        _ -> []
    end,
    Tsr = case epdg_ikev2_codec:find_payload(tsr, InnerPayloads) of
        {ok, #{data := D2}} ->
            case epdg_ikev2_codec:decode_ts_payload(D2) of
                {ok, Ts2} -> Ts2;
                _ -> []
            end;
        _ -> []
    end,
    {Tsi, Tsr}.

%% Cache helper for the first IKE_AUTH payloads we need later in
%% finalize_ike_auth/N (RFC 7296 §2.16 EAP flow carries SAi2/TSi/TSr in
%% the initial IKE_AUTH, not in the post-EAP-Success AUTH message).
stash_payload_body(Kind, Payloads) ->
    case epdg_ikev2_codec:find_payload(Kind, Payloads) of
        {ok, #{data := B}} -> B;
        _                  -> undefined
    end.

decode_ts_body(undefined) -> [];
decode_ts_body(Body) ->
    case epdg_ikev2_codec:decode_ts_payload(Body) of
        {ok, Ts} -> Ts;
        _        -> []
    end.

%% Prefer stashed TSi/TSr from the first IKE_AUTH; fall back to the
%% current inner payloads only if both are missing (e.g. non-EAP UE that
%% sent TS alongside AUTH).
extract_ts_stashed_or(#data{tsi_body = TsiB, tsr_body = TsrB}, InnerPayloads)
  when TsiB =/= undefined orelse TsrB =/= undefined ->
    {decode_ts_body(TsiB), decode_ts_body(TsrB)};
extract_ts_stashed_or(_Data, InnerPayloads) ->
    extract_ts_in(InnerPayloads).

encode_ts_or_default([]) ->
    %% Fallback: 0.0.0.0 - 255.255.255.255 full traffic selector
    epdg_ikev2_codec:encode_ts_payload([
        #{ts_type => ipv4_addr_range, ip_protocol => 0,
          start_port => 0, end_port => 65535,
          start_addr => {0,0,0,0}, end_addr => {255,255,255,255}}]);
encode_ts_or_default(List) when is_list(List), List /= [] ->
    epdg_ikev2_codec:encode_ts_payload(List).

%% Build a CFG_REPLY with the PDN attributes returned by the PGW.
build_cfg_reply(Ip4, DnsList, PcscfList) ->
    {A,B,C,D} = Ip4,
    Base = [{internal_ip4_address, <<A:8,B:8,C:8,D:8>>},
            {internal_ip4_netmask, <<255:8,255:8,255:8,255:8>>}],
    Dns = [{internal_ip4_dns, encode_ip4(X)} || X <- DnsList],
    Pcf = [{p_cscf_ip4_address, encode_ip4(X)} || X <- PcscfList],
    epdg_ikev2_codec:encode_cp_payload(2, Base ++ Dns ++ Pcf).

encode_ip4({A,B,C,D}) -> <<A:8,B:8,C:8,D:8>>.

%%--------------------------------------------------------------------
%% Install IPsec SAs + policies for the freshly-negotiated Child SA.
%% Error handling is best-effort: if xfrm fails the UE won't be able
%% to send/receive traffic but IKE signalling still stays up so the
%% operator sees the failure via logs/metrics.
%%--------------------------------------------------------------------

install_child_sas({U_A, U_B, U_C, U_D} = UeOuter, PeerPort, PeerSPI, RespSPI,
                   Suite,
                   SkEiChild, SkAiChild, SkErChild, SkArChild,
                   UeInnerIp) ->
    LocalOuter = local_outer_ip(),
    SpiInInt   = binary_to_int(RespSPI),
    SpiOutInt  = binary_to_int(PeerSPI),
    EncAlgIn   = child_enc_alg(maps:get(encr, Suite)),
    IntegAlgIn = child_integ_alg(maps:get(integ, Suite, none)),

    %% Inbound SA: UE → ePDG (SPI = responder SPI we picked)
    InboundParams0 = #{spi => SpiInInt,
                        src_ip => UeOuter,
                        dst_ip => LocalOuter,
                        enc_alg => EncAlgIn,
                        enc_key => SkEiChild,
                        auth_alg => IntegAlgIn,
                        auth_key => SkAiChild},
    InboundParams = maybe_nat_t(InboundParams0, UeOuter, PeerPort),
    %% Surface the real return of the xfrm call instead of swallowing it.
    %% A silent failure here (EPERM, shell syntax error, etc.) leaves the
    %% kernel without an IPsec SA while IKE_AUTH still completes, and the
    %% UE data plane breaks with no on-box error trail.
    log_xfrm_result(sa_in, SpiInInt,
                    catch epdg_xfrm:create_sa(InboundParams)),

    %% Outbound SA: ePDG → UE (SPI = UE's initiator SPI)
    OutboundParams0 = #{spi => SpiOutInt,
                         src_ip => LocalOuter,
                         dst_ip => UeOuter,
                         enc_alg => EncAlgIn,
                         enc_key => SkErChild,
                         auth_alg => IntegAlgIn,
                         auth_key => SkArChild},
    OutboundParams = maybe_nat_t(OutboundParams0, UeOuter, PeerPort),
    log_xfrm_result(sa_out, SpiOutInt,
                    catch epdg_xfrm:create_sa(OutboundParams)),

    UeCidr  = ip4_cidr(UeInnerIp, 32),
    AnyCidr = "0.0.0.0/0",

    log_xfrm_result(pol_in, 0,
        catch epdg_xfrm:create_policy(#{src => UeCidr, dst => AnyCidr,
                                          direction => in,
                                          tmpl_src => UeOuter,
                                          tmpl_dst => LocalOuter})),
    %% `dir fwd` is REQUIRED for the uplink data path: after XFRM
    %% decrypts an inbound ESP frame, the Linux kernel checks an
    %% inbound policy matching the *decrypted* inner packet. If that
    %% inner packet is destined for forwarding (dst is not local to
    %% the pod, which is the common case for ePDG → PGW), the kernel
    %% consults `dir fwd`, NOT `dir in`. Without it, every decrypted
    %% packet is dropped with XfrmInNoPols and never reaches the
    %% routing / TUN layer. See xfrm(8) and net/xfrm/xfrm_policy.c.
    log_xfrm_result(pol_fwd, 0,
        catch epdg_xfrm:create_policy(#{src => UeCidr, dst => AnyCidr,
                                          direction => fwd,
                                          tmpl_src => UeOuter,
                                          tmpl_dst => LocalOuter})),
    log_xfrm_result(pol_out, 0,
        catch epdg_xfrm:create_policy(#{src => AnyCidr, dst => UeCidr,
                                          direction => out,
                                          tmpl_src => LocalOuter,
                                          tmpl_dst => UeOuter})),
    _ = {U_A, U_B, U_C, U_D},  %% silence unused
    ok.

%% Log the return of an xfrm mutation. Keeps IKE signalling up on
%% failure (historical behaviour) but leaves a clear audit trail when
%% the kernel refuses the op (EPERM, shell parse, unknown algo, …).
log_xfrm_result(_Kind, _Spi, ok) -> ok;
log_xfrm_result(Kind, Spi, {error, Reason}) ->
    logger:warning("XFRM ~p spi=~.16B FAILED: ~p", [Kind, Spi, Reason]),
    epdg_metrics:inc(xfrm_sa_errors_total),
    error;
log_xfrm_result(Kind, Spi, Other) ->
    logger:warning("XFRM ~p spi=~.16B unexpected: ~p", [Kind, Spi, Other]),
    epdg_metrics:inc(xfrm_sa_errors_total),
    error.

maybe_nat_t(Params, PeerOuter, PeerPort) ->
    %% We infer NAT-T from the peer port: if the UE is sending from
    %% UDP/4500 the IKE_SA_INIT NAT_DETECTION exchange asserted that
    %% one end is behind a NAT, so turn on espinudp. 500 → plain ESP.
    case PeerPort of
        4500 ->
            Params#{nat_t => true,
                    peer_outer_ip => PeerOuter,
                    peer_udp_port => PeerPort,
                    local_udp_port => 4500};
        _ -> Params
    end.

%% When the UE completes the NAT_DETECTION_*_IP exchange during
%% IKE_SA_INIT and one end is behind a NAT, both peers move subsequent
%% IKE traffic to UDP/4500 (RFC 3948). Our FSM stored peer_port from
%% whatever port the very first packet arrived on (usually 500), so
%% without this refresh `maybe_nat_t/3` later sees 500 and installs a
%% plain-ESP XFRM state with no `encap espinudp`. That breaks decryption
%% of the UE's ESP-in-UDP packets silently (XfrmInNoStates stays 0).
refresh_peer_port(#data{peer_port = P} = Data, P) -> Data;
refresh_peer_port(#data{peer_port = Old} = Data, New)
  when is_integer(New), New > 0 ->
    logger:info("UE FSM peer_port updated ~p -> ~p (NAT-T switch)",
                [Old, New]),
    Data#data{peer_port = New};
refresh_peer_port(Data, _Other) -> Data.

local_outer_ip() ->
    %% Best-effort: parse configured outer IP or fall back to 0.0.0.0.
    case epdg_config:get(ike_bind_addr, "0.0.0.0") of
        Str when is_list(Str) ->
            case inet:parse_address(Str) of
                {ok, IP} -> IP;
                _ -> {0,0,0,0}
            end;
        _ -> {0,0,0,0}
    end.

%% IP to choose for the NAT_DETECTION_DESTINATION_IP hash. We want an
%% address that (a) is the one the UE's IKE arrives on internally, and
%% (b) differs from whatever public/NATed IP the UE originally connected
%% to — that's what forces the UE to conclude the ePDG is behind a NAT
%% and migrate to UDP/4500. Use the configured bind addr if it is a
%% concrete IP, otherwise scan interfaces for the first non-loopback
%% IPv4. Falling back to {0,0,0,0} is still safe: the hash will simply
%% differ from the UE's (UE hashes its destination IP), which is exactly
%% what we want.
local_hash_ip() ->
    case local_outer_ip() of
        {0,0,0,0} -> first_non_loopback_v4();
        IP        -> IP
    end.

first_non_loopback_v4() ->
    case inet:getifaddrs() of
        {ok, IFs} -> scan_ifaddrs(IFs);
        _         -> {0,0,0,0}
    end.

scan_ifaddrs([]) -> {0,0,0,0};
scan_ifaddrs([{"lo", _} | Rest]) -> scan_ifaddrs(Rest);
scan_ifaddrs([{_Name, Opts} | Rest]) ->
    case lists:filtermap(fun({addr, {A,B,C,D}}) when A =/= 127 ->
                                 {true, {A,B,C,D}};
                            (_) -> false
                         end, Opts) of
        [IP | _] -> IP;
        []       -> scan_ifaddrs(Rest)
    end.

ip_bytes({A,B,C,D}) -> <<A:8, B:8, C:8, D:8>>;
ip_bytes({A,B,C,D,E,F,G,H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>;
ip_bytes(_) -> <<0,0,0,0>>.

child_enc_alg(#{id := 20, attrs := #{key_length := 256}}) -> aes_gcm_256;
child_enc_alg(#{id := 20, attrs := #{key_length := 128}}) -> aes_gcm_128;
child_enc_alg(#{id := 12, attrs := #{key_length := 256}}) -> aes_cbc_256;
child_enc_alg(#{id := 12, attrs := #{key_length := 128}}) -> aes_cbc_128;
child_enc_alg(_) -> aes_cbc_128.

child_integ_alg(none)          -> none;
child_integ_alg(#{id := 12})   -> hmac_sha256;
child_integ_alg(#{id := 13})   -> hmac_sha384;
child_integ_alg(#{id := 14})   -> hmac_sha512;
child_integ_alg(_)             -> hmac_sha256.

ip4_cidr({A,B,C,D}, Prefix) ->
    lists:flatten(io_lib:format("~B.~B.~B.~B/~B", [A,B,C,D,Prefix])).

binary_to_int(<<N:32>>) -> N;
binary_to_int(<<N:64>>) -> N;
binary_to_int(B) when is_binary(B) ->
    Sz = byte_size(B) * 8,
    <<N:Sz>> = B, N;
binary_to_int(N) when is_integer(N) -> N.

new_teid() ->
    <<N:32>> = crypto:strong_rand_bytes(4),
    N band 16#FFFFFFFF.

%% Send an IKE_AUTH response carrying a Notify and tear down cleanly.
send_ike_notify_and_stop(MsgId, InFlags, ISPI, RSPI, NotifyType,
                          #data{keys_params = KeyParams, ike_keys = Keys,
                                peer_ip = PeerIP, peer_port = PeerPort} = Data) ->
    NotifyBin = epdg_ikev2_codec:encode_notify_payload(0, NotifyType, <<>>, <<>>),
    RespFlags = (InFlags band (bnot 16#08)) bor 16#20,
    Hdr = #{initiator_spi     => ISPI,
            responder_spi     => RSPI,
            exchange_type_raw => 35,
            flags             => RespFlags,
            message_id        => MsgId},
    case epdg_ikev2_crypto:encode_encrypted_message(
           KeyParams, Keys, responder, Hdr, [{notify, NotifyBin}]) of
        {ok, RespBytes} ->
            catch epdg_ikev2_listener:send(PeerIP, PeerPort, RespBytes);
        _ -> ok
    end,
    {stop, normal, Data}.

send_eap_to_ue(EapOut, MsgId, InFlags, ISPI, RSPI,
               #data{keys_params = KeyParams, ike_keys = Keys,
                     peer_ip = PeerIP, peer_port = PeerPort} = Data) ->
    EapBin = epdg_ikev2_codec:encode_eap_payload(EapOut),
    RespFlags = (InFlags band (bnot 16#08)) bor 16#20,
    Hdr = #{initiator_spi     => ISPI,
            responder_spi     => RSPI,
            exchange_type_raw => 35,
            flags             => RespFlags,
            message_id        => MsgId},
    InnerChain = [{eap, EapBin}],
    case epdg_ikev2_crypto:encode_encrypted_message(
           KeyParams, Keys, responder, Hdr, InnerChain) of
        {ok, RespBytes} ->
            catch epdg_ikev2_listener:send(PeerIP, PeerPort, RespBytes),
            logger:info("IKE_AUTH(cont) sent EAP relay (~p bytes) "
                        "MsgId=~B peer=~p:~p",
                        [byte_size(RespBytes), MsgId, PeerIP, PeerPort]),
            Data#data{ike_auth_last_resp = RespBytes,
                      ike_auth_last_msg_id = MsgId};
        {error, EErr} ->
            logger:warning("IKE_AUTH(cont) encrypt of relay-EAP failed: ~p",
                           [EErr]),
            Data
    end.

send_eap_failure_and_stop(MsgId, InFlags, ISPI, RSPI, Data) ->
    EapFailure = build_eap_failure_for(Data),
    Data1 = send_eap_to_ue(EapFailure, MsgId, InFlags, ISPI, RSPI, Data),
    {stop, normal, Data1}.

build_eap_failure_for(#data{eap_next_id = EapId}) ->
    <<4:8, EapId:8, 4:16>>.

pick_user_name(undefined, IMSI) when is_binary(IMSI) -> IMSI;
pick_user_name(<<>>, IMSI)      when is_binary(IMSI) -> IMSI;
pick_user_name(NAI, _)          when is_binary(NAI)  -> NAI;
pick_user_name(_, _) -> <<>>.

to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L)   -> list_to_binary(L);
to_bin(_)                   -> <<>>.

msk_len(B) when is_binary(B) -> byte_size(B);
msk_len(_) -> 0.

format_ip({A,B,C,D}) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B",[A,B,C,D]));
format_ip(Other) ->
    iolist_to_binary(io_lib:format("~p",[Other])).

%% Dump just enough of an EAP packet to identify what the UE sent.
%% EAP header (RFC 3748 §4): Code(1) | Id(1) | Length(2) | Type(1) | Data...
%% For EAP-AKA / EAP-AKA' (Type 23/50), next byte is Subtype (RFC 4187 §8.1).
log_eap_packet(<<>>) ->
    logger:warning("IKE_AUTH(cont): no EAP payload in inner chain");
log_eap_packet(<<Code:8, Id:8, Len:16>> = Bin) ->
    logger:info("IKE_AUTH(cont) EAP short packet code=~B id=~B len=~B "
                "bytes=~B", [Code, Id, Len, byte_size(Bin)]);
log_eap_packet(<<Code:8, Id:8, Len:16, Type:8, Rest/binary>>) ->
    CodeName = eap_code_name(Code),
    TypeName = eap_type_name(Type),
    SubInfo = case {Type, Rest} of
        {T, <<ST:8, _:8, _:8, _/binary>>} when T =:= 23; T =:= 50 ->
            io_lib:format("subtype=~B(~s)",
                          [ST, eap_aka_subtype_name(ST)]);
        _ -> "no-subtype"
    end,
    Preview = case byte_size(Rest) of
        N when N > 16 -> binary:part(Rest, 0, 16);
        _ -> Rest
    end,
    logger:info("IKE_AUTH(cont) EAP code=~B(~s) id=~B len=~B type=~B(~s) ~s "
                "rest_bytes=~B preview=~p",
                [Code, CodeName, Id, Len, Type, TypeName, SubInfo,
                 byte_size(Rest), Preview]);
log_eap_packet(Bin) ->
    logger:info("IKE_AUTH(cont) EAP malformed bytes=~B preview=~p",
                [byte_size(Bin), Bin]).

eap_code_name(1) -> "Request";
eap_code_name(2) -> "Response";
eap_code_name(3) -> "Success";
eap_code_name(4) -> "Failure";
eap_code_name(_) -> "?".

eap_type_name(1)  -> "Identity";
eap_type_name(2)  -> "Notification";
eap_type_name(3)  -> "Nak";
eap_type_name(23) -> "AKA";
eap_type_name(50) -> "AKA'";
eap_type_name(_)  -> "?".

eap_aka_subtype_name(1)  -> "AKA-Challenge";
eap_aka_subtype_name(2)  -> "AKA-Authentication-Reject";
eap_aka_subtype_name(4)  -> "AKA-Synchronization-Failure";
eap_aka_subtype_name(5)  -> "AKA-Identity";
eap_aka_subtype_name(11) -> "SIM/AKA-Notification";
eap_aka_subtype_name(12) -> "AKA-Reauthentication";
eap_aka_subtype_name(13) -> "AKA-Client-Error";
eap_aka_subtype_name(_)  -> "?".

%%====================================================================
%% INFORMATIONAL handler
%%====================================================================

handle_informational(#{message_id := MsgId, flags := InFlags} = _Header, RawData,
                     #data{keys_params = KeyParams, ike_keys = Keys,
                           initiator_spi = ISPI, responder_spi = RSPI,
                           peer_ip = PeerIP, peer_port = PeerPort,
                           imsi = IMSI} = Data)
  when is_map(KeyParams), is_map(Keys) ->
    %% RFC 7296 §1.4/§2.4: respond to every INFORMATIONAL request with an
    %% (empty) INFORMATIONAL response. This covers DPD liveness checks and
    %% DELETE notifications from the UE.
    RespFlags = 16#20,  %% Response=1, Initiator=0 (we are responder)
    Hdr = #{initiator_spi     => ISPI,
            responder_spi     => RSPI,
            exchange_type_raw => 37,
            flags             => RespFlags,
            message_id        => MsgId},
    case epdg_ikev2_crypto:encode_encrypted_message(
           KeyParams, Keys, responder, Hdr, []) of
        {ok, Bytes} ->
            catch epdg_ikev2_listener:send(PeerIP, PeerPort, Bytes);
        _ -> ok
    end,
    %% RFC 7296 §1.4.1: a UE-initiated DELETE (for the IKE SA or its
    %% Child SA) is the normal graceful VoWiFi detach. We acked it with
    %% the empty INFORMATIONAL response above; now tear the FSM down so
    %% terminate/3 releases the S2b GTP session (TS 29.274 Delete-Session)
    %% and the SWm Diameter session (TS 29.273 STR). A plain DPD/keepalive
    %% INFORMATIONAL carries no DELETE, so we just reset the DPD timer.
    case informational_has_delete(KeyParams, Keys, RawData) of
        true ->
            logger:info("INFORMATIONAL DELETE received from UE IMSI=~p "
                        "- tearing down tunnel", [IMSI]),
            {stop, {shutdown, ue_delete}, Data};
        false ->
            Interval = epdg_config:get(dpd_interval, ?DPD_INTERVAL),
            {keep_state, Data#data{dpd_failures = 0},
             [{state_timeout, Interval, dpd}]}
    end;
handle_informational(_Header, _RawData, Data) ->
    {keep_state, Data}.

%% Decrypt the INFORMATIONAL request and report whether it carries a
%% DELETE payload (RFC 7296 §3.11). The UE is the initiator of this
%% exchange so the peer-direction keys (SK_ei/SK_ai) decrypt it.
informational_has_delete(KeyParams, Keys, RawData) ->
    case epdg_ikev2_crypto:decode_encrypted_message(
           KeyParams, Keys, initiator, RawData) of
        {ok, #{payloads := Payloads}} ->
            case epdg_ikev2_codec:find_payload(delete, Payloads) of
                {ok, _} -> true;
                _       -> false
            end;
        _ ->
            false
    end.

%%====================================================================
%% DPD probe (RFC 7296 §2.4)
%%
%% An empty INFORMATIONAL request: the responder (us) initiates an
%% exchange with Flags=Initiator (we start this exchange), exchange_type
%% 37, no inner payloads. The UE must reply with an empty
%% INFORMATIONAL response.
%%====================================================================

send_dpd_probe(#data{ike_keys = Keys, keys_params = KeyParams,
                     initiator_spi = ISPI, responder_spi = RSPI,
                     peer_ip = PeerIP, peer_port = PeerPort,
                     message_id = MsgId} = Data)
  when is_map(Keys), is_map(KeyParams),
       is_integer(ISPI), is_integer(RSPI),
       is_tuple(PeerIP), is_integer(PeerPort) ->
    Hdr = #{initiator_spi     => ISPI,
            responder_spi     => RSPI,
            exchange_type_raw => 37,
            flags             => 16#00,
            message_id        => MsgId},
    try
        case epdg_ikev2_crypto:encode_encrypted_message(
               KeyParams, Keys, responder, Hdr, []) of
            {ok, Bytes} ->
                catch epdg_ikev2_listener:send(PeerIP, PeerPort, Bytes),
                epdg_metrics:inc(dpd_probes_sent_total),
                Data#data{message_id = MsgId + 1};
            {error, EncErr} ->
                logger:info("DPD: encode failed: ~p", [EncErr]),
                Data
        end
    catch
        Class:Reason:_ ->
            logger:info("DPD: send failed: ~p:~p", [Class, Reason]),
            Data
    end;
send_dpd_probe(Data) ->
    Data.

%%====================================================================
%% Graceful drain helpers
%%
%% On a rolling upgrade the preStop hook POSTs /admin/drain; that handler
%% flips the readiness flag (so the LoadBalancer de-registers this pod)
%% and casts {drain, Reason} to every live UE FSM via
%% epdg_ue_registry:broadcast/1. Each FSM picks a random jitter in
%% [0, ?DRAIN_MAX_JITTER_MS) so N UEs don't all reconnect to a sibling
%% pod at the same millisecond, then terminates when the jitter fires.
%%====================================================================

handle_drain(State, Reason, #data{peer_ip = PeerIP, imsi = IMSI} = Data) ->
    case get(drain_scheduled) of
        true ->
            {keep_state, Data};
        _ ->
            Jitter = rand:uniform(?DRAIN_MAX_JITTER_MS + 1) - 1,
            erlang:send_after(Jitter, self(), drain_stop),
            put(drain_scheduled, true),
            logger:info("UE FSM drain scheduled state=~p reason=~p peer=~p "
                        "IMSI=~p jitter_ms=~B",
                        [State, Reason, PeerIP, IMSI, Jitter]),
            {keep_state, Data}
    end.

%% Best-effort IKEv2 INFORMATIONAL(DELETE) from the established state.
%% Requires the IKE keys to have been derived; silently no-ops otherwise.
%% The pod is about to terminate anyway, so any failure here is logged
%% at info level and swallowed — the UE will notice via DPD after its
%% next interval.
try_send_delete_informational(#data{ike_keys = Keys,
                                    keys_params = KeyParams,
                                    initiator_spi = ISPI,
                                    responder_spi = RSPI,
                                    peer_ip = PeerIP,
                                    peer_port = PeerPort,
                                    message_id = MsgId})
  when is_map(Keys), is_map(KeyParams),
       is_integer(ISPI), is_integer(RSPI),
       is_tuple(PeerIP), is_integer(PeerPort) ->
    %% We are the IKE SA responder initiating an INFORMATIONAL exchange
    %% to gracefully tear down the SA (RFC 7296 §1.4.1). Per §2.2 each
    %% side uses its own SK_e*/SK_a* regardless of exchange role; the
    %% encoder we pass `responder` to selects the responder-half keys,
    %% RFC 7296 §2.2: Initiator flag MUST be clear when sent by the
    %% original responder. We are the responder initiating this exchange.
    %% Exchange type 37 = INFORMATIONAL.
    DeletePayload = epdg_ikev2_codec:encode_delete_ike_payload(),
    Hdr = #{initiator_spi     => ISPI,
            responder_spi     => RSPI,
            exchange_type_raw => 37,
            flags             => 16#00,
            message_id        => MsgId},
    try
        case epdg_ikev2_crypto:encode_encrypted_message(
               KeyParams, Keys, responder, Hdr, [{delete, DeletePayload}]) of
            {ok, Bytes} ->
                catch epdg_ikev2_listener:send(PeerIP, PeerPort, Bytes),
                logger:info("Drain: IKEv2 DELETE informational sent "
                            "(~B bytes) peer=~p:~p",
                            [byte_size(Bytes), PeerIP, PeerPort]),
                ok;
            {error, EncErr} ->
                logger:info("Drain: IKEv2 DELETE encode skipped: ~p", [EncErr]),
                ok
        end
    catch
        Class:CReason:_ ->
            logger:info("Drain: IKEv2 DELETE best-effort send failed: ~p:~p",
                        [Class, CReason]),
            ok
    end;
try_send_delete_informational(_Data) ->
    %% No keys yet (pre-auth) — nothing we can encrypt. The UE will
    %% time out its half-open IKE SA naturally.
    ok.

%%====================================================================
%% Internal: certificate loading
%%====================================================================

load_ike_certificate() ->
    CertFile = epdg_config:get(ike_cert_file, ""),
    KeyFile  = epdg_config:get(ike_key_file, ""),
    case {CertFile, KeyFile} of
        {"", _} ->
            logger:info("No IKE certificate file configured (EPDG_IKE_CERT_FILE)"),
            {undefined, undefined};
        {_, ""} ->
            logger:info("No IKE private key file configured (EPDG_IKE_KEY_FILE)"),
            {undefined, undefined};
        {CF, KF} ->
            CertResult = epdg_ikev2_crypto:load_certificate(CF),
            KeyResult  = epdg_ikev2_crypto:load_private_key(KF),
            case {CertResult, KeyResult} of
                {{ok, DerCert}, {ok, PrivKey}} ->
                    logger:info("IKE certificate loaded from ~s (~p bytes)",
                                [CF, byte_size(DerCert)]),
                    {DerCert, PrivKey};
                {{error, CertErr}, _} ->
                    logger:error("Failed to load IKE certificate ~s: ~p",
                                 [CF, CertErr]),
                    {undefined, undefined};
                {_, {error, KeyErr}} ->
                    logger:error("Failed to load IKE private key ~s: ~p",
                                 [KF, KeyErr]),
                    {undefined, undefined}
            end
    end.
