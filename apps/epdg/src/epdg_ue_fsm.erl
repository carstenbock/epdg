%%%-------------------------------------------------------------------
%%% @doc Per-UE state machine (gen_statem).
%%% Manages IKEv2/IPsec tunnel lifecycle for a single UE.
%%%
%%% States: idle → ike_sa_init → ike_auth → established
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_fsm).

-behaviour(gen_statem).

-export([start_link/1, handle_ikev2/3, get_state/1, disconnect/1]).
-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([idle/3, ike_sa_init/3, ike_auth/3, established/3]).

-define(IKE_SA_INIT_TIMEOUT, 30000).
-define(IKE_AUTH_TIMEOUT,    60000).
-define(DPD_INTERVAL,       120000).

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
    %% EAP identifier counter (monotonic per RFC 3748)
    eap_next_id      :: non_neg_integer(),
    %% X.509 certificate for IKEv2 responder auth (TS 33.402 §7.2.1)
    cert_der         :: binary() | undefined,
    private_key      :: term() | undefined,
    %% Stored IKE_SA_INIT response bytes for AUTH signature (RFC 7296 §2.15)
    %% and retransmission (RFC 7296 §2.1).
    ike_sa_init_resp :: binary() | undefined,
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
    eap_done         :: boolean()
}).

%%====================================================================
%% API
%%====================================================================

start_link(InitContext) ->
    gen_statem:start_link(?MODULE, InitContext, []).

-spec handle_ikev2(pid(), map(), binary()) -> ok.
handle_ikev2(Pid, Header, RawData) ->
    gen_statem:cast(Pid, {ikev2, Header, RawData}).

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
        eap_next_id   = 1,
        cert_der      = CertDer,
        private_key   = PrivKey,
        eap_done      = false
    }}.

terminate(_Reason, _State, #data{responder_spi = RSPI, imsi = IMSI,
                                  peer_ip = PeerIP, initiator_spi = ISPI,
                                  child_sa = ChildSA, pgw_session = PGW}) ->
    case ChildSA of
        #{spi_in := SPIIn, spi_out := SPIOut} ->
            catch epdg_xfrm:delete_sa(#{spi => SPIIn}),
            catch epdg_xfrm:delete_sa(#{spi => SPIOut});
        _ -> ok
    end,
    case PGW of
        #{pgw_teid := TEID} ->
            catch epdg_gtpc_client:delete_session_request(#{pgw_teid => TEID});
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

%%====================================================================
%% State: idle
%%====================================================================

idle(enter, _OldState, Data) ->
    {keep_state, Data, [{state_timeout, ?IKE_SA_INIT_TIMEOUT, timeout}]};

idle(cast, {ikev2, #{exchange_type := ike_sa_init} = Header, RawData}, Data) ->
    handle_ike_sa_init_request(Header, RawData, Data);

idle(cast, {ikev2, _, _}, Data) ->
    {keep_state, Data};

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

ike_sa_init(cast, {ikev2, #{exchange_type := ike_auth} = Header, RawData}, Data) ->
    handle_ike_auth_request(Header, RawData, Data);

%% IKE_SA_INIT retransmit from the initiator: re-send our cached response bytes
%% (RFC 7296 §2.1 - responder MUST retransmit the same response, not regenerate).
ike_sa_init(cast, {ikev2, #{exchange_type := ike_sa_init}, _RawData},
            #data{peer_ip = PeerIP, peer_port = PeerPort,
                  ike_sa_init_resp = Resp} = Data)
  when is_binary(Resp), byte_size(Resp) > 0 ->
    logger:info("IKE_SA_INIT retransmit detected, re-sending cached response "
                "(~p bytes) to ~p:~p", [byte_size(Resp), PeerIP, PeerPort]),
    catch epdg_ikev2_listener:send(PeerIP, PeerPort, Resp),
    {keep_state, Data};

ike_sa_init(cast, {ikev2, _, _}, Data) ->
    {keep_state, Data};

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

ike_auth(cast, {ikev2, #{exchange_type := ike_auth} = Header, RawData}, Data) ->
    handle_ike_auth_eap(Header, RawData, Data);

ike_auth(cast, disconnect, _Data) ->
    {stop, normal};

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
    {keep_state, Data, [{state_timeout, ?DPD_INTERVAL, dpd}]};

established(cast, {ikev2, #{exchange_type := informational} = Header, RawData}, Data) ->
    handle_informational(Header, RawData, Data);

established(cast, {ikev2, #{exchange_type := create_child_sa} = _Header, _RawData}, Data) ->
    %% MOBIKE or rekey
    {keep_state, Data};

established(cast, disconnect, _Data) ->
    {stop, normal};

established(state_timeout, dpd, #data{peer_ip = _PeerIP} = Data) ->
    %% Dead Peer Detection: send empty INFORMATIONAL
    %% If no response within timeout, terminate
    {keep_state, Data, [{state_timeout, ?DPD_INTERVAL, dpd}]};

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

    Payloads0 = [{sa, SAPayload}, {ke, KEPayload}, {nonce, NoncePayload}],
    Payloads  = case CertDer of
        undefined -> Payloads0;
        _ ->
            %% Hint the peer we authenticate via certificate (RFC 7296 §3.7).
            CertReq = epdg_ikev2_codec:encode_certreq_payload(<<>>),
            Payloads0 ++ [{certreq, CertReq}]
    end,

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

    case epdg_ikev2_listener:send(PeerIP, PeerPort, RespBytes) of
        ok ->
            logger:info("IKE_SA_INIT response sent to ~p:~p (~p bytes) "
                        "ISPI=~.16B RSPI=~.16B DH=~p",
                        [PeerIP, PeerPort, byte_size(RespBytes), ISPI, RSPI,
                         DHGroupId]);
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
    catch epdg_ikev2_listener:send(PeerIP, PeerPort, RespBytes),
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
                            {IDiType, UeNai} = extract_idi(InnerPayloads),
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
                                        imsi         = IMSI,
                                        ue_nai       = UeNai,
                                        eap_next_id  = (EapId + 1) rem 256
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
%% {IdType, IdData}. Returns {undefined, <<>>} if absent/unparseable.
extract_idi(Payloads) ->
    case epdg_ikev2_codec:find_payload(idi, Payloads) of
        {ok, #{data := D}} ->
            case epdg_ikev2_codec:decode_id_payload(D) of
                {ok, {T, Raw}} -> {T, Raw};
                _              -> {undefined, <<>>}
            end;
        _ -> {undefined, <<>>}
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
                        peer_ip = PeerIP, peer_port = PeerPort,
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
    % #region agent log
    write_fsm_log(<<"epdg_ue_fsm:relay_eap_via_swm">>, <<"B1">>,
                  #{session_id => SessionId,
                    imsi => IMSI,
                    ue_nai => UeNai,
                    eap_bytes_len => byte_size(EapBytes),
                    peer_ip => format_ip(PeerIP),
                    dest_host => DestHost0,
                    msg_id => MsgId}),
    % #endregion
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
    send_eap_to_ue(EapOut, MsgId, InFlags, ISPI, RSPI, Data),
    {keep_state, Data};
%% DIAMETER_SUCCESS (2001): EAP has completed; DEA carries EAP-Success and
%% the MSK for computing the final IKE AUTH.
handle_dea(2001, #{eap_payload := EapOut, msk := MSK}, MsgId, InFlags,
           ISPI, RSPI, Data)
  when is_binary(EapOut), byte_size(EapOut) >= 4,
       is_binary(MSK),    byte_size(MSK)    >= 32 ->
    logger:notice("SWm auth SUCCESS: MSK=~B bytes delivered", [byte_size(MSK)]),
    send_eap_to_ue(EapOut, MsgId, InFlags, ISPI, RSPI, Data),
    {keep_state, Data#data{eap_msk = MSK, eap_done = true}};
%% Failure codes or missing/short AVPs in the DEA.
handle_dea(RC, Dea, MsgId, InFlags, ISPI, RSPI, Data) ->
    EapOut = case maps:get(eap_payload, Dea, <<>>) of
        B when is_binary(B), byte_size(B) >= 4 -> B;
        _ -> build_eap_failure_for(Data)
    end,
    logger:warning("SWm auth FAILURE result_code=~B - sending EAP-Failure", [RC]),
    send_eap_to_ue(EapOut, MsgId, InFlags, ISPI, RSPI, Data),
    {stop, normal, Data}.

%% Placeholder for the post-EAP final AUTH exchange. We log the UE's
%% AUTH payload, verify it against MSK (when the helper lands in
%% epdg_ikev2_crypto), and then send our responder AUTH plus the CP /
%% SAr2 / TSi / TSr payloads. The child SA install (xfrm) follows in the
%% next patch — for now we just keep the FSM alive so the UE doesn't
%% see an RST-style IKE tear down while we wire the remainder.
handle_post_eap_auth(MsgId, _InFlags, AuthRaw, _InnerPayloads,
                     _ISPI, _RSPI, Data) ->
    logger:notice("IKE_AUTH(cont) post-EAP-Success AUTH received "
                  "(~B bytes); child-SA setup pending in next patch",
                  [byte_size(AuthRaw)]),
    % #region agent log
    write_fsm_log(<<"epdg_ue_fsm:handle_post_eap_auth">>, <<"B2">>,
                  #{auth_len => byte_size(AuthRaw),
                    msg_id => MsgId}),
    % #endregion
    {keep_state, Data}.

send_eap_to_ue(EapOut, MsgId, InFlags, ISPI, RSPI,
               #data{keys_params = KeyParams, ike_keys = Keys,
                     peer_ip = PeerIP, peer_port = PeerPort}) ->
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
            ok;
        {error, EErr} ->
            logger:warning("IKE_AUTH(cont) encrypt of relay-EAP failed: ~p",
                           [EErr]),
            error
    end.

send_eap_failure_and_stop(MsgId, InFlags, ISPI, RSPI, Data) ->
    EapFailure = build_eap_failure_for(Data),
    send_eap_to_ue(EapFailure, MsgId, InFlags, ISPI, RSPI, Data),
    {stop, normal, Data}.

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

% #region agent log helpers
write_fsm_log(Location, HypothesisId, Data) ->
    Entry = jsx:encode(#{
        sessionId    => <<"35d02f">>,
        runId        => <<"swm-wiring">>,
        hypothesisId => HypothesisId,
        location     => Location,
        message      => Location,
        data         => sanitize_log(Data),
        timestamp    => erlang:system_time(millisecond)}),
    catch file:write_file(
            "/home/carsten/Schreibtisch/volte.io/helm/.cursor/debug-35d02f.log",
            <<Entry/binary, "\n">>, [append]),
    ok.

sanitize_log(M) when is_map(M) ->
    maps:map(fun(_K, V) -> sanitize_log(V) end, M);
sanitize_log(L) when is_list(L) ->
    case io_lib:printable_list(L) of
        true  -> iolist_to_binary(L);
        false -> [sanitize_log(X) || X <- L]
    end;
sanitize_log(T) when is_tuple(T) -> sanitize_log(tuple_to_list(T));
sanitize_log(B) when is_binary(B), byte_size(B) > 64 ->
    <<B:64/binary>>;
sanitize_log(V) -> V.
% #endregion

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

handle_informational(_Header, _RawData, Data) ->
    %% Handle DPD (empty INFORMATIONAL) or DELETE payloads
    {keep_state, Data}.

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
