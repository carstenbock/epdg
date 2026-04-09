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
    apn              :: binary() | undefined,  % APN/DNN from UE or default "ims"
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
    dh_private       :: binary() | undefined
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
    {ok, idle, #data{
        peer_ip       = PeerIP,
        peer_port     = PeerPort,
        responder_spi = RSPI,
        message_id    = 0
    }}.

terminate(_Reason, _State, #data{responder_spi = RSPI, imsi = IMSI,
                                  child_sa = ChildSA, pgw_session = PGW}) ->
    %% Clean up XFRM state
    case ChildSA of
        #{spi_in := SPIIn, spi_out := SPIOut} ->
            catch epdg_xfrm:delete_sa(#{spi => SPIIn}),
            catch epdg_xfrm:delete_sa(#{spi => SPIOut});
        _ -> ok
    end,
    %% Delete GTP session
    case PGW of
        #{pgw_teid := TEID} ->
            catch epdg_gtpc_client:delete_session_request(#{pgw_teid => TEID});
        _ -> ok
    end,
    %% Deregister
    catch epdg_ue_registry:unregister(RSPI),
    epdg_metrics:gauge_dec(ue_sessions_active),
    logger:info("UE FSM terminated IMSI=~p RSPI=~.16B", [IMSI, RSPI]),
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

idle(state_timeout, timeout, _Data) ->
    {stop, init_timeout};

idle({call, From}, get_state, Data) ->
    {keep_state, Data, [{reply, From, {ok, idle}}]}.

%%====================================================================
%% State: ike_sa_init
%%====================================================================

ike_sa_init(enter, _OldState, Data) ->
    {keep_state, Data, [{state_timeout, ?IKE_AUTH_TIMEOUT, timeout}]};

ike_sa_init(cast, {ikev2, #{exchange_type := ike_auth} = Header, RawData}, Data) ->
    handle_ike_auth_request(Header, RawData, Data);

ike_sa_init(cast, {ikev2, _, _}, Data) ->
    {keep_state, Data};

ike_sa_init(state_timeout, timeout, _Data) ->
    {stop, auth_timeout};

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

ike_auth(state_timeout, timeout, _Data) ->
    {stop, eap_timeout};

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

handle_ike_sa_init_request(#{initiator_spi := ISPI} = _Header, _RawData,
                            #data{responder_spi = RSPI} = Data) ->
    %% 1. Parse SA, KE, Nonce payloads from initiator
    %% 2. Select crypto suite, generate DH key pair
    %% 3. Send IKE_SA_INIT response with our SA, KE, Nonce

    NonceR = epdg_ikev2_crypto:generate_nonce(),
    DHGroup = 14,
    {DHPub, DHPriv} = epdg_ikev2_crypto:dh_generate(DHGroup),

    NewData = Data#data{
        initiator_spi = ISPI,
        nonce_r       = NonceR,
        dh_group      = DHGroup,
        dh_public     = DHPub,
        dh_private    = DHPriv
    },

    %% Register SPI so subsequent messages find this FSM
    epdg_ue_registry:register(RSPI, self(), undefined),

    logger:debug("IKE_SA_INIT: ISPI=~.16B RSPI=~.16B DH=~p",
                 [ISPI, RSPI, DHGroup]),

    %% TODO: build and send IKE_SA_INIT response
    {next_state, ike_sa_init, NewData}.

%%====================================================================
%% IKE_AUTH handler (initial)
%%====================================================================

handle_ike_auth_request(_Header, _RawData, Data) ->
    %% 1. Decrypt SK payload
    %% 2. Extract IDi (IMSI from NAI: 0<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org)
    %% 3. Begin EAP-AKA' via SWm (Diameter to AAA Server)
    %%    - Send DER with EAP-Payload containing EAP-Identity
    %%    - Receive DEA with EAP-AKA' Challenge
    %% 4. Send IKE_AUTH response with EAP payload

    %% Transition to ike_auth state for EAP round-trips
    {next_state, ike_auth, Data}.

%%====================================================================
%% IKE_AUTH EAP continuation
%%====================================================================

handle_ike_auth_eap(_Header, _RawData,
                    #data{} = Data) ->
    %% Process EAP response from UE:
    %% 1. Forward EAP-Response to AAA Server via SWm DER
    %% 2a. If DEA contains EAP-Success:
    %%     - Derive MSK from auth vectors
    %%     - Create GTP-C session toward PGW (S2b Create Session Request)
    %%     - Install XFRM SA/SP for Child SA
    %%     - Send final IKE_AUTH with AUTH, CP(CFG_REPLY with inner IP, P-CSCF, DNS), SA, TSi, TSr
    %%     → transition to established
    %% 2b. If DEA contains another EAP challenge:
    %%     - Forward to UE
    %%     → stay in ike_auth
    %% 2c. If DEA contains EAP-Failure:
    %%     - Send failure notification
    %%     → stop

    %% Placeholder: transition to established
    {next_state, established, Data}.

%%====================================================================
%% INFORMATIONAL handler
%%====================================================================

handle_informational(_Header, _RawData, Data) ->
    %% Handle DPD (empty INFORMATIONAL) or DELETE payloads
    {keep_state, Data}.
