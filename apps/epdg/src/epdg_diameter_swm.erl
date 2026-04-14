%%%-------------------------------------------------------------------
%%% @doc Diameter SWm client (ePDG → 3GPP AAA Server).
%%% Application-ID 16777264 (TS 29.273).
%%% Sends DER/DEA for EAP relay, AAR/AAA for authorization.
%%% Connects to AAA Server via DRA.
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

-record(state, {
    service_started :: boolean(),
    transport_added :: boolean(),
    dns_retries     :: non_neg_integer(),
    dra_host        :: string() | undefined,
    dra_port        :: non_neg_integer() | undefined,
    transport_mod   :: module() | undefined,
    transport_ref   :: term() | undefined
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
    DRAHost     = epdg_config:get(dra_host, "dra-diameter"),
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

            State0 = #state{service_started = true,
                            transport_added = false,
                            dns_retries     = 0,
                            dra_host        = DRAHost,
                            dra_port        = DRAPort,
                            transport_mod   = TransMod},
            {ok, try_add_dra_transport(State0)};
        {error, Reason} ->
            logger:error("Failed to start SWm Diameter service: ~p", [Reason]),
            {ok, #state{service_started = false,
                        transport_added = false,
                        dns_retries     = 0}}
    end.

handle_call({der, IMSI, Opts}, _From, #state{service_started = true} = State) ->
    EAPPayload = maps:get(eap_payload, Opts, <<>>),
    SessionId  = generate_session_id(),

    %% Build DER message using base dictionary (simplified)
    Msg = ['ASR',  %% placeholder — real impl uses compiled SWm dictionary
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

handle_info(retry_dra_dns, #state{transport_added = false} = State) ->
    {noreply, try_add_dra_transport(State)};
handle_info(retry_dra_dns, State) ->
    {noreply, State};
handle_info(re_resolve_dra, #state{transport_added = true,
                                    transport_ref = OldRef} = State) ->
    logger:info("SWm: re-resolving DRA hostname after peer down"),
    catch diameter:remove_transport(?SVC_NAME, OldRef),
    {noreply, try_add_dra_transport(State#state{transport_added = false,
                                                 transport_ref = undefined,
                                                 dns_retries = 0})};
handle_info(re_resolve_dra, State) ->
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

peer_up(_SvcName, _Peer, State) ->
    logger:info("SWm Diameter peer up"),
    epdg_metrics:gauge_set(diameter_swm_peers, 1),
    State.

peer_down(_SvcName, _Peer, State) ->
    logger:warning("SWm Diameter peer down"),
    epdg_metrics:gauge_set(diameter_swm_peers, 0),
    erlang:send_after(15000, ?SERVER, re_resolve_dra),
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

try_add_dra_transport(#state{dra_host = DRAHost, dra_port = DRAPort,
                             transport_mod = TransMod,
                             dns_retries = Retries} = State) ->
    case resolve_host(DRAHost) of
        {ok, DRAIP} ->
            case diameter:add_transport(?SVC_NAME, {connect, [
                {transport_module, TransMod},
                {transport_config, [{raddr, DRAIP},
                                    {rport, DRAPort},
                                    {ip, {0,0,0,0}}]},
                {reconnect_timer, 5000}
            ]}) of
                {ok, Ref} ->
                    logger:info("SWm client → DRA ~s:~p", [DRAHost, DRAPort]),
                    State#state{transport_added = true, dns_retries = 0,
                                transport_ref = Ref};
                {error, TErr} ->
                    Delay = retry_delay(Retries),
                    logger:error("SWm transport to DRA ~s:~p failed: ~p, "
                                 "retrying in ~Bms",
                                 [DRAHost, DRAPort, TErr, Delay]),
                    erlang:send_after(Delay, self(), retry_dra_dns),
                    State#state{transport_added = false,
                                dns_retries = Retries + 1}
            end;
        {error, _} ->
            Delay = retry_delay(Retries),
            logger:warning("Cannot resolve DRA host ~s, retrying in ~Bms "
                           "(attempt ~B)",
                           [DRAHost, Delay, Retries + 1]),
            erlang:send_after(Delay, self(), retry_dra_dns),
            State#state{dns_retries = Retries + 1}
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
