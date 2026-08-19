%%%-------------------------------------------------------------------
%%% @doc EUnit tests for RFC 5998 EAP-only authentication handling in
%%% epdg_ue_fsm: detecting the UE's N(EAP_ONLY_AUTHENTICATION) offer and
%%% assembling the first IKE_AUTH response with or without the ePDG
%%% certificate and cert-based AUTH.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_fsm_eap_only_tests).

-include_lib("eunit/include/eunit.hrl").

%% RFC 5998 §4; IANA IKEv2 Notify Message Types.
-define(N_EAP_ONLY_AUTHENTICATION, 16417).
-define(N_MOBIKE_SUPPORTED,        16396).

%%====================================================================
%% First IKE_AUTH response chain
%%====================================================================

%% RFC 5998: when the UE offered EAP-only auth, the responder omits its
%% certificate and cert-based AUTH; the EAP-AKA' MSK exchange authenticates
%% it. The first response carries only IDr and the EAP request.
eap_only_chain_omits_cert_and_auth_test() ->
    Chain = epdg_ue_fsm:build_first_auth_chain(<<"idr">>, <<"eap">>, none),
    ?assertEqual([{idr, <<"idr">>}, {eap, <<"eap">>}], Chain).

%% Without an EAP-only offer the responder authenticates by certificate:
%% IDr | CERT | AUTH | EAP.
cert_chain_includes_cert_and_auth_test() ->
    Chain = epdg_ue_fsm:build_first_auth_chain(
              <<"idr">>, <<"eap">>, {<<"cert">>, <<"auth">>}),
    ?assertEqual([{idr, <<"idr">>}, {cert, <<"cert">>},
                  {auth, <<"auth">>}, {eap, <<"eap">>}], Chain).

%%====================================================================
%% Detecting the UE's EAP_ONLY_AUTHENTICATION notify
%%====================================================================

detects_eap_only_notify_test() ->
    Payloads = [#{type => idi, data => <<>>},
                notify(?N_EAP_ONLY_AUTHENTICATION)],
    ?assert(epdg_ue_fsm:find_notify(?N_EAP_ONLY_AUTHENTICATION, Payloads)).

absent_eap_only_notify_test() ->
    Payloads = [notify(?N_MOBIKE_SUPPORTED)],
    ?assertNot(epdg_ue_fsm:find_notify(?N_EAP_ONLY_AUTHENTICATION, Payloads)).

%%====================================================================
%% Helpers
%%====================================================================

%% Notify body: ProtocolId | SPISize | NotifyType | (no SPI, no data).
notify(Type) ->
    #{type => notify, data => <<0:8, 0:8, Type:16>>}.
