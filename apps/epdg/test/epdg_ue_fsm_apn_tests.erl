-module(epdg_ue_fsm_apn_tests).
-include_lib("eunit/include/eunit.hrl").

%% A UE holds one IKE SA per PDN connection and names the APN of each in
%% the IDr payload of IKE_AUTH (TS 24.302 §6.5.3, §7.2.2.1). If the ePDG
%% ignores it, an MMS or XCAP tunnel becomes a second IMS PDN connection
%% (KI-199). The APN read here goes to the AAA (SWm Service-Selection) and
%% the PGW-C (S2b APN), both of which match it exactly against the HSS's
%% APN names, so it must be the bare, lower-case network identifier.

-define(OWN, <<"epdg.epc.mnc024.mcc262.pub.3gppnetwork.org">>).

idr(Type, Data) ->
    #{type => idr, data => <<Type:8, 0:24, Data/binary>>}.

%% Handsets send the bare network identifier as ID_FQDN (GSMA IR.51
%% §4.7.4; AOSP Iwlan EpdgTunnelManager.getId()).
fqdn_idr_names_the_apn_test() ->
    ?assertEqual(<<"mms">>,
                 epdg_ue_fsm:requested_apn([idr(2, <<"mms">>)], ?OWN)).

%% Android can be configured to send ID_KEY_ID instead
%% (KEY_IKE_REMOTE_ID_TYPE_INT); the APN must still be found.
key_id_idr_names_the_apn_test() ->
    ?assertEqual(<<"xcap">>,
                 epdg_ue_fsm:requested_apn([idr(11, <<"xcap">>)], ?OWN)).

%% No IDr means the default APN (TS 24.302 §7.2.2.1); so does an identity
%% type that cannot carry an APN.
absent_or_other_idr_type_is_default_test() ->
    ?assertEqual(default, epdg_ue_fsm:requested_apn([], ?OWN)),
    ?assertEqual(default,
                 epdg_ue_fsm:requested_apn([idr(1, <<10, 0, 0, 1>>)], ?OWN)).

%% APN network identifiers are case-insensitive (TS 23.003 §9.1); the HSS
%% and PGW-C names are lower case.
apn_is_lower_cased_test() ->
    ?assertEqual(<<"ims">>, epdg_ue_fsm:normalise_apn(<<"IMS">>, ?OWN)).

%% An APN with the operator identifier appended is cut back to the
%% network identifier, or the S6b match at the AAA would fail.
operator_identifier_is_stripped_test() ->
    ?assertEqual(<<"internet">>,
                 epdg_ue_fsm:normalise_apn(<<"internet.mnc024.mcc262.gprs">>, ?OWN)),
    ?assertEqual(<<"mms">>,
                 epdg_ue_fsm:normalise_apn(
                   <<"mms.apn.epc.mnc024.mcc262.3gppnetwork.org">>, ?OWN)),
    ?assertEqual(<<"ims">>, epdg_ue_fsm:normalise_apn(<<"ims.">>, ?OWN)).

%% Generic IKEv2 clients (strongSwan as UE) often put the ePDG's own FQDN
%% in IDr. That names no APN and must keep giving the default (ims), as
%% before IDr was read.
epdg_fqdn_in_idr_is_default_test() ->
    ?assertEqual(default, epdg_ue_fsm:normalise_apn(?OWN, ?OWN)),
    ?assertEqual(default,
                 epdg_ue_fsm:normalise_apn(
                   <<"EPDG.EPC.MNC001.MCC001.PUB.3GPPNETWORK.ORG">>, ?OWN)).

%% Empty allow-list = all APNs (the HSS authorises); "ims" can never be
%% locked out by the list; emergency over SWu is not supported.
apn_acceptable_test_() ->
    {setup,
     fun() -> application:get_env(epdg, allowed_apns) end,
     fun(Old) -> restore(allowed_apns, Old) end,
     fun(_) ->
         [?_test(begin
              application:set_env(epdg, allowed_apns, []),
              ?assert(epdg_ue_fsm:apn_acceptable(<<"internet">>)),
              ?assertNot(epdg_ue_fsm:apn_acceptable(<<"emergency">>)),
              application:set_env(epdg, allowed_apns, [<<"mms">>]),
              ?assert(epdg_ue_fsm:apn_acceptable(<<"mms">>)),
              ?assert(epdg_ue_fsm:apn_acceptable(<<"ims">>)),
              ?assertNot(epdg_ue_fsm:apn_acceptable(<<"internet">>))
          end)]
     end}.

%% EPDG_RESPONSE_IDR: `fqdn' keeps what UEs in the field accept today;
%% `apn' is the TS 24.302 §7.4.1 behaviour.
response_idr_test_() ->
    {setup,
     fun() -> application:get_env(epdg, response_idr) end,
     fun(Old) -> restore(response_idr, Old) end,
     fun(_) ->
         [?_test(begin
              application:unset_env(epdg, response_idr),
              ?assertEqual(?OWN, epdg_ue_fsm:response_idr(?OWN, <<"mms">>)),
              application:set_env(epdg, response_idr, apn),
              ?assertEqual(<<"mms">>, epdg_ue_fsm:response_idr(?OWN, <<"mms">>))
          end)]
     end}.

%% A PGW-C refusal of the APN reaches the UE as the TS 24.302 notify it
%% understands, so it does not retry the same APN forever.
csr_reject_notify_test() ->
    ?assertEqual(9002, epdg_ue_fsm:csr_reject_notify(93)),
    ?assertEqual(9003, epdg_ue_fsm:csr_reject_notify(125)),
    ?assertEqual(37, epdg_ue_fsm:csr_reject_notify(73)).

%% The default bearer's EBI must survive in the stored response even when
%% the PGW does not echo it, or teardown would name EBI 5, which may be
%% another PDN connection's bearer.
linked_ebi_falls_back_to_the_requested_one_test() ->
    ?assertEqual(#{ebi => 6}, epdg_ue_fsm:with_linked_ebi(#{ebi => undefined}, 6)),
    ?assertEqual(#{ebi => 6}, epdg_ue_fsm:with_linked_ebi(#{}, 6)),
    ?assertEqual(#{ebi => 7}, epdg_ue_fsm:with_linked_ebi(#{ebi => 7}, 6)).

restore(Key, undefined) -> application:unset_env(epdg, Key);
restore(Key, {ok, V})   -> application:set_env(epdg, Key, V).
