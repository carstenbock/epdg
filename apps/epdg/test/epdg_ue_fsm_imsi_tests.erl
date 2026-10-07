-module(epdg_ue_fsm_imsi_tests).
-include_lib("eunit/include/eunit.hrl").

%% The IMSI for the S2b Create Session Request comes out of the UE's
%% identity. TS 23.003 section 19.3.2 puts one digit in front of it that
%% names the EAP method. If that digit is not understood the UE still
%% authenticates (the AAA server knows it), but the PGW gets a request
%% without an IMSI -- which aborted Open5GS' SMF and with it every session.

-define(REALM, "@nai.epc.mnc024.mcc262.3gppnetwork.org").

eap_aka_identity_test() ->
    ?assertEqual(<<"262240000099001">>,
                 epdg_ue_fsm:parse_imsi_from_nai(<<"0262240000099001", ?REALM>>)).

%% The case that was missed: EAP-AKA' identities start with "6".
eap_aka_prime_identity_test() ->
    ?assertEqual(<<"262240000099001">>,
                 epdg_ue_fsm:parse_imsi_from_nai(<<"6262240000099001", ?REALM>>)).

%% Pseudonyms and other method digits carry no IMSI; the caller must then
%% refuse the session instead of asking the PGW for one.
identity_without_imsi_is_undefined_test() ->
    ?assertEqual(undefined,
                 epdg_ue_fsm:parse_imsi_from_nai(<<"2pseudonym", ?REALM>>)),
    ?assertEqual(undefined,
                 epdg_ue_fsm:parse_imsi_from_nai(<<"1262240000099001", ?REALM>>)),
    ?assertEqual(undefined, epdg_ue_fsm:parse_imsi_from_nai(<<"6", ?REALM>>)),
    ?assertEqual(undefined, epdg_ue_fsm:parse_imsi_from_nai(<<>>)).
