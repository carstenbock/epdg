-module(epdg_swm_origin_state_tests).
%% The AAA server sees the ePDG only through the DRA, never its CER. To clean
%% up the sessions of an ePDG that restarted and lost them (KI-46), it needs
%% the ePDG's Origin-State-Id (RFC 6733 §8.16) in DER and STR. The value must
%% stay the same while the node keeps its sessions, and must not be sent when
%% the session store would restore them after a restart.
-include_lib("eunit/include/eunit.hrl").
-include_lib("diameter/include/diameter.hrl").

%% Encode with the SWm dictionary and decode again; returns the decoded
%% Origin-State-Id (AVP 278).
origin_state(Msg) ->
    Hdr = #diameter_header{version = 1, hop_by_hop_id = 1, end_to_end_id = 1},
    #diameter_packet{bin = Bin} =
        diameter_codec:encode(diameter_gen_swm, #diameter_packet{header = Hdr, msg = Msg}),
    #diameter_packet{avps = Avps, errors = []} = diameter_codec:decode(diameter_gen_swm, Bin),
    [V] = [V || #diameter_avp{code = 278, value = V} <- Avps],
    V.

der_carries_origin_state_id_test() ->
    Msg = ['DER', {'Session-Id', <<"epdg;1;1">>}, {'Auth-Application-Id', 16777264},
           {'Origin-Host', <<"epdg-a">>}, {'Origin-Realm', <<"r">>},
           {'Destination-Realm', <<"r">>}, {'Auth-Request-Type', 3},
           {'Origin-State-Id', 1762905600}],
    ?assertEqual(1762905600, origin_state(Msg)).

str_carries_origin_state_id_test() ->
    Msg = ['STR', {'Session-Id', <<"epdg;1;1">>}, {'Origin-Host', <<"epdg-a">>},
           {'Origin-Realm', <<"r">>}, {'Destination-Realm', <<"r">>},
           {'Auth-Application-Id', 16777264}, {'Termination-Cause', 1},
           {'Origin-State-Id', 1762905600}],
    ?assertEqual(1762905600, origin_state(Msg)).

marker_is_stable_and_off_with_the_session_store_test() ->
    application:set_env(epdg, session_store_enabled, false),
    A = epdg_diameter_swm:session_state_marker(),
    ?assert(is_integer(A)),
    ?assertEqual(A, epdg_diameter_swm:session_state_marker()),
    application:set_env(epdg, session_store_enabled, true),
    ?assertEqual(undefined, epdg_diameter_swm:session_state_marker()),
    application:unset_env(epdg, session_store_enabled).
