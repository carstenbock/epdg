-module(epdg_ue_fsm_sa_init_port_tests).
-include_lib("eunit/include/eunit.hrl").

%% RFC 7296 §2.11: a response leaves from the address and port the request
%% was sent to. A UE behind a NAT only has a mapping toward that one port, so
%% an IKE_SA_INIT response from any other port never reaches it and the
%% attach dies in retransmissions without a single log line on the ePDG.

%% §2.23 allows the initiator to start on UDP/4500. This is the case the
%% ePDG used to answer from 500.
request_on_natt_port_is_answered_from_natt_port_test() ->
    ?assertEqual(4500, epdg_ue_fsm:sa_init_reply_port(
                         #{local_port => 4500, from_port => 44303})).

%% The usual case. The peer's source port must not influence the choice: a
%% NAT'd UE sends IKE_SA_INIT to 500 from an arbitrary high port.
request_on_ike_port_is_answered_from_ike_port_test() ->
    ?assertEqual(500, epdg_ue_fsm:sa_init_reply_port(
                        #{local_port => 500, from_port => 44303})),
    ?assertEqual(500, epdg_ue_fsm:sa_init_reply_port(
                        #{local_port => 500, from_port => 4500})).

%% A header that does not say where it arrived keeps the classic IKE port.
unknown_local_port_falls_back_to_ike_port_test() ->
    ?assertEqual(500, epdg_ue_fsm:sa_init_reply_port(#{from_port => 4500})),
    ?assertEqual(500, epdg_ue_fsm:sa_init_reply_port(#{local_port => 0})).
