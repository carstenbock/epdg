-module(epdg_ue_fsm_teardown_tests).
-include_lib("eunit/include/eunit.hrl").

%% KI-4: a UE that detached from the ePDG kept its PDN connection at the
%% PGW, because terminate/3 built the S2b Delete Session Request from map
%% keys that epdg_gtpc_codec:decode_create_session_response/1 never
%% produces. These tests tie the Delete parameters to the decoder's own
%% output, so the two cannot drift apart again.

%% A Create Session Response as the decoder hands it to the FSM: PGW
%% control F-TEID (interface 32, S2b PGW GTP-C) and no EBI echoed.
decoded_csr_without_ebi() ->
    FTeid = <<1:1, 0:1, 32:6, 16#1234:32, 10, 0, 1, 10>>,
    epdg_gtpc_codec:decode_create_session_response(
      #{ies => [{cause, <<16, 0>>}, {fteid, FTeid}]}).

%% The FSM keeps the decoded response plus its own local keys.
pgw_session() ->
    (decoded_csr_without_ebi())#{ue_inner_ip => {10, 46, 0, 34},
                                 ue_inner_ip6 => undefined,
                                 local_c_teid => 111, local_u_teid => 222}.

delete_params_from_codec_shaped_session_test() ->
    ?assertEqual(undefined, maps:get(ebi, pgw_session())),
    ?assertEqual({ok, #{pgw_c_teid => 16#1234, ebi => 5}},
                 epdg_ue_fsm:pgw_delete_params(pgw_session())).

delete_params_keep_an_echoed_ebi_test() ->
    ?assertEqual({ok, #{pgw_c_teid => 16#1234, ebi => 6}},
                 epdg_ue_fsm:pgw_delete_params((pgw_session())#{ebi => 6})).

no_delete_without_pgw_session_test() ->
    ?assertEqual(none, epdg_ue_fsm:pgw_delete_params(undefined)),
    ?assertEqual(none, epdg_ue_fsm:pgw_delete_params(#{})),
    %% A rejected Create Session leaves a session map without a PGW TEID.
    Rejected = epdg_gtpc_codec:decode_create_session_response(
                 #{ies => [{cause, <<73, 0>>}]}),
    ?assertEqual(none, epdg_ue_fsm:pgw_delete_params(Rejected)).

%% Every teardown of an anchored session releases it at the PGW ...
teardown_reasons_send_delete_test_() ->
    Expected = {send, #{pgw_c_teid => 16#1234, ebi => 5}},
    [{atom_to_list(element(2, R)),
      ?_assertEqual(Expected, epdg_ue_fsm:s2b_delete_action(R, pgw_session()))}
     || R <- [{shutdown, ue_delete}, {shutdown, dpd_timeout},
              {shutdown, aaa_abort}, {shutdown, drained}]].

%% ... except when a newer session of the same IMSI superseded it: the PGW
%% replaced that PDN connection when it accepted the new Create Session
%% Request, and a Delete with the old TEID could hit a reused one.
supersede_skips_delete_test() ->
    ?assertEqual(skip, epdg_ue_fsm:s2b_delete_action({shutdown, superseded},
                                                     pgw_session())).

%% ... and when the PGW deleted the default bearer itself (PGW-initiated
%% release, e.g. a PGW-C shutdown drain, KI-119): the PDN connection is
%% already gone at the PGW, so a Delete Session would only hit an unknown or
%% reused TEID.
pgw_bearer_delete_skips_delete_test() ->
    ?assertEqual(skip, epdg_ue_fsm:s2b_delete_action({shutdown, pgw_bearer_delete},
                                                     pgw_session())).

no_session_skips_delete_test() ->
    ?assertEqual(skip, epdg_ue_fsm:s2b_delete_action({shutdown, ue_delete},
                                                     undefined)).
