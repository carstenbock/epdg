-module(epdg_ue_fsm_snapshot_tests).
-include_lib("eunit/include/eunit.hrl").

%% Pins the session_snapshot/1 <-> data_from_snapshot/1 roundtrip.
%%
%% Why this matters: the snapshot is what a crashed pod's successor has.
%% If someone adds a field to #data that restore needs but forgets one
%% side of the pair, sessions restore subtly broken (e.g. DPD encrypts
%% with missing keys, or the GTP-U TEID hint is lost and downlink
%% black-holes). Roundtripping every persisted field through #data and
%% back catches exactly that drift.

full_snapshot() ->
    #{peer_ip => {93, 204, 201, 107},
      peer_port => 23830,
      initiator_spi => 16#0123456789abcdef,
      responder_spi => 16#fedcba9876543210,
      imsi => <<"262240000010003">>,
      apn => <<"ims">>,
      ue_nai => <<"0262240000010003@nai.epc.mnc024.mcc262.3gppnetwork.org">>,
      keys_params => #{prf => hmac_sha256, enc_alg => aes_128_cbc,
                       enc_key_len => 16, integ_alg => hmac_sha256,
                       integ_key_len => 32, is_aead => false},
      ike_keys => #{sk_d => <<1>>, sk_ai => <<2>>, sk_ar => <<3>>,
                    sk_ei => <<4>>, sk_er => <<5>>, sk_pi => <<6>>,
                    sk_pr => <<7>>},
      message_id => 42,
      mobike => true,
      redirect_supported => false,
      eap_next_id => 5,
      child_sa => #{spi_in => 16#05974942, spi_out => 16#c91f55b2,
                    suite => #{},
                    reinstall => #{peer_spi => <<16#c9, 16#1f, 16#55, 16#b2>>,
                                   resp_spi => <<16#05, 16#97, 16#49, 16#42>>,
                                   suite => #{},
                                   sk_ei => <<8>>, sk_ai => <<9>>,
                                   sk_er => <<10>>, sk_ar => <<11>>,
                                   ue_inner_ip => {10, 46, 0, 34},
                                   ue_inner_ip6 => undefined}},
      pgw_session => #{pgw_c_fteid => #{teid => 77},
                       local_c_teid => 111, local_u_teid => 222,
                       ue_inner_ip => {10, 46, 0, 34}},
      ue_inner_ip => {10, 46, 0, 34},
      ue_inner_ip6 => {16#fd00, 16#230, 16#babe, 16#9c, 0, 0, 0, 1},
      gtpu_teid_local => 222,
      gtpu_teid_pgw => 333,
      dedicated_bearers => #{6 => #{ebi => 6, local_u_teid => 444,
                                    pgw_u_teid => 555,
                                    pgw_u_ip => {10, 0, 0, 9},
                                    filters => []}},
      swm_session_id => <<"epdg;1;2;3">>,
      swm_dest_host => <<"aaa-0.example.org">>}.

roundtrip_preserves_every_persisted_field_test() ->
    Snap = full_snapshot(),
    Data = epdg_ue_fsm:data_from_snapshot(Snap),
    Back = maps:remove(stored_at, epdg_ue_fsm:session_snapshot(Data)),
    ?assertEqual(Snap, Back).

%% Old snapshots may lack fields added later; restore must fill sane
%% defaults instead of crashing (the restore loop deletes only
%% undecodable entries, not merely old ones).
minimal_snapshot_gets_defaults_test() ->
    Minimal = #{peer_ip => {1, 2, 3, 4}, peer_port => 500,
                initiator_spi => 1, responder_spi => 2},
    Data = epdg_ue_fsm:data_from_snapshot(Minimal),
    Back = epdg_ue_fsm:session_snapshot(Data),
    ?assertEqual(0, maps:get(message_id, Back)),
    ?assertEqual(false, maps:get(mobike, Back)),
    ?assertEqual(#{}, maps:get(dedicated_bearers, Back)),
    ?assertEqual(undefined, maps:get(child_sa, Back)).
