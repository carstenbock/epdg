-module(epdg_session_store_tests).
-include_lib("eunit/include/eunit.hrl").

%% Snapshot codec tests. The contract: whatever put_session stored, a
%% LATER release restoring it must either decode it exactly or reject it
%% cleanly ({error, ...}) — never crash the restore loop and never
%% half-decode. The version tag is what turns a schema change from a
%% crash into a clean skip-and-delete.

sample_snapshot() ->
    #{imsi => <<"262240000010003">>,
      apn => <<"ims">>,
      peer_ip => {93, 204, 201, 107},
      peer_port => 23830,
      initiator_spi => 16#0123456789abcdef,
      responder_spi => 16#fedcba9876543210,
      message_id => 7,
      mobike => true,
      child_sa => #{spi_in => 16#05974942, spi_out => 16#c91f55b2,
                    reinstall => #{sk_ei => <<1, 2, 3>>}},
      ue_inner_ip => {10, 46, 0, 34},
      dedicated_bearers => #{6 => #{local_u_teid => 123}},
      swm_session_id => <<"dra;123;456">>}.

roundtrip_test() ->
    Snap = sample_snapshot(),
    Bin = epdg_session_store:encode_snapshot(Snap),
    ?assert(is_binary(Bin)),
    {ok, Decoded} = epdg_session_store:decode_snapshot(Bin),
    %% encode stamps the schema version; everything else must survive
    %% unchanged.
    ?assertEqual(Snap#{v => 1}, Decoded).

garbage_is_rejected_not_crashed_test() ->
    ?assertMatch({error, _}, epdg_session_store:decode_snapshot(<<"junk">>)),
    ?assertMatch({error, _}, epdg_session_store:decode_snapshot(<<>>)),
    %% A valid term that is not a versioned snapshot map
    NotSnap = term_to_binary([1, 2, 3]),
    ?assertMatch({error, _}, epdg_session_store:decode_snapshot(NotSnap)).

unknown_version_is_rejected_test() ->
    Bin = term_to_binary(#{v => 999, imsi => <<"1">>}),
    ?assertEqual({error, {unknown_version, 999}},
                 epdg_session_store:decode_snapshot(Bin)).

%% Key layout is part of the storage contract (SCAN pattern in
%% do_list_sessions and the per-pod prefix isolation depend on it).
session_key_test() ->
    application:set_env(epdg, redis_key_prefix, "epdg:cnaas-epdg-1"),
    try
        ?assertEqual(<<"epdg:cnaas-epdg-1:session:fedcba9876543210">>,
                     epdg_session_store:session_key(16#fedcba9876543210))
    after
        application:unset_env(epdg, redis_key_prefix)
    end.
