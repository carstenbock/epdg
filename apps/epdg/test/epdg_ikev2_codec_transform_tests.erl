%%%-------------------------------------------------------------------
%%% @doc EUnit tests for IKE SA proposal selection in epdg_ikev2_codec:
%%% the 3GPP TS 33.402 SWu profile transforms (AES-CBC/GCM at 128/192/256,
%%% SHA-1 and SHA-2 PRF/INTEG) must be selectable, while algorithms outside
%%% the profile (3DES) must still be rejected with unsupported_transforms.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_codec_transform_tests).

-include_lib("eunit/include/eunit.hrl").

%% Transform types (RFC 7296 §3.3.2)
-define(T_ENCR,  1).
-define(T_PRF,   2).
-define(T_INTEG, 3).
-define(T_DH,    4).

%% Transform IDs used below
-define(ENCR_3DES,        3).
-define(ENCR_AES_CBC,    12).
-define(ENCR_AES_GCM_16, 20).
-define(PRF_HMAC_SHA1,    2).
-define(PRF_HMAC_SHA2_256, 5).
-define(AUTH_HMAC_SHA1_96, 2).
-define(AUTH_HMAC_SHA2_256_128, 12).
-define(AUTH_HMAC_SHA2_512_256, 14).
-define(PRF_HMAC_SHA2_384, 6).
-define(PRF_HMAC_SHA2_512, 7).
-define(DH_MODP_2048,    14).
-define(DH_MODP_3072,    15).
-define(DH_MODP_4096,    16).

%%====================================================================
%% Helpers: encode a transforms binary and wrap it in a proposal map
%% shaped like decode_sa_payload/1 output, so select_proposal/1 can be
%% driven directly.
%%====================================================================

%% {Type, Id} or {Type, Id, KeyLenBits}
transforms_bin(Specs) ->
    N = length(Specs),
    iolist_to_binary(
        [enc_transform(S, case I of N -> 0; _ -> 3 end)
         || {I, S} <- lists:zip(lists:seq(1, N), Specs)]).

enc_transform({Type, Id}, Last) ->
    <<Last:8, 0:8, 8:16, Type:8, 0:8, Id:16>>;
enc_transform({Type, Id, KeyLen}, Last) ->
    %% Key Length attribute: TV (AF=1), type 14
    <<Last:8, 0:8, 12:16, Type:8, 0:8, Id:16, 1:1, 14:15, KeyLen:16>>.

ike_proposal(Specs) ->
    [#{number => 1, protocol_id => 1, spi => <<>>,
       num_transforms => length(Specs),
       transforms_data => transforms_bin(Specs)}].

%%====================================================================
%% Classic conservative Samsung/Qualcomm profile:
%% AES-CBC-128 + PRF_HMAC_SHA1 + AUTH_HMAC_SHA1_96 + MODP-2048.
%% Must select, not reject.
%%====================================================================

cbc128_sha1_selects_test() ->
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 128},
                              {?T_PRF, ?PRF_HMAC_SHA1},
                              {?T_INTEG, ?AUTH_HMAC_SHA1_96},
                              {?T_DH, ?DH_MODP_2048}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{encr := #{id := ?ENCR_AES_CBC,
                             attrs := #{key_length := 128}},
                   prf := #{id := ?PRF_HMAC_SHA1},
                   integ := #{id := ?AUTH_HMAC_SHA1_96},
                   dh := #{id := ?DH_MODP_2048}}, Suite),
    %% The selected suite must map to usable key-derivation parameters:
    %% OTP hash atom sha, 20-byte PRF/integrity keys.
    {ok, Params} = epdg_ikev2_codec:keys_params_for_suite(Suite),
    ?assertMatch(#{enc_alg := aes_cbc_128, enc_key_len := 16,
                   prf := sha, prf_key_len := 20,
                   integ_alg := hmac_sha1_96, integ_key_len := 20,
                   is_aead := false}, Params).

%%====================================================================
%% AES-XCBC suite (PRF_AES128_XCBC = 4, AUTH_AES_XCBC_96 = 5) from the
%% ESP profile must select and map to key-derivation parameters.
%%====================================================================

cbc128_xcbc_selects_test() ->
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 128},
                              {?T_PRF, 4},
                              {?T_INTEG, 5},
                              {?T_DH, ?DH_MODP_2048}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    {ok, Params} = epdg_ikev2_codec:keys_params_for_suite(Suite),
    ?assertMatch(#{prf := aes128_xcbc, prf_key_len := 16,
                   integ_alg := aes_xcbc_96, integ_key_len := 16,
                   is_aead := false}, Params).

%%====================================================================
%% AES-CBC-128 with SHA-2 must select (128-bit baseline of the profile).
%%====================================================================

cbc128_sha2_selects_test() ->
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 128},
                              {?T_PRF, ?PRF_HMAC_SHA2_256},
                              {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                              {?T_DH, ?DH_MODP_2048}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{encr := #{id := ?ENCR_AES_CBC,
                             attrs := #{key_length := 128}},
                   prf := #{id := ?PRF_HMAC_SHA2_256},
                   integ := #{id := ?AUTH_HMAC_SHA2_256_128},
                   dh := #{id := ?DH_MODP_2048}}, Suite),
    {ok, Params} = epdg_ikev2_codec:keys_params_for_suite(Suite),
    ?assertMatch(#{enc_alg := aes_cbc_128, enc_key_len := 16,
                   is_aead := false}, Params).

%%====================================================================
%% AES-GCM-16-128 + PRF_HMAC_SHA2_256 + MODP-2048: AEAD, no INTEG
%% transform offered. Must select with integ = none.
%%====================================================================

gcm128_selects_with_integ_none_test() ->
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_GCM_16, 128},
                              {?T_PRF, ?PRF_HMAC_SHA2_256},
                              {?T_DH, ?DH_MODP_2048}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{encr := #{id := ?ENCR_AES_GCM_16,
                             attrs := #{key_length := 128}},
                   integ := none}, Suite),
    {ok, Params} = epdg_ikev2_codec:keys_params_for_suite(Suite),
    %% RFC 5282: per-direction keying material = key + 4-byte salt.
    ?assertMatch(#{enc_alg := aes_gcm_128, enc_key_len := 20,
                   salt_len := 4, is_aead := true,
                   integ_alg := none, integ_key_len := 0}, Params).

%%====================================================================
%% 192-bit keys (TS 33.210 profile) must select and map to params.
%%====================================================================

cbc192_selects_test() ->
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 192},
                              {?T_PRF, ?PRF_HMAC_SHA2_256},
                              {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                              {?T_DH, ?DH_MODP_2048}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    {ok, Params} = epdg_ikev2_codec:keys_params_for_suite(Suite),
    ?assertMatch(#{enc_alg := aes_cbc_192, enc_key_len := 24}, Params).

gcm192_selects_test() ->
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_GCM_16, 192},
                              {?T_PRF, ?PRF_HMAC_SHA2_256},
                              {?T_DH, ?DH_MODP_2048}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    {ok, Params} = epdg_ikev2_codec:keys_params_for_suite(Suite),
    ?assertMatch(#{enc_alg := aes_gcm_192, enc_key_len := 28,
                   salt_len := 4, is_aead := true}, Params).

%%====================================================================
%% MODP-3072 (DH 15): the three customer-lab proposal lines that offer
%% dh:15 as the only group must now select instead of getting
%% NO_PROPOSAL_CHOSEN. MODP-4096 (DH 16) sanity-checked alongside.
%%====================================================================

lab_cbc256_sha256_dh15_selects_test() ->
    %% encr:12/keylen=256, integ:12, prf:5, dh:15
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 256},
                              {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                              {?T_PRF, ?PRF_HMAC_SHA2_256},
                              {?T_DH, ?DH_MODP_3072}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{encr := #{id := ?ENCR_AES_CBC,
                             attrs := #{key_length := 256}},
                   prf := #{id := ?PRF_HMAC_SHA2_256},
                   integ := #{id := ?AUTH_HMAC_SHA2_256_128},
                   dh := #{id := ?DH_MODP_3072}}, Suite).

lab_cbc256_sha512_dh15_selects_test() ->
    %% encr:12/keylen=256, integ:14, prf:7, dh:15
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 256},
                              {?T_INTEG, ?AUTH_HMAC_SHA2_512_256},
                              {?T_PRF, ?PRF_HMAC_SHA2_512},
                              {?T_DH, ?DH_MODP_3072}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{prf := #{id := ?PRF_HMAC_SHA2_512},
                   integ := #{id := ?AUTH_HMAC_SHA2_512_256},
                   dh := #{id := ?DH_MODP_3072}}, Suite).

lab_gcm256_sha384_dh15_selects_test() ->
    %% encr:20/keylen=256, prf:6, dh:15 (AEAD, no INTEG offered)
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_GCM_16, 256},
                              {?T_PRF, ?PRF_HMAC_SHA2_384},
                              {?T_DH, ?DH_MODP_3072}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{encr := #{id := ?ENCR_AES_GCM_16,
                             attrs := #{key_length := 256}},
                   integ := none,
                   dh := #{id := ?DH_MODP_3072}}, Suite).

dh16_selects_test() ->
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 256},
                              {?T_PRF, ?PRF_HMAC_SHA2_256},
                              {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                              {?T_DH, ?DH_MODP_4096}]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{dh := #{id := ?DH_MODP_4096}}, Suite).

%%====================================================================
%% Missing Key Length attribute (RFC 7296 §3.3.5 violation seen from
%% real handsets): AES-CBC (12) and AES-GCM-16 (20) without the
%% attribute are normalised to 128 bits at decode time, with a
%% key_length_defaulted marker. INTEG transforms share IDs 12/14
%% (HMAC-SHA2) and must never be touched.
%%====================================================================

keylen_defaulted_on_bare_encr12_test() ->
    TBin = transforms_bin([{?T_ENCR, ?ENCR_AES_CBC}]),
    {ok, [T]} = epdg_ikev2_codec:decode_transforms(TBin),
    ?assertMatch(#{id := ?ENCR_AES_CBC,
                   attrs := #{key_length := 128},
                   key_length_defaulted := true}, T).

keylen_defaulted_on_bare_encr20_test() ->
    TBin = transforms_bin([{?T_ENCR, ?ENCR_AES_GCM_16}]),
    {ok, [T]} = epdg_ikev2_codec:decode_transforms(TBin),
    ?assertMatch(#{id := ?ENCR_AES_GCM_16,
                   attrs := #{key_length := 128},
                   key_length_defaulted := true}, T).

keylen_not_defaulted_on_integ_test() ->
    %% INTEG 12 = HMAC-SHA2-256-128, same numeric ID as ENCR AES-CBC.
    TBin = transforms_bin([{?T_INTEG, ?AUTH_HMAC_SHA2_256_128}]),
    {ok, [T]} = epdg_ikev2_codec:decode_transforms(TBin),
    ?assertEqual(#{}, maps:get(attrs, T)),
    ?assertNot(maps:is_key(key_length_defaulted, T)).

keylen_present_no_marker_test() ->
    TBin = transforms_bin([{?T_ENCR, ?ENCR_AES_CBC, 256}]),
    {ok, [T]} = epdg_ikev2_codec:decode_transforms(TBin),
    ?assertMatch(#{attrs := #{key_length := 256}}, T),
    ?assertNot(maps:is_key(key_length_defaulted, T)).

keylen_not_defaulted_on_other_encr_test() ->
    %% ENCR 13 = AES-CTR: not in the defaulting set, stays unsupported.
    TBin = transforms_bin([{?T_ENCR, 13}]),
    {ok, [T]} = epdg_ikev2_codec:decode_transforms(TBin),
    ?assertEqual(#{}, maps:get(attrs, T)),
    ?assertNot(maps:is_key(key_length_defaulted, T)).

%%====================================================================
%% The two customer-lab lines that omit Key Length must now select.
%% Note on expectations: for ENCR/PRF/INTEG the codec picks the last
%% supported transform in initiator order (per-type lists are
%% accumulated in reverse), so the legacy line yields integ:5 and the
%% modern line prf:7. DH is picked first-in-initiator-order among the
%% built-in groups (see pick_dh/1), so both lines yield dh:14.
%%====================================================================

lab_legacy_no_keylen_selects_test() ->
    %% encr:1..13 (no keylen), prf:1..2, integ:0..5, dh:0,1,2,5,14..18
    Proposals = ike_proposal(
        [{?T_ENCR, E} || E <- [1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 13]] ++
        [{?T_PRF, P} || P <- [1, 2]] ++
        [{?T_INTEG, I} || I <- [0, 1, 2, 3, 4, 5]] ++
        [{?T_DH, D} || D <- [0, 1, 2, 5, 14, 15, 16, 17, 18]]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{encr := #{id := ?ENCR_AES_CBC,
                             attrs := #{key_length := 128},
                             key_length_defaulted := true},
                   prf := #{id := ?PRF_HMAC_SHA1},
                   integ := #{id := 5},
                   dh := #{id := ?DH_MODP_2048}}, Suite).

lab_modern_no_keylen_selects_test() ->
    %% encr:18,19,20,28 (no keylen), prf:1,2,5,6,7, dh:0,1,2,14,16,19,20
    Proposals = ike_proposal(
        [{?T_ENCR, E} || E <- [18, 19, 20, 28]] ++
        [{?T_PRF, P} || P <- [1, 2, 5, 6, 7]] ++
        [{?T_DH, D} || D <- [0, 1, 2, 14, 16, 19, 20]]),
    {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
    ?assertMatch(#{encr := #{id := ?ENCR_AES_GCM_16,
                             attrs := #{key_length := 128},
                             key_length_defaulted := true},
                   prf := #{id := ?PRF_HMAC_SHA2_512},
                   integ := none,
                   dh := #{id := ?DH_MODP_2048}}, Suite).

%%====================================================================
%% RFC 7296 §3.3.5: our SA response must carry the Key Length
%% attribute (TV, type 14, value 128) even though the initiator
%% omitted it — encoded from the normalised map, not the raw bytes.
%%====================================================================

sa_response_echoes_defaulted_keylen_test_() ->
    [{Desc,
      fun() ->
          Proposals = ike_proposal(Specs),
          {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
          Resp = epdg_ikev2_codec:encode_sa_response(Suite),
          %% TV attribute: AF=1, type 14, value 128 -> 80 0E 00 80.
          ?assertNotEqual(nomatch,
                          binary:match(Resp, <<16#80, 16#0E, 0, 128>>))
      end}
     || {Desc, Specs} <-
        [{"AES-CBC without keylen",
          [{?T_ENCR, ?ENCR_AES_CBC},
           {?T_PRF, ?PRF_HMAC_SHA1},
           {?T_INTEG, ?AUTH_HMAC_SHA1_96},
           {?T_DH, ?DH_MODP_2048}]},
         {"AES-GCM-16 without keylen",
          [{?T_ENCR, ?ENCR_AES_GCM_16},
           {?T_PRF, ?PRF_HMAC_SHA2_256},
           {?T_DH, ?DH_MODP_2048}]}]].

%%====================================================================
%% Legacy DH groups 2/5 (RFC 8247 SHOULD NOT): rejected by default,
%% selectable only when enabled via EPDG_IKE_LEGACY_DH_GROUPS (app env
%% ike_legacy_dh_groups). Even when enabled, a built-in group offered
%% anywhere in the proposal always wins (two-tier pick), and between
%% the legacy groups MODP-1536 outranks MODP-1024.
%%====================================================================

%% The three customer-lab lines offering only legacy groups.
legacy_lab_proposals() ->
    [{"encr:12/128 integ:2 prf:2 dh:2",
      ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 128},
                    {?T_INTEG, ?AUTH_HMAC_SHA1_96},
                    {?T_PRF, ?PRF_HMAC_SHA1},
                    {?T_DH, 2}]), 2},
     {"encr:12/256 prf:5 integ:12 dh:2",
      ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 256},
                    {?T_PRF, ?PRF_HMAC_SHA2_256},
                    {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                    {?T_DH, 2}]), 2},
     {"encr:12/256 prf:5 integ:12 dh:5",
      ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 256},
                    {?T_PRF, ?PRF_HMAC_SHA2_256},
                    {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                    {?T_DH, 5}]), 5}].

with_legacy_dh(Groups, Tests) ->
    {setup,
     fun() -> application:set_env(epdg, ike_legacy_dh_groups, Groups) end,
     fun(_) -> application:unset_env(epdg, ike_legacy_dh_groups) end,
     Tests}.

legacy_dh_disabled_rejects_test_() ->
    %% Env var unset (default []): all three lab lines are rejected.
    [{Desc,
      ?_assertEqual({error, unsupported_transforms},
                    epdg_ikev2_codec:select_proposal(Proposals))}
     || {Desc, Proposals, _} <- legacy_lab_proposals()].

legacy_dh_enabled_selects_test_() ->
    with_legacy_dh([2, 5],
        [{Desc,
          fun() ->
              {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
              ?assertMatch(#{dh := #{id := Expected}}, Suite)
          end}
         || {Desc, Proposals, Expected} <- legacy_lab_proposals()]).

legacy_dh_builtin_still_wins_test_() ->
    %% dh:2 listed before dh:14 — the built-in group must win even with
    %% legacy groups enabled.
    with_legacy_dh([2, 5],
        [fun() ->
             Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 128},
                                       {?T_PRF, ?PRF_HMAC_SHA1},
                                       {?T_INTEG, ?AUTH_HMAC_SHA1_96},
                                       {?T_DH, 2},
                                       {?T_DH, ?DH_MODP_2048}]),
             {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
             ?assertMatch(#{dh := #{id := ?DH_MODP_2048}}, Suite)
         end]).

legacy_dh_prefers_1536_over_1024_test_() ->
    %% Both legacy groups offered, 2 listed first: MODP-1536 wins.
    with_legacy_dh([2, 5],
        [fun() ->
             Proposals = ike_proposal([{?T_ENCR, ?ENCR_AES_CBC, 128},
                                       {?T_PRF, ?PRF_HMAC_SHA1},
                                       {?T_INTEG, ?AUTH_HMAC_SHA1_96},
                                       {?T_DH, 2},
                                       {?T_DH, 5}]),
             {ok, Suite} = epdg_ikev2_codec:select_proposal(Proposals),
             ?assertMatch(#{dh := #{id := 5}}, Suite)
         end]).

legacy_dh_partial_enable_test_() ->
    %% Only group 5 enabled: dh:2-only line stays rejected.
    with_legacy_dh([5],
        [fun() ->
             [{_, Dh2Line, 2} | _] = legacy_lab_proposals(),
             ?assertEqual({error, unsupported_transforms},
                          epdg_ikev2_codec:select_proposal(Dh2Line))
         end]).

%%====================================================================
%% A proposal offering only 3DES must still be rejected.
%%====================================================================

three_des_only_rejected_test() ->
    Proposals = ike_proposal([{?T_ENCR, ?ENCR_3DES},
                              {?T_PRF, ?PRF_HMAC_SHA2_256},
                              {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                              {?T_DH, ?DH_MODP_2048}]),
    ?assertEqual({error, unsupported_transforms},
                 epdg_ikev2_codec:select_proposal(Proposals)).

%%====================================================================
%% Child SA (ESP) selection inherits the widened encryption set via
%% is_supported_child_encr/1 — verify with an AES-CBC-128 + SHA1-96
%% ESP proposal, and check the derived ESP key lengths.
%%====================================================================

child_cbc128_sha1_selects_test() ->
    %% Transform type 5 = ESN, ID 0 = no ESN.
    Specs = [{?T_ENCR, ?ENCR_AES_CBC, 128},
             {?T_INTEG, ?AUTH_HMAC_SHA1_96},
             {5, 0}],
    TBin = transforms_bin(Specs),
    PropLen = 8 + 4 + byte_size(TBin),
    SaBin = <<0:8, 0:8, PropLen:16, 1:8, 3:8, 4:8, (length(Specs)):8,
              16#AABBCCDD:32, TBin/binary>>,
    {ok, Suite} = epdg_ikev2_codec:decode_child_sa_payload(SaBin),
    ?assertMatch(#{encr := #{id := ?ENCR_AES_CBC,
                             attrs := #{key_length := 128}},
                   integ := #{id := ?AUTH_HMAC_SHA1_96}}, Suite),
    ?assertEqual(16, epdg_ikev2_codec:child_enc_key_len(maps:get(encr, Suite))),
    ?assertEqual(20, epdg_ikev2_codec:child_integ_key_len(maps:get(integ, Suite))).

%%====================================================================
%% ESN negotiation (RFC 4304): a UE offering ESN exclusively must be
%% accepted; when it offers both, "no ESN" (ID 0) is preferred.
%%====================================================================

child_esp_bin(Specs) ->
    TBin = transforms_bin(Specs),
    PropLen = 8 + 4 + byte_size(TBin),
    <<0:8, 0:8, PropLen:16, 1:8, 3:8, 4:8, (length(Specs)):8,
      16#AABBCCDD:32, TBin/binary>>.

child_esn_only_accepted_test() ->
    SaBin = child_esp_bin([{?T_ENCR, ?ENCR_AES_CBC, 128},
                           {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                           {5, 1}]),
    {ok, Suite} = epdg_ikev2_codec:decode_child_sa_payload(SaBin),
    ?assertMatch(#{esn := #{id := 1}}, Suite).

child_esn_prefers_no_esn_test() ->
    %% UE lists ESN (1) before no-ESN (0); we still answer with 0.
    SaBin = child_esp_bin([{?T_ENCR, ?ENCR_AES_CBC, 128},
                           {?T_INTEG, ?AUTH_HMAC_SHA2_256_128},
                           {5, 1},
                           {5, 0}]),
    {ok, Suite} = epdg_ikev2_codec:decode_child_sa_payload(SaBin),
    ?assertMatch(#{esn := #{id := 0}}, Suite).

child_enc_key_len_gcm_salt_test() ->
    %% GCM ESP keying material = key + 4-byte salt for 128/192/256.
    ?assertEqual(20, epdg_ikev2_codec:child_enc_key_len(
                       #{id => 20, attrs => #{key_length => 128}})),
    ?assertEqual(28, epdg_ikev2_codec:child_enc_key_len(
                       #{id => 20, attrs => #{key_length => 192}})),
    ?assertEqual(36, epdg_ikev2_codec:child_enc_key_len(
                       #{id => 20, attrs => #{key_length => 256}})),
    ?assertEqual(24, epdg_ikev2_codec:child_enc_key_len(
                       #{id => 12, attrs => #{key_length => 192}})).
