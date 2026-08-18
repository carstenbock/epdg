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
-define(DH_MODP_2048,    14).

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
