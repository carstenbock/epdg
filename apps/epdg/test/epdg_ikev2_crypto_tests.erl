%%%-------------------------------------------------------------------
%%% @doc EUnit tests for epdg_ikev2_crypto: SK-protected message
%%% encode/decode round-trips across the widened TS 33.402 cipher set,
%%% ICV truncation lengths, and tamper detection (a flipped ciphertext
%%% byte must fail the integrity check, never decrypt silently).
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

-define(IKE_HDR_LEN, 28).
-define(SK_HDR_LEN, 4).

%% A fixed inner payload chain: one NONCE payload (4-byte generic
%% header + 16 bytes) = 20 bytes of inner plaintext.
-define(INNER_NONCE, <<"0123456789abcdef">>).
-define(INNER_LEN, 20).

%%====================================================================
%% Helpers
%%====================================================================

suite_params(EncrId, KeyLen, PrfId, IntegId) ->
    Suite = #{encr => #{id => EncrId, attrs => #{key_length => KeyLen}},
              prf => #{id => PrfId},
              integ => case IntegId of
                           none -> none;
                           I -> #{id => I}
                       end},
    {ok, Params} = epdg_ikev2_codec:keys_params_for_suite(Suite),
    Params.

derive_keys(Params) ->
    SharedSecret = crypto:strong_rand_bytes(256),
    NonceI = crypto:strong_rand_bytes(32),
    NonceR = crypto:strong_rand_bytes(32),
    epdg_ikev2_crypto:derive_ike_keys(
        SharedSecret, NonceI, NonceR,
        Params#{spi_i => <<16#1111:64>>, spi_r => <<16#2222:64>>}).

header() ->
    #{initiator_spi => 16#1111, responder_spi => 16#2222,
      exchange_type_raw => 37, flags => 16#20, message_id => 1}.

encode(Params, Keys) ->
    {ok, Msg} = epdg_ikev2_crypto:encode_encrypted_message(
        Params, Keys, responder, header(), [{nonce, ?INNER_NONCE}]),
    Msg.

decode(Params, Keys, Msg) ->
    epdg_ikev2_crypto:decode_encrypted_message(Params, Keys, responder, Msg).

roundtrip(Params) ->
    Keys = derive_keys(Params),
    Msg = encode(Params, Keys),
    {ok, #{payloads := Payloads}} = decode(Params, Keys, Msg),
    ?assertMatch([#{type := nonce, data := ?INNER_NONCE}], Payloads),
    {Msg, Keys}.

%% Actual ICV length on the wire, reconstructed from the message size:
%% total = IKE hdr + SK hdr + IV + ciphertext + ICV.
icv_len_of(Msg, IvLen, CtLen) ->
    byte_size(Msg) - ?IKE_HDR_LEN - ?SK_HDR_LEN - IvLen - CtLen.

%% Ciphertext length for the CBC path: inner | padding | pad-len byte,
%% padded to the AES block size (mirrors encode_encrypted_message/5).
cbc_ct_len(InnerLen) ->
    PadBytes = (16 - ((InnerLen + 1) rem 16)) rem 16,
    InnerLen + 1 + PadBytes.

flip_byte(Bin, Pos) ->
    <<Before:Pos/binary, B:8, Rest/binary>> = Bin,
    <<Before/binary, (B bxor 1):8, Rest/binary>>.

%% First ciphertext byte: after IKE hdr, SK hdr and IV.
flip_first_ct_byte(Msg, IvLen) ->
    flip_byte(Msg, ?IKE_HDR_LEN + ?SK_HDR_LEN + IvLen).

%%====================================================================
%% Round-trips (encrypt then decrypt) per suite
%%====================================================================

%% PRF_HMAC_SHA1 = 2, PRF_HMAC_SHA2_256 = 5,
%% AUTH_HMAC_SHA1_96 = 2, AUTH_HMAC_SHA2_256_128 = 12.

cbc128_sha1_roundtrip_test() ->
    %% Full SHA-1 suite: also exercises the prf+ key-derivation loop
    %% with 20-byte PRF blocks (not a multiple of 32).
    Params = suite_params(12, 128, 2, 2),
    {Msg, _} = roundtrip(Params),
    %% RFC 2404: HMAC-SHA-1-96 truncates to 12 bytes, not 16.
    ?assertEqual(12, icv_len_of(Msg, 16, cbc_ct_len(?INNER_LEN))).

cbc192_sha256_roundtrip_test() ->
    Params = suite_params(12, 192, 5, 12),
    {Msg, _} = roundtrip(Params),
    %% RFC 4868: HMAC-SHA-256-128 truncates to 16 bytes.
    ?assertEqual(16, icv_len_of(Msg, 16, cbc_ct_len(?INNER_LEN))).

gcm128_roundtrip_test() ->
    Params = suite_params(20, 128, 5, none),
    {Msg, _} = roundtrip(Params),
    %% AEAD ICV = 16-byte GCM tag; IV is 8 bytes (RFC 5282), CT = inner + pad-len byte.
    ?assertEqual(16, icv_len_of(Msg, 8, ?INNER_LEN + 1)).

gcm192_roundtrip_test() ->
    Params = suite_params(20, 192, 5, none),
    {Msg, _} = roundtrip(Params),
    ?assertEqual(16, icv_len_of(Msg, 8, ?INNER_LEN + 1)).

gcm256_roundtrip_test() ->
    %% Field-observed regression suite baseline (AEAD, 256-bit).
    Params = suite_params(20, 256, 5, none),
    {_Msg, _} = roundtrip(Params).

cbc256_sha256_roundtrip_test() ->
    %% Field-observed Samsung suite: AES-CBC-256 + HMAC-SHA-256-128.
    Params = suite_params(12, 256, 5, 12),
    {_Msg, _} = roundtrip(Params).

cbc128_sha256_roundtrip_test() ->
    Params = suite_params(12, 128, 5, 12),
    {_Msg, _} = roundtrip(Params).

%%====================================================================
%% Tamper detection: one flipped ciphertext byte must fail integrity
%%====================================================================

sha1_tamper_fails_test() ->
    Params = suite_params(12, 128, 2, 2),
    Keys = derive_keys(Params),
    Msg = encode(Params, Keys),
    Tampered = flip_first_ct_byte(Msg, 16),
    ?assertEqual({error, icv_check_failed}, decode(Params, Keys, Tampered)).

cbc_tamper_fails_test() ->
    Params = suite_params(12, 192, 5, 12),
    Keys = derive_keys(Params),
    Msg = encode(Params, Keys),
    Tampered = flip_first_ct_byte(Msg, 16),
    ?assertEqual({error, icv_check_failed}, decode(Params, Keys, Tampered)).

gcm_tamper_fails_test() ->
    Params = suite_params(20, 128, 5, none),
    Keys = derive_keys(Params),
    Msg = encode(Params, Keys),
    Tampered = flip_first_ct_byte(Msg, 8),
    ?assertEqual({error, icv_check_failed}, decode(Params, Keys, Tampered)).

gcm192_tamper_fails_test() ->
    Params = suite_params(20, 192, 5, none),
    Keys = derive_keys(Params),
    Msg = encode(Params, Keys),
    Tampered = flip_first_ct_byte(Msg, 8),
    ?assertEqual({error, icv_check_failed}, decode(Params, Keys, Tampered)).

%%====================================================================
%% PRF known-answer test: RFC 2202 §3 test case 1 for HMAC-SHA-1
%%====================================================================

prf_sha1_rfc2202_test() ->
    Key = binary:copy(<<16#0b>>, 20),
    Data = <<"Hi There">>,
    Expected = <<16#b6, 16#17, 16#31, 16#86, 16#55, 16#05, 16#72, 16#64,
                 16#e2, 16#8b, 16#c0, 16#b6, 16#fb, 16#37, 16#8c, 16#8e,
                 16#f1, 16#46, 16#be, 16#00>>,
    ?assertEqual(Expected, epdg_ikev2_crypto:prf(sha, Key, Data)).

%%====================================================================
%% encrypt_sk / decrypt_sk generalisation across key sizes
%%====================================================================

encrypt_sk_cbc_all_key_sizes_test_() ->
    [{atom_to_list(Alg),
      fun() ->
          Key = crypto:strong_rand_bytes(KeyLen),
          IV = crypto:strong_rand_bytes(16),
          Plain = <<"payload">>,
          Enc = epdg_ikev2_crypto:encrypt_sk(Alg, Key, IV, Plain),
          ?assertEqual(Plain, epdg_ikev2_crypto:decrypt_sk(Alg, Key, Enc, <<>>))
      end}
     || {Alg, KeyLen} <- [{aes_cbc_128, 16}, {aes_cbc_192, 24},
                          {aes_cbc_256, 32}]].

encrypt_sk_gcm_all_key_sizes_test_() ->
    [{atom_to_list(Alg),
      fun() ->
          Key = crypto:strong_rand_bytes(KeyLen),
          IV = crypto:strong_rand_bytes(12),
          Plain = <<"payload">>,
          Enc = epdg_ikev2_crypto:encrypt_sk(Alg, Key, IV, Plain),
          ?assertEqual(Plain, epdg_ikev2_crypto:decrypt_sk(Alg, Key, Enc, <<>>))
      end}
     || {Alg, KeyLen} <- [{aes_gcm_128, 16}, {aes_gcm_192, 24},
                          {aes_gcm_256, 32}]].
