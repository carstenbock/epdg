%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the ePDG's certificate AUTH signature.
%%%
%%% A UE that does not use EAP-only authentication (RFC 5998) verifies the
%%% AUTH payload of IKE_AUTH message 4 with the public key of the ePDG
%%% certificate (TS 33.402 §8.2.4.1). The AUTH method announces how: the
%%% UE verifies with exactly that scheme and hash, so a signature made any
%%% other way fails and the UE drops the tunnel. Each test therefore
%%% verifies the result the way a UE does.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ike_signature_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(OCTETS, <<"IKE_SA_INIT response | Ni | prf(SK_pr, IDr')">>).
%% RFC 7427 hash ids a typical UE announces: SHA2-256, SHA2-384, SHA2-512.
-define(UE_HASHES, [2, 3, 4]).

%% RFC 7427 Appendix A.1.3 and A.3.1.
-define(ALGID_SHA256_RSA, <<16#30,16#0d,16#06,16#09,16#2a,16#86,16#48,16#86,
                            16#f7,16#0d,16#01,16#01,16#0b,16#05,16#00>>).
-define(ALGID_ECDSA_SHA256, <<16#30,16#0a,16#06,16#08,16#2a,16#86,16#48,16#ce,
                              16#3d,16#04,16#03,16#02>>).

%%====================================================================
%% RSA
%%====================================================================

%% RFC 7427: a UE that announced SHA2-256 gets Digital Signature (14) with
%% sha256WithRSAEncryption, RSASSA-PKCS1-v1_5.
rsa_digital_signature_when_the_ue_announced_sha256_test() ->
    Key = rsa_key(),
    {Method, Data} = epdg_ikev2_crypto:sign_octets(Key, ?OCTETS, ?UE_HASHES),
    ?assertEqual(14, Method),
    <<Len:8, AlgId:Len/binary, Sig/binary>> = Data,
    ?assertEqual(?ALGID_SHA256_RSA, AlgId),
    ?assert(public_key:verify(?OCTETS, sha256, Sig, rsa_pub(Key))).

%% RFC 7296 §3.8: method 1 is RSASSA-PKCS1-v1_5, which UEs check over SHA-1.
%% A PSS signature (what the ePDG sent up to 0.0.112) fails this check.
rsa_signature_method_1_without_the_hash_notify_test() ->
    Key = rsa_key(),
    {Method, Sig} = epdg_ikev2_crypto:sign_octets(Key, ?OCTETS, []),
    ?assertEqual(1, Method),
    ?assert(public_key:verify(?OCTETS, sha, Sig, rsa_pub(Key))).

%% A UE that announced only SHA-1 cannot verify method 14 with SHA-256.
rsa_signature_method_1_when_the_ue_lacks_sha256_test() ->
    {Method, _} = epdg_ikev2_crypto:sign_octets(rsa_key(), ?OCTETS, [1]),
    ?assertEqual(1, Method).

%%====================================================================
%% ECDSA
%%====================================================================

%% RFC 4754 §7: methods 9/10 carry r and s as fixed-length integers, not DER.
ecdsa_p256_method_9_is_r_and_s_test() ->
    Key = ec_key(),
    {Method, Data} = epdg_ikev2_crypto:sign_octets(Key, ?OCTETS, []),
    ?assertEqual(9, Method),
    ?assertEqual(64, byte_size(Data)),
    <<R:32/unit:8, S:32/unit:8>> = Data,
    Der = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}),
    ?assert(public_key:verify(?OCTETS, sha256, Der, ec_pub(Key))).

%% RFC 7427 §3: method 14 carries the DER Ecdsa-Sig-Value.
ecdsa_p256_digital_signature_when_the_ue_announced_sha256_test() ->
    Key = ec_key(),
    {Method, Data} = epdg_ikev2_crypto:sign_octets(Key, ?OCTETS, ?UE_HASHES),
    ?assertEqual(14, Method),
    <<Len:8, AlgId:Len/binary, Sig/binary>> = Data,
    ?assertEqual(?ALGID_ECDSA_SHA256, AlgId),
    ?assert(public_key:verify(?OCTETS, sha256, Sig, ec_pub(Key))).

%%====================================================================
%% Reading the UE's N(SIGNATURE_HASH_ALGORITHMS)
%%====================================================================

reads_the_hash_ids_of_the_notify_test() ->
    Payloads = [#{type => sa, data => <<>>},
                #{type => notify, data => <<0, 0, 16388:16, "natd">>},
                #{type => notify, data => <<0, 0, 16431:16, 2:16, 3:16, 4:16>>}],
    ?assertEqual([2, 3, 4], epdg_ue_fsm:signature_hash_algorithms(Payloads)).

no_hash_ids_without_the_notify_test() ->
    ?assertEqual([], epdg_ue_fsm:signature_hash_algorithms(
                       [#{type => notify, data => <<0, 0, 16388:16, "natd">>}])).

%%====================================================================
%% Helpers
%%====================================================================

rsa_key() ->
    public_key:generate_key({rsa, 2048, 65537}).

rsa_pub(#'RSAPrivateKey'{modulus = N, publicExponent = E}) ->
    #'RSAPublicKey'{modulus = N, publicExponent = E}.

ec_key() ->
    public_key:generate_key({namedCurve, ?'secp256r1'}).

ec_pub(#'ECPrivateKey'{publicKey = Pub, parameters = Params}) ->
    {#'ECPoint'{point = Pub}, Params}.
