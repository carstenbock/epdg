%%%-------------------------------------------------------------------
%%% @doc IKEv2 cryptographic operations.
%%% Key derivation, PRF, encryption, integrity, DH, EAP-AKA' support.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_crypto).

-include_lib("public_key/include/public_key.hrl").

-export([generate_nonce/0, generate_spi/0,
         dh_generate/1, dh_compute/3,
         prf/3, prf_plus/4,
         derive_ike_keys/4,
         derive_child_keys/5,
         encrypt_sk/4, decrypt_sk/4,
         derive_aka_prime_keys/4,
         load_certificate/1, load_private_key/1,
         sign_auth_data/5, auth_method/1]).

-define(NONCE_LEN, 32).

%%====================================================================
%% Nonce / SPI
%%====================================================================

-spec generate_nonce() -> binary().
generate_nonce() ->
    crypto:strong_rand_bytes(?NONCE_LEN).

-spec generate_spi() -> non_neg_integer().
generate_spi() ->
    <<SPI:64>> = crypto:strong_rand_bytes(8),
    SPI.

%%====================================================================
%% Diffie-Hellman
%%====================================================================

-spec dh_generate(non_neg_integer()) -> {binary(), binary()}.
dh_generate(14) ->
    %% DH Group 14 (2048-bit MODP, RFC 3526)
    {Pub, Priv} = crypto:generate_key(dh, [dh_group14_prime(), <<2>>]),
    {Pub, Priv};
dh_generate(19) ->
    %% ECP 256 (RFC 5903)
    {Pub, Priv} = crypto:generate_key(ecdh, secp256r1),
    {Pub, Priv};
dh_generate(20) ->
    %% ECP 384 (RFC 5903)
    {Pub, Priv} = crypto:generate_key(ecdh, secp384r1),
    {Pub, Priv};
dh_generate(31) ->
    %% Curve25519 (RFC 8031)
    {Pub, Priv} = crypto:generate_key(ecdh, x25519),
    {Pub, Priv};
dh_generate(_) ->
    error(unsupported_dh_group).

-spec dh_compute(non_neg_integer(), binary(), binary()) -> binary().
dh_compute(14, PeerPub, MyPriv) ->
    crypto:compute_key(dh, PeerPub, MyPriv, [dh_group14_prime(), <<2>>]);
dh_compute(19, PeerPub, MyPriv) ->
    crypto:compute_key(ecdh, PeerPub, MyPriv, secp256r1);
dh_compute(20, PeerPub, MyPriv) ->
    crypto:compute_key(ecdh, PeerPub, MyPriv, secp384r1);
dh_compute(31, PeerPub, MyPriv) ->
    crypto:compute_key(ecdh, PeerPub, MyPriv, x25519);
dh_compute(_, _, _) ->
    error(unsupported_dh_group).

%%====================================================================
%% PRF (RFC 7296 section 2.13)
%%====================================================================

-spec prf(atom(), binary(), binary()) -> binary().
prf(sha256, Key, Data) ->
    crypto:mac(hmac, sha256, Key, Data);
prf(sha384, Key, Data) ->
    crypto:mac(hmac, sha384, Key, Data);
prf(sha512, Key, Data) ->
    crypto:mac(hmac, sha512, Key, Data).

-spec prf_plus(atom(), binary(), binary(), non_neg_integer()) -> binary().
prf_plus(PRF, Key, Seed, Needed) ->
    prf_plus_loop(PRF, Key, Seed, Needed, <<>>, <<>>, 1).

prf_plus_loop(_PRF, _Key, _Seed, Needed, Acc, _Prev, _N) when byte_size(Acc) >= Needed ->
    <<Result:Needed/binary, _/binary>> = Acc,
    Result;
prf_plus_loop(PRF, Key, Seed, Needed, Acc, Prev, N) ->
    T = prf(PRF, Key, <<Prev/binary, Seed/binary, N:8>>),
    prf_plus_loop(PRF, Key, Seed, Needed, <<Acc/binary, T/binary>>, T, N + 1).

%%====================================================================
%% IKE SA key derivation (RFC 7296 section 2.14)
%%====================================================================

-spec derive_ike_keys(binary(), binary(), binary(), map()) -> map().
derive_ike_keys(SharedSecret, NonceI, NonceR, #{prf := PRF,
                                                 enc_key_len := EncKeyLen,
                                                 integ_key_len := IntegKeyLen,
                                                 prf_key_len := PRFKeyLen}) ->
    SKEYSEED = prf(PRF, <<NonceI/binary, NonceR/binary>>, SharedSecret),

    Needed = PRFKeyLen + IntegKeyLen + EncKeyLen +
             PRFKeyLen + IntegKeyLen + EncKeyLen + PRFKeyLen,

    Seed = <<NonceI/binary, NonceR/binary>>,
    KeyMat = prf_plus(PRF, SKEYSEED, Seed, Needed),

    %% SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
    <<SK_d:PRFKeyLen/binary,
      SK_ai:IntegKeyLen/binary, SK_ar:IntegKeyLen/binary,
      SK_ei:EncKeyLen/binary, SK_er:EncKeyLen/binary,
      SK_pi:PRFKeyLen/binary, SK_pr:PRFKeyLen/binary,
      _/binary>> = KeyMat,

    #{skeyseed => SKEYSEED,
      sk_d  => SK_d,
      sk_ai => SK_ai, sk_ar => SK_ar,
      sk_ei => SK_ei, sk_er => SK_er,
      sk_pi => SK_pi, sk_pr => SK_pr}.

%%====================================================================
%% Child SA key derivation (RFC 7296 section 2.17)
%%====================================================================

-spec derive_child_keys(atom(), binary(), binary(), binary(), non_neg_integer()) -> map().
derive_child_keys(PRF, SK_d, NonceI, NonceR, Needed) ->
    Seed = <<NonceI/binary, NonceR/binary>>,
    KeyMat = prf_plus(PRF, SK_d, Seed, Needed),
    #{key_material => KeyMat}.

%%====================================================================
%% SK encrypt/decrypt (RFC 7296 section 3.14)
%%====================================================================

-spec encrypt_sk(atom(), binary(), binary(), binary()) -> binary().
encrypt_sk(aes_gcm_256, Key, IV, Plaintext) ->
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        aes_256_gcm, Key, IV, Plaintext, <<>>, 16, true),
    <<IV/binary, Ciphertext/binary, Tag/binary>>;
encrypt_sk(aes_cbc_256, Key, IV, Plaintext) ->
    PadLen = 16 - (byte_size(Plaintext) + 1) rem 16,
    Padding = binary:copy(<<PadLen:8>>, PadLen),
    Padded = <<Plaintext/binary, Padding/binary, PadLen:8>>,
    Ciphertext = crypto:crypto_one_time(aes_256_cbc, Key, IV, Padded, true),
    <<IV/binary, Ciphertext/binary>>.

-spec decrypt_sk(atom(), binary(), binary(), binary()) -> binary() | {error, term()}.
decrypt_sk(aes_gcm_256, Key, <<IV:12/binary, Rest/binary>>, _AAD) ->
    TagLen = 16,
    CTLen = byte_size(Rest) - TagLen,
    <<Ciphertext:CTLen/binary, Tag:TagLen/binary>> = Rest,
    case crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Ciphertext, <<>>, Tag, false) of
        error -> {error, decrypt_failed};
        Plain -> Plain
    end;
decrypt_sk(aes_cbc_256, Key, <<IV:16/binary, Ciphertext/binary>>, _AAD) ->
    Padded = crypto:crypto_one_time(aes_256_cbc, Key, IV, Ciphertext, false),
    PadLen = binary:last(Padded),
    DataLen = byte_size(Padded) - PadLen - 1,
    <<Data:DataLen/binary, _/binary>> = Padded,
    Data.

%%====================================================================
%% EAP-AKA' key derivation (RFC 5448 section 3.3)
%%====================================================================

-spec derive_aka_prime_keys(binary(), binary(), binary(), binary()) ->
    {binary(), binary()}.
derive_aka_prime_keys(CK, IK, ServingNetworkName, SQNxorAK) ->
    %% CK' and IK' derivation per RFC 5448 section 3.3
    %% FC = 0x20, serving network name, length, SQN xor AK, length
    FC = <<16#20>>,
    SNLen = byte_size(ServingNetworkName),
    SQNLen = byte_size(SQNxorAK),
    S = <<FC/binary,
          ServingNetworkName/binary, SNLen:16,
          SQNxorAK/binary, SQNLen:16>>,
    Key = <<CK/binary, IK/binary>>,
    Derived = crypto:mac(hmac, sha256, Key, S),
    %% First 16 bytes = CK', next 16 bytes = IK'
    <<CKPrime:16/binary, IKPrime:16/binary>> = Derived,
    {CKPrime, IKPrime}.

%%====================================================================
%% X.509 certificate loading (PEM → DER)
%%====================================================================

-spec load_certificate(string()) -> {ok, binary()} | {error, term()}.
load_certificate(PemFile) ->
    case file:read_file(PemFile) of
        {ok, PemBin} ->
            case public_key:pem_decode(PemBin) of
                [{'Certificate', DerCert, not_encrypted} | _] ->
                    {ok, DerCert};
                [] ->
                    {error, no_certificate_in_pem};
                _ ->
                    {error, unexpected_pem_entry}
            end;
        {error, Reason} ->
            {error, {read_file, Reason}}
    end.

-spec load_private_key(string()) -> {ok, term()} | {error, term()}.
load_private_key(PemFile) ->
    case file:read_file(PemFile) of
        {ok, PemBin} ->
            case public_key:pem_decode(PemBin) of
                [{KeyType, DerKey, not_encrypted} | _]
                  when KeyType =:= 'RSAPrivateKey';
                       KeyType =:= 'ECPrivateKey';
                       KeyType =:= 'PrivateKeyInfo' ->
                    Key = public_key:pem_entry_decode({KeyType, DerKey, not_encrypted}),
                    {ok, Key};
                [] ->
                    {error, no_key_in_pem};
                _ ->
                    {error, unexpected_pem_entry}
            end;
        {error, Reason} ->
            {error, {read_file, Reason}}
    end.

%%====================================================================
%% IKEv2 AUTH signature (RFC 7296 §2.15)
%%
%% SignedOctets = RealIKE_SA_INIT_response | NonceI | prf(SK_pr, IDr')
%% where IDr' is the ID payload body (type + reserved + identity data).
%%====================================================================

-spec sign_auth_data(atom(), binary(), binary(), binary(), term()) ->
    {non_neg_integer(), binary()}.
sign_auth_data(PRF, IkeSaInitResponseBytes, NonceI,
               #{sk_pr := SK_pr, id_payload := IDrPayload}, PrivateKey) ->
    MacOverId = prf(PRF, SK_pr, IDrPayload),
    SignedOctets = <<IkeSaInitResponseBytes/binary, NonceI/binary, MacOverId/binary>>,
    Signature = do_sign(PrivateKey, SignedOctets),
    {auth_method(PrivateKey), Signature}.

do_sign(#'RSAPrivateKey'{} = Key, Data) ->
    public_key:sign(Data, sha256, Key, [{rsa_padding, rsa_pkcs1_pss_padding},
                                         {rsa_pss_saltlen, 32}]);
do_sign(#'ECPrivateKey'{parameters = {namedCurve, Curve}} = Key, Data)
  when Curve =:= ?'secp256r1' ->
    public_key:sign(Data, sha256, Key);
do_sign(#'ECPrivateKey'{parameters = {namedCurve, Curve}} = Key, Data)
  when Curve =:= ?'secp384r1' ->
    public_key:sign(Data, sha384, Key);
do_sign(#'ECPrivateKey'{} = Key, Data) ->
    public_key:sign(Data, sha256, Key).

%% IKEv2 auth method byte per RFC 7296 §3.8
-spec auth_method(term()) -> non_neg_integer().
auth_method(#'RSAPrivateKey'{}) -> 1;     %% RSA Digital Signature
auth_method(#'ECPrivateKey'{parameters = {namedCurve, Curve}})
  when Curve =:= ?'secp256r1' -> 9;       %% ECDSA with SHA-256 on P-256
auth_method(#'ECPrivateKey'{parameters = {namedCurve, Curve}})
  when Curve =:= ?'secp384r1' -> 10;      %% ECDSA with SHA-384 on P-384
auth_method(#'ECPrivateKey'{}) -> 9;       %% default ECDSA
auth_method(_) -> 1.

%%====================================================================
%% Internal
%%====================================================================

dh_group14_prime() ->
    %% RFC 3526 group 14 (2048-bit MODP)
    <<16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF:2048>>.
