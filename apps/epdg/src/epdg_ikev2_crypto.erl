%%%-------------------------------------------------------------------
%%% @doc IKEv2 cryptographic operations.
%%% Key derivation, PRF, encryption, integrity, DH, EAP-AKA' support.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_crypto).

-include_lib("public_key/include/public_key.hrl").

-export([generate_nonce/0, generate_spi/0,
         dh_generate/1, dh_compute/3, dh_pub_len/1,
         prf/3, prf_plus/4,
         derive_ike_keys/4,
         derive_child_keys/5,
         encrypt_sk/4, decrypt_sk/4,
         encode_encrypted_message/5, decode_encrypted_message/4,
         derive_aka_prime_keys/4,
         load_certificate/1, load_private_key/1,
         sign_auth_data/5, auth_method/1,
         build_psk_auth/5,
         build_initiator_psk_auth/6,
         build_responder_psk_auth/6,
         verify_initiator_psk_auth/7]).

-ifdef(TEST).
%% MODP prime accessors for the EUnit sanity checks (byte length and the
%% FFFFFFFF FFFFFFFF endpoints all RFC 3526 primes share).
-export([dh_group14_prime/0, dh_group15_prime/0, dh_group16_prime/0]).
-endif.

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
    %% DH Group 14 (2048-bit MODP, RFC 3526 §3)
    modp_generate(dh_group14_prime());
dh_generate(15) ->
    %% DH Group 15 (3072-bit MODP, RFC 3526 §4)
    modp_generate(dh_group15_prime());
dh_generate(16) ->
    %% DH Group 16 (4096-bit MODP, RFC 3526 §5)
    modp_generate(dh_group16_prime());
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
    modp_compute(dh_group14_prime(), PeerPub, MyPriv);
dh_compute(15, PeerPub, MyPriv) ->
    modp_compute(dh_group15_prime(), PeerPub, MyPriv);
dh_compute(16, PeerPub, MyPriv) ->
    modp_compute(dh_group16_prime(), PeerPub, MyPriv);
dh_compute(19, PeerPub, MyPriv) ->
    crypto:compute_key(ecdh, PeerPub, MyPriv, secp256r1);
dh_compute(20, PeerPub, MyPriv) ->
    crypto:compute_key(ecdh, PeerPub, MyPriv, secp384r1);
dh_compute(31, PeerPub, MyPriv) ->
    crypto:compute_key(ecdh, PeerPub, MyPriv, x25519);
dh_compute(_, _, _) ->
    error(unsupported_dh_group).

%% MODP groups use generator 2. OTP's crypto returns unsigned big-endian
%% integers with leading zero bytes stripped, but RFC 7296 requires both
%% the KE public value (§3.4) and the Diffie-Hellman shared secret used
%% for SKEYSEED (§2.14) to be zero-padded to the length of the modulus —
%% without the padding roughly 1 in 256 handshakes emits a short KE or
%% derives a SKEYSEED the peer cannot reproduce.
modp_generate(Prime) ->
    {Pub, Priv} = crypto:generate_key(dh, [Prime, <<2>>]),
    {pad_to(Pub, byte_size(Prime)), Priv}.

modp_compute(Prime, PeerPub, MyPriv) ->
    Secret = crypto:compute_key(dh, PeerPub, MyPriv, [Prime, <<2>>]),
    pad_to(Secret, byte_size(Prime)).

pad_to(Bin, Len) when byte_size(Bin) >= Len -> Bin;
pad_to(Bin, Len) -> <<0:((Len - byte_size(Bin)) * 8), Bin/binary>>.

%% Expected KE public-value length per DH group: MODP values are exactly
%% the modulus length (RFC 7296 §3.4), X25519 is 32 bytes (RFC 8031).
%% ECP groups 19/20 return `any' — the current implementation exchanges
%% OTP's 0x04-prefixed point encoding, so their on-wire length is not
%% pinned here.
-spec dh_pub_len(non_neg_integer()) -> pos_integer() | any.
dh_pub_len(14) -> 256;
dh_pub_len(15) -> 384;
dh_pub_len(16) -> 512;
dh_pub_len(31) -> 32;
dh_pub_len(_)  -> any.

%%====================================================================
%% PRF (RFC 7296 section 2.13)
%%====================================================================

-spec prf(atom(), binary(), binary()) -> binary().
prf(sha, Key, Data) ->
    crypto:mac(hmac, sha, Key, Data);
prf(sha256, Key, Data) ->
    crypto:mac(hmac, sha256, Key, Data);
prf(sha384, Key, Data) ->
    crypto:mac(hmac, sha384, Key, Data);
prf(sha512, Key, Data) ->
    crypto:mac(hmac, sha512, Key, Data);
prf(aes128_xcbc, Key, Data) ->
    %% AES-XCBC-PRF-128 (RFC 4434): AES-XCBC-MAC without truncation,
    %% with the key first brought to exactly 128 bits.
    aes_xcbc_mac(xcbc_prf_key(Key), Data).

%%====================================================================
%% AES-XCBC-MAC (RFC 3566 §4)
%%
%% K1/K2/K3 are derived by encrypting the constants 0x01…/0x02…/0x03…
%% with the 128-bit key K. The message is CBC-MACed under K1; the last
%% block is additionally XORed with K2 when it is a full 128-bit block,
%% or 10*-padded and XORed with K3 otherwise (an empty message is one
%% padded block). AUTH_AES_XCBC_96 truncates the result to 96 bits;
%% the PRF uses the full 128 bits.
%%====================================================================

-spec aes_xcbc_mac(binary(), binary()) -> binary().
aes_xcbc_mac(Key, Message) when byte_size(Key) =:= 16 ->
    K1 = aes_ecb(Key, binary:copy(<<16#01>>, 16)),
    K2 = aes_ecb(Key, binary:copy(<<16#02>>, 16)),
    K3 = aes_ecb(Key, binary:copy(<<16#03>>, 16)),
    xcbc_mac_blocks(Message, K1, K2, K3, <<0:128>>).

xcbc_mac_blocks(<<Block:16/binary>>, K1, K2, _K3, E) ->
    %% Final full block: XOR with E[n-1] and K2, encrypt with K1.
    aes_ecb(K1, crypto:exor(crypto:exor(Block, E), K2));
xcbc_mac_blocks(<<Block:16/binary, Rest/binary>>, K1, K2, K3, E) ->
    xcbc_mac_blocks(Rest, K1, K2, K3, aes_ecb(K1, crypto:exor(Block, E)));
xcbc_mac_blocks(Last, K1, _K2, K3, E) when byte_size(Last) < 16 ->
    %% Final partial (or empty) block: pad with a single "1" bit then
    %% "0" bits, XOR with E[n-1] and K3, encrypt with K1.
    PadZeros = 15 - byte_size(Last),
    Padded = <<Last/binary, 16#80, 0:(PadZeros * 8)>>,
    aes_ecb(K1, crypto:exor(crypto:exor(Padded, E), K3)).

aes_ecb(Key, Block) ->
    crypto:crypto_one_time(aes_128_ecb, Key, Block, true).

%% RFC 4434 §2: bring the PRF key to exactly 128 bits — use as-is if
%% 16 bytes, right-pad with zeros if shorter, or reduce a longer key by
%% running AES-XCBC-PRF-128 over it with an all-zero 128-bit key.
xcbc_prf_key(Key) when byte_size(Key) =:= 16 -> Key;
xcbc_prf_key(Key) when byte_size(Key) < 16 ->
    <<Key/binary, 0:((16 - byte_size(Key)) * 8)>>;
xcbc_prf_key(Key) ->
    aes_xcbc_mac(<<0:128>>, Key).

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
                                                 prf_key_len := PRFKeyLen,
                                                 spi_i := SPIiBin,
                                                 spi_r := SPIrBin}) ->
    SKEYSEED = prf(PRF, skeyseed_key(PRF, NonceI, NonceR), SharedSecret),

    Needed = PRFKeyLen + IntegKeyLen + EncKeyLen +
             PRFKeyLen + IntegKeyLen + EncKeyLen + PRFKeyLen,

    %% RFC 7296 §2.14: prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
    Seed = <<NonceI/binary, NonceR/binary, SPIiBin/binary, SPIrBin/binary>>,
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

%% RFC 7296 §2.14: when the negotiated PRF takes a fixed-length key
%% (PRF_AES128_XCBC per RFC 4434 key-derivation semantics), half the
%% SKEYSEED key bits must come from Ni and half from Nr, taking the
%% first bits of each. Variable-key HMAC PRFs use the full Ni | Nr.
skeyseed_key(aes128_xcbc, NonceI, NonceR) ->
    <<NI:8/binary, _/binary>> = NonceI,
    <<NR:8/binary, _/binary>> = NonceR,
    <<NI/binary, NR/binary>>;
skeyseed_key(_PRF, NonceI, NonceR) ->
    <<NonceI/binary, NonceR/binary>>.

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
encrypt_sk(Alg, Key, IV, Plaintext)
  when Alg =:= aes_gcm_128; Alg =:= aes_gcm_192; Alg =:= aes_gcm_256 ->
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        aes_gcm_atom(Alg), Key, IV, Plaintext, <<>>, 16, true),
    <<IV/binary, Ciphertext/binary, Tag/binary>>;
encrypt_sk(Alg, Key, IV, Plaintext)
  when Alg =:= aes_cbc_128; Alg =:= aes_cbc_192; Alg =:= aes_cbc_256 ->
    PadLen = 16 - (byte_size(Plaintext) + 1) rem 16,
    Padding = binary:copy(<<PadLen:8>>, PadLen),
    Padded = <<Plaintext/binary, Padding/binary, PadLen:8>>,
    Ciphertext = crypto:crypto_one_time(aes_cbc_atom(Alg), Key, IV, Padded, true),
    <<IV/binary, Ciphertext/binary>>.

-spec decrypt_sk(atom(), binary(), binary(), binary()) -> binary() | {error, term()}.
decrypt_sk(Alg, Key, <<IV:12/binary, Rest/binary>>, _AAD)
  when Alg =:= aes_gcm_128; Alg =:= aes_gcm_192; Alg =:= aes_gcm_256 ->
    TagLen = 16,
    CTLen = byte_size(Rest) - TagLen,
    <<Ciphertext:CTLen/binary, Tag:TagLen/binary>> = Rest,
    case crypto:crypto_one_time_aead(aes_gcm_atom(Alg), Key, IV, Ciphertext,
                                     <<>>, Tag, false) of
        error -> {error, decrypt_failed};
        Plain -> Plain
    end;
decrypt_sk(Alg, Key, <<IV:16/binary, Ciphertext/binary>>, _AAD)
  when Alg =:= aes_cbc_128; Alg =:= aes_cbc_192; Alg =:= aes_cbc_256 ->
    Padded = crypto:crypto_one_time(aes_cbc_atom(Alg), Key, IV, Ciphertext, false),
    PadLen = binary:last(Padded),
    DataLen = byte_size(Padded) - PadLen - 1,
    <<Data:DataLen/binary, _/binary>> = Padded,
    Data.

%%====================================================================
%% Encrypted IKE message encode/decode (RFC 7296 §3.14, RFC 5282)
%%
%% These helpers operate on the full IKE message (including header) and
%% take care of IKEv2-specific framing:
%%   - SK payload header (4 bytes) immediately after IKE header
%%   - IV (8 bytes for AEAD per RFC 5282 §3; 16 bytes for AES-CBC)
%%   - Ciphertext over (inner payloads | Padding | Pad Length)
%%   - ICV: AEAD tag (AES-GCM: 16 bytes) OR HMAC trailer for CBC+INTEG
%%   - AEAD nonce = salt(4) | IV(8); salt comes from SK_e{i,r}
%%   - AEAD AAD = partial IKE header + SK payload header (32 bytes)
%%
%% AES-CBC + HMAC-SHA-2 (legacy suites — observed in the field on Samsung
%% VoWiFi clients proposing AES-CBC-256 + HMAC-SHA-256-128 / HMAC-SHA-512-256
%% + MODP-2048/3072) is handled by the `is_aead=false` clauses below. The
%% HMAC is computed over `IKE_Hdr | SK_Hdr | IV | Ciphertext` (RFC 7296
%% §3.14), truncated to the per-algorithm output length from RFC 4868
%% (HMAC-SHA-256-128 → 16 B, HMAC-SHA-384-192 → 24 B, HMAC-SHA-512-256
%% → 32 B).
%%====================================================================

-define(IKE_HDR_LEN, 28).
-define(SK_HDR_LEN, 4).
-define(PAYLOAD_SK, 46).

%% Encode a full IKE message with an SK payload chain.
%%
%% Params:
%%   SuiteParams - map from epdg_ikev2_codec:keys_params_for_suite/1
%%   Keys        - map from derive_ike_keys/4
%%   Direction   - responder | initiator (determines SK_e{i,r}/SK_a{i,r})
%%   HeaderIn    - map with initiator_spi, responder_spi, exchange_type_raw,
%%                 flags, message_id, next_payload_first_inner (atom or raw int)
%%   InnerChain  - [{AtomType, Bin}, ...] list consumed by codec encode_payloads
-spec encode_encrypted_message(map(), map(), responder | initiator,
                                map(), [{atom(), binary()}]) ->
    {ok, binary()} | {error, term()}.
encode_encrypted_message(#{is_aead := true, enc_alg := EncAlg,
                           enc_base_key_len := EncKeyLen, salt_len := SaltLen},
                         Keys, Direction,
                         #{initiator_spi := ISPI, responder_spi := RSPI,
                           exchange_type_raw := ExType, flags := Flags,
                           message_id := MsgId}, InnerChain) ->
    {SK_e_full, _SK_a} = keys_for_direction(Direction, Keys),
    <<EncKey:EncKeyLen/binary, Salt:SaltLen/binary>> = SK_e_full,

    {FirstInnerType, InnerBin} = epdg_ikev2_codec:encode_payloads(InnerChain),

    %% Pad-only trailer per RFC 7296 §3.14: last byte = pad length.
    %% For AEAD block alignment is not required; use a single pad-length
    %% byte of 0x00 (zero-length padding).
    Plaintext = <<InnerBin/binary, 0:8>>,
    IV = crypto:strong_rand_bytes(8),
    Nonce = <<Salt/binary, IV/binary>>,

    CtLen    = byte_size(Plaintext),
    SKBodyLen = ?SK_HDR_LEN + byte_size(IV) + CtLen + 16,
    TotalLen  = ?IKE_HDR_LEN + SKBodyLen,

    IkeHdr = <<ISPI:64, RSPI:64, ?PAYLOAD_SK:8, 2:4, 0:4,
               ExType:8, Flags:8, MsgId:32, TotalLen:32>>,
    %% SK payload header: next_payload = first inner payload type, critical=0,
    %% reserved=0, length = 4+IV+CT+ICV (i.e. full SK payload incl header).
    SKPLen  = SKBodyLen,
    SKHdr   = <<FirstInnerType:8, 0:8, SKPLen:16>>,
    AAD     = <<IkeHdr/binary, SKHdr/binary>>,

    {Ciphertext, Tag} =
        crypto:crypto_one_time_aead(aes_gcm_atom(EncAlg), EncKey, Nonce,
                                    Plaintext, AAD, 16, true),

    {ok, <<IkeHdr/binary, SKHdr/binary, IV/binary, Ciphertext/binary, Tag/binary>>};
encode_encrypted_message(#{is_aead := false, enc_alg := EncAlg,
                           enc_base_key_len := EncKeyLen,
                           integ_alg := IntegAlg, integ_key_len := IntegKeyLen},
                         Keys, Direction,
                         #{initiator_spi := ISPI, responder_spi := RSPI,
                           exchange_type_raw := ExType, flags := Flags,
                           message_id := MsgId}, InnerChain)
  when EncAlg =:= aes_cbc_256 orelse EncAlg =:= aes_cbc_192
       orelse EncAlg =:= aes_cbc_128 ->
    {SK_e, SK_a} = keys_for_direction(Direction, Keys),
    <<EncKey:EncKeyLen/binary, _/binary>> = SK_e,
    <<IntegKey:IntegKeyLen/binary, _/binary>> = SK_a,
    {FirstInnerType, InnerBin} = epdg_ikev2_codec:encode_payloads(InnerChain),
    %% Pad so (InnerBin | Padding | Pad-Length-byte) is a multiple of 16.
    InnerLen = byte_size(InnerBin),
    PadBytes = (16 - ((InnerLen + 1) rem 16)) rem 16,
    Padding = crypto:strong_rand_bytes(PadBytes),
    Plaintext = <<InnerBin/binary, Padding/binary, PadBytes:8>>,
    IV = crypto:strong_rand_bytes(16),
    Ciphertext = crypto:crypto_one_time(
        aes_cbc_atom(EncAlg), EncKey, IV, Plaintext, true),
    IcvLen = icv_len(IntegAlg),
    SKBodyLen = ?SK_HDR_LEN + 16 + byte_size(Ciphertext) + IcvLen,
    TotalLen  = ?IKE_HDR_LEN + SKBodyLen,
    IkeHdr = <<ISPI:64, RSPI:64, ?PAYLOAD_SK:8, 2:4, 0:4,
               ExType:8, Flags:8, MsgId:32, TotalLen:32>>,
    SKHdr = <<FirstInnerType:8, 0:8, SKBodyLen:16>>,
    MacIn = <<IkeHdr/binary, SKHdr/binary, IV/binary, Ciphertext/binary>>,
    MacFull = integ_mac(IntegAlg, IntegKey, MacIn),
    ICV = binary:part(MacFull, 0, IcvLen),
    {ok, <<IkeHdr/binary, SKHdr/binary, IV/binary, Ciphertext/binary, ICV/binary>>};
encode_encrypted_message(_, _, _, _, _) ->
    {error, unsupported_crypto_suite}.

%% Decode + decrypt an incoming SK-protected IKE message. Returns the
%% decoded inner payload list plus the message header (for convenience).
-spec decode_encrypted_message(map(), map(), responder | initiator, binary()) ->
    {ok, #{header := map(), payloads := [map()]}} | {error, term()}.
decode_encrypted_message(#{is_aead := true, enc_alg := EncAlg,
                           enc_base_key_len := EncKeyLen, salt_len := SaltLen},
                         Keys, PeerDirection, RawMessage)
  when byte_size(RawMessage) > (?IKE_HDR_LEN + ?SK_HDR_LEN + 8 + 16) ->
    {SK_e_full, _SK_a} = keys_for_direction(PeerDirection, Keys),
    <<EncKey:EncKeyLen/binary, Salt:SaltLen/binary>> = SK_e_full,

    case epdg_ikev2_codec:decode_header(RawMessage) of
        {ok, #{next_payload := ?PAYLOAD_SK, length := _TotalLen,
               payload_data := PayloadBin} = Header} ->
            case PayloadBin of
                <<InnerFirstType:8, _Crit:1, _Res:7, SKPLen:16, SKBody/binary>>
                  when byte_size(SKBody) >= (SKPLen - ?SK_HDR_LEN) ->
                    InnerBodyLen = SKPLen - ?SK_HDR_LEN,
                    <<SKBodyBin:InnerBodyLen/binary, _Trailing/binary>> = SKBody,
                    case SKBodyBin of
                        <<IV:8/binary, Rest/binary>>
                          when byte_size(Rest) >= 16 ->
                            CtLen = byte_size(Rest) - 16,
                            <<Ciphertext:CtLen/binary, Tag:16/binary>> = Rest,
                            Nonce = <<Salt/binary, IV/binary>>,
                            IkeHdrBytes = binary:part(RawMessage, 0, ?IKE_HDR_LEN),
                            SKHdrBytes  =
                                <<InnerFirstType:8, 0:8, SKPLen:16>>,
                            AAD = <<IkeHdrBytes/binary, SKHdrBytes/binary>>,
                            case crypto:crypto_one_time_aead(aes_gcm_atom(EncAlg),
                                                              EncKey,
                                                              Nonce, Ciphertext,
                                                              AAD, Tag, false) of
                                error ->
                                    {error, icv_check_failed};
                                Plaintext when is_binary(Plaintext) ->
                                    finalize_decrypted(Header, InnerFirstType, Plaintext)
                            end;
                        _ -> {error, sk_payload_truncated}
                    end;
                _ -> {error, sk_payload_malformed}
            end;
        {ok, #{next_payload := Other}} ->
            {error, {not_encrypted, Other}};
        {error, Reason} ->
            {error, Reason}
    end;
decode_encrypted_message(#{is_aead := false, enc_alg := EncAlg,
                           enc_base_key_len := EncKeyLen,
                           integ_alg := IntegAlg, integ_key_len := IntegKeyLen},
                         Keys, PeerDirection, RawMessage)
  when EncAlg =:= aes_cbc_256 orelse EncAlg =:= aes_cbc_192
       orelse EncAlg =:= aes_cbc_128 ->
    {SK_e, SK_a} = keys_for_direction(PeerDirection, Keys),
    <<EncKey:EncKeyLen/binary, _/binary>> = SK_e,
    <<IntegKey:IntegKeyLen/binary, _/binary>> = SK_a,
    IcvLen = icv_len(IntegAlg),
    case epdg_ikev2_codec:decode_header(RawMessage) of
        {ok, #{next_payload := ?PAYLOAD_SK,
               payload_data := PayloadBin} = Header} ->
            case PayloadBin of
                <<InnerFirstType:8, _Crit:1, _Res:7, SKPLen:16, SKBody/binary>>
                  when byte_size(SKBody) >= (SKPLen - ?SK_HDR_LEN) ->
                    InnerBodyLen = SKPLen - ?SK_HDR_LEN,
                    <<SKBodyBin:InnerBodyLen/binary, _/binary>> = SKBody,
                    case SKBodyBin of
                        <<IV:16/binary, Rest/binary>>
                          when byte_size(Rest) >= IcvLen ->
                            CtLen = byte_size(Rest) - IcvLen,
                            case CtLen rem 16 of
                                0 ->
                                    <<Ciphertext:CtLen/binary, ICV:IcvLen/binary>> = Rest,
                                    %% Use raw on-wire bytes for MAC input, exactly
                                    %% RawMessage[0 .. end-ICV_len] per RFC 7296 §3.14.
                                    MacInLen = byte_size(RawMessage) - IcvLen,
                                    MacIn = binary:part(RawMessage, 0, MacInLen),
                                    MacFull = integ_mac(IntegAlg, IntegKey, MacIn),
                                    Expected = binary:part(MacFull, 0, IcvLen),
                                    case Expected =:= ICV of
                                        false -> {error, icv_check_failed};
                                        true ->
                                            Plaintext = crypto:crypto_one_time(
                                                aes_cbc_atom(EncAlg), EncKey, IV,
                                                Ciphertext, false),
                                            finalize_decrypted(Header, InnerFirstType,
                                                               Plaintext)
                                    end;
                                _ -> {error, ciphertext_not_block_aligned}
                            end;
                        _ -> {error, sk_payload_truncated}
                    end;
                _ -> {error, sk_payload_malformed}
            end;
        {ok, #{next_payload := Other}} ->
            {error, {not_encrypted, Other}};
        {error, Reason} -> {error, Reason}
    end;
decode_encrypted_message(_, _, _, _) ->
    {error, unsupported_or_short_message}.

aes_cbc_atom(aes_cbc_128) -> aes_128_cbc;
aes_cbc_atom(aes_cbc_192) -> aes_192_cbc;
aes_cbc_atom(aes_cbc_256) -> aes_256_cbc.

aes_gcm_atom(aes_gcm_128) -> aes_128_gcm;
aes_gcm_atom(aes_gcm_192) -> aes_192_gcm;
aes_gcm_atom(aes_gcm_256) -> aes_256_gcm.

%% Full-length MAC for an SK-payload integrity algorithm (truncation to
%% icv_len/1 happens at the call sites).
integ_mac(aes_xcbc_96, Key, Data) -> aes_xcbc_mac(Key, Data);
integ_mac(Alg, Key, Data) -> crypto:mac(hmac, hmac_hash(Alg), Key, Data).

hmac_hash(hmac_sha1_96)    -> sha;
hmac_hash(hmac_sha256_128) -> sha256;
hmac_hash(hmac_sha384_192) -> sha384;
hmac_hash(hmac_sha512_256) -> sha512.

%% RFC 4868: truncated output length for HMAC-SHA-2-based integrity algos.
%% RFC 2404: HMAC-SHA-1-96 truncates to 96 bits (12 bytes).
%% RFC 3566: AUTH_AES_XCBC_96 truncates to 96 bits (12 bytes).
icv_len(hmac_sha1_96)    -> 12;
icv_len(aes_xcbc_96)     -> 12;
icv_len(hmac_sha256_128) -> 16;
icv_len(hmac_sha384_192) -> 24;
icv_len(hmac_sha512_256) -> 32.

finalize_decrypted(Header, InnerFirstType, Plaintext) ->
    %% Strip pad length byte + padding octets (RFC 7296 §3.14).
    case Plaintext of
        <<>> -> {error, empty_plaintext};
        _ ->
            PadLen = binary:last(Plaintext),
            Total  = byte_size(Plaintext),
            case Total > PadLen of
                true ->
                    InnerLen = Total - PadLen - 1,
                    <<InnerBin:InnerLen/binary, _/binary>> = Plaintext,
                    case epdg_ikev2_codec:decode_payloads(InnerFirstType, InnerBin) of
                        {ok, Payloads} ->
                            {ok, #{header => Header, payloads => Payloads,
                                   first_inner => InnerFirstType,
                                   plaintext => InnerBin}};
                        {error, R} -> {error, {inner_decode, R}}
                    end;
                false ->
                    {error, invalid_padding}
            end
    end.

%% Return the encryption+integrity keys to use for each direction.
%%   Direction=responder → we are encrypting an OUTGOING message (use SK_er/SK_ar)
%%   Direction=initiator → we are decrypting an INCOMING initiator message
%%                          (use SK_ei/SK_ai)
keys_for_direction(responder, #{sk_er := Er, sk_ar := Ar}) -> {Er, Ar};
keys_for_direction(initiator, #{sk_ei := Ei, sk_ai := Ai}) -> {Ei, Ai}.

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
%% Shared-secret MIC AUTH (RFC 7296 §2.15) / EAP-MSK AUTH (RFC 5998 §2.1)
%%
%% AUTH = prf(prf(SharedSecret, "Key Pad for IKEv2"), SignedOctets)
%%
%% For EAP methods that export an MSK, SharedSecret is the MSK (64 bytes
%% for EAP-AKA/AKA'); for pre-shared-key auth it is the PSK.
%%
%% SignedOctets per §2.15 depend on direction:
%%   Initiator: IKE_SA_INIT_request_bytes | NonceR | prf(SK_pi, IDi')
%%   Responder: IKE_SA_INIT_response_bytes | NonceI | prf(SK_pr, IDr')
%%
%% IDi'/IDr' are the ID payload body octets (IDType | 3-byte reserved |
%% identity data) — i.e. the full decoded payload body excluding the
%% 4-byte generic payload header.
%%====================================================================

-define(PSK_AUTH_KEY_PAD, <<"Key Pad for IKEv2">>).

-spec build_psk_auth(atom(), binary(), binary(), binary(), binary()) -> binary().
build_psk_auth(PRF, SharedSecret, RealMessage, NonceOther, MacOverId)
  when is_binary(SharedSecret), is_binary(RealMessage),
       is_binary(NonceOther), is_binary(MacOverId) ->
    Inner = prf(PRF, SharedSecret, ?PSK_AUTH_KEY_PAD),
    SignedOctets = <<RealMessage/binary, NonceOther/binary, MacOverId/binary>>,
    prf(PRF, Inner, SignedOctets).

%% Compute the AUTH payload that an IKEv2 initiator (UE) would produce,
%% given the MSK, its original IKE_SA_INIT request bytes, the responder's
%% nonce, and the SK_pi half of the IKE SA keys.
-spec build_initiator_psk_auth(atom(), binary(), binary(), binary(),
                                binary(), binary()) -> binary().
build_initiator_psk_auth(PRF, MSK, IkeSaInitReqBytes, NonceR,
                         SK_pi, IDiBody) ->
    MacOverId = prf(PRF, SK_pi, IDiBody),
    build_psk_auth(PRF, MSK, IkeSaInitReqBytes, NonceR, MacOverId).

%% Compute the AUTH payload that the IKEv2 responder (ePDG) emits after
%% EAP-Success, as defined by RFC 5998 §2.1 (MSK-based variant of §2.15).
-spec build_responder_psk_auth(atom(), binary(), binary(), binary(),
                                binary(), binary()) -> binary().
build_responder_psk_auth(PRF, MSK, IkeSaInitRespBytes, NonceI,
                         SK_pr, IDrBody) ->
    MacOverId = prf(PRF, SK_pr, IDrBody),
    build_psk_auth(PRF, MSK, IkeSaInitRespBytes, NonceI, MacOverId).

%% Verify the UE's AUTH payload against the MSK we received from the AAA
%% (TS 33.402 §7.2.2 step 14). Returns true on match, false otherwise.
%% Uses a constant-time comparison so we don't leak timing info.
-spec verify_initiator_psk_auth(atom(), binary(), binary(), binary(),
                                 binary(), binary(), binary()) -> boolean().
verify_initiator_psk_auth(PRF, MSK, IkeSaInitReqBytes, NonceR, SK_pi,
                          IDiBody, ReceivedAuth)
  when is_binary(ReceivedAuth) ->
    Expected = build_initiator_psk_auth(PRF, MSK, IkeSaInitReqBytes,
                                         NonceR, SK_pi, IDiBody),
    constant_time_equal(Expected, ReceivedAuth).

constant_time_equal(A, B) when is_binary(A), is_binary(B),
                                byte_size(A) =:= byte_size(B) ->
    constant_time_equal_bytes(A, B, 0);
constant_time_equal(_, _) ->
    false.

constant_time_equal_bytes(<<>>, <<>>, Acc) ->
    Acc =:= 0;
constant_time_equal_bytes(<<A:8, RestA/binary>>, <<B:8, RestB/binary>>, Acc) ->
    constant_time_equal_bytes(RestA, RestB, Acc bor (A bxor B)).

%%====================================================================
%% Internal
%%====================================================================

dh_group14_prime() ->
    %% RFC 3526 group 14 (2048-bit MODP)
    <<16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF:2048>>.

dh_group15_prime() ->
    %% RFC 3526 §4 group 15 (3072-bit MODP), copied verbatim
    <<16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF:3072>>.

dh_group16_prime() ->
    %% RFC 3526 §5 group 16 (4096-bit MODP), copied verbatim
    <<16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF:4096>>.
