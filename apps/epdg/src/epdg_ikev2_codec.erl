%%%-------------------------------------------------------------------
%%% @doc IKEv2 binary codec (RFC 7296).
%%% Encodes and decodes IKEv2 headers, payloads, and transforms.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_codec).

-export([decode_header/1, encode_header/1,
         decode_payloads/2, encode_payloads/1,
         decode_sa_payload/1, decode_transforms/1,
         select_proposal/1, encode_sa_response/1,
         decode_ke_payload/1, encode_ke_payload/2,
         decode_nonce_payload/1, encode_nonce_payload/1,
         encode_notify_payload/4,
         encode_redirect_notify_data/3, decode_redirect_notify_data/1,
         parse_redirect_target/1,
         encode_delete_ike_payload/0,
         encode_cert_payload/1, encode_auth_payload/2,
         encode_certreq_payload/1,
         encode_id_payload/2, decode_id_payload/1,
         encode_eap_payload/1, decode_eap_payload/1,
         encode_eap_request_identity/1,
         keys_params_for_suite/1,
         find_payload/2, payload_type_raw/1,
         decode_auth_payload/1,
         decode_cp_payload/1, encode_cp_payload/2,
         decode_ts_payload/1, encode_ts_payload/1,
         decode_child_sa_payload/1, encode_child_sa_response/1,
         child_enc_key_len/1, child_integ_key_len/1]).

%% Transform types (RFC 7296 §3.3.2)
-define(TRANS_ENCR,  1).
-define(TRANS_PRF,   2).
-define(TRANS_INTEG, 3).
-define(TRANS_DH,    4).
-define(TRANS_ESN,   5).

%% Transform attribute: Key Length (TV-encoded, AF=1, type=14)
-define(ATTR_KEY_LENGTH, 14).

%% Notify message types (RFC 7296 §3.10.1)
-define(NOTIFY_INVALID_KE_PAYLOAD,   17).
-define(NOTIFY_NO_PROPOSAL_CHOSEN,   14).

%% Exchange types (RFC 7296 section 3.1)
-define(IKE_SA_INIT,      34).
-define(IKE_AUTH,          35).
-define(CREATE_CHILD_SA,   36).
-define(INFORMATIONAL,     37).

%% Payload types (RFC 7296 section 3.2)
-define(PL_NONE,  0).
-define(PL_SA,    33).
-define(PL_KE,    34).
-define(PL_IDI,   35).
-define(PL_IDR,   36).
-define(PL_CERT,    37).
-define(PL_CERTREQ, 38).
-define(PL_AUTH,    39).
-define(PL_NONCE, 40).
-define(PL_NOTIFY,41).
-define(PL_DELETE,42).
-define(PL_TSI,   44).
-define(PL_TSR,   45).
-define(PL_SK,    46).
-define(PL_CP,    47).
-define(PL_EAP,   48).

%% IKE flags
-define(FLAG_INITIATOR, 16#08).
-define(FLAG_VERSION,   16#20).
-define(FLAG_RESPONSE,  16#20).

%%====================================================================
%% Header
%%====================================================================

-spec decode_header(binary()) -> {ok, map()} | {error, term()}.
decode_header(<<ISPI:64, RSPI:64, NextPL:8, MajVer:4, MinVer:4,
                ExType:8, Flags:8, MsgId:32, Len:32, Rest/binary>>)
  when MajVer =:= 2 ->
    {ok, #{initiator_spi => ISPI,
           responder_spi => RSPI,
           next_payload  => NextPL,
           version       => {MajVer, MinVer},
           exchange_type => exchange_type_atom(ExType),
           exchange_type_raw => ExType,
           flags         => Flags,
           is_initiator  => (Flags band ?FLAG_INITIATOR) =/= 0,
           is_response   => (Flags band ?FLAG_RESPONSE) =/= 0,
           message_id    => MsgId,
           length        => Len,
           payload_data  => Rest}};
decode_header(<<_:64, _:64, _:8, MajVer:4, _:4, _/binary>>) ->
    {error, {unsupported_version, MajVer}};
decode_header(_) ->
    {error, invalid_header}.

-spec encode_header(map()) -> binary().
encode_header(#{initiator_spi := ISPI, responder_spi := RSPI,
                next_payload := NextPL, exchange_type_raw := ExType,
                flags := Flags, message_id := MsgId,
                payload_bin := PayloadBin}) ->
    Len = 28 + byte_size(PayloadBin),
    <<ISPI:64, RSPI:64, NextPL:8, 2:4, 0:4,
      ExType:8, Flags:8, MsgId:32, Len:32, PayloadBin/binary>>.

%%====================================================================
%% Payload chain
%%====================================================================

-spec decode_payloads(non_neg_integer(), binary()) -> {ok, [map()]} | {error, term()}.
decode_payloads(?PL_NONE, <<>>) ->
    {ok, []};
decode_payloads(Type, <<NextPL:8, _Critical:1, _Res:7, PLLen:16, Rest/binary>>)
  when PLLen >= 4 ->
    DataLen = PLLen - 4,
    case Rest of
        <<PLData:DataLen/binary, Remaining/binary>> ->
            Payload = #{type => payload_type_atom(Type),
                        type_raw => Type,
                        data => PLData},
            case decode_payloads(NextPL, Remaining) of
                {ok, More} -> {ok, [Payload | More]};
                Err -> Err
            end;
        _ ->
            {error, truncated_payload}
    end;
decode_payloads(_Type, <<>>) ->
    {ok, []};
decode_payloads(_, _) ->
    {error, malformed_payload}.

-spec encode_payloads([{atom(), binary()}]) -> {non_neg_integer(), binary()}.
encode_payloads([]) ->
    {?PL_NONE, <<>>};
encode_payloads([{FirstType, _} | _] = Payloads) ->
    FirstTypeRaw = payload_type_raw(FirstType),
    {FirstTypeRaw, encode_payloads_chain(Payloads)}.

%% Each payload header carries the type of the NEXT payload in the chain.
%% The first payload's type is returned separately (for the IKE header's
%% next_payload field).
encode_payloads_chain([{_Type, Data}]) ->
    PLLen = 4 + byte_size(Data),
    <<?PL_NONE:8, 0:8, PLLen:16, Data/binary>>;
encode_payloads_chain([{_Type, Data}, {NextType, _} = NextP | Rest]) ->
    NextRaw = payload_type_raw(NextType),
    PLLen = 4 + byte_size(Data),
    Hdr = <<NextRaw:8, 0:8, PLLen:16, Data/binary>>,
    <<Hdr/binary, (encode_payloads_chain([NextP | Rest]))/binary>>.

%%====================================================================
%% SA payload parsing
%%====================================================================

-spec decode_sa_payload(binary()) -> {ok, [map()]} | {error, term()}.
decode_sa_payload(Data) ->
    decode_proposals(Data, []).

decode_proposals(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_proposals(<<Last:8, _Res:8, PropLen:16, PropNum:8,
                   ProtoId:8, SPISize:8, NumTransforms:8,
                   Rest/binary>>, Acc) when PropLen >= 8 ->
    SPIAndTransLen = PropLen - 8,
    case Rest of
        <<SPIAndTrans:SPIAndTransLen/binary, Remaining/binary>> ->
            <<SPI:SPISize/binary, TransData/binary>> = SPIAndTrans,
            Proposal = #{number => PropNum,
                         protocol_id => ProtoId,
                         spi => SPI,
                         num_transforms => NumTransforms,
                         transforms_data => TransData},
            case Last of
                0 -> {ok, lists:reverse([Proposal | Acc])};
                2 -> decode_proposals(Remaining, [Proposal | Acc]);
                _ -> {error, {bad_proposal_last, Last}}
            end;
        _ ->
            {error, truncated_proposal}
    end;
decode_proposals(_, _) ->
    {error, malformed_sa}.

%%====================================================================
%% Certificate / Auth payload helpers (RFC 7296 §3.6, §3.8, §3.7)
%%====================================================================

%% X.509 Certificate - Signature (encoding type 4, RFC 7296 §3.6)
-define(CERT_ENCODING_X509_SIGN, 4).

-spec encode_cert_payload(binary()) -> binary().
encode_cert_payload(DerCert) ->
    <<?CERT_ENCODING_X509_SIGN:8, DerCert/binary>>.

%% AUTH payload: auth method byte + signature data (RFC 7296 §3.8)
-spec encode_auth_payload(non_neg_integer(), binary()) -> binary().
encode_auth_payload(AuthMethod, Signature) ->
    <<AuthMethod:8, 0:24, Signature/binary>>.

%% CERTREQ payload: encoding type + SHA-1 hashes of trusted CA public keys
-spec encode_certreq_payload(binary()) -> binary().
encode_certreq_payload(CaPublicKeyHashes) ->
    <<?CERT_ENCODING_X509_SIGN:8, CaPublicKeyHashes/binary>>.

%%====================================================================
%% Atoms
%%====================================================================

exchange_type_atom(?IKE_SA_INIT)    -> ike_sa_init;
exchange_type_atom(?IKE_AUTH)       -> ike_auth;
exchange_type_atom(?CREATE_CHILD_SA)-> create_child_sa;
exchange_type_atom(?INFORMATIONAL)  -> informational;
exchange_type_atom(N)               -> {unknown, N}.

payload_type_atom(?PL_SA)     -> sa;
payload_type_atom(?PL_KE)     -> ke;
payload_type_atom(?PL_IDI)    -> idi;
payload_type_atom(?PL_IDR)    -> idr;
payload_type_atom(?PL_CERT)    -> cert;
payload_type_atom(?PL_CERTREQ) -> certreq;
payload_type_atom(?PL_AUTH)    -> auth;
payload_type_atom(?PL_NONCE)  -> nonce;
payload_type_atom(?PL_NOTIFY) -> notify;
payload_type_atom(?PL_DELETE) -> delete;
payload_type_atom(?PL_TSI)    -> tsi;
payload_type_atom(?PL_TSR)    -> tsr;
payload_type_atom(?PL_SK)     -> sk;
payload_type_atom(?PL_CP)     -> cp;
payload_type_atom(?PL_EAP)    -> eap;
payload_type_atom(N)          -> {unknown, N}.

payload_type_raw(sa)     -> ?PL_SA;
payload_type_raw(ke)     -> ?PL_KE;
payload_type_raw(idi)    -> ?PL_IDI;
payload_type_raw(idr)    -> ?PL_IDR;
payload_type_raw(cert)    -> ?PL_CERT;
payload_type_raw(certreq) -> ?PL_CERTREQ;
payload_type_raw(auth)    -> ?PL_AUTH;
payload_type_raw(nonce)  -> ?PL_NONCE;
payload_type_raw(notify) -> ?PL_NOTIFY;
payload_type_raw(delete) -> ?PL_DELETE;
payload_type_raw(tsi)    -> ?PL_TSI;
payload_type_raw(tsr)    -> ?PL_TSR;
payload_type_raw(sk)     -> ?PL_SK;
payload_type_raw(cp)     -> ?PL_CP;
payload_type_raw(eap)    -> ?PL_EAP;
payload_type_raw(_)      -> ?PL_NONE.

%%====================================================================
%% Payload helpers
%%====================================================================

-spec find_payload(atom(), [map()]) -> {ok, map()} | error.
find_payload(_Type, []) -> error;
find_payload(Type, [#{type := Type} = P | _]) -> {ok, P};
find_payload(Type, [_ | Rest]) -> find_payload(Type, Rest).

%%====================================================================
%% Transform parsing (RFC 7296 §3.3.2)
%%====================================================================

-spec decode_transforms(binary()) -> {ok, [map()]} | {error, term()}.
decode_transforms(Bin) ->
    decode_transforms_acc(Bin, []).

decode_transforms_acc(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
decode_transforms_acc(<<Last:8, _Res:8, TLen:16,
                         TType:8, _Res2:8, TId:16, Rest/binary>>, Acc)
  when TLen >= 8 ->
    AttrLen = TLen - 8,
    case Rest of
        <<AttrData:AttrLen/binary, More/binary>> ->
            Transform = #{type     => transform_type_atom(TType),
                          type_raw => TType,
                          id       => TId,
                          attrs    => decode_attrs(AttrData)},
            case Last of
                0 -> {ok, lists:reverse([Transform | Acc])};
                3 -> decode_transforms_acc(More, [Transform | Acc]);
                _ -> {error, {bad_transform_last, Last}}
            end;
        _ ->
            {error, truncated_transform}
    end;
decode_transforms_acc(_, _) ->
    {error, malformed_transform}.

%% Decode transform attributes. We only care about Key Length (TV, type 14).
decode_attrs(Bin) -> decode_attrs_acc(Bin, #{}).

decode_attrs_acc(<<>>, Acc) -> Acc;
decode_attrs_acc(<<1:1, AType:15, Value:16, Rest/binary>>, Acc) ->
    %% TV encoding (AF=1): 2-byte value
    Key = attr_type_atom(AType),
    decode_attrs_acc(Rest, Acc#{Key => Value});
decode_attrs_acc(<<0:1, AType:15, ALen:16, Rest/binary>>, Acc) ->
    %% TLV encoding (AF=0)
    case Rest of
        <<Val:ALen/binary, More/binary>> ->
            Key = attr_type_atom(AType),
            decode_attrs_acc(More, Acc#{Key => Val});
        _ ->
            Acc
    end;
decode_attrs_acc(_, Acc) -> Acc.

transform_type_atom(?TRANS_ENCR)  -> encr;
transform_type_atom(?TRANS_PRF)   -> prf;
transform_type_atom(?TRANS_INTEG) -> integ;
transform_type_atom(?TRANS_DH)    -> dh;
transform_type_atom(?TRANS_ESN)   -> esn;
transform_type_atom(N)            -> {unknown, N}.

attr_type_atom(?ATTR_KEY_LENGTH) -> key_length;
attr_type_atom(N)                -> {unknown_attr, N}.

%%====================================================================
%% Proposal selection (RFC 7296 §3.3)
%%
%% Picks the first proposal that contains supported transforms for
%% all required transform types (ENCR, PRF, INTEG [or none for AEAD],
%% D-H, ESN). Returns a map describing the chosen suite, ready to be
%% re-encoded as the SA_r proposal.
%%====================================================================

-spec select_proposal([map()]) -> {ok, map()} | {error, term()}.
select_proposal(Proposals) ->
    select_proposal_loop(Proposals, no_matching_proposal).

select_proposal_loop([], LastErr) ->
    {error, LastErr};
select_proposal_loop([#{protocol_id := 1, transforms_data := TData} = Prop | Rest], _) ->
    %% Protocol 1 = IKE
    case decode_transforms(TData) of
        {ok, Transforms} ->
            case pick_suite(Transforms) of
                {ok, Suite} ->
                    {ok, Suite#{proposal_number => maps:get(number, Prop),
                                protocol_id     => 1,
                                spi             => maps:get(spi, Prop, <<>>)}};
                {error, R} ->
                    select_proposal_loop(Rest, R)
            end;
        {error, R} ->
            select_proposal_loop(Rest, R)
    end;
select_proposal_loop([_ | Rest], LastErr) ->
    select_proposal_loop(Rest, LastErr).

pick_suite(Transforms) ->
    Groups = lists:foldl(
        fun(#{type := T} = Tr, Acc) ->
            maps:update_with(T, fun(L) -> [Tr | L] end, [Tr], Acc)
        end, #{}, Transforms),
    Encr  = pick_first_supported(maps:get(encr,  Groups, []), fun is_supported_encr/1),
    Prf   = pick_first_supported(maps:get(prf,   Groups, []), fun is_supported_prf/1),
    Integ = pick_first_supported(maps:get(integ, Groups, []), fun is_supported_integ/1),
    DH    = pick_first_supported(maps:get(dh,    Groups, []), fun is_supported_dh/1),
    %% Transform Type 5 (ESN) is defined only for ESP/AH Child SA proposals
    %% per RFC 7296 §3.3.3 and MUST NOT appear in IKE SA proposals. Real UEs
    %% (observed: Samsung VoWiFi dialer proposing AES-CBC-256/HMAC-SHA{256,512}/
    %% MODP-{2048,3072} without ESN) correctly omit it, so the IKE-SA matcher
    %% does not require it. The ESP matcher lives in the Child SA code path
    %% (SAi2 in IKE_AUTH) which is still to be wired.
    case {Encr, Prf, DH} of
        {{ok, E}, {ok, P}, {ok, D}} ->
            %% INTEG may be absent for AEAD (e.g. AES-GCM) but required otherwise.
            case {is_aead(E), Integ} of
                {true, _}        -> {ok, #{encr => E, prf => P, integ => none,
                                            dh => D, esn => none}};
                {false, {ok, I}} -> {ok, #{encr => E, prf => P, integ => I,
                                            dh => D, esn => none}};
                {false, _}       -> {error, missing_integ_transform}
            end;
        _ ->
            {error, unsupported_transforms}
    end.

pick_first_supported([], _Pred) -> error;
pick_first_supported([T | Rest], Pred) ->
    case Pred(T) of
        true  -> {ok, T};
        false -> pick_first_supported(Rest, Pred)
    end.

%% Supported algorithm predicates. Keep conservative — only algos we know
%% the crypto module implements today.
is_supported_encr(#{id := 20, attrs := #{key_length := 256}}) -> true; %% AES-GCM-16, 256
is_supported_encr(#{id := 12, attrs := #{key_length := 256}}) -> true; %% AES-CBC, 256
is_supported_encr(_) -> false.

is_supported_prf(#{id := 5}) -> true;  %% HMAC-SHA256
is_supported_prf(#{id := 6}) -> true;  %% HMAC-SHA384
is_supported_prf(#{id := 7}) -> true;  %% HMAC-SHA512
is_supported_prf(_) -> false.

is_supported_integ(#{id := 12}) -> true; %% HMAC-SHA256-128
is_supported_integ(#{id := 13}) -> true; %% HMAC-SHA384-192
is_supported_integ(#{id := 14}) -> true; %% HMAC-SHA512-256
is_supported_integ(_) -> false.

is_supported_dh(#{id := 14}) -> true;
is_supported_dh(#{id := 19}) -> true;
is_supported_dh(#{id := 20}) -> true;
is_supported_dh(#{id := 31}) -> true;
is_supported_dh(_) -> false.

is_supported_esn(#{id := 0}) -> true; %% No ESN
is_supported_esn(_)          -> false.

is_aead(#{id := 20}) -> true; %% AES-GCM-16
is_aead(_)           -> false.

%%====================================================================
%% SA response encoding (single selected proposal)
%%====================================================================

-spec encode_sa_response(map()) -> binary().
encode_sa_response(#{proposal_number := PN, protocol_id := Proto,
                     spi := SPI,
                     encr := Encr, prf := Prf, integ := Integ,
                     dh := DH, esn := Esn}) ->
    Transforms =
        [Encr, Prf] ++
        case Integ of
            none -> [];
            I    -> [I]
        end ++
        [DH] ++
        case Esn of
            none -> [];
            Es   -> [Es]
        end,
    TransformsBin = encode_transforms(Transforms),
    NumT = length(Transforms),
    SPISize = byte_size(SPI),
    PropLen = 8 + SPISize + byte_size(TransformsBin),
    %% Last = 0 (only proposal in response)
    PropBin = <<0:8, 0:8, PropLen:16, PN:8, Proto:8, SPISize:8, NumT:8,
                SPI/binary, TransformsBin/binary>>,
    PropBin.

encode_transforms([]) -> <<>>;
encode_transforms([T]) -> encode_transform(T, 0);
encode_transforms([T | Rest]) ->
    <<(encode_transform(T, 3))/binary, (encode_transforms(Rest))/binary>>.

encode_transform(#{type_raw := TType, id := TId, attrs := Attrs}, Last) ->
    AttrsBin = encode_attrs(maps:to_list(Attrs)),
    TLen = 8 + byte_size(AttrsBin),
    <<Last:8, 0:8, TLen:16, TType:8, 0:8, TId:16, AttrsBin/binary>>.

encode_attrs([]) -> <<>>;
encode_attrs([{key_length, V} | Rest]) ->
    %% TV, AF=1, type=14
    <<1:1, ?ATTR_KEY_LENGTH:15, V:16, (encode_attrs(Rest))/binary>>;
encode_attrs([{{unknown_attr, _}, _} | Rest]) ->
    encode_attrs(Rest);
encode_attrs([_ | Rest]) ->
    encode_attrs(Rest).

%%====================================================================
%% KE / Nonce / Notify payload helpers
%%====================================================================

-spec decode_ke_payload(binary()) -> {ok, {non_neg_integer(), binary()}} | {error, term()}.
decode_ke_payload(<<DHGroup:16, _Reserved:16, KeyData/binary>>) ->
    {ok, {DHGroup, KeyData}};
decode_ke_payload(_) ->
    {error, invalid_ke_payload}.

-spec encode_ke_payload(non_neg_integer(), binary()) -> binary().
encode_ke_payload(DHGroup, PubKey) ->
    <<DHGroup:16, 0:16, PubKey/binary>>.

-spec decode_nonce_payload(binary()) -> {ok, binary()}.
decode_nonce_payload(Bin) -> {ok, Bin}.

-spec encode_nonce_payload(binary()) -> binary().
encode_nonce_payload(Nonce) -> Nonce.

%% Notify payload (RFC 7296 §3.10)
-spec encode_notify_payload(non_neg_integer(), non_neg_integer(),
                             binary(), binary()) -> binary().
encode_notify_payload(ProtocolId, NotifyType, SPI, Data) ->
    SPISize = byte_size(SPI),
    <<ProtocolId:8, SPISize:8, NotifyType:16, SPI/binary, Data/binary>>.

%% REDIRECT / REDIRECT_SUPPORTED / REDIRECT_FROM notification data
%% (RFC 5685 §6):
%%   GW Ident Type (1) | GW Ident Len (1) | GW Identity (Len) | [Nonce Data]
%%
%% GW Ident Type: 1 = IPv4 (4-byte identity), 2 = IPv6 (16-byte identity),
%% 3 = FQDN (UTF-8 bytes, no null terminator, no inner length prefix).
%%
%% The trailing Nonce is included ONLY for a redirect during IKE_SA_INIT
%% (RFC 5685 §5), where it echoes the client's Ni. For IKE_AUTH and
%% active-session (INFORMATIONAL) redirects pass Nonce = <<>>.
-spec encode_redirect_notify_data(1..3, binary(), binary()) -> binary().
encode_redirect_notify_data(GwType, GwIdentity, Nonce)
  when GwType >= 1, GwType =< 3, is_binary(GwIdentity),
       byte_size(GwIdentity) =< 255, is_binary(Nonce) ->
    Len = byte_size(GwIdentity),
    <<GwType:8, Len:8, GwIdentity/binary, Nonce/binary>>.

%% Inverse of encode_redirect_notify_data/3 (used for round-trip tests and
%% any future initiator-side handling). Returns {GwType, Identity, Nonce}
%% where Nonce is <<>> when none was appended.
-spec decode_redirect_notify_data(binary()) ->
    {ok, {1..3, binary(), binary()}} | {error, term()}.
decode_redirect_notify_data(<<GwType:8, Len:8, Rest/binary>>)
  when GwType >= 1, GwType =< 3 ->
    case Rest of
        <<GwIdentity:Len/binary, Nonce/binary>> ->
            {ok, {GwType, GwIdentity, Nonce}};
        _ ->
            {error, truncated_redirect}
    end;
decode_redirect_notify_data(_) ->
    {error, invalid_redirect}.

%% Parse a configured redirect target string into the {GwIdentType,
%% GwIdentity} pair carried in a REDIRECT notification (RFC 5685 §6).
%%
%% A literal IPv4/IPv6 sends every draining UE to one node and recreates
%% the thundering herd the drain jitter exists to prevent; prefer an FQDN
%% so DNS can spread arrivals across the remaining healthy pods.
-spec parse_redirect_target(string()) -> {ok, {1..3, binary()}} | {error, term()}.
parse_redirect_target(Target) when is_list(Target) ->
    case string:trim(Target) of
        "" ->
            {error, empty};
        Trimmed ->
            case inet:parse_address(Trimmed) of
                {ok, {A, B, C, D}} ->
                    {ok, {1, <<A:8, B:8, C:8, D:8>>}};
                {ok, {A, B, C, D, E, F, G, H}} ->
                    {ok, {2, <<A:16, B:16, C:16, D:16,
                               E:16, F:16, G:16, H:16>>}};
                {error, _} ->
                    %% Not a literal address -> treat as FQDN (ID_FQDN form).
                    {ok, {3, unicode:characters_to_binary(Trimmed)}}
            end
    end.

%% Delete payload for the IKE SA itself (RFC 7296 §3.11):
%% Protocol ID = 1 (IKE), SPI Size = 0, Num SPIs = 0. The IKE SPIs
%% already live in the IKE header, so the payload body carries no SPIs.
-spec encode_delete_ike_payload() -> binary().
encode_delete_ike_payload() ->
    <<1:8, 0:8, 0:16>>.

%%====================================================================
%% Identification payload (RFC 7296 §3.5) — used for IDi and IDr
%%
%% ID Type values (RFC 7296 §3.5):
%%   1  ID_IPV4_ADDR
%%   2  ID_FQDN
%%   3  ID_RFC822_ADDR  (the EAP-AKA' NAI form used over SWu)
%%   5  ID_IPV6_ADDR
%%   9  ID_DER_ASN1_DN
%%  11  ID_KEY_ID
%%====================================================================

-spec encode_id_payload(non_neg_integer(), binary()) -> binary().
encode_id_payload(IdType, IdData) when IdType >= 0, IdType =< 255 ->
    %% 1 byte ID type | 3 bytes reserved | identification data
    <<IdType:8, 0:24, IdData/binary>>.

-spec decode_id_payload(binary()) ->
    {ok, {non_neg_integer(), binary()}} | {error, term()}.
decode_id_payload(<<IdType:8, _Reserved:24, IdData/binary>>) ->
    {ok, {IdType, IdData}};
decode_id_payload(_) ->
    {error, invalid_id_payload}.

%%====================================================================
%% AUTH payload decode (RFC 7296 §3.8)
%%====================================================================

-spec decode_auth_payload(binary()) ->
    {ok, {non_neg_integer(), binary()}} | {error, term()}.
decode_auth_payload(<<AuthMethod:8, _Reserved:24, Signature/binary>>) ->
    {ok, {AuthMethod, Signature}};
decode_auth_payload(_) ->
    {error, invalid_auth_payload}.

%%====================================================================
%% Configuration Payload (RFC 7296 §3.15)
%%
%% CP Type   (1 byte)  1=CFG_REQUEST, 2=CFG_REPLY, 3=CFG_SET, 4=CFG_ACK
%% Reserved  (3 bytes)
%% <Configuration Attributes>
%%
%% Attribute: R(1) | AttributeType(15) | Length(16) | Value(Length octets)
%%
%% Standard attributes (RFC 7296 §3.15.1):
%%    1 INTERNAL_IP4_ADDRESS
%%    2 INTERNAL_IP4_NETMASK
%%    3 INTERNAL_IP4_DNS
%%    4 INTERNAL_IP4_NBNS
%%    6 INTERNAL_IP4_DHCP
%%    7 APPLICATION_VERSION
%%    8 INTERNAL_IP6_ADDRESS  (17 octets: 16 + prefix-length)
%%   10 INTERNAL_IP6_DNS
%%   12 INTERNAL_IP6_DHCP
%%   13 INTERNAL_IP4_SUBNET
%%   15 INTERNAL_IP6_SUBNET
%%
%% 3GPP TS 24.302 additions used for VoWiFi:
%%   20 P_CSCF_IP4_ADDRESS
%%   22 P_CSCF_IP6_ADDRESS
%%====================================================================

-define(CP_CFG_REQUEST, 1).
-define(CP_CFG_REPLY,   2).

-spec decode_cp_payload(binary()) ->
    {ok, {non_neg_integer(), [{atom() | {unknown, non_neg_integer()}, binary()}]}}
    | {error, term()}.
decode_cp_payload(<<CfgType:8, _Reserved:24, Attrs/binary>>) ->
    case decode_cp_attrs(Attrs, []) of
        {ok, Parsed} -> {ok, {CfgType, Parsed}};
        E            -> E
    end;
decode_cp_payload(_) ->
    {error, invalid_cp_payload}.

decode_cp_attrs(<<>>, Acc) -> {ok, lists:reverse(Acc)};
decode_cp_attrs(<<_R:1, AType:15, ALen:16, Rest/binary>>, Acc) ->
    case Rest of
        <<Val:ALen/binary, More/binary>> ->
            decode_cp_attrs(More, [{cp_attr_atom(AType), Val} | Acc]);
        _ ->
            {error, truncated_cp_attr}
    end;
decode_cp_attrs(_, _) ->
    {error, malformed_cp}.

cp_attr_atom( 1) -> internal_ip4_address;
cp_attr_atom( 2) -> internal_ip4_netmask;
cp_attr_atom( 3) -> internal_ip4_dns;
cp_attr_atom( 4) -> internal_ip4_nbns;
cp_attr_atom( 6) -> internal_ip4_dhcp;
cp_attr_atom( 7) -> application_version;
cp_attr_atom( 8) -> internal_ip6_address;
cp_attr_atom(10) -> internal_ip6_dns;
cp_attr_atom(12) -> internal_ip6_dhcp;
cp_attr_atom(13) -> internal_ip4_subnet;
cp_attr_atom(15) -> internal_ip6_subnet;
cp_attr_atom(20) -> p_cscf_ip4_address;
cp_attr_atom(22) -> p_cscf_ip6_address;
cp_attr_atom(N)  -> {unknown, N}.

cp_attr_raw(internal_ip4_address) -> 1;
cp_attr_raw(internal_ip4_netmask) -> 2;
cp_attr_raw(internal_ip4_dns)     -> 3;
cp_attr_raw(internal_ip4_nbns)    -> 4;
cp_attr_raw(internal_ip4_dhcp)    -> 6;
cp_attr_raw(application_version)  -> 7;
cp_attr_raw(internal_ip6_address) -> 8;
cp_attr_raw(internal_ip6_dns)     -> 10;
cp_attr_raw(internal_ip6_dhcp)    -> 12;
cp_attr_raw(internal_ip4_subnet)  -> 13;
cp_attr_raw(internal_ip6_subnet)  -> 15;
cp_attr_raw(p_cscf_ip4_address)   -> 20;
cp_attr_raw(p_cscf_ip6_address)   -> 22;
cp_attr_raw(N) when is_integer(N) -> N.

-spec encode_cp_payload(non_neg_integer(),
                        [{atom() | non_neg_integer(), binary()}]) -> binary().
encode_cp_payload(CfgType, Attrs) when CfgType >= 0, CfgType =< 255 ->
    AttrsBin = << <<(encode_cp_attr(A))/binary>> || A <- Attrs >>,
    <<CfgType:8, 0:24, AttrsBin/binary>>.

encode_cp_attr({AType, Val}) when is_binary(Val) ->
    TypeRaw = cp_attr_raw(AType),
    ALen = byte_size(Val),
    <<0:1, TypeRaw:15, ALen:16, Val/binary>>.

%%====================================================================
%% Traffic Selector payload (RFC 7296 §3.13)
%%
%% Number of TSs (1) | Reserved (3) | <Traffic Selector ...>
%%
%% Traffic Selector:
%%   TS Type (1)      7 = TS_IPV4_ADDR_RANGE, 8 = TS_IPV6_ADDR_RANGE
%%   IP Protocol (1)  0 = any
%%   Selector Length (2)
%%   Start Port (2)
%%   End Port   (2)
%%   Start Addr (4 or 16)
%%   End Addr   (4 or 16)
%%====================================================================

-define(TS_IPV4_ADDR_RANGE, 7).
-define(TS_IPV6_ADDR_RANGE, 8).

-spec decode_ts_payload(binary()) -> {ok, [map()]} | {error, term()}.
decode_ts_payload(<<NumTs:8, _Reserved:24, Rest/binary>>) ->
    decode_ts_list(NumTs, Rest, []);
decode_ts_payload(_) ->
    {error, invalid_ts_payload}.

decode_ts_list(0, _Tail, Acc) ->
    {ok, lists:reverse(Acc)};
decode_ts_list(N, <<TsType:8, Proto:8, SelLen:16, Rest/binary>>, Acc)
  when SelLen >= 8 ->
    BodyLen = SelLen - 4,
    case Rest of
        <<Body:BodyLen/binary, More/binary>> ->
            case decode_ts_body(TsType, Proto, Body) of
                {ok, TS} ->
                    decode_ts_list(N - 1, More, [TS | Acc]);
                E -> E
            end;
        _ -> {error, truncated_ts}
    end;
decode_ts_list(_, _, _) ->
    {error, malformed_ts}.

decode_ts_body(?TS_IPV4_ADDR_RANGE, Proto,
               <<StartPort:16, EndPort:16,
                 A1:8, A2:8, A3:8, A4:8,
                 B1:8, B2:8, B3:8, B4:8>>) ->
    {ok, #{ts_type    => ipv4_addr_range,
           ip_protocol=> Proto,
           start_port => StartPort,
           end_port   => EndPort,
           start_addr => {A1, A2, A3, A4},
           end_addr   => {B1, B2, B3, B4}}};
decode_ts_body(?TS_IPV6_ADDR_RANGE, Proto,
               <<StartPort:16, EndPort:16,
                 Start:16/binary, End:16/binary>>) ->
    {ok, #{ts_type    => ipv6_addr_range,
           ip_protocol=> Proto,
           start_port => StartPort,
           end_port   => EndPort,
           start_addr => bin_to_ip6(Start),
           end_addr   => bin_to_ip6(End)}};
decode_ts_body(TsType, Proto, Body) ->
    {ok, #{ts_type => {unknown, TsType}, ip_protocol => Proto, body => Body}}.

bin_to_ip6(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

-spec encode_ts_payload([map()]) -> binary().
encode_ts_payload(Selectors) ->
    N = length(Selectors),
    Body = iolist_to_binary([encode_ts_one(S) || S <- Selectors]),
    <<N:8, 0:24, Body/binary>>.

encode_ts_one(#{ts_type := ipv4_addr_range,
                ip_protocol := Proto,
                start_port := SP, end_port := EP,
                start_addr := {A1,A2,A3,A4},
                end_addr   := {B1,B2,B3,B4}}) ->
    %% SelectorLength = 4 (hdr) + 4 (ports) + 4 + 4 = 16
    <<?TS_IPV4_ADDR_RANGE:8, Proto:8, 16:16,
      SP:16, EP:16,
      A1:8, A2:8, A3:8, A4:8,
      B1:8, B2:8, B3:8, B4:8>>;
encode_ts_one(#{ts_type := ipv6_addr_range,
                ip_protocol := Proto,
                start_port := SP, end_port := EP,
                start_addr := Start, end_addr := End}) ->
    StartBin = ip6_to_bin(Start),
    EndBin   = ip6_to_bin(End),
    <<?TS_IPV6_ADDR_RANGE:8, Proto:8, 40:16,
      SP:16, EP:16, StartBin/binary, EndBin/binary>>.

ip6_to_bin({A,B,C,D,E,F,G,H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%%====================================================================
%% Child SA (ESP) proposal selection and response encoding
%% (RFC 7296 §3.3). Protocol-Id = 3 for ESP; SPI = 4 bytes.
%%====================================================================

%% Decode the first ESP proposal from a Child SA payload body and pick
%% the first transform our crypto module supports. Returns a suite map
%% ready for encode_child_sa_response/1 together with the UE's inbound
%% SPI (Child SA initiator SPI).
-spec decode_child_sa_payload(binary()) ->
    {ok, map()} | {error, term()}.
decode_child_sa_payload(Data) ->
    case decode_sa_payload(Data) of
        {ok, Proposals} ->
            pick_child_proposal(Proposals);
        E -> E
    end.

pick_child_proposal([]) -> {error, no_esp_proposal};
pick_child_proposal([#{protocol_id := 3, spi := SPI,
                        transforms_data := TData,
                        number := PN} | Rest]) ->
    case decode_transforms(TData) of
        {ok, Transforms} ->
            case pick_child_suite(Transforms) of
                {ok, Suite} ->
                    {ok, Suite#{proposal_number  => PN,
                                protocol_id      => 3,
                                peer_spi         => SPI}};
                {error, _} ->
                    pick_child_proposal(Rest)
            end;
        {error, _} ->
            pick_child_proposal(Rest)
    end;
pick_child_proposal([_ | Rest]) ->
    pick_child_proposal(Rest).

pick_child_suite(Transforms) ->
    Groups = lists:foldl(
        fun(#{type := T} = Tr, Acc) ->
            maps:update_with(T, fun(L) -> [Tr | L] end, [Tr], Acc)
        end, #{}, Transforms),
    Encr  = pick_first_supported(maps:get(encr,  Groups, []),
                                  fun is_supported_child_encr/1),
    Integ = pick_first_supported(maps:get(integ, Groups, []),
                                  fun is_supported_child_integ/1),
    Esn   = pick_first_supported(maps:get(esn,   Groups, []),
                                  fun is_supported_esn/1),
    case {Encr, Integ} of
        {{ok, E}, {ok, I}} ->
            {ok, #{encr  => E,
                   integ => I,
                   esn   => case Esn of {ok, Es} -> Es;
                                       _        -> #{type => esn, type_raw => 5,
                                                     id => 0, attrs => #{}}
                            end}};
        {{ok, E}, error} ->
            case is_aead(E) of
                true  -> {ok, #{encr => E, integ => none,
                                esn  => case Esn of {ok, Es} -> Es;
                                                   _        -> #{type => esn,
                                                                 type_raw => 5,
                                                                 id => 0,
                                                                 attrs => #{}}
                                        end}};
                false -> {error, missing_integ_transform}
            end;
        _ ->
            {error, unsupported_child_transforms}
    end.

%% For ESP we accept the same AES/GCM/CBC set as for IKE.
is_supported_child_encr(T) -> is_supported_encr(T).
is_supported_child_integ(#{id := 2}) -> true; %% HMAC-SHA1-96 (legacy but common)
is_supported_child_integ(T)          -> is_supported_integ(T).

%% Length of the ESP enc key (including AES-GCM salt for AEAD).
-spec child_enc_key_len(map()) -> non_neg_integer().
child_enc_key_len(#{id := 20, attrs := #{key_length := K}}) -> (K div 8) + 4;
child_enc_key_len(#{id := 12, attrs := #{key_length := K}}) -> K div 8;
child_enc_key_len(_) -> 0.

%% Length of the ESP integ key (0 for AEAD).
-spec child_integ_key_len(map() | none) -> non_neg_integer().
child_integ_key_len(none)         -> 0;
child_integ_key_len(#{id :=  2})  -> 20; %% HMAC-SHA1
child_integ_key_len(#{id := 12})  -> 32; %% HMAC-SHA256-128
child_integ_key_len(#{id := 13})  -> 48; %% HMAC-SHA384-192
child_integ_key_len(#{id := 14})  -> 64; %% HMAC-SHA512-256
child_integ_key_len(_)            -> 0.

%% Encode the single selected ESP proposal back to the UE with the SPI
%% we allocated on our side (responder/inbound).
-spec encode_child_sa_response(map()) -> binary().
encode_child_sa_response(#{proposal_number := PN,
                            encr := Encr, integ := Integ,
                            esn := Esn, responder_spi := RSPI}) ->
    Transforms =
        [Encr] ++
        case Integ of
            none -> [];
            I    -> [I]
        end ++
        [Esn],
    TransformsBin = encode_transforms(Transforms),
    NumT = length(Transforms),
    SPISize = byte_size(RSPI),
    PropLen = 8 + SPISize + byte_size(TransformsBin),
    <<0:8, 0:8, PropLen:16, PN:8, 3:8, SPISize:8, NumT:8,
      RSPI/binary, TransformsBin/binary>>.

%%====================================================================
%% EAP payload (RFC 7296 §3.16) — wraps RFC 3748 EAP packet verbatim
%%====================================================================

-spec encode_eap_payload(binary()) -> binary().
encode_eap_payload(EapPkt) when is_binary(EapPkt) ->
    EapPkt.

-spec decode_eap_payload(binary()) -> {ok, binary()} | {error, term()}.
decode_eap_payload(Bin) when is_binary(Bin) ->
    {ok, Bin}.

%% Build an EAP-Request/Identity packet (RFC 3748 §5.1): Code=1 (Request),
%% Identifier, Length, Type=1 (Identity), Type-Data (optional prompt).
-spec encode_eap_request_identity(non_neg_integer()) -> binary().
encode_eap_request_identity(Id) when Id >= 0, Id =< 255 ->
    %% Code=1 Request | Id | Length (2 bytes: 4 header + 1 type) | Type=1 Identity
    <<1:8, Id:8, 5:16, 1:8>>.

%%====================================================================
%% Key derivation parameters for a negotiated IKE crypto suite
%%
%% Returns a map consumable by epdg_ikev2_crypto:derive_ike_keys/4. The
%% `enc_key_len` for AEAD transforms follows RFC 5282: keying material
%% per direction = algorithm key + 4-byte salt; `integ_key_len` is 0 for
%% AEAD since authentication is combined.
%%====================================================================

-spec keys_params_for_suite(map()) -> {ok, map()} | {error, term()}.
keys_params_for_suite(#{encr := Encr, prf := Prf, integ := Integ}) ->
    case prf_atom(Prf) of
        {ok, PrfAtom, PrfKeyLen} ->
            case encr_params(Encr) of
                {ok, EncAlg, EncKeyLen, SaltLen, IsAead} ->
                    case integ_params(Integ, IsAead) of
                        {ok, IntegAlg, IntegKeyLen} ->
                            {ok, #{prf           => PrfAtom,
                                   prf_key_len   => PrfKeyLen,
                                   enc_alg       => EncAlg,
                                   enc_key_len   => EncKeyLen + SaltLen,
                                   enc_base_key_len => EncKeyLen,
                                   salt_len      => SaltLen,
                                   is_aead       => IsAead,
                                   integ_alg     => IntegAlg,
                                   integ_key_len => IntegKeyLen}};
                        {error, R} -> {error, R}
                    end;
                {error, R} -> {error, R}
            end;
        {error, R} -> {error, R}
    end;
keys_params_for_suite(_) ->
    {error, incomplete_suite}.

prf_atom(#{id := 5}) -> {ok, sha256, 32};
prf_atom(#{id := 6}) -> {ok, sha384, 48};
prf_atom(#{id := 7}) -> {ok, sha512, 64};
prf_atom(_)          -> {error, unsupported_prf}.

%% {EncAlg, KeyLen, SaltLen, IsAead}
encr_params(#{id := 20, attrs := #{key_length := 256}}) ->
    {ok, aes_gcm_256, 32, 4, true};
encr_params(#{id := 20, attrs := #{key_length := 128}}) ->
    {ok, aes_gcm_128, 16, 4, true};
encr_params(#{id := 12, attrs := #{key_length := 256}}) ->
    {ok, aes_cbc_256, 32, 0, false};
encr_params(#{id := 12, attrs := #{key_length := 128}}) ->
    {ok, aes_cbc_128, 16, 0, false};
encr_params(_) ->
    {error, unsupported_encr}.

integ_params(none, true) ->
    {ok, none, 0};
integ_params(#{id := 12}, false) -> {ok, hmac_sha256_128, 32};
integ_params(#{id := 13}, false) -> {ok, hmac_sha384_192, 48};
integ_params(#{id := 14}, false) -> {ok, hmac_sha512_256, 64};
integ_params(_, _) ->
    {error, unsupported_integ}.
