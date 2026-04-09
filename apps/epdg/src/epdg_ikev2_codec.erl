%%%-------------------------------------------------------------------
%%% @doc IKEv2 binary codec (RFC 7296).
%%% Encodes and decodes IKEv2 headers, payloads, and transforms.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_codec).

-export([decode_header/1, encode_header/1,
         decode_payloads/2, encode_payloads/1,
         decode_sa_payload/1]).

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
-define(PL_CERT,  37).
-define(PL_AUTH,  39).
-define(PL_NONCE, 40).
-define(PL_NOTIFY,41).
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
encode_payloads(Payloads) ->
    encode_payloads_acc(Payloads, []).

encode_payloads_acc([{Type, Data}], Acc) ->
    PLLen = 4 + byte_size(Data),
    PL = <<?PL_NONE:8, 0:8, PLLen:16, Data/binary>>,
    FirstType = payload_type_raw(Type),
    {FirstType, iolist_to_binary(lists:reverse([PL | Acc]))};
encode_payloads_acc([{Type, Data} | Rest], Acc) ->
    {NextType, _} = hd(Rest),
    NextTypeRaw = payload_type_raw(NextType),
    PLLen = 4 + byte_size(Data),
    PL = <<NextTypeRaw:8, 0:8, PLLen:16, Data/binary>>,
    case Acc of
        [] ->
            encode_payloads_acc(Rest, [PL]);
        _ ->
            encode_payloads_acc(Rest, [PL | Acc])
    end;
encode_payloads_acc([], Acc) ->
    {?PL_NONE, iolist_to_binary(lists:reverse(Acc))}.

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
payload_type_atom(?PL_CERT)   -> cert;
payload_type_atom(?PL_AUTH)   -> auth;
payload_type_atom(?PL_NONCE)  -> nonce;
payload_type_atom(?PL_NOTIFY) -> notify;
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
payload_type_raw(cert)   -> ?PL_CERT;
payload_type_raw(auth)   -> ?PL_AUTH;
payload_type_raw(nonce)  -> ?PL_NONCE;
payload_type_raw(notify) -> ?PL_NOTIFY;
payload_type_raw(tsi)    -> ?PL_TSI;
payload_type_raw(tsr)    -> ?PL_TSR;
payload_type_raw(sk)     -> ?PL_SK;
payload_type_raw(cp)     -> ?PL_CP;
payload_type_raw(eap)    -> ?PL_EAP;
payload_type_raw(_)      -> ?PL_NONE.
