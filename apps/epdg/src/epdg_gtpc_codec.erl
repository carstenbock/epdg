%%%-------------------------------------------------------------------
%%% @doc GTPv2-C minimal codec for S2b (Create/Delete Session).
%%% Encodes and decodes GTPv2-C headers and a subset of IEs needed
%%% for ePDG ↔ PGW-C/SMF communication.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_gtpc_codec).

-export([encode_create_session_request/1,
         encode_delete_session_request/1,
         decode_header/1]).

%% GTPv2 message types
-define(CREATE_SESSION_REQ,  32).
-define(CREATE_SESSION_RSP,  33).
-define(DELETE_SESSION_REQ,  36).
-define(DELETE_SESSION_RSP,  37).

%% IE types
-define(IE_IMSI,             1).
-define(IE_CAUSE,            2).
-define(IE_APN,             71).
-define(IE_MSISDN,          76).
-define(IE_RAT_TYPE,        82).
-define(IE_FTEID,           87).
-define(IE_BEARER_CTX,      93).
-define(IE_PDN_TYPE,        99).
-define(IE_PCO,             78).
-define(IE_EBI,             73).

%%====================================================================
%% Encode
%%====================================================================

-spec encode_create_session_request(map()) -> binary().
encode_create_session_request(#{seq_num := Seq, imsi := IMSI,
                                 apn := APN, rat_type := RAT,
                                 local_ip := {A,B,C,D}} = Params) ->
    MSISDN = maps:get(msisdn, Params, <<>>),

    IEs = iolist_to_binary([
        encode_ie(?IE_IMSI, encode_tbcd(IMSI)),
        encode_ie(?IE_MSISDN, encode_tbcd(MSISDN)),
        encode_ie(?IE_APN, APN),
        encode_ie(?IE_RAT_TYPE, <<RAT:8>>),
        encode_ie(?IE_PDN_TYPE, <<1:8>>),
        encode_ie(?IE_FTEID, <<0:4, 1:1, 0:1, 0:1, 0:1, 31:8, 0:32, A:8, B:8, C:8, D:8>>),
        encode_pco_ie(),
        encode_bearer_context_ie()
    ]),

    encode_gtpv2_header(?CREATE_SESSION_REQ, 0, Seq, IEs).

-spec encode_delete_session_request(map()) -> binary().
encode_delete_session_request(#{seq_num := Seq, teid := TEID, ebi := EBI}) ->
    IEs = encode_ie(?IE_EBI, <<0:4, EBI:4>>),
    encode_gtpv2_header(?DELETE_SESSION_REQ, TEID, Seq, IEs).

%%====================================================================
%% Decode
%%====================================================================

-spec decode_header(binary()) -> {ok, map()} | {error, term()}.
decode_header(<<2:3, _P:1, _T:1, _Spare:3, Type:8, Len:16,
                TEID:32, Seq:24, _Spare2:8, Rest/binary>>)
  when byte_size(Rest) >= (Len - 8) ->
    IELen = Len - 8,
    <<IEData:IELen/binary, _/binary>> = Rest,
    {ok, #{type => Type, teid => TEID, seq_num => Seq,
           ies => decode_ies(IEData)}};
decode_header(<<2:3, _P:1, 0:1, _Spare:3, Type:8, Len:16,
                Seq:24, _Spare2:8, Rest/binary>>)
  when byte_size(Rest) >= (Len - 4) ->
    IELen = Len - 4,
    <<IEData:IELen/binary, _/binary>> = Rest,
    {ok, #{type => Type, teid => 0, seq_num => Seq,
           ies => decode_ies(IEData)}};
decode_header(_) ->
    {error, invalid_gtpv2_header}.

%%====================================================================
%% Internal — IE encoding
%%====================================================================

encode_gtpv2_header(Type, TEID, Seq, IEs) ->
    Len = 8 + byte_size(IEs),
    <<2:3, 0:1, 1:1, 0:3, Type:8, Len:16, TEID:32, Seq:24, 0:8, IEs/binary>>.

encode_ie(Type, Value) ->
    Len = byte_size(Value),
    <<Type:8, Len:16, 0:4, 0:4, Value/binary>>.

encode_pco_ie() ->
    %% PCO requesting P-CSCF (IPv4+IPv6), DNS, IM CN signaling flag
    PCO = <<16#80,
            16#00, 16#0C, 16#00,
            16#00, 16#0D, 16#00,
            16#00, 16#0A, 16#00,
            16#00, 16#02, 16#00>>,
    encode_ie(?IE_PCO, PCO).

encode_bearer_context_ie() ->
    %% Bearer context with EBI=5, QCI=5, ARP priority=1
    EBI = encode_ie(?IE_EBI, <<0:4, 5:4>>),
    QoS = <<0:8, 5:8, 1:4, 0:1, 0:1, 0:2, 0:64, 0:64>>,
    BearerQoS = encode_ie(80, QoS),
    Inner = iolist_to_binary([EBI, BearerQoS]),
    encode_ie(?IE_BEARER_CTX, Inner).

encode_tbcd(<<>>) -> <<>>;
encode_tbcd(Bin) when is_binary(Bin) ->
    Digits = [D - $0 || <<D>> <= Bin, D >= $0, D =< $9],
    encode_tbcd_digits(Digits);
encode_tbcd(_) -> <<>>.

encode_tbcd_digits([]) -> <<>>;
encode_tbcd_digits([A]) -> <<16#F:4, A:4>>;
encode_tbcd_digits([A, B | Rest]) ->
    <<B:4, A:4, (encode_tbcd_digits(Rest))/binary>>.

%%====================================================================
%% Internal — IE decoding
%%====================================================================

decode_ies(<<>>) -> [];
decode_ies(<<Type:8, Len:16, _CR:4, _Inst:4, Value:Len/binary, Rest/binary>>) ->
    [{ie_type_atom(Type), Value} | decode_ies(Rest)];
decode_ies(_) -> [].

ie_type_atom(?IE_CAUSE)    -> cause;
ie_type_atom(?IE_IMSI)     -> imsi;
ie_type_atom(?IE_APN)      -> apn;
ie_type_atom(?IE_FTEID)    -> fteid;
ie_type_atom(?IE_BEARER_CTX) -> bearer_context;
ie_type_atom(?IE_PCO)      -> pco;
ie_type_atom(?IE_EBI)      -> ebi;
ie_type_atom(?IE_PDN_TYPE) -> pdn_type;
ie_type_atom(?IE_RAT_TYPE) -> rat_type;
ie_type_atom(?IE_MSISDN)   -> msisdn;
ie_type_atom(N)            -> {unknown_ie, N}.
