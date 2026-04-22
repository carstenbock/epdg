%%%-------------------------------------------------------------------
%%% @doc GTPv2-C minimal codec for S2b (Create/Delete/Echo).
%%% Encodes and decodes GTPv2-C headers and the IEs the ePDG actually
%%% exchanges with a PGW-C/SMF (Open5GS in our deployments).
%%%
%%% References:
%%%   3GPP TS 29.274 — GTPv2-C
%%%   3GPP TS 24.008 §10.5.6.3 — Protocol Configuration Options (PCO)
%%%   3GPP TS 23.402 §7.2.4 — S2b reference point
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_gtpc_codec).

-export([encode_create_session_request/1,
         encode_delete_session_request/1,
         encode_echo_request/1,
         encode_echo_response/1,
         decode_header/1,
         decode_create_session_response/1,
         decode_recovery/1]).

%% GTPv2 message types (TS 29.274 §7)
-define(ECHO_REQ,            1).
-define(ECHO_RSP,            2).
-define(CREATE_SESSION_REQ,  32).
-define(CREATE_SESSION_RSP,  33).
-define(DELETE_SESSION_REQ,  36).
-define(DELETE_SESSION_RSP,  37).

%% IE types (TS 29.274 §8)
-define(IE_IMSI,             1).
-define(IE_CAUSE,            2).
-define(IE_RECOVERY,         3).
-define(IE_APN,             71).
-define(IE_AMBR,            72).
-define(IE_EBI,             73).
-define(IE_MEI,             75).
-define(IE_MSISDN,          76).
-define(IE_INDICATION,      77).
-define(IE_PCO,             78).
-define(IE_PAA,             79).
-define(IE_BEARER_QOS,      80).
-define(IE_RAT_TYPE,        82).
-define(IE_SERVING_NET,     83).
-define(IE_ULI,             86).
-define(IE_FTEID,           87).
-define(IE_BEARER_CTX,      93).
-define(IE_CHARGING_ID,     94).
-define(IE_PDN_TYPE,        99).
-define(IE_UE_TIME_ZONE,   114).
-define(IE_APN_RESTRICTION, 127).
-define(IE_SELECTION_MODE, 128).

%% TS 29.274 §8.22 Interface Types (for F-TEID)
-define(IFACE_S2B_EPDG_GTPC,  30).
-define(IFACE_S2B_EPDG_GTPU,  31).
-define(IFACE_S2B_PGW_GTPC,   32).
-define(IFACE_S2B_PGW_GTPU,   33).

%%====================================================================
%% Encode — Create-Session-Request
%%====================================================================

-spec encode_create_session_request(map()) -> binary().
encode_create_session_request(#{seq_num := Seq,
                                 apn     := APN,
                                 rat_type := RAT,
                                 local_ip := LIP} = Params) ->
    IMSI     = maps:get(imsi,     Params, <<>>),
    MSISDN   = maps:get(msisdn,   Params, <<>>),
    MEI      = maps:get(mei,      Params, <<>>),
    Recovery = maps:get(recovery, Params, undefined),
    SN       = maps:get(serving_network, Params, undefined),
    UeTZ     = maps:get(ue_time_zone,    Params, undefined),
    AmbrDl   = maps:get(ambr_dl_kbps, Params, 1000000),
    AmbrUl   = maps:get(ambr_ul_kbps, Params,  500000),
    EBI      = maps:get(ebi, Params, 5),
    LocalCTeid = maps:get(local_c_teid, Params, 0),
    LocalUTeid = maps:get(local_u_teid, Params, 0),
    PdnType  = maps:get(pdn_type, Params, 1), %% 1=IPv4 2=IPv6 3=IPv4v6

    IEs = lists:flatten([
        ie_opt(IMSI /= <<>>,    encode_ie(?IE_IMSI, encode_tbcd(IMSI))),
        ie_opt(MSISDN /= <<>>,  encode_ie(?IE_MSISDN, encode_tbcd(MSISDN))),
        ie_opt(MEI /= <<>>,     encode_ie(?IE_MEI, encode_tbcd(MEI))),
        encode_ie(?IE_RAT_TYPE, <<RAT:8>>),
        ie_opt(SN /= undefined,     encode_serving_network_ie(SN)),
        encode_fteid_ie(0, ?IFACE_S2B_EPDG_GTPC, LocalCTeid, LIP),
        encode_ie(?IE_APN, encode_apn_labels(APN)),
        encode_ie(?IE_SELECTION_MODE, <<0:8>>),
        encode_ie(?IE_PDN_TYPE, <<0:5, PdnType:3>>),
        encode_paa_ie(PdnType),
        encode_apn_ambr_ie(AmbrUl, AmbrDl),
        encode_pco_request_ie(),
        encode_bearer_context_req_ie(EBI, LocalUTeid, LIP),
        ie_opt(UeTZ /= undefined,   encode_ie(?IE_UE_TIME_ZONE, UeTZ)),
        ie_opt(Recovery /= undefined,
               encode_ie(?IE_RECOVERY, <<Recovery:8>>))
    ]),
    encode_gtpv2_header(?CREATE_SESSION_REQ, 0, Seq,
                        iolist_to_binary(IEs)).

%%====================================================================
%% Encode — Delete-Session-Request
%%====================================================================

-spec encode_delete_session_request(map()) -> binary().
encode_delete_session_request(#{seq_num := Seq, teid := TEID, ebi := EBI}) ->
    IEs = encode_ie(?IE_EBI, <<0:4, EBI:4>>),
    encode_gtpv2_header(?DELETE_SESSION_REQ, TEID, Seq,
                        iolist_to_binary([IEs])).

%%====================================================================
%% Encode — Echo Request / Response (TS 29.274 §7.1)
%%
%% Echo messages are TEID-less (no TEID field in the header) and carry
%% a Recovery IE with the sender's restart counter.
%%====================================================================

-spec encode_echo_request(map()) -> binary().
encode_echo_request(#{seq_num := Seq, recovery := R}) ->
    IEs = encode_ie(?IE_RECOVERY, <<R:8>>),
    encode_gtpv2_header_teidless(?ECHO_REQ, Seq, iolist_to_binary([IEs])).

-spec encode_echo_response(map()) -> binary().
encode_echo_response(#{seq_num := Seq, recovery := R}) ->
    IEs = encode_ie(?IE_RECOVERY, <<R:8>>),
    encode_gtpv2_header_teidless(?ECHO_RSP, Seq, iolist_to_binary([IEs])).

%%====================================================================
%% Decode — header + IE list
%%====================================================================

-spec decode_header(binary()) -> {ok, map()} | {error, term()}.
%% Version=2, P=*, T=1 (TEID present)
decode_header(<<2:3, _P:1, 1:1, _Spare:3, Type:8, Len:16,
                TEID:32, Seq:24, _Spare2:8, Rest/binary>>)
  when byte_size(Rest) >= (Len - 8) ->
    IELen = Len - 8,
    <<IEData:IELen/binary, _/binary>> = Rest,
    {ok, #{type => Type, teid => TEID, seq_num => Seq,
           ies => decode_ies(IEData)}};
%% T=0 (no TEID): Echo, Version Not Supported Notification
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
%% Decode — Create-Session-Response extraction (TS 29.274 §7.2.2)
%%
%% Returns a map with the fields the ePDG needs to bring up the tunnel:
%%   cause           - numeric cause value (16 = Request accepted)
%%   paa             - {pdn_type, Addr}
%%   pgw_c_fteid     - {Iface, TEID, IP} from top-level F-TEID (iface 32)
%%   pgw_u_fteid     - {Iface, TEID, IP} from Bearer Context F-TEID (iface 33)
%%   pco             - map with optional pcscf_v4, dns_v4, pcscf_v6, dns_v6
%%   ebi             - EBS-Bearer-Identity from Bearer Context
%%   charging_id     - integer (optional)
%%====================================================================

-spec decode_create_session_response(map()) -> map().
decode_create_session_response(#{ies := IEs}) ->
    Base = #{cause        => undefined,
             paa          => undefined,
             pgw_c_fteid  => undefined,
             pgw_u_fteid  => undefined,
             ebi          => undefined,
             pco          => #{},
             charging_id  => undefined,
             recovery     => undefined},
    lists:foldl(fun extract_csr_ie/2, Base, IEs).

extract_csr_ie({cause, <<C:8, _/binary>>}, Acc) -> Acc#{cause => C};
extract_csr_ie({recovery, <<R:8>>}, Acc)         -> Acc#{recovery => R};
extract_csr_ie({paa, PaaBin}, Acc)              -> Acc#{paa => decode_paa(PaaBin)};
extract_csr_ie({fteid, FBin}, Acc) ->
    case decode_fteid(FBin) of
        #{iface := 32} = F -> Acc#{pgw_c_fteid => F};
        _ -> Acc
    end;
extract_csr_ie({bearer_context, BCBin}, Acc) ->
    Inner = decode_ies(BCBin),
    EBI = case lists:keyfind(ebi, 1, Inner) of
        {ebi, <<_:4, E:4>>} -> E;
        _ -> undefined
    end,
    ChId = case lists:keyfind(charging_id, 1, Inner) of
        {charging_id, <<I:32>>} -> I;
        _ -> undefined
    end,
    PgwUF = case lists:keyfind(fteid, 1, Inner) of
        {fteid, FBin} ->
            case decode_fteid(FBin) of
                #{iface := 33} = F -> F;
                _                  -> undefined
            end;
        _ -> undefined
    end,
    maps:merge(Acc, #{ebi => EBI,
                       pgw_u_fteid => PgwUF,
                       charging_id => ChId});
extract_csr_ie({pco, PcoBin}, Acc) -> Acc#{pco => decode_pco_containers(PcoBin)};
extract_csr_ie(_, Acc) -> Acc.

-spec decode_recovery(binary()) -> non_neg_integer() | undefined.
decode_recovery(<<R:8>>) -> R;
decode_recovery(_) -> undefined.

%%====================================================================
%% Header builders
%%====================================================================

encode_gtpv2_header(Type, TEID, Seq, IEs) ->
    Len = 8 + byte_size(IEs),
    %% Version=2, P=0, T=1 (TEID present)
    <<2:3, 0:1, 1:1, 0:3, Type:8, Len:16, TEID:32, Seq:24, 0:8, IEs/binary>>.

encode_gtpv2_header_teidless(Type, Seq, IEs) ->
    Len = 4 + byte_size(IEs),
    <<2:3, 0:1, 0:1, 0:3, Type:8, Len:16, Seq:24, 0:8, IEs/binary>>.

%%====================================================================
%% Generic IE encoding — TS 29.274 §8.2
%%
%%   Type (8) | Length (16) | Spare(4) | Instance(4) | Value
%%
%% Instance is 0 for the first occurrence; we use non-zero only inside
%% Bearer Context for the grouped F-TEID case.
%%====================================================================

encode_ie(Type, Value) -> encode_ie(Type, 0, Value).

encode_ie(Type, Inst, Value) ->
    Len = byte_size(Value),
    <<Type:8, Len:16, 0:4, Inst:4, Value/binary>>.

ie_opt(true, Bin) -> Bin;
ie_opt(false, _)  -> <<>>.

%%====================================================================
%% Specific IE encoders
%%====================================================================

%% F-TEID — TS 29.274 §8.22
%%   V4(1) | V6(1) | Interface Type (6) | TEID (32)
%%   [IPv4 Address (32)]
%%   [IPv6 Address (128)]
encode_fteid_ie(Inst, Iface, TEID, {A,B,C,D}) ->
    V = <<1:1, 0:1, Iface:6, TEID:32, A:8, B:8, C:8, D:8>>,
    encode_ie(?IE_FTEID, Inst, V);
encode_fteid_ie(Inst, Iface, TEID, {A,B,C,D,E,F,G,H}) ->
    Addr6 = <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>,
    V = <<0:1, 1:1, Iface:6, TEID:32, Addr6/binary>>,
    encode_ie(?IE_FTEID, Inst, V).

%% PDN Address Allocation (PAA) — TS 29.274 §8.14
%%   Spare(5) | PDN Type (3) | Address(es)
%%     1=IPv4  2=IPv6  3=IPv4v6
%% In the request we send 0.0.0.0 (dynamic allocation).
encode_paa_ie(1) -> encode_ie(?IE_PAA, <<0:5, 1:3, 0:32>>);
encode_paa_ie(2) -> encode_ie(?IE_PAA, <<0:5, 2:3, 0:8, 0:128>>);
encode_paa_ie(3) -> encode_ie(?IE_PAA, <<0:5, 3:3, 0:8, 0:128, 0:32>>);
encode_paa_ie(_) -> <<>>.

%% APN Aggregate Maximum Bit Rate (APN-AMBR) — TS 29.274 §8.7
%%   Uplink (32 bits, kbps) | Downlink (32 bits, kbps)
encode_apn_ambr_ie(UlKbps, DlKbps) ->
    encode_ie(?IE_AMBR, <<UlKbps:32, DlKbps:32>>).

%% Serving Network — TS 29.274 §8.18 (TBCD MCC+MNC, 3 octets)
encode_serving_network_ie({MCC, MNC}) when is_binary(MCC), is_binary(MNC) ->
    encode_ie(?IE_SERVING_NET, encode_plmn(MCC, MNC));
encode_serving_network_ie(Bin) when is_binary(Bin), byte_size(Bin) == 3 ->
    encode_ie(?IE_SERVING_NET, Bin).

%% TS 24.008 §10.5.1.3 PLMN encoding (TBCD nibble swap).
encode_plmn(<<M1,M2,M3>>, MNC) ->
    {N1, N2, N3} = case MNC of
        <<X1, X2>>     -> {c2n(X1), c2n(X2), 16#F};
        <<X1, X2, X3>> -> {c2n(X1), c2n(X2), c2n(X3)}
    end,
    A = c2n(M2) bsl 4 bor c2n(M1),
    B = N3     bsl 4 bor c2n(M3),
    C = N2     bsl 4 bor N1,
    <<A, B, C>>.

c2n(C) when C >= $0, C =< $9 -> C - $0.

%% Bearer Context IE (93) — grouped, contains EBI + Bearer QoS
%% + ePDG S2b-U F-TEID (iface 31).
encode_bearer_context_req_ie(EBI, LocalUTeid, LIP) ->
    EBIBin  = encode_ie(?IE_EBI, <<0:4, EBI:4>>),
    FTeid   = encode_fteid_ie(2, ?IFACE_S2B_EPDG_GTPU, LocalUTeid, LIP),
    %% TS 29.274 §8.15 Bearer QoS: PCI(1)|PL(4)|PVI(1) | Label(8) |
    %% MBR UL(40) | MBR DL(40) | GBR UL(40) | GBR DL(40)
    QoS = <<0:1, 15:4, 0:1, 0:2,  %% reserved bits around ARP
            9:8,                 %% QCI = 9 (default non-GBR for IMS signalling)
            0:40, 0:40, 0:40, 0:40>>,
    BQoS = encode_ie(?IE_BEARER_QOS, QoS),
    Inner = iolist_to_binary([EBIBin, BQoS, FTeid]),
    encode_ie(?IE_BEARER_CTX, Inner).

%% APN encoding per TS 23.003 §9.1: dotted-label form with 1-byte
%% length prefixes for each label (e.g. "ims" → <<3, "ims">>).
encode_apn_labels(Bin) when is_binary(Bin) ->
    Parts = binary:split(Bin, <<".">>, [global]),
    iolist_to_binary([<<(byte_size(P)):8, P/binary>> || P <- Parts]).

%%====================================================================
%% PCO — TS 24.008 §10.5.6.3 (carried verbatim inside the PCO IE)
%%
%% Octet 3  : bit 8 (ext) = 1 | bits 7..4 spare | bits 3..1 config proto
%%            0x80 = PPP for IP PDP / IP PDN
%% Followed : Protocol/Container ID (16) | Length (8) | Value (Length)
%%
%% Request-side container IDs for VoWiFi (all zero-length in the request):
%%   0x0001 P-CSCF IPv6 Address Request
%%   0x0002 IM CN Subsystem Signalling Flag
%%   0x0003 DNS Server IPv6 Address Request
%%   0x000A IP Address Allocation via NAS Signalling
%%   0x000C P-CSCF IPv4 Address Request
%%   0x000D DNS Server IPv4 Address Request
%%====================================================================

-define(PCO_CFG_PPP_IP, 16#80).

-define(PCO_PCSCF_IPV6,        16#0001).
-define(PCO_IM_CN_FLAG,        16#0002).
-define(PCO_DNS_IPV6,          16#0003).
-define(PCO_IP_ALLOC_NAS,      16#000A).
-define(PCO_PCSCF_IPV4,        16#000C).
-define(PCO_DNS_IPV4,          16#000D).

encode_pco_request_ie() ->
    Containers = [
        {?PCO_PCSCF_IPV4,   <<>>},
        {?PCO_DNS_IPV4,     <<>>},
        {?PCO_PCSCF_IPV6,   <<>>},
        {?PCO_DNS_IPV6,     <<>>},
        {?PCO_IP_ALLOC_NAS, <<>>},
        {?PCO_IM_CN_FLAG,   <<>>}
    ],
    Body = iolist_to_binary([encode_pco_container(C) || C <- Containers]),
    encode_ie(?IE_PCO, <<?PCO_CFG_PPP_IP:8, Body/binary>>).

encode_pco_container({Id, Val}) ->
    L = byte_size(Val),
    <<Id:16, L:8, Val/binary>>.

%% Decode the PCO IE the PGW returns. We surface the attributes that
%% matter for VoWiFi: P-CSCF v4/v6 lists and DNS v4/v6 lists.
decode_pco_containers(<<?PCO_CFG_PPP_IP:8, Rest/binary>>) ->
    decode_pco_list(Rest, #{});
decode_pco_containers(<<_:8, Rest/binary>>) ->
    decode_pco_list(Rest, #{});
decode_pco_containers(_) ->
    #{}.

decode_pco_list(<<>>, Acc) -> Acc;
decode_pco_list(<<Id:16, Len:8, Rest/binary>>, Acc) ->
    case Rest of
        <<Val:Len/binary, More/binary>> ->
            decode_pco_list(More, merge_pco(Id, Val, Acc));
        _ -> Acc
    end;
decode_pco_list(_, Acc) -> Acc.

merge_pco(?PCO_PCSCF_IPV4, <<A:8,B:8,C:8,D:8, _/binary>>, Acc) ->
    append_list(pcscf_v4, {A,B,C,D}, Acc);
merge_pco(?PCO_DNS_IPV4,   <<A:8,B:8,C:8,D:8, _/binary>>, Acc) ->
    append_list(dns_v4, {A,B,C,D}, Acc);
merge_pco(?PCO_PCSCF_IPV6, <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16, _/binary>>, Acc) ->
    append_list(pcscf_v6, {A,B,C,D,E,F,G,H}, Acc);
merge_pco(?PCO_DNS_IPV6,   <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16, _/binary>>, Acc) ->
    append_list(dns_v6, {A,B,C,D,E,F,G,H}, Acc);
merge_pco(?PCO_IM_CN_FLAG, _, Acc) ->
    Acc#{im_cn => true};
merge_pco(_, _, Acc) -> Acc.

append_list(K, V, Acc) ->
    maps:update_with(K, fun(L) -> L ++ [V] end, [V], Acc).

%%====================================================================
%% PAA / F-TEID decoders for use on the response path
%%====================================================================

decode_paa(<<_:5, 1:3, A:8, B:8, C:8, D:8>>) ->
    #{pdn_type => v4, ipv4 => {A,B,C,D}};
decode_paa(<<_:5, 2:3, _Prefix:8, A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>) ->
    #{pdn_type => v6, ipv6 => {A,B,C,D,E,F,G,H}};
decode_paa(<<_:5, 3:3, _Prefix:8,
              A6:16,B6:16,C6:16,D6:16,E6:16,F6:16,G6:16,H6:16,
              A:8,B:8,C:8,D:8>>) ->
    #{pdn_type => v4v6,
      ipv4     => {A,B,C,D},
      ipv6     => {A6,B6,C6,D6,E6,F6,G6,H6}};
decode_paa(_) -> #{}.

decode_fteid(<<V4:1, V6:1, Iface:6, TEID:32, Rest/binary>>) ->
    {IP, _} = pop_fteid_addr(V4, V6, Rest),
    #{iface => Iface, teid => TEID, ip => IP};
decode_fteid(_) -> #{}.

pop_fteid_addr(1, 0, <<A:8,B:8,C:8,D:8, R/binary>>) -> {{A,B,C,D}, R};
pop_fteid_addr(0, 1, <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16, R/binary>>) ->
    {{A,B,C,D,E,F,G,H}, R};
pop_fteid_addr(1, 1, <<A:8,B:8,C:8,D:8,
                        A6:16,B6:16,C6:16,D6:16,E6:16,F6:16,G6:16,H6:16, R/binary>>) ->
    {[{A,B,C,D}, {A6,B6,C6,D6,E6,F6,G6,H6}], R};
pop_fteid_addr(_, _, R) -> {undefined, R}.

%%====================================================================
%% TBCD encoding (IMSI/MSISDN/MEI) — swapped nibbles, pad with 0xF
%%====================================================================

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
%% Generic IE decoder
%%====================================================================

decode_ies(<<>>) -> [];
decode_ies(<<Type:8, Len:16, _CR:4, _Inst:4, Value:Len/binary, Rest/binary>>) ->
    [{ie_type_atom(Type), Value} | decode_ies(Rest)];
decode_ies(_) -> [].

ie_type_atom(?IE_CAUSE)         -> cause;
ie_type_atom(?IE_RECOVERY)      -> recovery;
ie_type_atom(?IE_IMSI)          -> imsi;
ie_type_atom(?IE_APN)           -> apn;
ie_type_atom(?IE_AMBR)          -> ambr;
ie_type_atom(?IE_FTEID)         -> fteid;
ie_type_atom(?IE_BEARER_CTX)    -> bearer_context;
ie_type_atom(?IE_BEARER_QOS)    -> bearer_qos;
ie_type_atom(?IE_PAA)           -> paa;
ie_type_atom(?IE_PCO)           -> pco;
ie_type_atom(?IE_EBI)           -> ebi;
ie_type_atom(?IE_MEI)           -> mei;
ie_type_atom(?IE_MSISDN)        -> msisdn;
ie_type_atom(?IE_PDN_TYPE)      -> pdn_type;
ie_type_atom(?IE_RAT_TYPE)      -> rat_type;
ie_type_atom(?IE_SERVING_NET)   -> serving_network;
ie_type_atom(?IE_ULI)           -> uli;
ie_type_atom(?IE_CHARGING_ID)   -> charging_id;
ie_type_atom(?IE_UE_TIME_ZONE)  -> ue_time_zone;
ie_type_atom(?IE_SELECTION_MODE)-> selection_mode;
ie_type_atom(?IE_INDICATION)    -> indication;
ie_type_atom(?IE_APN_RESTRICTION) -> apn_restriction;
ie_type_atom(N)                 -> {unknown_ie, N}.
