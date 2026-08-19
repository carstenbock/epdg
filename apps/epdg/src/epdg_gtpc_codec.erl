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
         decode_recovery/1,
         %% PGW-initiated dedicated bearer signalling (TS 29.274 §7.2.3-§7.2.10)
         decode_create_bearer_request/1,
         decode_update_bearer_request/1,
         decode_delete_bearer_request/1,
         encode_create_bearer_response/1,
         encode_update_bearer_response/1,
         encode_delete_bearer_response/1]).

%% ?UE6_PREFIX_LEN: IPv6 prefix length carried in the PAA IE (TS 29.274 §8.14).
-include("epdg_ipv6.hrl").

%% GTPv2 message types (TS 29.274 §7)
-define(ECHO_REQ,            1).
-define(ECHO_RSP,            2).
-define(CREATE_SESSION_REQ,  32).
-define(CREATE_SESSION_RSP,  33).
-define(DELETE_SESSION_REQ,  36).
-define(DELETE_SESSION_RSP,  37).
-define(CREATE_BEARER_REQ,   95).
-define(CREATE_BEARER_RSP,   96).
-define(UPDATE_BEARER_REQ,   97).
-define(UPDATE_BEARER_RSP,   98).
-define(DELETE_BEARER_REQ,   99).
-define(DELETE_BEARER_RSP,  100).

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
-define(IE_BEARER_TFT,      84).
-define(IE_ULI,             86).
-define(IE_FTEID,           87).
-define(IE_BEARER_CTX,      93).
-define(IE_CHARGING_ID,     94).
-define(IE_PDN_TYPE,        99).

-define(IE_PTI,            100).
-define(IE_UE_TIME_ZONE,   114).
-define(IE_APN_RESTRICTION, 127).
-define(IE_SELECTION_MODE, 128).

%% TS 29.274 §8.22 Interface Types (for F-TEID)
-define(IFACE_S2B_EPDG_GTPC,  30).
-define(IFACE_S2B_EPDG_GTPU,  31).
-define(IFACE_S2B_PGW_GTPC,   32).
-define(IFACE_S2B_PGW_GTPU,   33).

%% TS 29.274 §8.22 — S5/S8 interface types (MME/SGW-emulation mode)
-define(IFACE_S5S8_SGW_GTPC,   6).
-define(IFACE_S5S8_SGW_GTPU,   4).
-define(IFACE_S5S8_PGW_GTPC,   7).
-define(IFACE_S5S8_PGW_GTPU,   5).

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
    LocalUIP = maps:get(local_u_ip, Params, LIP),
    PdnType  = maps:get(pdn_type, Params, 1), %% 1=IPv4 2=IPv6 3=IPv4v6
    HoV4     = maps:get(handover_v4, Params, undefined), %% {A,B,C,D} on handover
    HoV6     = maps:get(handover_v6, Params, undefined), %% /64 prefix tuple
    Mode     = maps:get(mode, Params, s2b),
    {CIface, UIface, UInst} =
        case Mode of
            s5s8 -> {?IFACE_S5S8_SGW_GTPC, ?IFACE_S5S8_SGW_GTPU, 2};
            _    -> {?IFACE_S2B_EPDG_GTPC, ?IFACE_S2B_EPDG_GTPU, 5}
        end,
    %% s5s8 dialect is always E-UTRAN (RAT=6, TS 29.274 §8.17).
    %% Force it here — the codec owns mode→dialect mapping — so callers
    %% (incl. the FSM which hardcodes rat_type => 3) are always correct.
    %% s2b uses whatever rat_type the caller supplies (default 3 = WLAN).
    ActualRAT = case Mode of
        s5s8 -> 6;
        _    -> RAT
    end,

    IEs = lists:flatten([
        ie_opt(IMSI /= <<>>,    encode_ie(?IE_IMSI, encode_tbcd(IMSI))),
        ie_opt(MSISDN /= <<>>,  encode_ie(?IE_MSISDN, encode_tbcd(MSISDN))),
        ie_opt(MEI /= <<>>,     encode_ie(?IE_MEI, encode_tbcd(MEI))),
        encode_ie(?IE_RAT_TYPE, <<ActualRAT:8>>),
        encode_serving_network_ie(SN),
        encode_fteid_ie(0, CIface, LocalCTeid, LIP),
        encode_ie(?IE_APN, encode_apn_labels(APN)),
        encode_ie(?IE_SELECTION_MODE, <<0:8>>),
        encode_ie(?IE_PDN_TYPE, <<0:5, PdnType:3>>),
        encode_paa_ie(PdnType, HoV4, HoV6),
        encode_indication_ho_ie(HoV4, HoV6),
        encode_apn_ambr_ie(AmbrUl, AmbrDl),
        encode_pco_request_ie(),
        encode_bearer_context_req_ie(EBI, LocalUTeid, LocalUIP, UIface, UInst),
        case Mode of
            s5s8 when SN =/= undefined ->
                encode_uli_ie(SN, maps:get(eci, Params, 0));
            _ -> <<>>
        end,
        case UeTZ of
            undefined -> <<>>;
            _         -> encode_ie(?IE_UE_TIME_ZONE, UeTZ)
        end,
        case Recovery of
            undefined -> <<>>;
            _         -> encode_ie(?IE_RECOVERY, <<Recovery:8>>)
        end
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
%% Encode — triggered responses to PGW-initiated bearer requests
%%
%%   Create Bearer Response (96) — TS 29.274 §7.2.4
%%   Update Bearer Response (98) — TS 29.274 §7.2.8
%%   Delete Bearer Response (100)— TS 29.274 §7.2.10.1
%%
%% Each carries the request's Sequence Number and is addressed to the PGW's
%% control-plane TEID (learned from the Create-Session-Response F-TEID). A
%% top-level Cause plus a Bearer Context (EBI + per-bearer Cause) per bearer.
%% The Create Bearer Response additionally advertises the ePDG's user-plane
%% F-TEID for the newly accepted bearer.
%%====================================================================

-spec encode_create_bearer_response(map()) -> binary().
encode_create_bearer_response(#{seq_num := Seq, teid := TEID} = P) ->
    Mode    = maps:get(mode, P, s2b),
    Cause   = maps:get(cause, P, 16),
    Bearers = maps:get(bearers, P, []),
    {OwnIface, OwnInst, PgwIface, PgwInst} = resp_uplane_ifaces(Mode),
    BCs = [ begin
                UTeid    = maps:get(u_teid, B, 0),
                UIp      = maps:get(u_ip, B, {0,0,0,0}),
                PgwUTeid = maps:get(pgw_u_teid, B, 0),
                PgwUIp   = maps:get(pgw_u_ip, B, {0,0,0,0}),
                EBIBin = encode_ie(?IE_EBI, <<0:4, Ebi:4>>),
                CBin   = encode_cause_ie(16),
                %% Own user-plane F-TEID: the endpoint the PGW-U sends downlink
                %% to (S2b-U ePDG instance 8 / S5/S8-U SGW instance 2).
                OwnF   = encode_fteid_ie(OwnInst, OwnIface, UTeid, UIp),
                %% Echo the PGW's user-plane F-TEID from the request so the PGW-C
                %% can bind the response to the pending bearer via
                %% smf_bearer_find_by_pgw_s5u_teid() (TS 29.274 §7.2.4; mirrors
                %% the SGW Create Bearer Response Open5GS expects). S2b-U PGW
                %% instance 9 / S5/S8-U PGW instance 3.
                PgwF   = case PgwUTeid of
                             T when is_integer(T), T > 0 ->
                                 encode_fteid_ie(PgwInst, PgwIface, T, PgwUIp);
                             _ -> <<>>
                         end,
                encode_ie(?IE_BEARER_CTX,
                          iolist_to_binary([EBIBin, CBin, OwnF, PgwF]))
            end
          || #{ebi := Ebi} = B <- Bearers ],
    Body = iolist_to_binary([encode_cause_ie(Cause) | BCs]),
    encode_gtpv2_header(?CREATE_BEARER_RSP, TEID, Seq, Body).

-spec encode_update_bearer_response(map()) -> binary().
encode_update_bearer_response(#{seq_num := Seq, teid := TEID} = P) ->
    encode_bearer_ack(?UPDATE_BEARER_RSP, Seq, TEID, P).

-spec encode_delete_bearer_response(map()) -> binary().
encode_delete_bearer_response(#{seq_num := Seq, teid := TEID} = P) ->
    encode_bearer_ack(?DELETE_BEARER_RSP, Seq, TEID, P).

%% Update/Delete Bearer Response share the shape: top-level Cause + one Bearer
%% Context (EBI + Cause) per affected bearer. No F-TEID (the bearer's user-plane
%% endpoints are unchanged / released).
encode_bearer_ack(MsgType, Seq, TEID, P) ->
    Cause   = maps:get(cause, P, 16),
    Bearers = maps:get(bearers, P, []),
    BCs = [ encode_ie(?IE_BEARER_CTX,
              iolist_to_binary([encode_ie(?IE_EBI, <<0:4, Ebi:4>>),
                                encode_cause_ie(16)]))
            || #{ebi := Ebi} <- Bearers ],
    Body = iolist_to_binary([encode_cause_ie(Cause) | BCs]),
    encode_gtpv2_header(MsgType, TEID, Seq, Body).

%% Responder + echoed-PGW user-plane F-TEID interfaces and Bearer-Context
%% instances for a Create Bearer Response (TS 29.274 Table 7.2.4-2).
%%
%% Unlike the Create Session Request (where the ePDG S2b-U F-TEID lives at
%% instance 5), the Create Bearer Response bearer context uses DIFFERENT
%% instances: the responder's own user-plane F-TEID is instance 8 (S2b ePDG)
%% or 2 (S5/S8 SGW), and the peer PGW's user-plane F-TEID is echoed at
%% instance 9 (S2b PGW) or 3 (S5/S8 PGW). Open5GS requires BOTH to be present
%% or it rejects the response ("No PGW TEID" / "No SGW TEID") and tears the
%% dedicated bearer back down.
%%
%% Returns {OwnIface, OwnInst, PgwIface, PgwInst}.
resp_uplane_ifaces(s5s8) ->
    {?IFACE_S5S8_SGW_GTPU, 2, ?IFACE_S5S8_PGW_GTPU, 3};
resp_uplane_ifaces(_) ->
    {?IFACE_S2B_EPDG_GTPU, 8, ?IFACE_S2B_PGW_GTPU, 9}.

%% Cause IE — TS 29.274 §8.4. Two octets: Cause value + spare/flags octet.
%% Offending-IE fields (octets 7-8) are only present for specific causes and
%% are omitted here.
encode_cause_ie(Cause) ->
    encode_ie(?IE_CAUSE, <<Cause:8, 0:8>>).

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
%%   pgw_c_fteid     - {Iface, TEID, IP} from top-level F-TEID (iface 32 S2b, or 7 S5/S8)
%%   pgw_u_fteid     - {Iface, TEID, IP} from Bearer Context F-TEID (iface 33 S2b, or 5 S5/S8)
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
        #{iface := I} = F when I =:= 32; I =:= 7 -> Acc#{pgw_c_fteid => F};
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
                #{iface := Iface} = F when Iface =:= 33; Iface =:= 5 -> F;
                _                                                      -> undefined
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
%% Decode — PGW-initiated dedicated bearer requests
%%
%%   Create Bearer Request  (95) — TS 29.274 §7.2.3
%%   Update Bearer Request  (97) — TS 29.274 §7.2.7
%%   Delete Bearer Request  (99) — TS 29.274 §7.2.9.1
%%
%% All three arrive on the ePDG's S2b-C TEID (GTPv2 header TEID field) and
%% carry the same Sequence Number the triggered response must echo. The
%% caller (`epdg_gtpc_client`) passes the already header-decoded map
%% (`#{type, teid, seq_num, ies}`), like decode_create_session_response/1.
%%====================================================================

-spec decode_create_bearer_request(map()) -> map().
decode_create_bearer_request(#{seq_num := Seq, teid := TEID, ies := IEs}) ->
    #{seq_num         => Seq,
      local_c_teid    => TEID,
      lbi             => first_ebi(IEs),
      pti             => first_pti(IEs),
      bearer_contexts => [decode_bearer_ctx(BC)
                          || {bearer_context, BC} <- IEs]}.

-spec decode_update_bearer_request(map()) -> map().
decode_update_bearer_request(#{seq_num := Seq, teid := TEID, ies := IEs}) ->
    #{seq_num         => Seq,
      local_c_teid    => TEID,
      pti             => first_pti(IEs),
      bearer_contexts => [decode_bearer_ctx(BC)
                          || {bearer_context, BC} <- IEs]}.

-spec decode_delete_bearer_request(map()) -> map().
decode_delete_bearer_request(#{seq_num := Seq, teid := TEID, ies := IEs}) ->
    %% The Delete Bearer Request carries either the Linked EPS Bearer ID (LBI,
    %% releasing the default bearer and thus the whole PDN connection) or a list
    %% of dedicated EPS Bearer IDs. decode_ies/1 does not retain the IE Instance
    %% that formally distinguishes the two, so we return every EBI present (top
    %% level plus any inside Bearer Contexts) and let the FSM decide: if the
    %% default (linked) bearer EBI is in the set it is a full PDN release,
    %% otherwise the listed dedicated bearers are removed.
    EbisTop = [E || {ebi, <<_:4, E:4>>} <- IEs],
    EbisBC  = lists:flatten(
                [ [Eb || {ebi, <<_:4, Eb:4>>} <- decode_ies(BC)]
                  || {bearer_context, BC} <- IEs ]),
    #{seq_num      => Seq,
      local_c_teid => TEID,
      pti          => first_pti(IEs),
      ebis         => lists:usort(EbisTop ++ EbisBC)}.

%% Decode a Bearer Context grouped IE from a request. `ebi` is `undefined` in a
%% Create Bearer Request (the ePDG assigns it) but present in Update Bearer.
decode_bearer_ctx(BCBin) ->
    Inner = decode_ies(BCBin),
    #{ebi         => first_ebi(Inner),
      tft         => kf_bin(bearer_tft, Inner),
      bearer_qos  => kf_bin(bearer_qos, Inner),
      charging_id => case lists:keyfind(charging_id, 1, Inner) of
                        {charging_id, <<I:32>>} -> I;
                        _                        -> undefined
                     end,
      pgw_u_fteid => bc_pgw_u_fteid(Inner)}.

first_ebi(IEs) ->
    case lists:keyfind(ebi, 1, IEs) of
        {ebi, <<_:4, E:4>>} -> E;
        _                   -> undefined
    end.

first_pti(IEs) ->
    case lists:keyfind(pti, 1, IEs) of
        {pti, <<P:8>>} -> P;
        _              -> undefined
    end.

kf_bin(Key, IEs) ->
    case lists:keyfind(Key, 1, IEs) of
        {Key, V} -> V;
        _        -> undefined
    end.

%% Pick the PGW's user-plane F-TEID from a Bearer Context: prefer the S2b-U
%% PGW GTP-U interface (33) or the S5/S8-U PGW GTP-U interface (5); fall back
%% to the first F-TEID present.
bc_pgw_u_fteid(Inner) ->
    Fs = [decode_fteid(F) || {fteid, F} <- Inner],
    case [F || #{iface := I} = F <- Fs, I =:= 33 orelse I =:= 5] of
        [F | _] -> F;
        []      -> case Fs of
                       [F0 | _] -> F0;
                       []       -> undefined
                   end
    end.

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
%% Handover attach: when the UE requested its existing address (via the IKEv2
%% CFG_REQUEST), relay it here so the PGW re-uses it. Open5GS treats a non-zero
%% PAA as a static address (ogs_pfcp_ue_ip_alloc), preserving the PDN/IP across
%% 3GPP<->non-3GPP handover (TS 23.402 §8). Fresh attach => zeros (dynamic).
%%
%% For IPv6 the relayed value is the /64 PDN prefix; the PGW allocates prefixes,
%% not addresses, and the UE forms its own interface identifier inside it.
encode_paa_ie(1, {A,B,C,D}, _) ->
    encode_ie(?IE_PAA, <<0:5, 1:3, A:8, B:8, C:8, D:8>>);
encode_paa_ie(2, _, {A,B,C,D,E,F,G,H}) ->
    encode_ie(?IE_PAA, <<0:5, 2:3, ?UE6_PREFIX_LEN:8,
                         A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>);
%% Dual-stack handover: either half may be absent (the UE is only moving one
%% family); the missing one goes as zeros so the PGW allocates it dynamically.
encode_paa_ie(3, HoV4, HoV6) when HoV4 =/= undefined; HoV6 =/= undefined ->
    {A,B,C,D} = case HoV4 of
        undefined -> {0,0,0,0};
        _         -> HoV4
    end,
    {A6,B6,C6,D6,E6,F6,G6,H6} = case HoV6 of
        undefined -> {0,0,0,0,0,0,0,0};
        _         -> HoV6
    end,
    encode_ie(?IE_PAA, <<0:5, 3:3, ?UE6_PREFIX_LEN:8,
                         A6:16,B6:16,C6:16,D6:16,E6:16,F6:16,G6:16,H6:16,
                         A:8,B:8,C:8,D:8>>);
encode_paa_ie(PdnType, _, _) ->
    encode_paa_ie(PdnType).

%% In the request we send 0.0.0.0 (dynamic allocation).
encode_paa_ie(1) -> encode_ie(?IE_PAA, <<0:5, 1:3, 0:32>>);
encode_paa_ie(2) -> encode_ie(?IE_PAA, <<0:5, 2:3, 0:8, 0:128>>);
encode_paa_ie(3) -> encode_ie(?IE_PAA, <<0:5, 3:3, 0:8, 0:128, 0:32>>);
encode_paa_ie(_) -> <<>>.

%% Indication IE (TS 29.274 §8.12) with only the Handover Indication (HI) flag
%% set (octet 1 bit 6 = 0x20). Signals a 3GPP->non-3GPP handover attach so the
%% PGW treats the Create-Session as PDN continuity rather than a fresh PDN. The
%% 10-octet body matches sizeof(ogs_gtp2_indication_t) in the paired Open5GS
%% build; all other flags are zero. Emitted whenever either family is being
%% handed over — an IPv6-only handover needs the HI flag just as much as an
%% IPv4 one, and without it the PGW builds a second PDN alongside the live one.
encode_indication_ho_ie(undefined, undefined) ->
    <<>>;
encode_indication_ho_ie(_HoV4, _HoV6) ->
    encode_ie(?IE_INDICATION,
              <<16#20, 0, 0, 0, 0, 0, 0, 0, 0, 0>>).

%% APN Aggregate Maximum Bit Rate (APN-AMBR) — TS 29.274 §8.7
%%   Uplink (32 bits, kbps) | Downlink (32 bits, kbps)
encode_apn_ambr_ie(UlKbps, DlKbps) ->
    encode_ie(?IE_AMBR, <<UlKbps:32, DlKbps:32>>).

%% Serving Network — TS 29.274 §8.18 (TBCD MCC+MNC, 3 octets)
%% Optional in a CSR on S2b; omit the IE when the caller has not supplied
%% a PLMN. TS 29.274 §7.2.1 lists Serving Network as Conditional-Optional.
encode_serving_network_ie(undefined) ->
    <<>>;
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

%% ULI (86) — TS 29.274 §8.21.
%% Flags octet selects which location fields follow.
%% Bit 4 (0x10) = ECGI present; ECGI = PLMN(3 octets) + ECI(28-bit, 4 octets).
encode_uli_ie({MCC, MNC}, ECI) ->
    Plmn = encode_plmn(MCC, MNC),
    encode_ie(?IE_ULI, <<2#00010000:8, Plmn/binary, ECI:32>>).

%% Bearer Context IE (93) — grouped, contains EBI + Bearer QoS + user-plane F-TEID.
%%
%% F-TEID Instance inside the Bearer Context on a CSR is per
%% TS 29.274 Table 7.2.1-2/3:
%%   S2b (RAT=WLAN):  iface 31 (S2b-U ePDG), instance 5
%%   S5/S8 (E-UTRAN): iface 4  (S5/S8 SGW GTP-U), instance 2
%% The caller selects UIface and UInst via the mode switch in
%% encode_create_session_request/1.
encode_bearer_context_req_ie(EBI, LocalUTeid, LIP, UIface, UInst) ->
    EBIBin  = encode_ie(?IE_EBI, <<0:4, EBI:4>>),
    FTeid   = encode_fteid_ie(UInst, UIface, LocalUTeid, LIP),
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
ie_type_atom(?IE_BEARER_TFT)    -> bearer_tft;
ie_type_atom(?IE_PTI)           -> pti;
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
