%%%-------------------------------------------------------------------
%%% @doc EPS Bearer Level Traffic Flow Template (TFT) parsing and packet
%%% matching for S2b dedicated bearers.
%%%
%%% When the PGW activates a dedicated bearer over S2b it sends the uplink
%%% packet filters as a Bearer TFT (TS 29.274 §8.19, carrying the TS 24.008
%%% §10.5.6.12 TFT structure). The ePDG has no radio to hand the TFT to, so
%%% it uses the filters itself: uplink inner-IP packets that match a
%%% dedicated bearer's uplink filters are steered onto that bearer's S2b-U
%%% GTP-U tunnel instead of the default bearer (see epdg_gtpu_forwarder).
%%%
%%% `parse/1' turns raw TFT bytes into a list of packet filters;
%%% `match/2' returns whether an inner IP packet matches any uplink (or
%%% bidirectional) filter in a parsed set.
%%%
%%% Scope: the address / protocol / port component types that VoWiFi voice
%%% and video bearers actually use are matched precisely. Type-of-service,
%%% flow-label and IPsec SPI components are accepted but not evaluated (they
%%% do not affect which UE's own bearer a packet belongs to). Any component
%%% type we cannot parse marks the filter invalid, so the packet falls back
%%% to the default bearer rather than being misrouted.
%%%
%%% References:
%%%   3GPP TS 24.008 §10.5.6.12 — Traffic Flow Template
%%%   3GPP TS 29.274 §8.19      — Bearer TFT IE
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_tft).

-export([parse/1, match/2]).

-type filter() :: #{id := non_neg_integer(),
                    direction := non_neg_integer(),
                    precedence := non_neg_integer(),
                    components := [term()]}.
-export_type([filter/0]).

%% TFT operation codes (TS 24.008 §10.5.6.12, octet 1 bits 8-6).
-define(TFT_OP_CREATE,  2#001).
-define(TFT_OP_ADD,     2#011).
-define(TFT_OP_REPLACE, 2#100).

%%====================================================================
%% Parse
%%====================================================================

%% Parse a raw Bearer TFT into a list of packet filters. Only the operations
%% that carry full packet filters (create / add / replace) are decoded; delete
%% and "no operation" TFTs yield an empty list (nothing to classify on).
-spec parse(binary() | undefined) -> [filter()].
parse(undefined) -> [];
parse(<<Op:3, _E:1, N:4, Rest/binary>>)
  when Op =:= ?TFT_OP_CREATE; Op =:= ?TFT_OP_ADD; Op =:= ?TFT_OP_REPLACE ->
    parse_filters(N, Rest, []);
parse(_) -> [].

parse_filters(0, _Rest, Acc) -> lists:reverse(Acc);
parse_filters(N, <<_Spare:2, Dir:2, Id:4, Prec:8, Len:8,
                   Contents:Len/binary, Rest/binary>>, Acc) when N > 0 ->
    Filter = #{id         => Id,
               direction  => Dir,
               precedence => Prec,
               components => parse_components(Contents)},
    parse_filters(N - 1, Rest, [Filter | Acc]);
parse_filters(_, _, Acc) ->
    %% Truncated / malformed filter list — keep whatever parsed cleanly.
    lists:reverse(Acc).

parse_components(<<>>) -> [];
parse_components(<<Type:8, Rest/binary>>) ->
    case parse_component(Type, Rest) of
        {ok, Comp, Rest2} -> [Comp | parse_components(Rest2)];
        error             -> [invalid]
    end;
parse_components(_) -> [invalid].

%% Component type identifiers — TS 24.008 §10.5.6.12 Table 10.5.162.
parse_component(16#10, <<A:8,B:8,C:8,D:8, M1:8,M2:8,M3:8,M4:8, R/binary>>) ->
    {ok, {ipv4_remote, {A,B,C,D}, {M1,M2,M3,M4}}, R};
parse_component(16#11, <<A:8,B:8,C:8,D:8, M1:8,M2:8,M3:8,M4:8, R/binary>>) ->
    {ok, {ipv4_local, {A,B,C,D}, {M1,M2,M3,M4}}, R};
parse_component(16#20, <<Addr:16/binary, Mask:16/binary, R/binary>>) ->
    {ok, {ipv6_remote_mask, Addr, Mask}, R};
parse_component(16#21, <<Addr:16/binary, Pref:8, R/binary>>) ->
    {ok, {ipv6_remote_pref, Addr, Pref}, R};
parse_component(16#23, <<Addr:16/binary, Pref:8, R/binary>>) ->
    {ok, {ipv6_local_pref, Addr, Pref}, R};
parse_component(16#30, <<P:8, R/binary>>) ->
    {ok, {proto, P}, R};
parse_component(16#40, <<Port:16, R/binary>>) ->
    {ok, {local_port, Port}, R};
parse_component(16#41, <<Lo:16, Hi:16, R/binary>>) ->
    {ok, {local_port_range, Lo, Hi}, R};
parse_component(16#50, <<Port:16, R/binary>>) ->
    {ok, {remote_port, Port}, R};
parse_component(16#51, <<Lo:16, Hi:16, R/binary>>) ->
    {ok, {remote_port_range, Lo, Hi}, R};
%% Accepted but not evaluated (do not narrow which UE-own bearer a packet is).
parse_component(16#60, <<_Spi:32, R/binary>>)           -> {ok, ignore, R};
parse_component(16#70, <<_Tos:8, _Mask:8, R/binary>>)   -> {ok, ignore, R};
parse_component(16#80, <<_Flow:24, R/binary>>)          -> {ok, ignore, R};
parse_component(_, _) -> error.

%%====================================================================
%% Match
%%====================================================================

%% Does the inner IP packet match any uplink (or bidirectional) filter in the
%% parsed set? Used on the uplink forwarding hot path, so it short-circuits.
-spec match([filter()], binary()) -> boolean().
match([], _Pkt) -> false;
match(Filters, PktBin) when is_binary(PktBin), is_list(Filters) ->
    case packet_5tuple(PktBin) of
        undefined -> false;
        Tuple     -> lists:any(fun(F) -> filter_matches_uplink(F, Tuple) end,
                               Filters)
    end;
match(_, _) -> false.

%% Direction (TS 24.008 §10.5.6.12): 1 = downlink only, 2 = uplink only,
%% 3 = bidirectional, 0 = reserved (treated as any). Only uplink-applicable
%% filters (0/2/3) are considered for uplink packets.
filter_matches_uplink(#{direction := Dir, components := Comps}, Tuple)
  when Dir =:= 0; Dir =:= 2; Dir =:= 3 ->
    Comps =/= []
        andalso (not lists:member(invalid, Comps))
        andalso lists:all(fun(C) -> component_matches(C, Tuple) end, Comps);
filter_matches_uplink(_, _) ->
    false.

%% For an uplink packet: source = UE side (local), destination = far end
%% (remote). Ports likewise.
component_matches({proto, P}, #{proto := PP}) -> P =:= PP;
component_matches({ipv4_remote, Addr, Mask}, #{version := 4, dst := Dst}) ->
    v4_masked_eq(Dst, Addr, Mask);
component_matches({ipv4_local, Addr, Mask}, #{version := 4, src := Src}) ->
    v4_masked_eq(Src, Addr, Mask);
component_matches({ipv6_remote_mask, Addr, Mask}, #{version := 6, dst := Dst}) ->
    v6_masked_eq(Dst, Addr, Mask);
component_matches({ipv6_remote_pref, Addr, Pref}, #{version := 6, dst := Dst}) ->
    v6_prefix_eq(Dst, Addr, Pref);
component_matches({ipv6_local_pref, Addr, Pref}, #{version := 6, src := Src}) ->
    v6_prefix_eq(Src, Addr, Pref);
component_matches({remote_port, Port}, #{dport := DP}) -> DP =:= Port;
component_matches({remote_port_range, Lo, Hi}, #{dport := DP}) ->
    is_integer(DP) andalso DP >= Lo andalso DP =< Hi;
component_matches({local_port, Port}, #{sport := SP}) -> SP =:= Port;
component_matches({local_port_range, Lo, Hi}, #{sport := SP}) ->
    is_integer(SP) andalso SP >= Lo andalso SP =< Hi;
component_matches(ignore, _) -> true;
%% Address-family mismatch (e.g. an IPv4 component against an IPv6 packet) or
%% a component we can't evaluate for this packet — does not match.
component_matches(_, _) -> false.

%%====================================================================
%% Address helpers
%%====================================================================

v4_masked_eq({A,B,C,D}, {A2,B2,C2,D2}, {M1,M2,M3,M4}) ->
    (A band M1) =:= (A2 band M1) andalso
    (B band M2) =:= (B2 band M2) andalso
    (C band M3) =:= (C2 band M3) andalso
    (D band M4) =:= (D2 band M4);
v4_masked_eq(_, _, _) -> false.

v6_masked_eq(<<Pkt:128>>, <<Addr:128>>, <<Mask:128>>) ->
    (Pkt band Mask) =:= (Addr band Mask);
v6_masked_eq(_, _, _) -> false.

v6_prefix_eq(<<Pkt:128>>, <<Addr:128>>, Pref)
  when is_integer(Pref), Pref >= 0, Pref =< 128 ->
    Mask = case Pref of
        0 -> 0;
        _ -> ((1 bsl Pref) - 1) bsl (128 - Pref)
    end,
    (Pkt band Mask) =:= (Addr band Mask);
v6_prefix_eq(_, _, _) -> false.

%%====================================================================
%% Inner IP packet parsing (5-tuple)
%%
%% The forwarder hands us the decrypted inner IP packet (no link header —
%% the per-UE TUN is IFF_NO_PI). We only need version, protocol, addresses
%% and the L4 ports for TCP/UDP.
%%====================================================================

packet_5tuple(<<4:4, IHL:4, _TOS:8, _Len:16, _Id:16, _Flags:3, _Frag:13,
                _TTL:8, Proto:8, _Csum:16,
                S1:8,S2:8,S3:8,S4:8, D1:8,D2:8,D3:8,D4:8, Rest/binary>>)
  when IHL >= 5 ->
    OptLen = (IHL - 5) * 4,
    case Rest of
        <<_Opts:OptLen/binary, L4/binary>> ->
            {SP, DP} = l4_ports(Proto, L4),
            #{version => 4, proto => Proto,
              src => {S1,S2,S3,S4}, dst => {D1,D2,D3,D4},
              sport => SP, dport => DP};
        _ -> undefined
    end;
packet_5tuple(<<6:4, _TC:8, _Flow:20, _PayLen:16, NextHdr:8, _Hop:8,
                Src:16/binary, Dst:16/binary, L4/binary>>) ->
    %% Extension headers are not walked; ports are only read when the next
    %% header is TCP/UDP directly (the common VoWiFi media case).
    {SP, DP} = l4_ports(NextHdr, L4),
    #{version => 6, proto => NextHdr, src => Src, dst => Dst,
      sport => SP, dport => DP};
packet_5tuple(_) -> undefined.

%% TCP (6) and UDP (17) carry source/destination ports in their first 4 bytes.
l4_ports(P, <<SP:16, DP:16, _/binary>>) when P =:= 6; P =:= 17 -> {SP, DP};
l4_ports(_, _) -> {undefined, undefined}.
