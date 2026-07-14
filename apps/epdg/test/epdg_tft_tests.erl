-module(epdg_tft_tests).
-include_lib("eunit/include/eunit.hrl").

%% Build a "create new TFT" (TS 24.008 §10.5.6.12) with a single packet
%% filter: <op=001,E=0,N=1>, then one filter <spare=00,dir,id>, precedence,
%% length, contents.
tft(Dir, Contents) ->
    Filter = <<0:2, Dir:2, 1:4, 0:8, (byte_size(Contents)):8, Contents/binary>>,
    <<2#001:3, 0:1, 1:4, Filter/binary>>.

%% Component: protocol/next-header (0x30) = UDP (17).
udp_proto() -> <<16#30:8, 17:8>>.

%% Component: remote port range (0x51) low..high — this is the RTP media the
%% VoWiFi voice dedicated bearer carries.
remote_port_range(Lo, Hi) -> <<16#51:8, Lo:16, Hi:16>>.

%% A raw IPv4/UDP packet (no link header — the ePDG TUN is IFF_NO_PI).
%% src = UE side (local), dst = far end (remote).
ipv4_udp(Src, Dst, SPort, DPort) ->
    {S1,S2,S3,S4} = Src,
    {D1,D2,D3,D4} = Dst,
    UDP = <<SPort:16, DPort:16, 8:16, 0:16>>,
    IPLen = 20 + byte_size(UDP),
    <<4:4, 5:4, 0:8, IPLen:16, 0:16, 0:3, 0:13, 64:8, 17:8, 0:16,
      S1:8,S2:8,S3:8,S4:8, D1:8,D2:8,D3:8,D4:8, UDP/binary>>.

%% Rule 9: this test fails if uplink RTP inside the TFT's remote port range no
%% longer classifies onto the dedicated bearer.
uplink_rtp_matches_dedicated_bearer_test() ->
    Tft = tft(2, <<(udp_proto())/binary, (remote_port_range(16384, 16483))/binary>>),
    Filters = epdg_tft:parse(Tft),
    ?assertEqual(1, length(Filters)),
    Pkt = ipv4_udp({10,45,0,2}, {203,0,113,5}, 40000, 16400),
    ?assert(epdg_tft:match(Filters, Pkt)).

%% A destination port outside the media range stays on the default bearer.
uplink_out_of_range_port_no_match_test() ->
    Tft = tft(2, <<(udp_proto())/binary, (remote_port_range(16384, 16483))/binary>>),
    Filters = epdg_tft:parse(Tft),
    Pkt = ipv4_udp({10,45,0,2}, {203,0,113,5}, 40000, 30000),
    ?assertNot(epdg_tft:match(Filters, Pkt)).

%% Protocol component must match: a TCP packet does not match a UDP filter.
protocol_mismatch_no_match_test() ->
    Tft = tft(2, <<(udp_proto())/binary, (remote_port_range(16384, 16483))/binary>>),
    Filters = epdg_tft:parse(Tft),
    {S1,S2,S3,S4} = {10,45,0,2},
    {D1,D2,D3,D4} = {203,0,113,5},
    TCP = <<40000:16, 16400:16, 0:32, 0:32, 0:16, 0:16>>,
    IPLen = 20 + byte_size(TCP),
    Pkt = <<4:4, 5:4, 0:8, IPLen:16, 0:16, 0:3, 0:13, 64:8, 6:8, 0:16,
            S1:8,S2:8,S3:8,S4:8, D1:8,D2:8,D3:8,D4:8, TCP/binary>>,
    ?assertNot(epdg_tft:match(Filters, Pkt)).

%% A downlink-only filter (direction 01) must not classify uplink packets.
downlink_only_filter_ignored_for_uplink_test() ->
    Tft = tft(1, <<(udp_proto())/binary, (remote_port_range(16384, 16483))/binary>>),
    Filters = epdg_tft:parse(Tft),
    Pkt = ipv4_udp({10,45,0,2}, {203,0,113,5}, 40000, 16400),
    ?assertNot(epdg_tft:match(Filters, Pkt)).

%% Local (UE-side) source-port range matches the uplink packet's source port.
uplink_local_port_range_matches_test() ->
    Local = <<16#41:8, 40000:16, 40100:16>>,   %% local port range
    Tft = tft(3, <<(udp_proto())/binary, Local/binary>>),
    Filters = epdg_tft:parse(Tft),
    Pkt = ipv4_udp({10,45,0,2}, {203,0,113,5}, 40050, 16400),
    ?assert(epdg_tft:match(Filters, Pkt)).

%% An empty filter set never matches (no dedicated bearers installed).
empty_filters_no_match_test() ->
    Pkt = ipv4_udp({10,45,0,2}, {203,0,113,5}, 40000, 16400),
    ?assertNot(epdg_tft:match([], Pkt)).

%% A TFT carrying an unparseable component marks the filter invalid, so the
%% packet falls back to the default bearer rather than being misrouted.
unparseable_component_no_match_test() ->
    %% 0x99 is not a defined component type identifier.
    Tft = tft(2, <<(udp_proto())/binary, 16#99:8, 1:8>>),
    Filters = epdg_tft:parse(Tft),
    Pkt = ipv4_udp({10,45,0,2}, {203,0,113,5}, 40000, 16400),
    ?assertNot(epdg_tft:match(Filters, Pkt)).

%% A delete-type TFT operation carries no packet filters to classify on.
delete_operation_yields_no_filters_test() ->
    %% op code 101 = delete packet filters.
    ?assertEqual([], epdg_tft:parse(<<2#101:3, 0:1, 0:4>>)).
