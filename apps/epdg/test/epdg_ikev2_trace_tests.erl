%%%-------------------------------------------------------------------
%%% @doc EUnit tests for epdg_ikev2_trace, the plaintext IKEv2 trace
%%% mirror.
%%%
%%% Everything under test here is a pure helper, so no gen_server (and no
%%% listening socket) is started. The properties that matter are the ones
%%% a consumer relies on:
%%%
%%%   * the pcapng framing is well-formed — tshark rejects the whole
%%%     stream on a single bad block length, so a broken block means no
%%%     trace at all rather than one missing message;
%%%   * the synthetic IP/UDP headers carry correct lengths and checksums,
%%%     so an operator is not left wondering whether "bad checksum" in
%%%     Wireshark means the trace is lying to them;
%%%   * the RFC 3948 non-ESP marker is present exactly when the port is
%%%     4500, because without it Wireshark dissects the datagram as
%%%     UDP-encapsulated ESP and never reaches the ISAKMP dissector;
%%%   * the metadata JSON that rides in the opt_comment keeps the IMSI a
%%%     consumer reads out of `frame.comment'.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_trace_tests).

-include_lib("eunit/include/eunit.hrl").

%% pcapng block types
-define(BT_SHB, 16#0A0D0D0A).
-define(BT_IDB, 16#00000001).
-define(BT_EPB, 16#00000006).
-define(LINKTYPE_RAW, 101).

-define(IPPROTO_UDP, 17).

-define(ISPI, <<16#11,16#22,16#33,16#44,16#55,16#66,16#77,16#88>>).
-define(RSPI, <<16#88,16#77,16#66,16#55,16#44,16#33,16#22,16#11>>).

%%====================================================================
%% Helpers
%%====================================================================

%% A minimal well-formed IKE message: 28-byte header plus one Nonce
%% payload. ExType/Flags are parameters so the metadata tests can drive
%% IKE_SA_INIT vs IKE_AUTH and request vs response.
ike_msg(ExType, Flags) ->
    Nonce = <<0:128>>,
    Payload = <<0:8, 0:8, (4 + byte_size(Nonce)):16, Nonce/binary>>,
    <<(?ISPI)/binary, (?RSPI)/binary,
      40:8,                        %% next payload = Nonce
      2:4, 0:4,                    %% version 2.0
      ExType:8, Flags:8,
      0:32,                        %% message id
      (28 + byte_size(Payload)):32,
      Payload/binary>>.

ike_msg() -> ike_msg(34, 16#08).

%% Split a pcapng block into {Type, Body} and assert the framing
%% invariants every reader depends on.
parse_block(<<Type:32, Total:32, Rest/binary>> = Block) ->
    ?assertEqual(Total, byte_size(Block)),
    ?assertEqual(0, Total rem 4),
    BodyLen = Total - 12,
    <<Body:BodyLen/binary, Trailer:32>> = Rest,
    %% The trailing length is what lets a reader walk the file backwards;
    %% a mismatch is the classic hand-rolled-pcapng bug.
    ?assertEqual(Total, Trailer),
    {Type, Body}.

%% Walk a pcapng option list into a plain proplist.
parse_opts(<<>>, Acc) ->
    lists:reverse(Acc);
parse_opts(<<0:16, 0:16, _/binary>>, Acc) ->
    lists:reverse(Acc);
parse_opts(<<Code:16, Len:16, Rest/binary>>, Acc) ->
    Padded = Len + ((4 - Len rem 4) rem 4),
    <<Value:Len/binary, _Pad:(Padded - Len)/binary, More/binary>> = Rest,
    parse_opts(More, [{Code, Value} | Acc]).

%% Strip an IPv4 header and return {SrcIP, DstIP, UdpBin}.
parse_ipv4(<<4:4, 5:4, _TOS:8, Total:16, _Id:16, _Frag:16, _TTL:8,
             Proto:8, _Sum:16, SA:4/binary, DA:4/binary, Udp/binary>> = Pkt) ->
    ?assertEqual(?IPPROTO_UDP, Proto),
    ?assertEqual(Total, byte_size(Pkt)),
    %% The one's complement sum over a header that already carries its own
    %% checksum is zero. This is the actual property Wireshark checks.
    ?assertEqual(0, epdg_ikev2_trace:checksum(binary:part(Pkt, 0, 20))),
    {SA, DA, Udp}.

parse_ipv6(<<6:4, _TC:8, _Flow:20, PayLen:16, Next:8, _Hops:8,
             SA:16/binary, DA:16/binary, Udp/binary>>) ->
    ?assertEqual(?IPPROTO_UDP, Next),
    ?assertEqual(PayLen, byte_size(Udp)),
    {SA, DA, Udp}.

%% Strip a UDP header, verifying its length and checksum against the
%% pseudo-header, and return {SrcPort, DstPort, Payload}.
parse_udp(SA, DA, <<SrcPort:16, DstPort:16, Len:16, _Sum:16,
                    Payload/binary>> = Udp) ->
    ?assertEqual(Len, byte_size(Udp)),
    Pseudo = case byte_size(SA) of
        4  -> <<SA/binary, DA/binary, 0:8, ?IPPROTO_UDP:8, Len:16>>;
        16 -> <<SA/binary, DA/binary, Len:32, 0:24, ?IPPROTO_UDP:8>>
    end,
    ?assertEqual(0, epdg_ikev2_trace:checksum([Pseudo, Udp])),
    {SrcPort, DstPort, Payload}.

%%====================================================================
%% checksum/1 (RFC 1071)
%%====================================================================

checksum_rfc1071_vector_test() ->
    %% The worked example from RFC 1071 §3: the octets sum to 0xDDF2, so
    %% the checksum is 0x220D.
    ?assertEqual(16#220D,
                 epdg_ikev2_trace:checksum(
                   <<16#00,16#01,16#F2,16#03,16#F4,16#F5,16#F6,16#F7>>)).

checksum_empty_test() ->
    ?assertEqual(16#FFFF, epdg_ikev2_trace:checksum(<<>>)).

checksum_odd_length_pads_with_zero_test() ->
    %% 0x0102 + 0x0304 + 0x0500 = 0x0906 -> complement 0xF6F9. The trailing
    %% odd byte is the HIGH byte of the final word; padding it low instead
    %% silently corrupts every odd-length payload.
    ?assertEqual(16#F6F9,
                 epdg_ikev2_trace:checksum(<<1, 2, 3, 4, 5>>)).

checksum_accepts_iolist_test() ->
    Flat = <<1, 2, 3, 4, 5, 6>>,
    ?assertEqual(epdg_ikev2_trace:checksum(Flat),
                 epdg_ikev2_trace:checksum([<<1, 2>>, [<<3, 4>>], <<5, 6>>])).

%%====================================================================
%% pcapng blocks
%%====================================================================

shb_is_well_formed_test() ->
    {Type, Body} = parse_block(epdg_ikev2_trace:shb()),
    ?assertEqual(?BT_SHB, Type),
    <<Bom:32, Major:16, Minor:16, SectionLen:64, Opts/binary>> = Body,
    %% Byte-order magic written big-endian; readers detect the section's
    %% endianness from these four bytes.
    ?assertEqual(16#1A2B3C4D, Bom),
    ?assertEqual({1, 0}, {Major, Minor}),
    %% -1 == "unknown", which is the only correct value for a stream.
    ?assertEqual(16#FFFFFFFFFFFFFFFF, SectionLen),
    ?assertEqual(<<"epdg">>, proplists:get_value(4, parse_opts(Opts, []))).

idb_declares_linktype_raw_test() ->
    {Type, Body} = parse_block(epdg_ikev2_trace:idb()),
    ?assertEqual(?BT_IDB, Type),
    <<LinkType:16, _Reserved:16, _SnapLen:32, Opts/binary>> = Body,
    %% LINKTYPE_RAW: block data starts at the IP header, so no fabricated
    %% Ethernet addresses appear in the trace.
    ?assertEqual(?LINKTYPE_RAW, LinkType),
    Parsed = parse_opts(Opts, []),
    %% if_tsresol = 6 -> microseconds, matching the EPB timestamps.
    ?assertEqual(<<6>>, proplists:get_value(9, Parsed)),
    ?assertEqual(<<"epdg-ike">>, proplists:get_value(2, Parsed)).

epb_round_trips_packet_and_comment_test() ->
    Pkt = <<"not-really-a-packet">>,   %% 19 bytes: exercises the padding
    Comment = <<"{\"imsi\":\"262011234567890\"}">>,
    Micros = 1755000000123456,
    {Type, Body} = parse_block(epdg_ikev2_trace:epb(Pkt, Micros, Comment)),
    ?assertEqual(?BT_EPB, Type),
    <<IfId:32, TsHigh:32, TsLow:32, CapLen:32, OrigLen:32, Rest/binary>> = Body,
    ?assertEqual(0, IfId),
    ?assertEqual(Micros, (TsHigh bsl 32) bor TsLow),
    ?assertEqual(byte_size(Pkt), CapLen),
    ?assertEqual(byte_size(Pkt), OrigLen),
    PadLen = (4 - CapLen rem 4) rem 4,
    <<Data:CapLen/binary, _Pad:PadLen/binary, Opts/binary>> = Rest,
    ?assertEqual(Pkt, Data),
    %% opt_comment (code 1) is how tshark surfaces this as frame.comment.
    ?assertEqual(Comment, proplists:get_value(1, parse_opts(Opts, []))).

epb_pads_packet_to_four_bytes_test() ->
    %% Any captured length must still leave the block 4-aligned.
    [begin
         Block = epdg_ikev2_trace:epb(<<0:(N * 8)>>, 1, <<"{}">>),
         ?assertEqual(0, byte_size(Block) rem 4),
         parse_block(Block)
     end || N <- lists:seq(1, 8)],
    ok.

%%====================================================================
%% synth_datagram/5
%%====================================================================

synth_ipv4_headers_are_consistent_test() ->
    Ike = ike_msg(),
    Pkt = epdg_ikev2_trace:synth_datagram({10, 20, 30, 40}, 500,
                                          {192, 0, 2, 1}, 500, Ike),
    {SA, DA, Udp} = parse_ipv4(Pkt),
    ?assertEqual(<<10, 20, 30, 40>>, SA),
    ?assertEqual(<<192, 0, 2, 1>>, DA),
    {SrcPort, DstPort, Payload} = parse_udp(SA, DA, Udp),
    ?assertEqual({500, 500}, {SrcPort, DstPort}),
    %% Port 500 is plain IKE: no non-ESP marker.
    ?assertEqual(Ike, Payload).

synth_prepends_non_esp_marker_on_4500_test() ->
    Ike = ike_msg(),
    Pkt = epdg_ikev2_trace:synth_datagram({10, 20, 30, 40}, 51234,
                                          {192, 0, 2, 1}, 4500, Ike),
    {SA, DA, Udp} = parse_ipv4(Pkt),
    {_, 4500, Payload} = parse_udp(SA, DA, Udp),
    %% RFC 3948 §2.2. Without these four zero bytes Wireshark reads the
    %% datagram as ESP-in-UDP and the IKE message never gets dissected.
    ?assertEqual(<<0, 0, 0, 0, Ike/binary>>, Payload).

synth_marker_also_when_source_is_4500_test() ->
    %% ePDG -> UE: our side is 4500, the UE's NAT port is arbitrary.
    Ike = ike_msg(),
    Pkt = epdg_ikev2_trace:synth_datagram({192, 0, 2, 1}, 4500,
                                          {10, 20, 30, 40}, 51234, Ike),
    {SA, DA, Udp} = parse_ipv4(Pkt),
    {4500, 51234, Payload} = parse_udp(SA, DA, Udp),
    ?assertEqual(<<0, 0, 0, 0, Ike/binary>>, Payload).

synth_ipv6_headers_are_consistent_test() ->
    Ike = ike_msg(),
    Src = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
    Dst = {16#2001, 16#db8, 0, 0, 0, 0, 0, 2},
    Pkt = epdg_ikev2_trace:synth_datagram(Src, 500, Dst, 500, Ike),
    {SA, DA, Udp} = parse_ipv6(Pkt),
    ?assertEqual(40, byte_size(Pkt) - byte_size(Udp)),
    %% IPv6 has no header checksum, so the UDP checksum is mandatory
    %% rather than optional — parse_udp asserts it.
    {500, 500, Payload} = parse_udp(SA, DA, Udp),
    ?assertEqual(Ike, Payload).

%%====================================================================
%% ike_bytes/1
%%====================================================================

ike_bytes_passes_through_assembled_message_test() ->
    Ike = ike_msg(),
    ?assertEqual(Ike, epdg_ikev2_trace:ike_bytes(#{msg => Ike})).

ike_bytes_rebuilds_from_header_and_inner_chain_test() ->
    %% What mirror_out/3 in epdg_ue_fsm hands over: the header map used for
    %% encryption plus the plaintext inner chain.
    {FirstInner, Inner} =
        epdg_ikev2_codec:encode_payloads([{notify, <<0:8, 0:8, 16388:16>>}]),
    Msg = epdg_ikev2_trace:ike_bytes(
            #{header => #{initiator_spi     => 16#1122334455667788,
                          responder_spi     => 16#8877665544332211,
                          exchange_type_raw => 37,
                          flags             => 16#20,
                          message_id        => 7},
              first_inner => FirstInner,
              inner       => Inner}),
    {ok, Decoded} = epdg_ikev2_codec:decode_header(Msg),
    ?assertEqual(16#1122334455667788, maps:get(initiator_spi, Decoded)),
    ?assertEqual(37, maps:get(exchange_type_raw, Decoded)),
    ?assertEqual(7, maps:get(message_id, Decoded)),
    ?assertEqual(true, maps:get(is_response, Decoded)),
    %% The SK payload is gone: the mirrored message advertises the first
    %% *decrypted* payload instead, which is what makes it dissectable.
    ?assertEqual(FirstInner, maps:get(next_payload, Decoded)),
    ?assertEqual(byte_size(Msg), maps:get(length, Decoded)).

%%====================================================================
%% endpoints/2
%%====================================================================

-define(LOCALS, [{192, 0, 2, 1}, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}]).

endpoints_inbound_puts_ue_first_test() ->
    Ev = #{dir => in, peer_ip => {10, 20, 30, 40}, peer_port => 51234},
    ?assertEqual({{10, 20, 30, 40}, 51234, {192, 0, 2, 1}, 4500},
                 epdg_ikev2_trace:endpoints(Ev, ?LOCALS)).

endpoints_outbound_puts_epdg_first_test() ->
    Ev = #{dir => out, peer_ip => {10, 20, 30, 40}, peer_port => 51234},
    ?assertEqual({{192, 0, 2, 1}, 4500, {10, 20, 30, 40}, 51234},
                 epdg_ikev2_trace:endpoints(Ev, ?LOCALS)).

endpoints_uses_500_for_a_non_natted_ue_test() ->
    %% A UE talking to 500 is not behind NAT, so our side is 500 too.
    Ev = #{dir => in, peer_ip => {10, 20, 30, 40}, peer_port => 500},
    ?assertMatch({_, 500, _, 500},
                 epdg_ikev2_trace:endpoints(Ev, ?LOCALS)).

endpoints_honours_explicit_local_port_test() ->
    Ev = #{dir => in, peer_ip => {10, 20, 30, 40}, peer_port => 51234,
           local_port => 500},
    ?assertMatch({_, 51234, _, 500},
                 epdg_ikev2_trace:endpoints(Ev, ?LOCALS)).

endpoints_picks_local_address_of_peer_family_test() ->
    %% The whole reason EPDG_IKE_TRACE_LOCAL_ADDR is a list: a v6 UE must
    %% not be rendered against the v4 local address, which would produce a
    %% mixed-family datagram no dissector can read.
    Ev = #{dir => in, peer_ip => {16#2001, 16#db8, 0, 0, 0, 0, 0, 2},
           peer_port => 500},
    {_, _, Local, _} = epdg_ikev2_trace:endpoints(Ev, ?LOCALS),
    ?assertEqual({16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, Local).

endpoints_ignores_extra_addresses_of_the_same_family_test() ->
    Locals = [{192, 0, 2, 1}, {198, 51, 100, 7}],
    Ev = #{dir => out, peer_ip => {10, 20, 30, 40}, peer_port => 500},
    ?assertMatch({{192, 0, 2, 1}, _, _, _},
                 epdg_ikev2_trace:endpoints(Ev, Locals)).

endpoints_falls_back_to_unspecified_when_family_missing_test() ->
    %% Nothing configured for the peer's family: render :: rather than drop
    %% the message, so the gap is visible in the trace instead of silent.
    V6Ev = #{dir => in, peer_ip => {16#2001, 16#db8, 0, 0, 0, 0, 0, 2},
             peer_port => 500},
    {_, _, V6Local, _} =
        epdg_ikev2_trace:endpoints(V6Ev, [{192, 0, 2, 1}]),
    ?assertEqual({0, 0, 0, 0, 0, 0, 0, 0}, V6Local),

    V4Ev = #{dir => in, peer_ip => {10, 20, 30, 40}, peer_port => 500},
    {_, _, V4Local, _} =
        epdg_ikev2_trace:endpoints(V4Ev, [{16#2001, 16#db8, 0, 0, 0, 0, 0, 1}]),
    ?assertEqual({0, 0, 0, 0}, V4Local),

    %% Empty list (nothing configured at all) must behave the same.
    {_, _, NoneLocal, _} = epdg_ikev2_trace:endpoints(V4Ev, []),
    ?assertEqual({0, 0, 0, 0}, NoneLocal).

%%====================================================================
%% meta_of/2 and encode_meta/1
%%====================================================================

meta_derives_spis_and_exchange_test() ->
    Meta = epdg_ikev2_trace:meta_of(#{dir => in}, ike_msg(35, 16#08)),
    ?assertEqual(<<"1122334455667788">>, maps:get(initiator_spi, Meta)),
    ?assertEqual(<<"8877665544332211">>, maps:get(responder_spi, Meta)),
    %% The join key every mirrored document carries, so an IKE_SA_INIT
    %% that has no IMSI yet can still be tied to the IKE_AUTH that does.
    ?assertEqual(<<"1122334455667788:8877665544332211">>,
                 maps:get(ike_spi_pair, Meta)),
    ?assertEqual(<<"IKE_AUTH">>, maps:get(exchange_type, Meta)),
    ?assertEqual(false, maps:get(is_response, Meta)),
    ?assertEqual(true, maps:get(from_initiator, Meta)).

meta_names_known_exchanges_test() ->
    Name = fun(ExType) ->
        maps:get(exchange_type,
                 epdg_ikev2_trace:meta_of(#{dir => in}, ike_msg(ExType, 0)))
    end,
    ?assertEqual(<<"IKE_SA_INIT">>, Name(34)),
    ?assertEqual(<<"CREATE_CHILD_SA">>, Name(36)),
    ?assertEqual(<<"INFORMATIONAL">>, Name(37)),
    %% Unknown exchange types stay visible as their number rather than
    %% collapsing to "unknown".
    ?assertEqual(<<"99">>, Name(99)).

meta_marks_responses_test() ->
    Meta = epdg_ikev2_trace:meta_of(#{dir => out}, ike_msg(35, 16#20)),
    ?assertEqual(true, maps:get(is_response, Meta)),
    ?assertEqual(false, maps:get(from_initiator, Meta)).

meta_caller_values_win_test() ->
    %% The FSM knows the real exchange context; a caller-supplied value
    %% must not be clobbered by the derived one.
    Meta = epdg_ikev2_trace:meta_of(
             #{dir => in, meta => #{imsi => <<"262011234567890">>,
                                    exchange_type => <<"custom">>}},
             ike_msg(35, 16#08)),
    ?assertEqual(<<"262011234567890">>, maps:get(imsi, Meta)),
    ?assertEqual(<<"custom">>, maps:get(exchange_type, Meta)).

meta_survives_a_truncated_message_test() ->
    %% Never crash the trace server on a short frame.
    Meta = epdg_ikev2_trace:meta_of(#{dir => in}, <<1, 2, 3>>),
    ?assertEqual(in, maps:get(dir, Meta)),
    ?assertEqual(false, maps:is_key(ike_spi_pair, Meta)).

encode_meta_drops_undefined_test() ->
    %% An unauthenticated UE has no IMSI yet. Emitting nulls would leave a
    %% consumer's schema full of empty fields.
    Json = epdg_ikev2_trace:encode_meta(
             #{imsi => undefined, apn => <<"ims">>, ue_nai => undefined}),
    Decoded = jsx:decode(Json, [return_maps]),
    ?assertEqual(#{<<"apn">> => <<"ims">>}, Decoded).

encode_meta_normalises_terms_test() ->
    Json = epdg_ikev2_trace:encode_meta(
             #{dir => in, message_id => 3, is_response => false,
               peer_ip => {10, 20, 30, 40},
               peer_ip6 => {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
               apn => "ims"}),
    D = jsx:decode(Json, [return_maps]),
    ?assertEqual(<<"in">>, maps:get(<<"dir">>, D)),
    ?assertEqual(3, maps:get(<<"message_id">>, D)),
    %% `false' must stay a JSON boolean, not become the string "false".
    ?assertEqual(false, maps:get(<<"is_response">>, D)),
    ?assertEqual(<<"10.20.30.40">>, maps:get(<<"peer_ip">>, D)),
    ?assertEqual(<<"2001:db8::1">>, maps:get(<<"peer_ip6">>, D)),
    ?assertEqual(<<"ims">>, maps:get(<<"apn">>, D)).

encode_meta_is_valid_json_for_empty_map_test() ->
    ?assertEqual(#{}, jsx:decode(epdg_ikev2_trace:encode_meta(#{}),
                                 [return_maps])).

%%====================================================================
%% End to end: one mirrored CFG_REPLY
%%====================================================================

%% Assembles what the trace mirror actually emits for the message the
%% whole feature exists to expose — the IKE_AUTH response carrying
%% CFG_REPLY with the P-CSCF addresses — and walks it back apart.
cfg_reply_block_round_trips_test() ->
    %% P_CSCF_IP4_ADDRESS (20) plus the 3GPP private-use siblings iOS asks
    %% for: 16389 for IPv4 and 16390 for IPv6 (TS 24.302 §8.1.2.2).
    CfgReply = epdg_ikev2_codec:encode_cp_payload(
                 2,
                 [{internal_ip4_address, <<10, 44, 1, 7>>},
                  {p_cscf_ip4_address, <<10, 55, 0, 10>>},
                  {p_cscf_ip4_address_3gpp, <<10, 55, 0, 11>>},
                  {p_cscf_ip6_address_3gpp, <<16#20, 16#01, 16#0d, 16#b8,
                                              0, 16#55, 0, 0,
                                              0, 0, 0, 0, 0, 0, 0, 16#11>>}]),
    {FirstInner, Inner} = epdg_ikev2_codec:encode_payloads([{cp, CfgReply}]),
    Ev = #{dir         => out,
           peer_ip     => {10, 20, 30, 40},
           peer_port   => 51234,
           header      => #{initiator_spi     => 16#1122334455667788,
                            responder_spi     => 16#8877665544332211,
                            exchange_type_raw => 35,
                            flags             => 16#20,
                            message_id        => 1},
           first_inner => FirstInner,
           inner       => Inner,
           meta        => #{imsi => <<"262011234567890">>,
                            apn  => <<"ims">>}},

    IkeMsg = epdg_ikev2_trace:ike_bytes(Ev),
    {SrcIP, SrcPort, DstIP, DstPort} =
        epdg_ikev2_trace:endpoints(Ev, ?LOCALS),
    Pkt = epdg_ikev2_trace:synth_datagram(SrcIP, SrcPort, DstIP, DstPort,
                                          IkeMsg),
    Block = epdg_ikev2_trace:epb(
              Pkt, 1755000000123456,
              epdg_ikev2_trace:encode_meta(
                epdg_ikev2_trace:meta_of(Ev, IkeMsg))),

    {?BT_EPB, Body} = parse_block(Block),
    <<_IfId:32, _Hi:32, _Lo:32, CapLen:32, _Orig:32, Rest/binary>> = Body,
    PadLen = (4 - CapLen rem 4) rem 4,
    <<Data:CapLen/binary, _Pad:PadLen/binary, Opts/binary>> = Rest,

    %% Unwrap IP -> UDP -> non-ESP marker -> IKE and confirm we get the
    %% exact bytes back.
    {SA, DA, Udp} = parse_ipv4(Data),
    ?assertEqual(<<192, 0, 2, 1>>, SA),
    ?assertEqual(<<10, 20, 30, 40>>, DA),
    {4500, 51234, Payload} = parse_udp(SA, DA, Udp),
    ?assertEqual(<<0, 0, 0, 0, IkeMsg/binary>>, Payload),

    %% ... and that the CFG_REPLY inside survives, attributes intact.
    {ok, Hdr} = epdg_ikev2_codec:decode_header(IkeMsg),
    {ok, Payloads} = epdg_ikev2_codec:decode_payloads(
                       maps:get(next_payload, Hdr),
                       maps:get(payload_data, Hdr)),
    {ok, #{data := CpData}} = epdg_ikev2_codec:find_payload(cp, Payloads),
    {ok, {CfgType, Attrs}} = epdg_ikev2_codec:decode_cp_payload(CpData),
    ?assertEqual(2, CfgType),                     %% CFG_REPLY
    ?assertEqual(<<10, 55, 0, 10>>,
                 proplists:get_value(p_cscf_ip4_address, Attrs)),
    ?assertEqual(<<10, 55, 0, 11>>,
                 proplists:get_value(p_cscf_ip4_address_3gpp, Attrs)),
    ?assertEqual(16, byte_size(
                       proplists:get_value(p_cscf_ip6_address_3gpp, Attrs))),

    %% The IMSI a consumer reads out of frame.comment.
    Comment = proplists:get_value(1, parse_opts(Opts, [])),
    Meta = jsx:decode(Comment, [return_maps]),
    ?assertEqual(<<"262011234567890">>, maps:get(<<"imsi">>, Meta)),
    ?assertEqual(<<"ims">>, maps:get(<<"apn">>, Meta)),
    ?assertEqual(<<"IKE_AUTH">>, maps:get(<<"exchange_type">>, Meta)),
    ?assertEqual(<<"1122334455667788:8877665544332211">>,
                 maps:get(<<"ike_spi_pair">>, Meta)).
