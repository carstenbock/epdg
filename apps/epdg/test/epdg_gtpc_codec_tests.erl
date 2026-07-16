-module(epdg_gtpc_codec_tests).
-include_lib("eunit/include/eunit.hrl").

%% Build the exact F-TEID IE bytes the encoder must emit:
%%   IE: Type=87, Len, Spare/Inst, then V4=1,V6=0, Iface(6), TEID(32), IPv4(32)
fteid_ie(Inst, Iface, TEID, {A,B,C,D}) ->
    V = <<1:1, 0:1, Iface:6, TEID:32, A:8, B:8, C:8, D:8>>,
    <<87:8, (byte_size(V)):16, 0:4, Inst:4, V/binary>>.

rat_ie(RAT) -> <<82:8, 1:16, 0:8, RAT:8>>.

base_params() ->
    #{seq_num => 1, apn => <<"ims">>, rat_type => 3,
      local_ip => {10,0,0,1}, imsi => <<"262220000000001">>,
      local_c_teid => 16#11111111, local_u_teid => 16#22222222, ebi => 5}.

s2b_default_uses_iface_30_and_rat_wlan_test() ->
    Bin = epdg_gtpc_codec:encode_create_session_request(base_params()),
    %% control F-TEID at instance 0, iface 30 (S2b ePDG GTP-C)
    ?assertNotEqual(nomatch,
        binary:match(Bin, fteid_ie(0, 30, 16#11111111, {10,0,0,1}))),
    %% bearer-U F-TEID at instance 5, iface 31 (S2b-U ePDG)
    ?assertNotEqual(nomatch,
        binary:match(Bin, fteid_ie(5, 31, 16#22222222, {10,0,0,1}))),
    ?assertNotEqual(nomatch, binary:match(Bin, rat_ie(3))).

s5s8_mode_uses_sgw_ifaces_and_rat_eutran_test() ->
    P = (base_params())#{mode => s5s8, rat_type => 6},
    Bin = epdg_gtpc_codec:encode_create_session_request(P),
    %% control F-TEID instance 0, iface 6 (S5/S8 SGW GTP-C)
    ?assertNotEqual(nomatch,
        binary:match(Bin, fteid_ie(0, 6, 16#11111111, {10,0,0,1}))),
    %% bearer-U F-TEID instance 2, iface 4 (S5/S8 SGW GTP-U)  [confirm instance via Task 2]
    ?assertNotEqual(nomatch,
        binary:match(Bin, fteid_ie(2, 4, 16#22222222, {10,0,0,1}))),
    ?assertNotEqual(nomatch, binary:match(Bin, rat_ie(6))).

%% ULI marker — exact bytes produced by encode_uli_ie/2 for MCC=262, MNC=22, ECI=0.
%% Flags octet 0x10 (bit 4 = ECGI present), then PLMN(3) + ECI(4).
%% encode_plmn(<<"262">>, <<"22">>):
%%   M1=$2, M2=$6, M3=$2 => A = (c2n($6)<<4)|c2n($2) = 0x62
%%   MNC="22" (2 digits) => N1=2, N2=2, N3=0xF
%%   B = (N3<<4)|c2n($2) = 0xF2,  C = (N2<<4)|N1 = 0x22
%%   PLMN = <<0x62, 0xF2, 0x22>>
%% IE = <<86, 8:16, 0:8, 0x10, 0x62, 0xF2, 0x22, 0:32>>
uli_marker() ->
    <<86:8, 8:16, 0:8, 16#10:8, 16#62:8, 16#F2:8, 16#22:8, 0:32>>.

s5s8_csr_includes_uli_test() ->
    P = (base_params())#{mode => s5s8, rat_type => 6,
                         serving_network => {<<"262">>, <<"22">>}},
    Bin = epdg_gtpc_codec:encode_create_session_request(P),
    ?assertNotEqual(nomatch, binary:match(Bin, uli_marker())),
    %% s2b mode must NOT gain ULI (no regression to Open5GS path)
    Bin2 = epdg_gtpc_codec:encode_create_session_request(base_params()),
    ?assertEqual(nomatch, binary:match(Bin2, uli_marker())).

%% Regression: when the FSM hardcodes rat_type => 3 but mode => s5s8,
%% the codec must still emit RAT-Type 6 (E-UTRAN), not 3 (WLAN).
s5s8_mode_forces_rat_eutran_regardless_of_caller_test() ->
    %% Simulate FSM hardcoding rat_type => 3 with s5s8 mode
    P = (base_params())#{mode => s5s8, rat_type => 3},
    Bin = epdg_gtpc_codec:encode_create_session_request(P),
    ?assertNotEqual(nomatch, binary:match(Bin, rat_ie(6))),
    ?assertEqual(nomatch, binary:match(Bin, rat_ie(3))).

csr_response_decodes_s5s8_pgw_fteids_test() ->
    %% top-level PGW S5/S8 GTP-C F-TEID (iface 7) + cause 16 + bearer ctx with iface 5
    %% Cause IE: type=2, len=3 (3 bytes of value: cause-code + 2 flag bytes)
    Cause = <<2:8, 3:16, 0:8, 16:8, 0:16>>,
    TopF  = fteid_ie(0, 7, 16#AAAAAAAA, {10,0,0,9}),
    BU    = fteid_ie(2, 5, 16#BBBBBBBB, {10,0,0,9}),
    EBI   = <<73:8, 1:16, 0:8, 5:8>>,
    BCInner = <<EBI/binary, BU/binary>>,
    BC    = <<93:8, (byte_size(BCInner)):16, 0:8, BCInner/binary>>,
    Body  = <<Cause/binary, TopF/binary, BC/binary>>,
    Hdr   = <<2:3, 0:1, 1:1, 0:3, 33:8, (8 + byte_size(Body)):16,
              0:32, 1:24, 0:8, Body/binary>>,
    {ok, Decoded} = epdg_gtpc_codec:decode_header(Hdr),
    R = epdg_gtpc_codec:decode_create_session_response(Decoded),
    ?assertMatch(#{iface := 7}, maps:get(pgw_c_fteid, R)),
    ?assertMatch(#{iface := 5}, maps:get(pgw_u_fteid, R)).

%%====================================================================
%% Dedicated bearer signalling (TS 29.274 §7.2.3-§7.2.10)
%%====================================================================

%% A minimal but valid "create new TFT" with one uplink UDP filter.
sample_tft() ->
    Contents = <<16#30:8, 17:8>>,
    Filter = <<0:2, 2:2, 1:4, 0:8, (byte_size(Contents)):8, Contents/binary>>,
    <<2#001:3, 0:1, 1:4, Filter/binary>>.

ie(Type, Value) ->
    <<Type:8, (byte_size(Value)):16, 0:8, Value/binary>>.

%% Build a Create Bearer Request (type 95): header TEID = ePDG S2b-C TEID,
%% top-level LBI (EBI 5), one Bearer Context {Bearer QoS, TFT, PGW-U F-TEID,
%% Charging Id}. `PgwUIface' is 33 for s2b, 5 for the s5s8 emulation.
create_bearer_request(PgwUIface) ->
    LBI  = ie(73, <<5:8>>),
    QoS  = ie(80, <<0:8, 1:8>>),
    Tft  = ie(84, sample_tft()),
    PgwF = fteid_ie(2, PgwUIface, 16#CAFEBABE, {10,0,0,9}),
    ChId = ie(94, <<16#00000007:32>>),
    BCInner = <<QoS/binary, Tft/binary, PgwF/binary, ChId/binary>>,
    BC   = ie(93, BCInner),
    Body = <<LBI/binary, BC/binary>>,
    <<2:3, 0:1, 1:1, 0:3, 95:8, (8 + byte_size(Body)):16,
      16#11111111:32, 42:24, 0:8, Body/binary>>.

create_bearer_request_decode_s2b_test() ->
    {ok, Decoded} = epdg_gtpc_codec:decode_header(create_bearer_request(33)),
    R = epdg_gtpc_codec:decode_create_bearer_request(Decoded),
    ?assertEqual(42, maps:get(seq_num, R)),
    ?assertEqual(16#11111111, maps:get(local_c_teid, R)),
    ?assertEqual(5, maps:get(lbi, R)),
    [BC] = maps:get(bearer_contexts, R),
    ?assertMatch(#{teid := 16#CAFEBABE, ip := {10,0,0,9}},
                 maps:get(pgw_u_fteid, BC)),
    ?assertEqual(7, maps:get(charging_id, BC)),
    ?assert(is_binary(maps:get(tft, BC))).

create_bearer_request_decode_s5s8_test() ->
    %% s5s8 emulation: the PGW's user-plane F-TEID uses the S5/S8-U interface (5).
    {ok, Decoded} = epdg_gtpc_codec:decode_header(create_bearer_request(5)),
    R = epdg_gtpc_codec:decode_create_bearer_request(Decoded),
    [BC] = maps:get(bearer_contexts, R),
    ?assertMatch(#{iface := 5, teid := 16#CAFEBABE}, maps:get(pgw_u_fteid, BC)).

create_bearer_response_encode_s2b_test() ->
    Bin = epdg_gtpc_codec:encode_create_bearer_response(
            #{seq_num => 42, teid => 16#AAAAAAAA, mode => s2b,
              bearers => [#{ebi => 6, u_teid => 16#22222222,
                            u_ip => {10,0,0,1},
                            pgw_u_teid => 16#33333333,
                            pgw_u_ip => {10,156,15,229}}]}),
    {ok, D} = epdg_gtpc_codec:decode_header(Bin),
    ?assertEqual(96, maps:get(type, D)),
    ?assertEqual(42, maps:get(seq_num, D)),
    ?assertEqual(16#AAAAAAAA, maps:get(teid, D)),
    %% Create Bearer Response bearer context (TS 29.274 Table 7.2.4-2):
    %% the ePDG's own S2b-U F-TEID at iface 31, instance 8 ...
    ?assertNotEqual(nomatch,
        binary:match(Bin, fteid_ie(8, 31, 16#22222222, {10,0,0,1}))),
    %% ... and the echoed PGW S2b-U F-TEID at iface 33, instance 9.
    ?assertNotEqual(nomatch,
        binary:match(Bin, fteid_ie(9, 33, 16#33333333, {10,156,15,229}))).

create_bearer_response_encode_s5s8_test() ->
    Bin = epdg_gtpc_codec:encode_create_bearer_response(
            #{seq_num => 42, teid => 16#AAAAAAAA, mode => s5s8,
              bearers => [#{ebi => 6, u_teid => 16#22222222,
                            u_ip => {10,0,0,1},
                            pgw_u_teid => 16#33333333,
                            pgw_u_ip => {10,156,15,229}}]}),
    %% s5s8 emulation: own SGW S5/S8-U F-TEID at iface 4, instance 2 ...
    ?assertNotEqual(nomatch,
        binary:match(Bin, fteid_ie(2, 4, 16#22222222, {10,0,0,1}))),
    %% ... and the echoed PGW S5/S8-U F-TEID at iface 5, instance 3.
    ?assertNotEqual(nomatch,
        binary:match(Bin, fteid_ie(3, 5, 16#33333333, {10,156,15,229}))).

update_bearer_response_encode_test() ->
    Bin = epdg_gtpc_codec:encode_update_bearer_response(
            #{seq_num => 7, teid => 16#AAAAAAAA,
              bearers => [#{ebi => 6}]}),
    {ok, D} = epdg_gtpc_codec:decode_header(Bin),
    ?assertEqual(98, maps:get(type, D)),
    ?assertEqual(7, maps:get(seq_num, D)),
    %% top-level Cause 16 (Request accepted).
    ?assertNotEqual(nomatch, binary:match(Bin, <<2:8, 2:16, 0:8, 16:8, 0:8>>)).

delete_bearer_response_encode_test() ->
    Bin = epdg_gtpc_codec:encode_delete_bearer_response(
            #{seq_num => 9, teid => 16#AAAAAAAA,
              bearers => [#{ebi => 6}]}),
    {ok, D} = epdg_gtpc_codec:decode_header(Bin),
    ?assertEqual(100, maps:get(type, D)),
    ?assertEqual(9, maps:get(seq_num, D)).

delete_bearer_request_decode_test() ->
    %% Delete Bearer Request (type 99) listing one dedicated EBI (6).
    EBI  = ie(73, <<6:8>>),
    Hdr  = <<2:3, 0:1, 1:1, 0:3, 99:8, (8 + byte_size(EBI)):16,
             16#11111111:32, 3:24, 0:8, EBI/binary>>,
    {ok, Decoded} = epdg_gtpc_codec:decode_header(Hdr),
    R = epdg_gtpc_codec:decode_delete_bearer_request(Decoded),
    ?assertEqual(3, maps:get(seq_num, R)),
    ?assertEqual([6], maps:get(ebis, R)).
