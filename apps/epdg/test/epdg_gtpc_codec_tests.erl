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
