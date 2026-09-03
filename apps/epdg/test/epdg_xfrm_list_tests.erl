-module(epdg_xfrm_list_tests).
-include_lib("eunit/include/eunit.hrl").

%% Parser tests for `ip xfrm state list` / `ip xfrm policy list` output.
%%
%% The reconciler DELETES kernel state based on these parses, so the
%% contract under test is asymmetric: a block the parser does not fully
%% understand must be DROPPED (never guessed at), because a misparsed
%% src/dst/spi would tear down a live UE's tunnel. Sample output is from
%% iproute2 on the GKE ePDG nodes (NAT-T espinudp SA, per-UE in/fwd/out
%% policies, plus the socket policies every UDP socket owns).

%%====================================================================
%% ip xfrm state list
%%====================================================================

state_output() ->
    "src 93.204.201.107 dst 34.107.29.11\n"
    "\tproto esp spi 0x05974942 reqid 93800770 mode tunnel\n"
    "\treplay-window 32 flag af-unspec\n"
    "\tauth-trunc hmac(sha256) 0xabcdef 128\n"
    "\tenc cbc(aes) 0x0011223344556677\n"
    "\tencap type espinudp sport 23830 dport 4500 addr 0.0.0.0\n"
    "\tanti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000\n"
    "\tsel src 0.0.0.0/0 dst 0.0.0.0/0\n"
    "src 34.107.29.11 dst 93.204.201.107\n"
    "\tproto esp spi 0xc91f55b2 reqid 93800770 mode tunnel\n"
    "\treplay-window 32 flag af-unspec\n"
    "\tenc rfc4106(gcm(aes)) 0x99aabb\n"
    "\tsel src 0.0.0.0/0 dst 0.0.0.0/0\n".

parses_both_sas_test() ->
    SAs = epdg_xfrm:parse_state_list(state_output()),
    ?assertEqual(2, length(SAs)),
    [In, Out] = SAs,
    ?assertEqual(#{src => {93,204,201,107}, dst => {34,107,29,11},
                   spi => 16#05974942, reqid => 93800770}, In),
    ?assertEqual(#{src => {34,107,29,11}, dst => {93,204,201,107},
                   spi => 16#c91f55b2, reqid => 93800770}, Out).

empty_state_output_test() ->
    ?assertEqual([], epdg_xfrm:parse_state_list("")),
    ?assertEqual([], epdg_xfrm:parse_state_list("\n")).

%% A non-ESP state (e.g. AH, or a truncated block without an spi) must
%% be dropped, not misattributed.
non_esp_state_dropped_test() ->
    Out = "src 10.0.0.1 dst 10.0.0.2\n"
          "\tproto ah spi 0x00000123 reqid 7 mode tunnel\n",
    ?assertEqual([], epdg_xfrm:parse_state_list(Out)).

state_without_spi_dropped_test() ->
    Out = "src 10.0.0.1 dst 10.0.0.2\n"
          "\tproto esp mode tunnel\n",
    ?assertEqual([], epdg_xfrm:parse_state_list(Out)).

%%====================================================================
%% ip xfrm policy list
%%====================================================================

policy_output() ->
    "src 10.46.0.34/32 dst 0.0.0.0/0\n"
    "\tdir fwd priority 0\n"
    "\ttmpl src 93.204.201.107 dst 34.107.29.11\n"
    "\t\tproto esp reqid 93800770 mode tunnel\n"
    "src 0.0.0.0/0 dst 10.46.0.34/32\n"
    "\tdir out priority 0\n"
    "\ttmpl src 34.107.29.11 dst 93.204.201.107\n"
    "\t\tproto esp reqid 93800770 mode tunnel\n"
    "src 0.0.0.0/0 dst 0.0.0.0/0\n"
    "\tsocket in priority 0\n"
    "src fd00:230:babe:9c::/64 dst ::/0\n"
    "\tdir in priority 0\n"
    "\ttmpl src 93.204.201.107 dst 34.107.29.11\n"
    "\t\tproto esp reqid 93800770 mode tunnel\n".

parses_policies_and_skips_socket_test() ->
    Pols = epdg_xfrm:parse_policy_list(policy_output()),
    %% The "socket in" block has no `dir` keyword and is dropped.
    ?assertEqual(3, length(Pols)),
    [Fwd, Out, In6] = Pols,
    ?assertEqual(#{src => "10.46.0.34/32", dst => "0.0.0.0/0", dir => fwd,
                   tmpl_src => {93,204,201,107}, tmpl_dst => {34,107,29,11},
                   reqid => 93800770}, Fwd),
    ?assertEqual(out, maps:get(dir, Out)),
    ?assertEqual({34,107,29,11}, maps:get(tmpl_src, Out)),
    %% IPv6 selector over IPv4 outer template (dual-stack PDN)
    ?assertEqual("fd00:230:babe:9c::/64", maps:get(src, In6)),
    ?assertEqual({93,204,201,107}, maps:get(tmpl_src, In6)).

%% A policy without any template (not installed by the ePDG) still
%% parses, with reqid 0 — the reconciler skips reqid-0 policies.
policy_without_tmpl_test() ->
    Out = "src 10.1.0.0/16 dst 0.0.0.0/0\n"
          "\tdir in priority 100\n",
    [P] = epdg_xfrm:parse_policy_list(Out),
    ?assertEqual(0, maps:get(reqid, P)),
    ?assertEqual(undefined, maps:get(tmpl_src, P)).
