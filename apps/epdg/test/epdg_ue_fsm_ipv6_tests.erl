-module(epdg_ue_fsm_ipv6_tests).
-include_lib("eunit/include/eunit.hrl").

%% IPv6 PDN plumbing: the inner XFRM selector, what goes into the CFG_REPLY, and
%% the handover addresses read out of the UE's CFG_REQUEST.
%%
%% The constants below are the real values from the 2026-08-18 15:55 lab capture
%% (iPhone 12 mini, IMSI 262034860127847, LTE -> VoWiFi handover), so each test
%% pins the exact failure that was observed rather than an invented one.

%% What the UE held on LTE and asked to keep (CFG_REQUEST InternalIP6Address).
-define(UE_LTE_ADDR,   {16#fd00, 16#230, 16#babe, 16#22, 0, 0, 0, 1}).
-define(UE_LTE_PREFIX, {16#fd00, 16#230, 16#babe, 16#22, 0, 0, 0, 0}).
%% What the PGW handed out instead, and the address the UE then actually used —
%% same /64, its own interface identifier.
-define(ASSIGNED,      {16#fd00, 16#230, 16#babe, 16#24, 0, 0, 0, 1}).
-define(UE_ACTUAL_SRC, {16#fd00, 16#230, 16#babe, 16#24,
                        16#ff75, 16#386e, 16#bef4, 16#74ad}).
%% The core's real IPv6 P-CSCF, and the IPv4 one the PGW put in the PCO.
-define(PCSCF6, {16#fd00, 16#230, 16#babe, 1, 0, 0, 0, 1}).
-define(PCSCF4, {10, 42, 0, 1}).

ip6_bin({A,B,C,D,E,F,G,H}) -> <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>.

%%====================================================================
%% Inner XFRM selector
%%====================================================================

ue6_selector_masks_host_bits_test() ->
    ?assertEqual("fd00:230:babe:24::/64", epdg_ue_fsm:ue6_selector(?ASSIGNED)).

%% The property the data plane depends on: the address the UE actually sources
%% from and receives on must land inside the selector we installed for the
%% address the PAA named.
ue6_selector_covers_ue_autoconfigured_address_test() ->
    ?assertEqual(epdg_ue_fsm:ue6_selector(?ASSIGNED),
                 epdg_ue_fsm:ue6_selector(?UE_ACTUAL_SRC)).

%% The failure this replaced: a /128 selector on the PAA address matched nothing
%% the UE sent or received, so the kernel dropped the uplink on the inbound
%% policy check and never encapsulated the downlink. The tunnel came up and
%% carried no traffic — the UE's REGISTER sat in "Trying" for 100 s and then it
%% deleted the tunnel.
ue6_selector_is_not_a_host_route_test() ->
    Sel = epdg_ue_fsm:ue6_selector(?ASSIGNED),
    ?assertEqual(nomatch, string:find(Sel, "/128")),
    ?assertNotEqual("fd00:230:babe:24::1/128", Sel).

%% install_v6_policies/4 and delete_ue6_policies/1 both go through
%% ue6_selector/1 precisely so the strings match; `ip xfrm' deletes by selector,
%% and a mismatch leaks the policy into the next session. Any address in the /64
%% must therefore produce a byte-identical selector.
ue6_selector_is_stable_across_the_prefix_test() ->
    Expected = epdg_ue_fsm:ue6_selector(?ASSIGNED),
    [?assertEqual(Expected, epdg_ue_fsm:ue6_selector(A))
     || A <- [?ASSIGNED, ?UE_ACTUAL_SRC,
              {16#fd00, 16#230, 16#babe, 16#24, 0, 0, 0, 0},
              {16#fd00, 16#230, 16#babe, 16#24, 16#ffff, 16#ffff,
               16#ffff, 16#ffff}]],
    ok.

ue6_selector_distinguishes_different_prefixes_test() ->
    ?assertNotEqual(epdg_ue_fsm:ue6_selector(?ASSIGNED),
                    epdg_ue_fsm:ue6_selector(?UE_LTE_ADDR)).

ip6_mask_test() ->
    ?assertEqual(?UE_LTE_PREFIX, epdg_ue_fsm:ip6_mask(?UE_LTE_ADDR, 64)),
    ?assertEqual(?UE_LTE_ADDR,   epdg_ue_fsm:ip6_mask(?UE_LTE_ADDR, 128)),
    ?assertEqual({0,0,0,0,0,0,0,0}, epdg_ue_fsm:ip6_mask(?UE_LTE_ADDR, 0)),
    ?assertEqual({16#fd00, 16#230, 0, 0, 0, 0, 0, 0},
                 epdg_ue_fsm:ip6_mask(?UE_LTE_ADDR, 32)),
    %% Not hextet-aligned, to prove the mask is bit- and not word-based.
    ?assertEqual({16#fd00, 16#200, 0, 0, 0, 0, 0, 0},
                 epdg_ue_fsm:ip6_mask(?UE_LTE_ADDR, 24)).

%%====================================================================
%% CFG_REPLY contents
%%====================================================================

cfg_attrs(Reply) ->
    {ok, {2, Attrs}} = epdg_ikev2_codec:decode_cp_payload(Reply),
    Attrs.

pick(Key, Attrs) -> [V || {K, V} <- Attrs, K =:= Key].

%% An IPv6-only PDN, with the PGW returning only an IPv4 P-CSCF in the PCO —
%% exactly what the lab core did.
v6_only_pdn() ->
    #{ip4 => {0,0,0,0}, ip6 => ?ASSIGNED,
      dns4 => [], dns6 => [],
      pcscf4 => [?PCSCF4], pcscf6 => []}.

%% The failure this replaced: DNS and P-CSCF lived inside the "an IPv4 address
%% was granted" branch, so on an IPv6-only PDN the reply went out carrying the
%% address and NOTHING else. The UE had no P-CSCF to register against and only
%% limped on because it still had one cached from its LTE PCO.
v6_only_pdn_still_carries_pcscf_test() ->
    Attrs = cfg_attrs(epdg_ue_fsm:build_cfg_reply(v6_only_pdn())),
    ?assertEqual([<<10, 42, 0, 1>>], pick(p_cscf_ip4_address, Attrs)),
    %% The address attribute is still there, with the /64 prefix length.
    ?assertMatch([<<_:128, 64:8>>], pick(internal_ip6_address, Attrs)),
    %% ...and no IPv4 address/netmask is invented, since none was granted.
    ?assertEqual([], pick(internal_ip4_address, Attrs)),
    ?assertEqual([], pick(internal_ip4_netmask, Attrs)).

%% iOS requests the IPv6 P-CSCF as the 3GPP private attribute 16390 and ignores
%% RFC 7651's 21; other stacks do the reverse. Send both.
pcscf6_sent_under_both_attribute_numbers_test() ->
    Pdn = (v6_only_pdn())#{pcscf6 => [?PCSCF6]},
    Attrs = cfg_attrs(epdg_ue_fsm:build_cfg_reply(Pdn)),
    Bin = ip6_bin(?PCSCF6),
    ?assertEqual([Bin], pick(p_cscf_ip6_address, Attrs)),
    ?assertEqual([Bin], pick(p_cscf_ip6_address_3gpp, Attrs)).

%% Guards the attribute numbers on the wire: 21 (RFC 7651) and 16390 (3GPP),
%% never 22 — which is what we used to emit and which IANA assigns to something
%% else entirely, so no UE read it as a P-CSCF.
pcscf6_attribute_numbers_on_the_wire_test() ->
    Pdn = (v6_only_pdn())#{pcscf6 => [?PCSCF6]},
    Reply = epdg_ue_fsm:build_cfg_reply(Pdn),
    ?assertNotEqual(nomatch, binary:match(Reply, <<0:1,    21:15, 16:16>>)),
    ?assertNotEqual(nomatch, binary:match(Reply, <<0:1, 16390:15, 16:16>>)),
    ?assertEqual(nomatch,    binary:match(Reply, <<0:1,    22:15, 16:16>>)).

dns_sent_for_both_families_test() ->
    Pdn = (v6_only_pdn())#{dns4 => [{10,42,0,2}], dns6 => [?PCSCF6]},
    Attrs = cfg_attrs(epdg_ue_fsm:build_cfg_reply(Pdn)),
    ?assertEqual([<<10, 42, 0, 2>>], pick(internal_ip4_dns, Attrs)),
    ?assertEqual([ip6_bin(?PCSCF6)], pick(internal_ip6_dns, Attrs)).

v4_only_pdn_unchanged_test() ->
    Pdn = #{ip4 => {10,42,0,94}, ip6 => undefined,
            dns4 => [], dns6 => [], pcscf4 => [?PCSCF4], pcscf6 => []},
    Attrs = cfg_attrs(epdg_ue_fsm:build_cfg_reply(Pdn)),
    ?assertEqual([<<10, 42, 0, 94>>], pick(internal_ip4_address, Attrs)),
    ?assertEqual([<<255, 255, 255, 255>>], pick(internal_ip4_netmask, Attrs)),
    ?assertEqual([<<10, 42, 0, 1>>], pick(p_cscf_ip4_address, Attrs)),
    ?assertEqual([], pick(internal_ip6_address, Attrs)).

dual_stack_pdn_carries_both_addresses_test() ->
    Pdn = #{ip4 => {10,42,0,94}, ip6 => ?ASSIGNED,
            dns4 => [], dns6 => [],
            pcscf4 => [?PCSCF4], pcscf6 => [?PCSCF6]},
    Attrs = cfg_attrs(epdg_ue_fsm:build_cfg_reply(Pdn)),
    ?assertEqual([<<10, 42, 0, 94>>], pick(internal_ip4_address, Attrs)),
    ?assertMatch([<<_:128, 64:8>>], pick(internal_ip6_address, Attrs)),
    ?assertEqual([<<10, 42, 0, 1>>], pick(p_cscf_ip4_address, Attrs)),
    ?assertEqual([ip6_bin(?PCSCF6)], pick(p_cscf_ip6_address, Attrs)).

%% A PDN with nothing granted must still produce a well-formed (empty) reply
%% rather than crashing the IKE_AUTH response path.
empty_pdn_yields_empty_reply_test() ->
    Pdn = #{ip4 => {0,0,0,0}, ip6 => undefined,
            dns4 => [], dns6 => [], pcscf4 => [], pcscf6 => []},
    ?assertEqual([], cfg_attrs(epdg_ue_fsm:build_cfg_reply(Pdn))).
