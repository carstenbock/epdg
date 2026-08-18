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
