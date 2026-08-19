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

%% The IPv4 sibling: one P-CSCF, sent as RFC 7651's 20 and as 3GPP's
%% private-use 16389 (TS 24.302 §8.1.2.2) with the same 4-byte value, exactly
%% like the 21/16390 pair above.
pcscf4_sent_under_both_attribute_numbers_test() ->
    Attrs = cfg_attrs(epdg_ue_fsm:build_cfg_reply(v6_only_pdn())),
    Bin = <<10, 42, 0, 1>>,
    ?assertEqual([Bin], pick(p_cscf_ip4_address, Attrs)),
    ?assertEqual([Bin], pick(p_cscf_ip4_address_3gpp, Attrs)).

pcscf4_attribute_numbers_on_the_wire_test() ->
    Reply = epdg_ue_fsm:build_cfg_reply(v6_only_pdn()),
    ?assertNotEqual(nomatch, binary:match(Reply, <<0:1,    20:15, 4:16>>)),
    ?assertNotEqual(nomatch, binary:match(Reply, <<0:1, 16389:15, 4:16>>)).

%% No IPv4 P-CSCF granted -> neither attribute number is invented.
no_pcscf4_means_neither_attribute_test() ->
    Pdn = (v6_only_pdn())#{pcscf4 => []},
    Attrs = cfg_attrs(epdg_ue_fsm:build_cfg_reply(Pdn)),
    ?assertEqual([], pick(p_cscf_ip4_address, Attrs)),
    ?assertEqual([], pick(p_cscf_ip4_address_3gpp, Attrs)).

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

%%====================================================================
%% Handover addresses from the UE's CFG_REQUEST
%%====================================================================

cfg_request(Attrs) -> epdg_ikev2_codec:encode_cp_payload(1, Attrs).

%% The failure this replaced: iOS handing an IPv6 IMS PDN over from LTE sends
%% INTERNAL_IP6_ADDRESS and no IPv4 attribute at all. Reading only the IPv4
%% attribute left the handover address undefined, so no PAA and no Handover
%% Indication reached the PGW, it allocated a different prefix, and the UE saw
%% its cellular and WiFi contexts on two addresses for one APN
%% ("kDataProtocolFamilyIPv6 - conflict" ->
%% kDataContextDeactivateHandoverConflict -> "Error bringing interface online")
%% and deleted the tunnel ~50 ms after it came up.
handover_v6_read_from_ipv6_only_request_test() ->
    Req = cfg_request([{internal_ip6_address,
                        <<(ip6_bin(?UE_LTE_ADDR))/binary, 64:8>>},
                       {internal_ip6_dns, <<0:128>>}]),
    ?assertEqual(#{v4 => undefined, v6 => ?UE_LTE_PREFIX},
                 epdg_ue_fsm:requested_handover_addrs(Req)).

%% We ask the PGW for the prefix, not the UE's full address: the interface
%% identifier is the UE's own and may rotate for privacy.
handover_v6_masks_ue_interface_identifier_test() ->
    Req = cfg_request([{internal_ip6_address,
                        <<(ip6_bin(?UE_ACTUAL_SRC))/binary, 64:8>>}]),
    ?assertEqual(#{v4 => undefined,
                   v6 => {16#fd00, 16#230, 16#babe, 16#24, 0, 0, 0, 0}},
                 epdg_ue_fsm:requested_handover_addrs(Req)).

handover_v6_tolerates_missing_prefix_length_test() ->
    Req = cfg_request([{internal_ip6_address, ip6_bin(?UE_LTE_ADDR)}]),
    ?assertMatch(#{v6 := ?UE_LTE_PREFIX},
                 epdg_ue_fsm:requested_handover_addrs(Req)).

%% Fresh attach: the UE names the family it wants without naming an address.
fresh_attach_has_no_handover_addrs_test() ->
    Req = cfg_request([{internal_ip4_address, <<0, 0, 0, 0>>},
                       {internal_ip6_address, <<0:128, 64:8>>}]),
    ?assertEqual(#{v4 => undefined, v6 => undefined},
                 epdg_ue_fsm:requested_handover_addrs(Req)).

handover_v4_still_read_test() ->
    Req = cfg_request([{internal_ip4_address, <<10, 46, 0, 33>>}]),
    ?assertEqual(#{v4 => {10,46,0,33}, v6 => undefined},
                 epdg_ue_fsm:requested_handover_addrs(Req)).

dual_stack_handover_reads_both_families_test() ->
    Req = cfg_request([{internal_ip4_address, <<10, 46, 0, 33>>},
                       {internal_ip6_address,
                        <<(ip6_bin(?UE_LTE_ADDR))/binary, 64:8>>}]),
    ?assertEqual(#{v4 => {10,46,0,33}, v6 => ?UE_LTE_PREFIX},
                 epdg_ue_fsm:requested_handover_addrs(Req)).

%% A CFG_REQUEST we cannot parse (or no CP payload at all) is a fresh attach,
%% not a crash: undefined addresses simply mean dynamic allocation.
unparseable_cp_body_is_a_fresh_attach_test() ->
    None = #{v4 => undefined, v6 => undefined},
    ?assertEqual(None, epdg_ue_fsm:requested_handover_addrs(<<1, 2, 3>>)),
    ?assertEqual(None, epdg_ue_fsm:requested_handover_addrs(<<>>)),
    ?assertEqual(None, epdg_ue_fsm:requested_handover_addrs(undefined)).

%% End-to-end over the two modules that have to agree: the address the UE asks
%% to keep, once granted by the PGW, must produce a selector that covers the
%% address the UE will actually use inside that prefix.
handover_prefix_round_trips_into_the_selector_test() ->
    Req = cfg_request([{internal_ip6_address,
                        <<(ip6_bin(?UE_LTE_ADDR))/binary, 64:8>>}]),
    #{v6 := Prefix} = epdg_ue_fsm:requested_handover_addrs(Req),
    %% PGW honours the PAA and hands the prefix back as the PDN address.
    ?assertEqual(epdg_ue_fsm:ue6_selector(Prefix),
                 epdg_ue_fsm:ue6_selector(?UE_LTE_ADDR)),
    %% ...and the UE's own interface identifier in that prefix is covered too.
    {A, B, C, D, _, _, _, _} = Prefix,
    Autoconf = {A, B, C, D, 16#dead, 16#beef, 16#0, 16#1},
    ?assertEqual(epdg_ue_fsm:ue6_selector(Prefix),
                 epdg_ue_fsm:ue6_selector(Autoconf)).
