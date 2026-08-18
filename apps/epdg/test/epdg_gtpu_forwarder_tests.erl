-module(epdg_gtpu_forwarder_tests).
-include_lib("eunit/include/eunit.hrl").

%% Tests for the shared-TUN datapath: inner source-IP parsing, pool
%% validation, uplink-to-bearer classification and the dedicated-bearer
%% TFT regression. All tests run against the forwarder's pure
%% bookkeeping functions (exported under -ifdef(TEST)) on a socket-less,
%% TUN-less #state{} — registration must not shell out, so none of this
%% needs NET_ADMIN.

-define(POOLS, [{{10, 46, 0, 0}, 16},
                {{16#cafe, 0, 16#46, 0, 0, 0, 0, 0}, 48}]).

-define(PGW_IP1, {203, 0, 113, 1}).
-define(PGW_IP2, {203, 0, 113, 2}).

%%====================================================================
%% Packet builders (raw L3, IFF_NO_PI — same shape the TUN delivers)
%%====================================================================

ipv4_udp(Src, Dst, SPort, DPort) ->
    {S1, S2, S3, S4} = Src,
    {D1, D2, D3, D4} = Dst,
    UDP = <<SPort:16, DPort:16, 8:16, 0:16>>,
    IPLen = 20 + byte_size(UDP),
    <<4:4, 5:4, 0:8, IPLen:16, 0:16, 0:3, 0:13, 64:8, 17:8, 0:16,
      S1:8, S2:8, S3:8, S4:8, D1:8, D2:8, D3:8, D4:8, UDP/binary>>.

ipv6_udp(Src, Dst, SPort, DPort) ->
    {S1, S2, S3, S4, S5, S6, S7, S8} = Src,
    {D1, D2, D3, D4, D5, D6, D7, D8} = Dst,
    UDP = <<SPort:16, DPort:16, 8:16, 0:16>>,
    <<6:4, 0:8, 0:20, (byte_size(UDP)):16, 17:8, 64:8,
      S1:16, S2:16, S3:16, S4:16, S5:16, S6:16, S7:16, S8:16,
      D1:16, D2:16, D3:16, D4:16, D5:16, D6:16, D7:16, D8:16,
      UDP/binary>>.

%% TFT builders — same encoding as epdg_tft_tests (TS 24.008 §10.5.6.12).
tft(Dir, Contents) ->
    Filter = <<0:2, Dir:2, 1:4, 0:8, (byte_size(Contents)):8, Contents/binary>>,
    <<2#001:3, 0:1, 1:4, Filter/binary>>.

udp_proto() -> <<16#30:8, 17:8>>.

remote_port_range(Lo, Hi) -> <<16#51:8, Lo:16, Hi:16>>.

%%====================================================================
%% Registration helpers
%%====================================================================

reg(Ip4, Ip6, Teid, PgwTeid, PgwIP, State) ->
    reg_imsi(Ip4, Ip6, Teid, PgwTeid, PgwIP, <<"001010000000001">>, State).

reg_imsi(Ip4, Ip6, Teid, PgwTeid, PgwIP, Imsi, State) ->
    Params0 = #{pgw_u_teid => PgwTeid, pgw_u_ip => PgwIP,
                ue_inner_ip => Ip4, local_teid_hint => Teid,
                imsi => Imsi},
    Params = case Ip6 of
                 undefined -> Params0;
                 _         -> Params0#{ue_inner_ip6 => Ip6}
             end,
    epdg_gtpu_forwarder:register_ue_for_test(Params, State).

%%====================================================================
%% Inner source-IP parser
%%====================================================================

%% Uplink attribution is keyed on the inner source IP; if the parser
%% reads the wrong offset every packet lands on the wrong bearer.
inner_src_key_v4_test() ->
    Pkt = ipv4_udp({10, 46, 0, 2}, {203, 0, 113, 5}, 40000, 5060),
    ?assertEqual({ok, {10, 46, 0, 2}}, epdg_gtpu_forwarder:inner_src_key(Pkt)).

%% IPv6 keys on the /64 prefix, NOT the full address: the PGW delegates
%% the whole /64 to the UE, which may source from any SLAAC/privacy
%% address inside it.
inner_src_key_v6_is_prefix_test() ->
    Src = {16#cafe, 0, 16#46, 1, 16#aaaa, 16#bbbb, 16#cccc, 16#dddd},
    Pkt = ipv6_udp(Src, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 40000, 5060),
    ?assertEqual({ok, {v6, {16#cafe, 0, 16#46, 1}}},
                 epdg_gtpu_forwarder:inner_src_key(Pkt)).

%% A truncated header must not be classified from garbage bytes.
inner_src_key_truncated_v4_test() ->
    Full = ipv4_udp({10, 46, 0, 2}, {203, 0, 113, 5}, 40000, 5060),
    Short = binary:part(Full, 0, 19),
    ?assertEqual(error, epdg_gtpu_forwarder:inner_src_key(Short)).

inner_src_key_truncated_v6_test() ->
    Full = ipv6_udp({16#cafe, 0, 16#46, 1, 0, 0, 0, 1},
                    {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 40000, 5060),
    Short = binary:part(Full, 0, 39),
    ?assertEqual(error, epdg_gtpu_forwarder:inner_src_key(Short)).

%% Non-IP payloads (bad version nibble, empty frames) must be rejected,
%% not misread as addresses.
inner_src_key_non_ip_test() ->
    ?assertEqual(error, epdg_gtpu_forwarder:inner_src_key(<<>>)),
    ?assertEqual(error, epdg_gtpu_forwarder:inner_src_key(<<16#ff, 0:200>>)),
    ?assertEqual(error, epdg_gtpu_forwarder:inner_src_key(<<0:160>>)).

%%====================================================================
%% CIDR membership
%%====================================================================

ip_in_cidr_v4_test() ->
    Pool = {{10, 46, 0, 0}, 16},
    ?assert(epdg_gtpu_forwarder:ip_in_cidr({10, 46, 0, 1}, Pool)),
    ?assert(epdg_gtpu_forwarder:ip_in_cidr({10, 46, 255, 255}, Pool)),
    ?assertNot(epdg_gtpu_forwarder:ip_in_cidr({10, 47, 0, 0}, Pool)),
    ?assertNot(epdg_gtpu_forwarder:ip_in_cidr({10, 45, 255, 255}, Pool)).

ip_in_cidr_v6_test() ->
    Pool = {{16#cafe, 0, 16#46, 0, 0, 0, 0, 0}, 48},
    ?assert(epdg_gtpu_forwarder:ip_in_cidr(
              {16#cafe, 0, 16#46, 16#ffff, 0, 0, 0, 1}, Pool)),
    ?assertNot(epdg_gtpu_forwarder:ip_in_cidr(
                 {16#cafe, 0, 16#47, 0, 0, 0, 0, 1}, Pool)).

%% An address never matches a pool of the other family — otherwise a v4
%% address could leak through a v6-only pool list.
ip_in_cidr_family_mismatch_test() ->
    ?assertNot(epdg_gtpu_forwarder:ip_in_cidr(
                 {10, 46, 0, 1}, {{16#cafe, 0, 16#46, 0, 0, 0, 0, 0}, 48})),
    ?assertNot(epdg_gtpu_forwarder:ip_in_cidr(
                 {16#cafe, 0, 16#46, 0, 0, 0, 0, 1}, {{10, 46, 0, 0}, 16})).

validate_inner_ips_test() ->
    ?assertEqual(ok, epdg_gtpu_forwarder:validate_inner_ips(
                       {10, 46, 0, 2}, undefined, ?POOLS)),
    %% The v4 unspecified address means "v6-only bearer" and is skipped.
    ?assertEqual(ok, epdg_gtpu_forwarder:validate_inner_ips(
                       {0, 0, 0, 0},
                       {16#cafe, 0, 16#46, 1, 0, 0, 0, 1}, ?POOLS)),
    ?assertMatch({error, [{192, 168, 1, 2}]},
                 epdg_gtpu_forwarder:validate_inner_ips(
                   {192, 168, 1, 2}, undefined, ?POOLS)),
    %% BOTH addresses must be inside a pool; one stray family is enough
    %% to reject (that family's uplink would be unroutable).
    ?assertMatch({error, [{16#fd00, 0, 0, 0, 0, 0, 0, 1}]},
                 epdg_gtpu_forwarder:validate_inner_ips(
                   {10, 46, 0, 2}, {16#fd00, 0, 0, 0, 0, 0, 0, 1}, ?POOLS)).

%%====================================================================
%% Registration + uplink classification
%%====================================================================

%% Two UEs with different inner IPs must classify onto their own TEIDs —
%% this is the property that replaced the per-UE TUN isolation.
two_ues_classify_to_own_bearers_test() ->
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    {{ok, #{local_teid := 1001, tun_name := TunName}}, S1} =
        reg({10, 46, 0, 2}, undefined, 1001, 501, ?PGW_IP1, S0),
    %% API compatibility: callers still get a tun_name, now the shared one.
    ?assertEqual("epdg0", TunName),
    {{ok, #{local_teid := 1002}}, S2} =
        reg({10, 46, 0, 3}, undefined, 1002, 502, ?PGW_IP2, S1),
    PktA = ipv4_udp({10, 46, 0, 2}, {203, 0, 113, 5}, 40000, 5060),
    PktB = ipv4_udp({10, 46, 0, 3}, {203, 0, 113, 5}, 40000, 5060),
    ?assertEqual({ok, 1001, {501, ?PGW_IP1}},
                 epdg_gtpu_forwarder:classify_for_test(PktA, S2)),
    ?assertEqual({ok, 1002, {502, ?PGW_IP2}},
                 epdg_gtpu_forwarder:classify_for_test(PktB, S2)).

%% A v6 UE must be found for ANY source address within its delegated /64
%% (e.g. an RFC 4941 privacy address), not just the PAA address.
v6_ue_classified_by_prefix_test() ->
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    Paa = {16#cafe, 0, 16#46, 1, 0, 0, 0, 1},
    {{ok, _}, S1} = reg({0, 0, 0, 0}, Paa, 1001, 501, ?PGW_IP1, S0),
    Privacy = {16#cafe, 0, 16#46, 1, 16#dead, 16#beef, 16#1234, 16#5678},
    Pkt = ipv6_udp(Privacy, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 40000, 5060),
    ?assertEqual({ok, 1001, {501, ?PGW_IP1}},
                 epdg_gtpu_forwarder:classify_for_test(Pkt, S1)),
    %% A different /64 (another UE's delegation) must NOT match.
    Other = ipv6_udp({16#cafe, 0, 16#46, 2, 0, 0, 0, 1},
                     {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 40000, 5060),
    ?assertEqual(unknown_src, epdg_gtpu_forwarder:classify_for_test(Other, S1)).

%% Uplink from a source IP that no bearer owns must be dropped and
%% counted — with a pool-wide rule the TUN now sees such packets, and a
%% silent drop would be undebuggable.
unknown_src_dropped_and_counted_test() ->
    epdg_metrics:init(),
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    {{ok, _}, S1} = reg({10, 46, 0, 2}, undefined, 1001, 501, ?PGW_IP1, S0),
    Before = epdg_metrics:get(gtpu_uplink_unknown_src_total),
    Pkt = ipv4_udp({10, 46, 9, 9}, {203, 0, 113, 5}, 40000, 5060),
    _ = epdg_gtpu_forwarder:uplink_for_test(Pkt, S1),
    ?assertEqual(Before + 1,
                 epdg_metrics:get(gtpu_uplink_unknown_src_total)),
    %% Malformed frames cannot be attributed either and count the same.
    _ = epdg_gtpu_forwarder:uplink_for_test(<<16#ff, 1, 2, 3>>, S1),
    ?assertEqual(Before + 2,
                 epdg_metrics:get(gtpu_uplink_unknown_src_total)).

%% A UE whose PGW-assigned IP is outside every configured pool must be
%% rejected loudly at registration: it would otherwise attach with an
%% uplink black-hole that is invisible until a subscriber complains.
outside_pool_rejected_test() ->
    epdg_metrics:init(),
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    Before = epdg_metrics:get(ue_ip_outside_pool_total),
    {Reply, S1} = reg({192, 168, 1, 2}, undefined, 1001, 501, ?PGW_IP1, S0),
    ?assertEqual({error, ue_ip_outside_configured_pools}, Reply),
    ?assertEqual(Before + 1, epdg_metrics:get(ue_ip_outside_pool_total)),
    %% Nothing must have been registered.
    Pkt = ipv4_udp({192, 168, 1, 2}, {203, 0, 113, 5}, 40000, 5060),
    ?assertEqual(unknown_src, epdg_gtpu_forwarder:classify_for_test(Pkt, S1)).

%% Re-attach reusing the same inner IP before the stale session's
%% cleanup ran: the NEW session owns the IP (last writer wins), and the
%% stale session's teardown must not tear the fresh mapping down.
reattach_same_ip_supersedes_test() ->
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    Ip = {10, 46, 0, 2},
    {{ok, _}, S1} = reg(Ip, undefined, 1001, 501, ?PGW_IP1, S0),
    {{ok, _}, S2} = reg(Ip, undefined, 1003, 503, ?PGW_IP2, S1),
    Pkt = ipv4_udp(Ip, {203, 0, 113, 5}, 40000, 5060),
    ?assertEqual({ok, 1003, {503, ?PGW_IP2}},
                 epdg_gtpu_forwarder:classify_for_test(Pkt, S2)),
    %% Stale session unregisters — fresh mapping survives.
    S3 = epdg_gtpu_forwarder:unregister_ue_for_test(1001, S2),
    ?assertEqual({ok, 1003, {503, ?PGW_IP2}},
                 epdg_gtpu_forwarder:classify_for_test(Pkt, S3)),
    %% Fresh session unregisters — mapping is gone.
    S4 = epdg_gtpu_forwarder:unregister_ue_for_test(1003, S3),
    ?assertEqual(unknown_src, epdg_gtpu_forwarder:classify_for_test(Pkt, S4)).

%%====================================================================
%% Inner-IP key collision detection
%%====================================================================

%% Two DIFFERENT subscribers addressed inside the same /64 collapse onto
%% one uplink key (the PGW must delegate one /64 per UE). Registration
%% keeps last-writer-wins — the re-attach path must survive — but the
%% collision has to become visible: without the metric several
%% subscribers silently share one GTP tunnel, the same failure class as
%% the legacy TEID-table collision.
v6_same_prefix_different_imsi_counts_collision_test() ->
    epdg_metrics:init(),
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    Before = epdg_metrics:get(ue_inner_ip_key_collision_total),
    Ue1 = {16#cafe, 0, 16#46, 1, 0, 0, 0, 1},
    Ue2 = {16#cafe, 0, 16#46, 1, 0, 0, 0, 2},  %% same /64 as Ue1
    {{ok, _}, S1} = reg_imsi({0, 0, 0, 0}, Ue1, 1001, 501, ?PGW_IP1,
                             <<"001010000000001">>, S0),
    {{ok, _}, S2} = reg_imsi({0, 0, 0, 0}, Ue2, 1002, 502, ?PGW_IP2,
                             <<"001010000000002">>, S1),
    ?assertEqual(Before + 1,
                 epdg_metrics:get(ue_inner_ip_key_collision_total)),
    %% Documented last-writer-wins: the shared key now belongs to the
    %% most recently registered TEID.
    Pkt = ipv6_udp(Ue1, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 40000, 5060),
    ?assertEqual({ok, 1002, {502, ?PGW_IP2}},
                 epdg_gtpu_forwarder:classify_for_test(Pkt, S2)).

%% A re-attach (same IMSI reusing its IP) is NOT a collision and must
%% not pollute the metric — reattach_same_ip_supersedes_test above stays
%% the behavioural reference for the mapping semantics.
reattach_same_imsi_not_counted_as_collision_test() ->
    epdg_metrics:init(),
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    Before = epdg_metrics:get(ue_inner_ip_key_collision_total),
    Ip = {10, 46, 0, 2},
    {{ok, _}, S1} = reg(Ip, undefined, 1001, 501, ?PGW_IP1, S0),
    {{ok, _}, _S2} = reg(Ip, undefined, 1003, 503, ?PGW_IP2, S1),
    ?assertEqual(Before,
                 epdg_metrics:get(ue_inner_ip_key_collision_total)).

%% Same IPv4 address handed to two different subscribers is the v4
%% variant of the same misconfiguration and counts as well.
v4_same_ip_different_imsi_counts_collision_test() ->
    epdg_metrics:init(),
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    Before = epdg_metrics:get(ue_inner_ip_key_collision_total),
    Ip = {10, 46, 0, 7},
    {{ok, _}, S1} = reg_imsi(Ip, undefined, 1001, 501, ?PGW_IP1,
                             <<"001010000000001">>, S0),
    {{ok, _}, _S2} = reg_imsi(Ip, undefined, 1002, 502, ?PGW_IP2,
                              <<"001010000000002">>, S1),
    ?assertEqual(Before + 1,
                 epdg_metrics:get(ue_inner_ip_key_collision_total)).

%%====================================================================
%% Startup pool-list guard
%%====================================================================

%% A forwarder started without any configured UE pool installs no
%% `from <pool>' rule: sessions would attach fine but no uplink packet
%% could ever reach the shared TUN. The start must fail loudly
%% (CrashLoopBackOff) instead of coming up seemingly healthy.
init_empty_pools_refuses_to_start_test() ->
    Saved = save_pool_env(),
    application:unset_env(epdg, ue_ip_pools),
    application:unset_env(epdg, allow_empty_ue_pools),
    try
        ?assertEqual({stop, no_ue_ip_pools}, epdg_gtpu_forwarder:init([]))
    after
        restore_pool_env(Saved)
    end.

%% Unit-test environments (no pools, no NET_ADMIN) must opt in via the
%% explicit allow_empty_ue_pools switch — no guessing from eaddrinuse.
init_empty_pools_allowed_by_switch_test() ->
    epdg_metrics:init(),
    Saved = save_pool_env(),
    application:unset_env(epdg, ue_ip_pools),
    application:set_env(epdg, allow_empty_ue_pools, true),
    %% Ephemeral port: the real GTP-U port may be taken on the build host.
    application:set_env(epdg, gtpu_port, 0),
    try
        ?assertMatch({ok, _}, epdg_gtpu_forwarder:init([]))
    after
        application:unset_env(epdg, gtpu_port),
        restore_pool_env(Saved)
    end.

save_pool_env() ->
    {application:get_env(epdg, ue_ip_pools),
     application:get_env(epdg, allow_empty_ue_pools)}.

restore_pool_env({Pools, Allow}) ->
    set_or_unset(ue_ip_pools, Pools),
    set_or_unset(allow_empty_ue_pools, Allow).

set_or_unset(Key, undefined)   -> application:unset_env(epdg, Key);
set_or_unset(Key, {ok, Value}) -> application:set_env(epdg, Key, Value).

%%====================================================================
%% Dedicated bearer regression
%%====================================================================

%% The TFT classification must keep working on top of the by_inner_ip
%% lookup: RTP inside the dedicated bearer's port range rides the
%% dedicated tunnel, everything else stays on the default bearer.
dedicated_bearer_tft_still_applies_test() ->
    S0 = epdg_gtpu_forwarder:new_state_for_test(?POOLS),
    UeIp = {10, 46, 0, 2},
    {{ok, _}, S1} = reg(UeIp, undefined, 1001, 501, ?PGW_IP1, S0),
    Tft = tft(2, <<(udp_proto())/binary,
                   (remote_port_range(16384, 16483))/binary>>),
    Filters = epdg_tft:parse(Tft),
    ?assertEqual(1, length(Filters)),
    {ok, S2} = epdg_gtpu_forwarder:register_bearer_for_test(
                 #{default_teid => 1001, local_teid => 2001,
                   pgw_u_teid => 601, pgw_u_ip => ?PGW_IP2,
                   filters => Filters}, S1),
    Rtp   = ipv4_udp(UeIp, {203, 0, 113, 5}, 40000, 16400),
    Other = ipv4_udp(UeIp, {203, 0, 113, 5}, 40000, 5060),
    ?assertEqual({ok, 1001, {601, ?PGW_IP2}},
                 epdg_gtpu_forwarder:classify_for_test(Rtp, S2)),
    ?assertEqual({ok, 1001, {501, ?PGW_IP1}},
                 epdg_gtpu_forwarder:classify_for_test(Other, S2)),
    %% Tearing down the default bearer also drops the dedicated one.
    S3 = epdg_gtpu_forwarder:unregister_ue_for_test(1001, S2),
    ?assertEqual(unknown_src, epdg_gtpu_forwarder:classify_for_test(Rtp, S3)).
