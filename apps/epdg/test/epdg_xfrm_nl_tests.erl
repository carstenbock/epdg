-module(epdg_xfrm_nl_tests).
-include_lib("eunit/include/eunit.hrl").

%% The netlink backend replaces `ip xfrm' / `ip route' (KI-42: 7 to 12
%% process spawns per attach). Two layers are tested:
%%
%%  * the structures must match the kernel's UAPI layout byte for byte, so
%%    their sizes and a decode of what was encoded are checked without a
%%    kernel;
%%  * with NET_ADMIN (the ePDG build runs these in Docker with the
%%    capability; elsewhere they are skipped), SAs, policies and routes are
%%    installed through netlink and read back with `ip', the tool the module
%%    replaces, so the two agree on every field that broke the data plane
%%    before: SPI, reqid, mode, af-unspec, auth-trunc length, encap port
%%    order, ESN, GCM as AEAD, if_id, the route's table and device.

-define(EPDG_OUTER, {212, 9, 60, 20}).
-define(UE_OUTER,   {93, 204, 201, 107}).
-define(SPI,        16#05974942).
-define(REQID,      1186832296).
-define(KEY16, <<0:128>>).
-define(KEY32, <<1:256>>).

%%====================================================================
%% Layout
%%====================================================================

struct_sizes_test() ->
    ?assertEqual(56,  byte_size(epdg_xfrm_nl:encode_selector(#{}))),
    ?assertEqual(224, byte_size(epdg_xfrm_nl:encode_sa_info(
                         #{src => ?UE_OUTER, dst => ?EPDG_OUTER, spi => ?SPI, family => 2,
                           mode => 1, reqid => ?REQID, flags => 32}))),
    ?assertEqual(168, byte_size(epdg_xfrm_nl:encode_policy_info(
                         #{sel => #{family => 2}, dir => 1}))),
    ?assertEqual(64,  byte_size(epdg_xfrm_nl:encode_tmpl(
                         #{src => ?EPDG_OUTER, dst => ?UE_OUTER, reqid => ?REQID,
                           mode => 1, family => 2}))).

nla_is_padded_to_four_bytes_test() ->
    ?assertEqual(8, byte_size(epdg_xfrm_nl:nla(31, <<9:32/native>>))),
    ?assertEqual(8, byte_size(epdg_xfrm_nl:nla(25, <<50:8>>))).

sa_info_roundtrip_test() ->
    Bin = epdg_xfrm_nl:encode_sa_info(#{src => ?UE_OUTER, dst => ?EPDG_OUTER, spi => ?SPI,
                                        family => 2, mode => 1, reqid => ?REQID, flags => 32}),
    ?assertMatch(#{src := ?UE_OUTER, dst := ?EPDG_OUTER, spi := ?SPI, reqid := ?REQID,
                   family := 2, mode := 1, proto := 50}, epdg_xfrm_nl:decode_sa_info(Bin)).

cidr_roundtrip_test() ->
    ?assertEqual({{10, 46, 0, 34}, 32}, epdg_xfrm_nl:parse_cidr("10.46.0.34/32")),
    ?assertEqual({{10, 46, 0, 34}, 32}, epdg_xfrm_nl:parse_cidr("10.46.0.34")),
    ?assertEqual({{0, 0, 0, 0}, 0}, epdg_xfrm_nl:parse_cidr("0.0.0.0/0")),
    ?assertEqual({{16#cafe, 0, 16#46, 1, 0, 0, 0, 0}, 64}, epdg_xfrm_nl:parse_cidr("cafe:0:46:1::/64")),
    ?assertEqual("10.46.0.34/32", epdg_xfrm_nl:format_cidr({10, 46, 0, 34}, 32)).

%%====================================================================
%% Against the kernel (needs NET_ADMIN and iproute2; skipped otherwise)
%%====================================================================

kernel_test_() ->
    case epdg_xfrm_nl:available() andalso os:find_executable("ip") =/= false of
        true ->
            {setup, fun() -> epdg_xfrm_nl:flush_all() end, fun(_) -> epdg_xfrm_nl:flush_all() end,
             [fun sa_fields_agree_with_ip/0,
              fun gcm_sa_is_an_aead_state/0,
              fun deleting_a_missing_sa_is_reported/0,
              fun inbound_sa_carries_the_source_check_mark/0,
              fun flush_endpoint_removes_both_sas/0,
              fun policy_fields_agree_with_ip/0,
              fun wildcard_policies_stay_outside_the_reconcilers_view/0,
              fun accept_local_is_set_over_netlink/0,
              fun route_lands_in_the_table/0]};
        false ->
            {"netlink kernel tests skipped: no NET_ADMIN or no ip", fun() -> ok end}
    end.

ip(Args) -> os:cmd("ip " ++ Args ++ " 2>&1").

sa_fields_agree_with_ip() ->
    ok = epdg_xfrm_nl:create_sa(
           #{spi => ?SPI, src_ip => ?UE_OUTER, dst_ip => ?EPDG_OUTER,
             enc_alg => aes_cbc_128, enc_key => ?KEY16,
             auth_alg => hmac_sha256, auth_key => ?KEY32,
             nat_t => true, sa_dir => in, local_udp_port => 4500, peer_udp_port => 23830,
             peer_outer_ip => ?UE_OUTER, reqid => ?REQID, esn => true},
           none, "lo", #{id => 7, name => "epdgx7", local_table => 407}),
    Out = ip("xfrm state"),
    [?assertEqual({Needle, found}, {Needle, case string:find(Out, Needle) of
                                               nomatch -> {nomatch, Out}; _ -> found end}) ||
        Needle <- ["src 93.204.201.107 dst 212.9.60.20",
                   "spi 0x05974942", "reqid 1186832296", "mode tunnel",
                   "auth-trunc hmac(sha256)", " 128", "enc cbc(aes)",
                   "encap type espinudp sport 23830 dport 4500",
                   "flag af-unspec esn", "if_id 0x7"]],
    %% our own inventory sees it, keyed on the outer endpoint
    ?assertEqual([#{src => ?UE_OUTER, dst => ?EPDG_OUTER, spi => ?SPI, reqid => ?REQID}],
                 epdg_xfrm_nl:list_sas(?EPDG_OUTER)),
    ok = epdg_xfrm_nl:delete_sa(#{spi => ?SPI, src_ip => ?UE_OUTER, dst_ip => ?EPDG_OUTER}),
    ?assertEqual([], epdg_xfrm_nl:list_sas(?EPDG_OUTER)).

%% The kernel knows GCM only as an AEAD transform; `enc rfc4106(gcm(aes))'
%% was refused ("Requested CRYPT algorithm not found"), so GCM Child SAs
%% never got installed with the ip backend.
gcm_sa_is_an_aead_state() ->
    ok = epdg_xfrm_nl:create_sa(
           #{spi => 16#2222, src_ip => ?EPDG_OUTER, dst_ip => ?UE_OUTER,
             enc_alg => aes_gcm_128, enc_key => <<0:160>>, auth_alg => none,
             sa_dir => out, reqid => 5},
           none, "lo", undefined),
    Out = ip("xfrm state"),
    ?assertNotEqual(nomatch, string:find(Out, "aead rfc4106(gcm(aes))")),
    ?assertNotEqual(nomatch, string:find(Out, " 128")),
    ok = epdg_xfrm_nl:delete_sa(#{spi => 16#2222}).

%% The SA gauge counts a delete only when this returns ok (KI-59), so a
%% delete that finds nothing must say so, by address and by SPI alone.
deleting_a_missing_sa_is_reported() ->
    ?assertMatch({error, _}, epdg_xfrm_nl:delete_sa(
                               #{spi => 16#3333, src_ip => ?UE_OUTER, dst_ip => ?EPDG_OUTER})),
    ?assertEqual({error, esrch}, epdg_xfrm_nl:delete_sa(#{spi => 16#3333})).

%% KI-58: the inbound SA writes the UE's mark into what it decrypts,
%% leaving bits 0 to 12 to the node.
inbound_sa_carries_the_source_check_mark() ->
    ok = epdg_xfrm_nl:create_sa(
           #{spi => 16#4444, src_ip => ?UE_OUTER, dst_ip => ?EPDG_OUTER,
             enc_alg => aes_cbc_128, enc_key => ?KEY16, auth_alg => hmac_sha256,
             auth_key => binary:copy(<<1>>, 32), sa_dir => in, reqid => 6,
             set_mark => 16#4000, set_mark_mask => 16#FFFFE000},
           none, "lo", undefined),
    ?assertNotEqual(nomatch, string:find(ip("xfrm state"), "output-mark 0x4000/0xffffe000")),
    ok = epdg_xfrm_nl:delete_sa(#{spi => 16#4444}).

flush_endpoint_removes_both_sas() ->
    [ok = epdg_xfrm_nl:create_sa(
            #{spi => S, src_ip => ?UE_OUTER, dst_ip => ?EPDG_OUTER,
              enc_alg => aes_cbc_128, enc_key => ?KEY16, auth_alg => none, sa_dir => in},
            none, "lo", undefined) || S <- [16#1001, 16#1002]],
    ?assertEqual(2, length(epdg_xfrm_nl:list_sas(?EPDG_OUTER))),
    ok = epdg_xfrm_nl:flush_sa_endpoint(#{src_ip => ?UE_OUTER, dst_ip => ?EPDG_OUTER}),
    ?assertEqual([], epdg_xfrm_nl:list_sas(?EPDG_OUTER)).

policy_fields_agree_with_ip() ->
    P = #{src => "10.46.0.34/32", dst => "0.0.0.0/0", direction => out,
          tmpl_src => ?EPDG_OUTER, tmpl_dst => ?UE_OUTER, reqid => ?REQID},
    If = #{id => 7, name => "epdgx7", local_table => 407},
    ok = epdg_xfrm_nl:create_policy(P, If),
    %% update, not add: a second call with another reqid must not fail
    ok = epdg_xfrm_nl:create_policy(P#{reqid => 42}, If),
    Out = ip("xfrm policy"),
    [?assertEqual({Needle, found}, {Needle, case string:find(Out, Needle) of
                                               nomatch -> {nomatch, Out}; _ -> found end}) ||
        Needle <- ["src 10.46.0.34/32 dst 0.0.0.0/0", "dir out", "if_id 0x7",
                   "tmpl src 212.9.60.20 dst 93.204.201.107", "reqid 42 mode tunnel"]],
    ?assertEqual([#{src => "10.46.0.34/32", dst => "0.0.0.0/0", dir => out,
                    tmpl_src => ?EPDG_OUTER, tmpl_dst => ?UE_OUTER, reqid => 42}],
                 epdg_xfrm_nl:list_policies(?EPDG_OUTER)),
    ok = epdg_xfrm_nl:delete_policy(P, If),
    ?assertEqual([], epdg_xfrm_nl:list_policies(?EPDG_OUTER)),
    ?assertMatch({error, _}, epdg_xfrm_nl:delete_policy(P, If)).

%% Static policy mode: the kernel must take an inbound and a forward policy
%% with an any-to-any selector and a tunnel template without addresses, and
%% list_policies/1 (what the reconciler sees) must not return them, or the
%% reconciler would delete them as orphans after the grace period.
wildcard_policies_stay_outside_the_reconcilers_view() ->
    If = #{id => 7, name => "epdgx7", local_table => 407},
    Any = #{src => "0.0.0.0/0", dst => "0.0.0.0/0", tmpl_src => {0, 0, 0, 0},
            tmpl_dst => {0, 0, 0, 0}, reqid => 0},
    ok = epdg_xfrm_nl:create_policy(Any#{direction => in}, If),
    ok = epdg_xfrm_nl:create_policy(Any#{direction => fwd}, If),
    %% update, not add: a second incarnation re-installs them
    ok = epdg_xfrm_nl:create_policy(Any#{direction => in}, If),
    Out = ip("xfrm policy"),
    [?assertEqual({Needle, found}, {Needle, case string:find(Out, Needle) of
                                               nomatch -> {nomatch, Out}; _ -> found end}) ||
        Needle <- ["src 0.0.0.0/0 dst 0.0.0.0/0", "dir in", "dir fwd", "if_id 0x7",
                   "reqid 0 mode tunnel"]],
    ?assertEqual([], epdg_xfrm_nl:list_policies(?EPDG_OUTER)),
    ok = epdg_xfrm_nl:delete_policy(Any#{direction => in}, If),
    ok = epdg_xfrm_nl:delete_policy(Any#{direction => fwd}, If),
    ?assertEqual(nomatch, string:find(ip("xfrm policy"), "dir fwd")).

%% The forwarder cannot write /proc/sys in a hostNetwork pod; the TUN's
%% accept_local has to arrive over rtnetlink, and the kernel must read it
%% back as set (KI-53, run r9: the gateway's replies to a co-located UE
%% re-enter the node through the TUN with a local source address).
accept_local_is_set_over_netlink() ->
    Read = fun() ->
        {ok, B} = file:read_file("/proc/sys/net/ipv4/conf/lo/accept_local"),
        string:trim(binary_to_list(B))
    end,
    ok = epdg_xfrm_nl:dev_accept_local("lo", true),
    ?assertEqual("1", Read()),
    ok = epdg_xfrm_nl:dev_accept_local("lo", false),
    ?assertEqual("0", Read()),
    ?assertMatch({error, _}, epdg_xfrm_nl:dev_accept_local("nosuchdev9", true)).

route_lands_in_the_table() ->
    ok = epdg_xfrm_nl:route(replace, "10.46.0.34/32", "lo", 407),
    Out = ip("route show table 407"),
    ?assertNotEqual(nomatch, string:find(Out, "10.46.0.34 dev lo")),
    ok = epdg_xfrm_nl:route(del, "10.46.0.34/32", "lo", 407),
    ?assertEqual(nomatch, string:find(ip("route show table 407"), "10.46.0.34")).
