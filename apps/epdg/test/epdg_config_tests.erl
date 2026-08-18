-module(epdg_config_tests).
-include_lib("eunit/include/eunit.hrl").

gtpc_mode_defaults_to_s2b_test() ->
    os:unsetenv("EPDG_GTPC_MODE"),
    ?assertEqual(s2b, epdg_config:parse_gtpc_mode(os:getenv("EPDG_GTPC_MODE"))).

gtpc_mode_reads_s5s8_test() ->
    ?assertEqual(s5s8, epdg_config:parse_gtpc_mode("s5s8")).

gtpc_mode_unknown_falls_back_to_s2b_test() ->
    ?assertEqual(s2b, epdg_config:parse_gtpc_mode("garbage")).

%% EPDG_UE_IP_POOLS drives the shared-TUN policy routing AND the
%% register-time pool check — a silently mis-parsed pool would strand
%% every UE, so the parser must be strict.

ue_ip_pools_parses_mixed_families_test() ->
    ?assertEqual([{{10, 46, 0, 0}, 16},
                  {{16#cafe, 0, 16#46, 0, 0, 0, 0, 0}, 48}],
                 epdg_config:parse_ue_ip_pools("10.46.0.0/16, cafe:0:46::/48")).

ue_ip_pools_skips_empty_entries_test() ->
    ?assertEqual([{{10, 46, 0, 0}, 16}],
                 epdg_config:parse_ue_ip_pools("10.46.0.0/16,")),
    ?assertEqual([], epdg_config:parse_ue_ip_pools("")).

ue_ip_pools_missing_prefix_raises_test() ->
    ?assertError({invalid_cidr, "10.46.0.0"},
                 epdg_config:parse_ue_ip_pools("10.46.0.0")).

ue_ip_pools_prefix_out_of_range_raises_test() ->
    ?assertError({invalid_cidr, "10.46.0.0/33"},
                 epdg_config:parse_ue_ip_pools("10.46.0.0/33")),
    ?assertError({invalid_cidr, "cafe::/129"},
                 epdg_config:parse_ue_ip_pools("cafe::/129")).

ue_ip_pools_invalid_address_raises_test() ->
    ?assertError({invalid_cidr, "not-an-ip/16"},
                 epdg_config:parse_ue_ip_pools("not-an-ip/16")),
    ?assertError({invalid_cidr, "10.46.0.0/abc"},
                 epdg_config:parse_ue_ip_pools("10.46.0.0/abc")).

%% An IPv6 pool of /64 or longer can hold at most ONE distinguishable UE
%% — uplink attribution is keyed on the per-UE delegated /64 prefix
%% (epdg_gtpu_forwarder:inner_src_key/1), so all UEs the PGW addresses
%% inside such a pool would collapse onto one uplink key and silently
%% share one GTP tunnel. The parser must reject it at boot, with a
%% message explaining why.
ue_ip_pools_v6_64_or_longer_rejected_test() ->
    ?assertError({invalid_cidr, "cafe:0:46::/64", _},
                 epdg_config:parse_ue_ip_pools("cafe:0:46::/64")),
    ?assertError({invalid_cidr, "::/64", _},
                 epdg_config:parse_ue_ip_pools("::/64")),
    ?assertError({invalid_cidr, "cafe:0:46::/72", _},
                 epdg_config:parse_ue_ip_pools("cafe:0:46::/72")),
    ?assertError({invalid_cidr, "cafe:0:46::1/128", _},
                 epdg_config:parse_ue_ip_pools("cafe:0:46::1/128")).

%% Pools that leave room for more than one /64 delegation stay valid.
ue_ip_pools_v6_wider_than_64_accepted_test() ->
    ?assertEqual([{{16#cafe, 0, 16#46, 0, 0, 0, 0, 0}, 48}],
                 epdg_config:parse_ue_ip_pools("cafe:0:46::/48")),
    ?assertEqual([{{16#cafe, 0, 16#46, 0, 0, 0, 0, 0}, 56}],
                 epdg_config:parse_ue_ip_pools("cafe:0:46::/56")),
    ?assertEqual([{{16#cafe, 0, 16#46, 0, 0, 0, 0, 0}, 63}],
                 epdg_config:parse_ue_ip_pools("cafe:0:46::/63")).

%% The /64 restriction is IPv6-only: v4 uplink is keyed on the exact
%% address, so narrow v4 pools remain legitimate.
ue_ip_pools_v4_narrow_pool_still_valid_test() ->
    ?assertEqual([{{10, 46, 1, 0}, 24}],
                 epdg_config:parse_ue_ip_pools("10.46.1.0/24")).
