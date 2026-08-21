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

%% Instance-id derivation (EPDG_INSTANCE_ID / POD_NAME): several ePDG
%% pods on one hostNetwork node share the network namespace, and the
%% instance id is the ONLY thing keeping their TUN devices, routing
%% tables and rules apart — the derivation must be stable, predictable
%% and hard-fail on invalid explicit values.

instance_id_explicit_env_wins_test() ->
    %% An explicit id beats any POD_NAME-derived value.
    ?assertEqual(7, epdg_config:parse_instance_id("7", "epdg-3")),
    ?assertEqual(0, epdg_config:parse_instance_id("0", false)),
    ?assertEqual(63, epdg_config:parse_instance_id(" 63 ", false)).

%% A typo silently mapping onto some other id would recreate exactly
%% the device/table collision the id exists to prevent — fail the boot.
instance_id_invalid_explicit_fails_boot_test() ->
    ?assertError({invalid_config, _},
                 epdg_config:parse_instance_id("64", false)),
    ?assertError({invalid_config, _},
                 epdg_config:parse_instance_id("-1", false)),
    ?assertError({invalid_config, _},
                 epdg_config:parse_instance_id("abc", false)),
    ?assertError({invalid_config, _},
                 epdg_config:parse_instance_id("", false)).

%% StatefulSet ordinals are the expected steady-state source: epdg-0 /
%% epdg-1 on one node get distinct, predictable ids.
instance_id_statefulset_ordinal_test() ->
    ?assertEqual(0, epdg_config:parse_instance_id(false, "epdg-0")),
    ?assertEqual(1, epdg_config:parse_instance_id(false, "epdg-1")),
    ?assertEqual(5, epdg_config:parse_instance_id(false, "epdg-gw-5")),
    %% Ordinals beyond the 64-instance space wrap into 0..63.
    ?assertEqual(2, epdg_config:parse_instance_id(false, "epdg-66")).

%% Non-ordinal pod names (e.g. Deployment hash suffixes) hash stably
%% into the id space: the same pod always derives the same id.
instance_id_hash_fallback_is_stable_test() ->
    Name = "epdg-7f9c4d8b6d-x2v4q",
    Id = epdg_config:parse_instance_id(false, Name),
    ?assertEqual(Id, epdg_config:parse_instance_id(false, Name)),
    ?assert(Id >= 0 andalso Id =< 63).

%% Single instance / local development: no env at all means id 0.
instance_id_defaults_to_zero_test() ->
    ?assertEqual(0, epdg_config:parse_instance_id(false, false)),
    ?assertEqual(0, epdg_config:parse_instance_id(false, "")).

%% EPDG_IKE_LEGACY_DH_GROUPS opts weak DH groups (RFC 8247 SHOULD NOT)
%% back in. Only 2 and 5 exist as opt-ins; any other value must fail
%% the boot rather than silently enable or skip a group.
legacy_dh_groups_default_empty_test() ->
    ?assertEqual([], epdg_config:parse_legacy_dh_groups(false)),
    ?assertEqual([], epdg_config:parse_legacy_dh_groups("")).

legacy_dh_groups_parses_valid_test() ->
    ?assertEqual([2], epdg_config:parse_legacy_dh_groups("2")),
    ?assertEqual([5], epdg_config:parse_legacy_dh_groups("5")),
    ?assertEqual([2, 5], epdg_config:parse_legacy_dh_groups("2,5")),
    ?assertEqual([2, 5], epdg_config:parse_legacy_dh_groups(" 5 , 2 ")),
    ?assertEqual([2], epdg_config:parse_legacy_dh_groups("2,2,")).

legacy_dh_groups_rejects_other_values_test() ->
    ?assertError({invalid_config, _},
                 epdg_config:parse_legacy_dh_groups("1")),
    ?assertError({invalid_config, _},
                 epdg_config:parse_legacy_dh_groups("14")),
    ?assertError({invalid_config, _},
                 epdg_config:parse_legacy_dh_groups("2,14")),
    ?assertError({invalid_config, _},
                 epdg_config:parse_legacy_dh_groups("garbage")).

%% EPDG_EAP_ONLY_AUTH (set_from_env_bool): unset defaults true;
%% 0/false → false; 1/true → true.
eap_only_auth_unset_defaults_true_test() ->
    ?assertEqual(true, epdg_config:parse_bool(false, true)).

eap_only_auth_false_values_test() ->
    ?assertEqual(false, epdg_config:parse_bool("0", true)),
    ?assertEqual(false, epdg_config:parse_bool("false", true)).

eap_only_auth_true_values_test() ->
    ?assertEqual(true, epdg_config:parse_bool("1", true)),
    ?assertEqual(true, epdg_config:parse_bool("true", true)).

%% EPDG_IKE_TRACE_LOCAL_ADDR (epdg_ikev2_trace): a comma-separated list,
%% because one address cannot label both address families in the trace.
%% Unlike the pool parser this one is deliberately lenient — it only
%% affects how a diagnostic trace reads, so a typo must not fail the boot.

trace_local_addrs_can_parse_only_one_addr() ->
    ?assertEqual([{192, 0, 2, 1}],
                 epdg_config:parse_trace_local_addrs(
                   "192.0.2.1")).

trace_local_addrs_parses_mixed_families_test() ->
    ?assertEqual([{192, 0, 2, 1}, {16#2001, 16#db8, 0, 0, 0, 0, 0, 1}],
                 epdg_config:parse_trace_local_addrs(
                   "192.0.2.1, 2001:db8::1")).

trace_local_addrs_preserves_order_test() ->
    %% The mirror takes the first entry of the peer's family, so order is
    %% the operator's way of choosing which address gets rendered.
    ?assertEqual([{198, 51, 100, 7}, {192, 0, 2, 1}],
                 epdg_config:parse_trace_local_addrs("198.51.100.7,192.0.2.1")).

trace_local_addrs_skips_empty_entries_test() ->
    ?assertEqual([{192, 0, 2, 1}],
                 epdg_config:parse_trace_local_addrs("192.0.2.1,")),
    ?assertEqual([], epdg_config:parse_trace_local_addrs("")),
    ?assertEqual([], epdg_config:parse_trace_local_addrs("  ,  ")).

trace_local_addrs_unset_is_empty_test() ->
    ?assertEqual([], epdg_config:parse_trace_local_addrs(false)).

trace_local_addrs_drops_garbage_without_raising_test() ->
    ?assertEqual([{192, 0, 2, 1}],
                 epdg_config:parse_trace_local_addrs("nonsense,192.0.2.1")),
    ?assertEqual([], epdg_config:parse_trace_local_addrs("nonsense")).
