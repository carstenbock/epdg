%%%-------------------------------------------------------------------
%%% @doc ePDG configuration read from environment variables.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_config).

-export([init/0, get/1, get/2, parse_gtpc_mode/1, parse_ue_ip_pools/1,
         parse_instance_id/2, parse_legacy_dh_groups/1, parse_bool/2]).

%% ?UE6_PREFIX_LEN: floor for UE IPv6 pool widths (check_v6_pool_width/3).
-include("epdg_ipv6.hrl").

-define(APP, epdg).

init() ->
    %% Diameter identity
    set_from_env("EPDG_ORIGIN_HOST", origin_host, fun hostname_default/0),
    set_from_env("EPDG_ORIGIN_REALM", origin_realm, "localdomain"),

    %% IKEv2
    set_from_env_resolved_addr("EPDG_IKE_BIND_ADDR",
                               "EPDG_IKE_BIND_ADDR_BY_POD",
                               "EPDG_IKE_BIND_ADDR_BY_NODE",
                               ike_bind_addr, "0.0.0.0"),
    set_from_env_int("EPDG_IKE_PORT", ike_port, 500),
    set_from_env_int("EPDG_IKE_NATT_PORT", ike_natt_port, 4500),

    %% IKE X.509 certificate (TS 33.402 §7.2.1)
    set_from_env("EPDG_IKE_CERT_FILE", ike_cert_file, ""),
    set_from_env("EPDG_IKE_KEY_FILE", ike_key_file, ""),
    %% IDr (FQDN the ePDG presents as its IKEv2 identity; should match
    %% the SubjectAltName:DNS of the configured certificate).
    set_from_env("EPDG_IKE_ID_FQDN", ike_id_fqdn, fun default_ike_id_fqdn/0),

    %% Legacy IKE DH groups: MODP-1024 (2) and MODP-1536 (5), off by
    %% default. Parsed once at boot into app env so the per-packet
    %% proposal check is a cheap ETS read.
    set_ike_legacy_dh_groups(),

    %% EAP-AKA'
    set_from_env("EPDG_EAP_METHOD", eap_method, "aka-prime"),

    %% RFC 5998 EAP-only authentication. Default on: honour
    %% N(EAP_ONLY_AUTHENTICATION) and omit CERT+AUTH from message 4.
    %% false restores strict RFC 7296 (always send CERT+AUTH).
    set_from_env_bool("EPDG_EAP_ONLY_AUTH", eap_only_auth, true),
    logger:notice("IKE auth mode: eap_only_auth=~p "
                  "(RFC 5998; false always sends CERT+AUTH)",
                  [get(eap_only_auth, true)]),

    %% XFRM / IPsec
    set_from_env("EPDG_IPSEC_OFFLOAD", ipsec_offload, "auto"),
    set_from_env("EPDG_IPSEC_IFACE", ipsec_iface, "eth0"),

    %% XFRM kernel-state reconciliation (epdg_xfrm_reconciler): sweep
    %% every INTERVAL seconds, delete kernel SAs/policies that stayed
    %% unclaimed by any live UE FSM for GRACE seconds. INTERVAL=0 is the
    %% single off-switch and disables reconciliation completely,
    %% INCLUDING the startup sweep.
    set_from_env_int("EPDG_XFRM_RECONCILE_INTERVAL", xfrm_reconcile_interval, 30),
    set_from_env_int("EPDG_XFRM_RECONCILE_GRACE", xfrm_reconcile_grace, 30),

    %% Redis-backed session store (opt-in): survives pod crashes by
    %% restoring established UE sessions at startup. Key prefix defaults
    %% to "epdg:<pod-name>" so each pod only restores its own sessions
    %% (per-ordinal VIPs make sessions non-portable across pods anyway).
    set_from_env_bool("EPDG_SESSION_STORE_ENABLED", session_store_enabled, false),
    set_from_env("EPDG_REDIS_HOST", redis_host, "127.0.0.1"),
    set_from_env_int("EPDG_REDIS_PORT", redis_port, 6379),
    set_from_env_int("EPDG_REDIS_DB", redis_db, 0),
    set_from_env("EPDG_REDIS_KEY_PREFIX", redis_key_prefix,
                 fun default_redis_prefix/0),

    %% GTP-C S2b toward PGW-C/SMF.
    %%
    %% `PGW_FQDN` is the preferred setting: the GTP-C client re-resolves
    %% the FQDN on TTL expiry, on send failure, and after Echo timeouts,
    %% so the ePDG survives PGW pod restarts / rescheduling in K8s without
    %% config changes. `PGW_ADDR` is kept as a fallback for bare-metal /
    %% single-node deployments but logs a warning at startup.
    set_from_env("PGW_FQDN", pgw_fqdn, ""),
    set_from_env("PGW_ADDR", pgw_addr, "127.0.0.1"),
    set_from_env_int("PGW_PORT", pgw_port, 2123),
    set_from_env("EPDG_GTPC_BIND_ADDR", gtpc_bind_addr, "0.0.0.0"),
    set_from_env_int("EPDG_GTPC_PORT", gtpc_port, 2123),
    %% GTP-U (TS 29.281) bind and advertised S2b-U F-TEID address.
    %% `gtpu_advertise_addr` defaults to "same as local GTP-C IP" when empty.
    set_from_env_resolved_addr("EPDG_GTPU_BIND_ADDR",
                               "EPDG_GTPU_BIND_ADDR_BY_POD",
                               "EPDG_GTPU_BIND_ADDR_BY_NODE",
                               gtpu_bind_addr, "0.0.0.0"),
    set_from_env_resolved_addr("EPDG_GTPU_ADVERTISE_ADDR",
                               "EPDG_GTPU_ADVERTISE_ADDR_BY_POD",
                               "EPDG_GTPU_ADVERTISE_ADDR_BY_NODE",
                               gtpu_advertise_addr, ""),
    set_from_env_int("EPDG_GTPU_PORT", gtpu_port, 2152),
    %% GTP-C Echo heartbeat & reconnect tunables (TS 29.274 §7.1)
    set_from_env_int("EPDG_GTPC_ECHO_INTERVAL_SEC", gtpc_echo_interval_sec, 60),
    set_from_env_int("EPDG_GTPC_ECHO_TIMEOUT_SEC", gtpc_echo_timeout_sec, 3),
    set_from_env_int("EPDG_GTPC_ECHO_MAX_MISSES", gtpc_echo_max_misses, 3),
    set_from_env_int("EPDG_GTPC_BACKOFF_MAX_SEC", gtpc_backoff_max_sec, 30),
    set_from_env_int("EPDG_GTPC_MAX_DOWN_SEC", gtpc_max_down_sec, 30),
    set_from_env_int("EPDG_GTPC_PENDING_LIMIT", gtpc_pending_limit, 16),
    set_from_env_int("EPDG_DNS_MIN_TTL_SEC", dns_min_ttl_sec, 5),
    set_from_env_int("EPDG_DNS_MAX_TTL_SEC", dns_max_ttl_sec, 60),
    application:set_env(?APP, gtpc_mode,
                        parse_gtpc_mode(os:getenv("EPDG_GTPC_MODE"))),

    %% Diameter SWm (toward AAA Server via DRA)
    %% DRA_HOSTS takes precedence (comma-separated); falls back to DRA_HOST
    set_dra_hosts(),
    set_from_env_int("DRA_PORT", dra_port, 3868),
    set_from_env("DRA_TRANSPORT", dra_transport, "tcp"),
    set_from_env_int("EPDG_DIAMETER_PORT", diameter_port, 3868),
    %% Destination realm for routed SWm DERs (AAA realm, not DRA realm).
    %% Falls back to our Origin-Realm so single-realm deployments work
    %% out of the box.
    set_from_env("EPDG_SWM_DEST_REALM", swm_dest_realm,
                 fun() -> epdg_config:get(origin_realm, "localdomain") end),
    %% RAT-Type value for SWm DER (TS 29.273 §5.2.3.6). 0 = WLAN (default
    %% for ePDG/untrusted Wi-Fi access per TS 29.212 §5.3.31).
    set_from_env_int("EPDG_SWM_RAT_TYPE", swm_rat_type, 0),

    %% PLMN
    set_from_env("MCC", mcc, "001"),
    set_from_env("MNC", mnc, "01"),

    %% HTTP API
    set_from_env_int("EPDG_API_PORT", api_port, 8080),

    %% UE inner-IP pools (EPDG_UE_IP_POOLS): comma-separated CIDR list,
    %% IPv4 and IPv6 mixed, e.g. "10.46.0.0/16,cafe:0:46::/48". These are
    %% the ranges the PGW allocates PAA addresses from; the GTP-U
    %% forwarder installs one policy-routing rule per pool at startup and
    %% REJECTS any UE whose PGW-assigned inner IP falls outside every
    %% pool. There is deliberately no default: a wrong pool list silently
    %% strands every attach, so a missing value must fail the boot
    %% instead. (Replaces the never-evaluated EPDG_UE_IP_POOL /
    %% EPDG_UE_IP6_POOL of pre-shared-TUN releases.)
    set_ue_ip_pools(),

    %% Pod instance id (0..63): makes the shared TUN device name, the
    %% policy-routing table and the rule priority unique per ePDG pod on
    %% a hostNetwork node — see epdg_gtpu_forwarder.
    application:set_env(?APP, instance_id,
                        parse_instance_id(os:getenv("EPDG_INSTANCE_ID"),
                                          os:getenv("POD_NAME"))),

    %% Dual-stack toggle. When false (default) the ePDG always requests an
    %% IPv4-only S2b PDN and only ever hands the UE an IPv4 inner address --
    %% the historical behaviour. When true the ePDG honours the PDN type the
    %% UE asks for in its IKEv2 CFG_REQUEST (INTERNAL_IP4_ADDRESS /
    %% INTERNAL_IP6_ADDRESS) and grants whatever the PGW actually allocates
    %% in the Create-Session PAA (IPv4, IPv6 or IPv4v6). GSMA IR.51/IR.92.
    set_from_env_bool("EPDG_IPV6_ENABLED", ipv6_enabled, false),

    %% Allowed APNs (comma-separated; empty = allow all, "ims" is always allowed)
    set_from_env("EPDG_ALLOWED_APNS", allowed_apns, "ims"),
    set_from_env("EPDG_DEFAULT_APN", default_apn, "ims"),

    %% Dead Peer Detection (RFC 7296 §2.4). Default 120 s: VoWiFi UEs behind
    %% residential CPE NAT with aggressive power-save go briefly silent while
    %% idle; a short probe interval tears the tunnel down during those gaps.
    %% 120 s matches the documented sys.config default and the epdg-chart
    %% ike.dpd.intervalMs default.
    set_from_env_int("EPDG_DPD_INTERVAL", dpd_interval, 120000),
    set_from_env_int("EPDG_DPD_TIMEOUT", dpd_timeout, 10000),
    set_from_env_int("EPDG_DPD_RETRIES", dpd_retries, 3),

    %% MOBIKE return-routability (COOKIE2) check (RFC 4555 §3.7). When on
    %% (default), an UPDATE_SA_ADDRESSES does not move the kernel SAs until
    %% the UE echoes a random COOKIE2 sent to its new outer address, so an
    %% on-path attacker cannot redirect the IPsec SAs. Disable only for
    %% interop debugging with a non-conformant UE.
    set_from_env_bool("EPDG_MOBIKE_RR_CHECK", mobike_rr_check, true),
    set_from_env_int("EPDG_MOBIKE_RR_TIMEOUT", mobike_rr_timeout, 3000),
    set_from_env_int("EPDG_MOBIKE_RR_RETRIES", mobike_rr_retries, 2),

    %% IKEv2 Redirect (RFC 5685). When enabled, a draining pod steers UEs
    %% that advertised N(REDIRECT_SUPPORTED) to `redirect_target` before it
    %% DELETEs the SA, so they re-establish on a healthy node instead of
    %% racing back onto a sibling pod. Off by default (no behaviour change).
    %%
    %% Prefer an FQDN for the target: a literal IP sends every draining UE
    %% to one node and recreates the thundering herd the drain jitter exists
    %% to prevent, whereas an FQDN lets DNS spread arrivals across the
    %% remaining healthy pods.
    set_from_env_bool("EPDG_REDIRECT_ENABLE", redirect_enable, false),
    set_from_env("EPDG_REDIRECT_TARGET", redirect_target, ""),

    %% Log level (applied to the primary logger in epdg_app:start/2).
    %% Default `notice' matches the OTP default primary level; lower it to
    %% `warning'/`error' to silence the per-attach NOTICE chatter.
    set_from_env("EPDG_LOG_LEVEL", log_level, "notice"),

    ok.

-spec get(atom()) -> term().
get(Key) ->
    application:get_env(?APP, Key, undefined).

-spec get(atom(), term()) -> term().
get(Key, Default) ->
    application:get_env(?APP, Key, Default).

-spec parse_gtpc_mode(string() | binary() | false) -> s2b | s5s8.
parse_gtpc_mode("s5s8")    -> s5s8;
parse_gtpc_mode(<<"s5s8">>) -> s5s8;
parse_gtpc_mode(_)          -> s2b.

%%====================================================================
%% Internal
%%====================================================================

set_from_env(EnvVar, AppKey, Default) ->
    Value = case os:getenv(EnvVar) of
        false when is_function(Default) -> Default();
        false -> Default;
        Val -> Val
    end,
    application:set_env(?APP, AppKey, Value).

set_from_env_int(EnvVar, AppKey, Default) ->
    Value = case os:getenv(EnvVar) of
        false -> Default;
        Val -> list_to_integer(Val)
    end,
    application:set_env(?APP, AppKey, Value).

set_from_env_bool(EnvVar, AppKey, Default) ->
    application:set_env(?APP, AppKey, parse_bool(os:getenv(EnvVar), Default)).

%% Used by set_from_env_bool/3 and exported so tests can assert the
%% EPDG_EAP_ONLY_AUTH parser without running init/0 (which requires
%% EPDG_UE_IP_POOLS). Unset (false) keeps Default; "1"/"true"/"yes"/"on"
%% are true; everything else is false.
-spec parse_bool(string() | false, boolean()) -> boolean().
parse_bool(false, Default) -> Default;
parse_bool(Val, _Default) ->
    case string:lowercase(string:trim(Val)) of
        "1"    -> true;
        "true" -> true;
        "yes"  -> true;
        "on"   -> true;
        _      -> false
    end.

set_from_env_resolved_addr(PrimaryEnv, ByPodEnv, ByNodeEnv, AppKey, Default) ->
    Primary = os:getenv(PrimaryEnv, Default),
    Hostname = os:getenv("HOSTNAME", ""),
    NodeName = os:getenv("NODE_NAME", ""),
    ByPodMap = parse_addr_map(os:getenv(ByPodEnv, "")),
    ByNodeMap = parse_addr_map(os:getenv(ByNodeEnv, "")),
    Value = case maps:get(Hostname, ByPodMap, undefined) of
        undefined -> case maps:get(NodeName, ByNodeMap, undefined) of
            undefined -> Primary;
            NodeVal -> NodeVal
        end;
        PodVal -> PodVal
    end,
    application:set_env(?APP, AppKey, Value).

parse_addr_map(false) -> #{};
parse_addr_map("") -> #{};
parse_addr_map(Csv) when is_list(Csv) ->
    lists:foldl(
      fun(Ent, Acc) ->
              Parts = string:split(string:trim(Ent), "=", all),
              case Parts of
                  [K, V] when K =/= "", V =/= "" ->
                      Acc#{K => V};
                  _ ->
                      Acc
              end
      end,
      #{},
      string:split(Csv, ",", all)
    ).

%% EPDG_UE_IP_POOLS is mandatory: a wrong or missing pool list makes the
%% GTP-U forwarder reject every attach, so fail the boot loudly instead
%% of coming up in a state that black-holes all subscribers.
set_ue_ip_pools() ->
    case os:getenv("EPDG_UE_IP_POOLS") of
        false ->
            error({missing_config,
                   "EPDG_UE_IP_POOLS is required: comma-separated CIDR list "
                   "of UE inner-IP pools, e.g. "
                   "\"10.46.0.0/16,cafe:0:46::/48\""});
        Csv ->
            case parse_ue_ip_pools(Csv) of
                [] ->
                    error({missing_config,
                           "EPDG_UE_IP_POOLS is empty: at least one CIDR "
                           "UE inner-IP pool is required"});
                Pools ->
                    application:set_env(?APP, ue_ip_pools, Pools)
            end
    end.

%% Parse a comma-separated CIDR list ("10.46.0.0/16,cafe:0:46::/48") into
%% [{BaseAddr, PrefixLen}]. Any invalid entry raises {invalid_cidr, Entry}
%% — silently skipping a pool would strand every UE the PGW puts there.
%% IPv6 pools must be strictly wider than /64 (see check_v6_pool_width/3).
-spec parse_ue_ip_pools(string()) -> [{inet:ip_address(), 0..128}].
parse_ue_ip_pools(Csv) when is_list(Csv) ->
    Entries = [string:trim(E) || E <- string:split(Csv, ",", all)],
    [parse_cidr(E) || E <- Entries, E =/= ""].

parse_cidr(Str) ->
    case string:split(Str, "/", all) of
        [AddrS, LenS] ->
            case {inet:parse_address(AddrS), string:to_integer(LenS)} of
                {{ok, Addr}, {Len, ""}} when is_integer(Len) ->
                    Max = case tuple_size(Addr) of
                              4 -> 32;
                              8 -> 128
                          end,
                    case Len >= 0 andalso Len =< Max of
                        true  -> check_v6_pool_width(Addr, Len, Str);
                        false -> error({invalid_cidr, Str})
                    end;
                _ ->
                    error({invalid_cidr, Str})
            end;
        _ ->
            error({invalid_cidr, Str})
    end.

%% The GTP-U forwarder attributes IPv6 uplink to its bearer by the /64
%% prefix of the inner source address, because the PGW delegates one
%% /64 per UE (see epdg_gtpu_forwarder:inner_src_key/1). A pool with
%% prefix length >= 64 therefore contains at most ONE distinguishable
%% UE: every further UE the PGW addresses inside it collapses onto the
%% same uplink key and silently shares the first UE's GTP tunnel.
%% Reject such pools at boot instead. IPv4 pools are unaffected (v4
%% uplink is keyed on the exact address).
check_v6_pool_width(Addr, Len, Str) when tuple_size(Addr) =:= 8,
                                         Len >= ?UE6_PREFIX_LEN ->
    error({invalid_cidr, Str,
           lists:flatten(io_lib:format(
               "IPv6 UE pools must be wider than /~B: uplink attribution is "
               "keyed on the per-UE delegated /~B prefix, so a pool of /~B "
               "or longer can hold at most one distinguishable UE",
               [?UE6_PREFIX_LEN, ?UE6_PREFIX_LEN, ?UE6_PREFIX_LEN]))});
check_v6_pool_width(Addr, Len, _Str) ->
    {Addr, Len}.

%% Resolve the pod instance id (0..63) that makes the shared TUN device
%% name, policy-routing table and rule priority unique per ePDG pod.
%% Several ePDG pods on one hostNetwork node share the node's network
%% namespace: without distinct ids the second pod would attach to the
%% first pod's TUN device, overwrite its rules, and tear the neighbour's
%% whole datapath down on exit.
%%
%% Precedence:
%%   1. EPDG_INSTANCE_ID — explicit integer 0..63. Anything else fails
%%      the boot: a typo that silently mapped to some other id would
%%      recreate exactly the collision this exists to prevent.
%%   2. POD_NAME — a StatefulSet ordinal suffix ("epdg-1" -> 1, taken
%%      mod 64); any other shape hashes stably into 0..63.
%%   3. 0 — single instance / local development.
-spec parse_instance_id(string() | false, string() | false) -> 0..63.
parse_instance_id(false, PodName) ->
    instance_id_from_pod_name(PodName);
parse_instance_id(Explicit, _PodName) ->
    case string:to_integer(string:trim(Explicit)) of
        {Id, ""} when Id >= 0, Id =< 63 ->
            Id;
        _ ->
            error({invalid_config,
                   "EPDG_INSTANCE_ID must be an integer 0..63, got: \""
                   ++ Explicit ++ "\""})
    end.

instance_id_from_pod_name(false) -> 0;
instance_id_from_pod_name("")    -> 0;
instance_id_from_pod_name(PodName) ->
    case ordinal_suffix(PodName) of
        {ok, Ordinal} -> Ordinal rem 64;
        error         -> erlang:phash2(PodName, 64)
    end.

%% "epdg-3" -> {ok, 3}; no all-digit trailing segment -> error
%% (e.g. Deployment pod names like "epdg-7f9c4d8b6d-x2v4q").
ordinal_suffix(Name) ->
    case string:split(Name, "-", trailing) of
        [_, Digits] when Digits =/= "" ->
            case lists:all(fun(C) -> C >= $0 andalso C =< $9 end, Digits) of
                true  -> {ok, list_to_integer(Digits)};
                false -> error
            end;
        _ ->
            error
    end.

%% SPEC-DEVIATION: RFC 8247 §2.4 -- DH groups 2 (MODP-1024) and 5
%% (MODP-1536) are rated SHOULD NOT. They are accepted only when the
%% operator explicitly opts in for a known legacy device population,
%% and the choice is warned about at boot so it shows up in an audit.
set_ike_legacy_dh_groups() ->
    Groups = parse_legacy_dh_groups(os:getenv("EPDG_IKE_LEGACY_DH_GROUPS")),
    case Groups of
        [] -> ok;
        _  ->
            logger:warning("EPDG_IKE_LEGACY_DH_GROUPS enables weak DH "
                           "group(s) ~w (RFC 8247 rates MODP-1024/1536 as "
                           "SHOULD NOT); intended only for legacy device "
                           "populations", [Groups])
    end,
    application:set_env(?APP, ike_legacy_dh_groups, Groups).

%% Comma-separated list; only 2 and 5 exist as legacy opt-ins. Any other
%% value fails the boot: a typo like "14" must not silently enable (or
%% silently skip) a group the operator did not intend.
-spec parse_legacy_dh_groups(string() | false) -> [2 | 5].
parse_legacy_dh_groups(false) -> [];
parse_legacy_dh_groups(Csv) when is_list(Csv) ->
    Entries = [string:trim(E) || E <- string:split(Csv, ",", all)],
    lists:usort([parse_legacy_dh_group(E) || E <- Entries, E =/= ""]).

parse_legacy_dh_group(E) ->
    case string:to_integer(E) of
        {2, ""} -> 2;
        {5, ""} -> 5;
        _ ->
            error({invalid_config,
                   "EPDG_IKE_LEGACY_DH_GROUPS accepts only the values 2 "
                   "(MODP-1024) and 5 (MODP-1536), got: \"" ++ E ++ "\""})
    end.

set_dra_hosts() ->
    Hosts = case os:getenv("DRA_HOSTS") of
        false ->
            Single = case os:getenv("DRA_HOST") of
                false -> "dra-diameter";
                V     -> V
            end,
            [Single];
        Csv ->
            [string:trim(H) || H <- string:split(Csv, ",", all),
                                string:trim(H) =/= ""]
    end,
    application:set_env(?APP, dra_hosts, Hosts).

hostname_default() ->
    case os:getenv("HOSTNAME") of
        false -> "epdg.localdomain";
        H ->
            Realm = os:getenv("EPDG_ORIGIN_REALM", "localdomain"),
            H ++ "." ++ Realm
    end.

%% Per-pod Redis key prefix. POD_NAME (fieldRef metadata.name) is
%% preferred over HOSTNAME because hostNetwork pods inherit the NODE
%% hostname — which changes when the pod is rescheduled, orphaning every
%% stored session.
default_redis_prefix() ->
    Pod = case os:getenv("POD_NAME") of
        false -> os:getenv("HOSTNAME", "epdg");
        P     -> P
    end,
    "epdg:" ++ Pod.

%% Default IDr FQDN per TS 23.003 §19.4.2.4: epdg.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org.
default_ike_id_fqdn() ->
    MCC = os:getenv("MCC", "001"),
    MNC = os:getenv("MNC", "01"),
    MNC3 = case length(MNC) of
        2 -> "0" ++ MNC;
        _ -> MNC
    end,
    "epdg.epc.mnc" ++ MNC3 ++ ".mcc" ++ MCC ++ ".3gppnetwork.org".
