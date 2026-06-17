%%%-------------------------------------------------------------------
%%% @doc ePDG configuration read from environment variables.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_config).

-export([init/0, get/1, get/2]).

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

    %% EAP-AKA'
    set_from_env("EPDG_EAP_METHOD", eap_method, "aka-prime"),

    %% XFRM / IPsec
    set_from_env("EPDG_IPSEC_OFFLOAD", ipsec_offload, "auto"),
    set_from_env("EPDG_IPSEC_IFACE", ipsec_iface, "eth0"),

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

    %% UE IP pool (dual-stack: IPv4 + optional IPv6)
    set_from_env("EPDG_UE_IP_POOL", ue_ip_pool, "10.47.0.0/16"),
    set_from_env("EPDG_UE_IP6_POOL", ue_ip6_pool, ""),

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

    %% TUN device garbage collection interval (ms)
    set_from_env_int("EPDG_TUN_GC_INTERVAL", tun_gc_interval, 300000),

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
    Value = case os:getenv(EnvVar) of
        false -> Default;
        Val ->
            case string:lowercase(string:trim(Val)) of
                "1"    -> true;
                "true" -> true;
                "yes"  -> true;
                "on"   -> true;
                _      -> false
            end
    end,
    application:set_env(?APP, AppKey, Value).

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

%% Default IDr FQDN per TS 23.003 §19.4.2.4: epdg.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org.
default_ike_id_fqdn() ->
    MCC = os:getenv("MCC", "001"),
    MNC = os:getenv("MNC", "01"),
    MNC3 = case length(MNC) of
        2 -> "0" ++ MNC;
        _ -> MNC
    end,
    "epdg.epc.mnc" ++ MNC3 ++ ".mcc" ++ MCC ++ ".3gppnetwork.org".
