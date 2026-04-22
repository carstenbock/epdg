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
    set_from_env("EPDG_IKE_BIND_ADDR", ike_bind_addr, "0.0.0.0"),
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

    %% GTP-C S2b toward PGW-C/SMF
    set_from_env("PGW_ADDR", pgw_addr, "127.0.0.1"),
    set_from_env_int("PGW_PORT", pgw_port, 2123),
    set_from_env("EPDG_GTPC_BIND_ADDR", gtpc_bind_addr, "0.0.0.0"),
    set_from_env_int("EPDG_GTPC_PORT", gtpc_port, 2123),

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

    %% Allowed APNs (comma-separated; empty = allow all, "ims" is always allowed)
    set_from_env("EPDG_ALLOWED_APNS", allowed_apns, "ims"),
    set_from_env("EPDG_DEFAULT_APN", default_apn, "ims"),

    %% Log level
    set_from_env("EPDG_LOG_LEVEL", log_level, "info"),

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
