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
    set_from_env("DRA_HOST", dra_host, "dra-diameter"),
    set_from_env_int("DRA_PORT", dra_port, 3868),
    set_from_env("DRA_TRANSPORT", dra_transport, "tcp"),
    set_from_env_int("EPDG_DIAMETER_PORT", diameter_port, 3868),

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

hostname_default() ->
    case os:getenv("HOSTNAME") of
        false -> "epdg.localdomain";
        H ->
            Realm = os:getenv("EPDG_ORIGIN_REALM", "localdomain"),
            H ++ "." ++ Realm
    end.
