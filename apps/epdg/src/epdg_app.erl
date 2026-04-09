%%%-------------------------------------------------------------------
%%% @doc ePDG application module.
%%% Evolved Packet Data Gateway for VoWiFi (TS 23.402 / TS 29.273).
%%% Native Erlang IKEv2 control plane with Linux kernel XFRM data plane.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    logger:info("Starting ePDG application"),
    epdg_config:init(),
    epdg_metrics:init(),
    epdg_sup:start_link().

stop(_State) ->
    logger:info("Stopping ePDG application"),
    ok.
