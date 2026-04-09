%%%-------------------------------------------------------------------
%%% @doc HTTP server for health checks and Prometheus metrics.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_http).

-export([start_link/0]).

start_link() ->
    Port = epdg_config:get(api_port, 8080),
    Dispatch = cowboy_router:compile([
        {'_', [
            {"/healthz",  epdg_http_handler, #{action => health}},
            {"/readyz",   epdg_http_handler, #{action => ready}},
            {"/metrics",  epdg_http_handler, #{action => metrics}},
            {"/api/status", epdg_http_handler, #{action => status}}
        ]}
    ]),
    {ok, _} = cowboy:start_clear(epdg_http_listener,
        [{port, Port}],
        #{env => #{dispatch => Dispatch}}),
    logger:info("ePDG HTTP API on port ~p", [Port]),
    %% Return ignore since cowboy manages its own supervision
    ignore.
