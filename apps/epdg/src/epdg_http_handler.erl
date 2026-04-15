%%%-------------------------------------------------------------------
%%% @doc Cowboy handler for ePDG HTTP endpoints.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_http_handler).

-export([init/2]).

init(Req, #{action := health} = State) ->
    Reply = cowboy_req:reply(200,
        #{<<"content-type">> => <<"text/plain">>},
        <<"ok">>, Req),
    {ok, Reply, State};

init(Req, #{action := ready} = State) ->
    %% Ready if at least one Diameter peer is up
    Peers = epdg_metrics:get(diameter_swm_peers),
    {Code, Body} = case Peers > 0 of
        true  -> {200, <<"ready">>};
        false ->
            logger:warning("Readiness check failed: no SWm Diameter peers connected"),
            {503, <<"not ready: no diameter peers">>}
    end,
    Reply = cowboy_req:reply(Code,
        #{<<"content-type">> => <<"text/plain">>},
        Body, Req),
    {ok, Reply, State};

init(Req, #{action := metrics} = State) ->
    Body = iolist_to_binary(epdg_metrics:format_prometheus()),
    Reply = cowboy_req:reply(200,
        #{<<"content-type">> => <<"text/plain; version=0.0.4">>},
        Body, Req),
    {ok, Reply, State};

init(Req, #{action := status} = State) ->
    Status = #{
        ue_sessions_active => epdg_metrics:get(ue_sessions_active),
        ue_sessions_total  => epdg_metrics:get(ue_sessions_total),
        tunnels_established => epdg_metrics:get(ike_tunnels_established_total),
        offload_mode => atom_to_binary(epdg_xfrm:get_offload_mode()),
        diameter_peers => epdg_metrics:get(diameter_swm_peers)
    },
    Body = jsx:encode(Status),
    Reply = cowboy_req:reply(200,
        #{<<"content-type">> => <<"application/json">>},
        Body, Req),
    {ok, Reply, State}.
