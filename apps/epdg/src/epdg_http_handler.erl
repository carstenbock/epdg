%%%-------------------------------------------------------------------
%%% @doc Cowboy handler for ePDG HTTP endpoints.
%%%
%%% /readyz honours a persistent_term drain flag so that the LoadBalancer
%%% in front of the pod de-registers it as soon as a graceful drain has
%%% started, letting in-flight UE re-connects land on a sibling pod
%%% before this one's kernel XFRM state is destroyed.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_http_handler).

-export([init/2, is_draining/0]).

%% persistent_term key used to signal graceful drain. Absent/undefined
%% means "serving"; any truthy value means "drain in progress".
-define(DRAIN_KEY, {?MODULE, draining}).

init(Req, #{action := health} = State) ->
    Reply = cowboy_req:reply(200,
        #{<<"content-type">> => <<"text/plain">>},
        <<"ok">>, Req),
    {ok, Reply, State};

init(Req, #{action := ready} = State) ->
    {Code, Body} =
        case is_draining() of
            true ->
                {503, <<"not ready: draining">>};
            false ->
                %% Ready if at least one Diameter peer is up.
                Peers = epdg_metrics:get(diameter_swm_peers),
                case Peers > 0 of
                    true  -> {200, <<"ready">>};
                    false ->
                        logger:warning(
                            "Readiness check failed: no SWm Diameter peers connected"),
                        {503, <<"not ready: no diameter peers">>}
                end
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
        diameter_peers => epdg_metrics:get(diameter_swm_peers),
        draining => is_draining()
    },
    Body = jsx:encode(Status),
    Reply = cowboy_req:reply(200,
        #{<<"content-type">> => <<"application/json">>},
        Body, Req),
    {ok, Reply, State};

init(Req, #{action := drain} = State) ->
    %% Idempotent: repeated POSTs just re-broadcast the drain intent,
    %% which is harmless — UE FSMs that are already scheduling teardown
    %% will see the duplicate and ignore it.
    Method = cowboy_req:method(Req),
    case Method of
        <<"POST">> ->
            set_draining(true),
            Count = safe_registry_count(),
            ok = broadcast_drain(),
            logger:warning(
                "Graceful drain initiated via /admin/drain; broadcast to ~p UE FSM(s)",
                [Count]),
            Body = jsx:encode(#{draining => true, broadcast_to => Count}),
            Reply = cowboy_req:reply(202,
                #{<<"content-type">> => <<"application/json">>},
                Body, Req),
            {ok, Reply, State};
        _ ->
            Reply = cowboy_req:reply(405,
                #{<<"content-type">> => <<"text/plain">>,
                  <<"allow">> => <<"POST">>},
                <<"method not allowed">>, Req),
            {ok, Reply, State}
    end.

%% @doc Returns true iff a graceful drain has been initiated on this node.
%% Intended for readiness probes and any other code path that needs to
%% stop accepting new work.
-spec is_draining() -> boolean().
is_draining() ->
    case persistent_term:get(?DRAIN_KEY, false) of
        true -> true;
        _    -> false
    end.

-spec set_draining(boolean()) -> ok.
set_draining(true) ->
    persistent_term:put(?DRAIN_KEY, true);
set_draining(false) ->
    _ = persistent_term:erase(?DRAIN_KEY),
    ok.

%% Broadcast a drain notification to every live UE FSM. Tolerates the
%% registry being absent during start-up / shutdown races.
-spec broadcast_drain() -> ok.
broadcast_drain() ->
    try
        epdg_ue_registry:broadcast({drain, rolling_upgrade})
    catch
        Class:Reason:Stack ->
            logger:error(
                "broadcast_drain failed: ~p:~p~n~p", [Class, Reason, Stack]),
            ok
    end.

-spec safe_registry_count() -> non_neg_integer().
safe_registry_count() ->
    try
        case epdg_ue_registry:count() of
            N when is_integer(N), N >= 0 -> N;
            _ -> 0
        end
    catch
        _:_ -> 0
    end.
