%%%-------------------------------------------------------------------
%%% @doc Prometheus-style metrics for ePDG.
%%% Counters and gauges stored in ETS, exposed via HTTP /metrics.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_metrics).

-export([init/0, inc/1, inc/2,
         gauge_inc/1, gauge_dec/1, gauge_set/2,
         observe_latency/2,
         get/1, format_prometheus/0]).

-define(TAB, epdg_metrics_tab).

init() ->
    case ets:info(?TAB) of
        undefined ->
            ets:new(?TAB, [named_table, public, set, {write_concurrency, true}]);
        _ ->
            ok
    end,
    %% Pre-create counters
    lists:foreach(fun(K) -> ets:insert_new(?TAB, {K, 0}) end, [
        ikev2_packets_received_total,
        ue_sessions_total,
        ue_sessions_active,
        ike_tunnels_established_total,
        ike_auth_success_total,
        ike_auth_failure_total,
        ike_auth_duration_ms_sum,
        ike_auth_duration_ms_count,
        gtpc_requests_total,
        gtpc_responses_total,
        gtpc_timeouts_total,
        gtpc_latency_ms_sum,
        gtpc_latency_ms_count,
        diameter_swm_requests_total,
        diameter_swm_latency_ms_sum,
        diameter_swm_latency_ms_count,
        diameter_swm_peers,
        xfrm_sa_created_total,
        xfrm_sa_deleted_total,
        xfrm_sa_errors_total,
        xfrm_sa_active,
        gtpc_echo_sent_total,
        gtpc_echo_timeouts_total,
        gtpc_dns_resolves_total,
        gtpc_dns_resolve_errors_total,
        gtpc_peer_down_total,
        gtpc_peer_restarts_total,
        gtpu_tx_bytes,
        gtpu_rx_bytes,
        gtpu_tx_pkts,
        gtpu_rx_pkts,
        gtpu_peer_down_total
    ]),
    ok.

-spec inc(atom()) -> ok.
inc(Key) -> inc(Key, 1).

-spec inc(atom(), integer()) -> ok.
inc(Key, N) ->
    try ets:update_counter(?TAB, Key, N)
    catch error:badarg -> ets:insert(?TAB, {Key, N})
    end,
    ok.

-spec gauge_inc(atom()) -> ok.
gauge_inc(Key) -> inc(Key, 1).

-spec gauge_dec(atom()) -> ok.
gauge_dec(Key) ->
    try ets:update_counter(?TAB, Key, -1)
    catch error:badarg -> ok
    end,
    ok.

-spec gauge_set(atom(), integer()) -> ok.
gauge_set(Key, Val) ->
    ets:insert(?TAB, {Key, Val}),
    ok.

-spec get(atom()) -> integer().
get(Key) ->
    case ets:lookup(?TAB, Key) of
        [{_, V}] -> V;
        [] -> 0
    end.

-spec observe_latency(atom(), non_neg_integer()) -> ok.
observe_latency(Prefix, DurationMs) ->
    inc(list_to_atom(atom_to_list(Prefix) ++ "_ms_sum"), DurationMs),
    inc(list_to_atom(atom_to_list(Prefix) ++ "_ms_count")),
    ok.

-spec format_prometheus() -> iolist().
format_prometheus() ->
    Entries = ets:tab2list(?TAB),
    [format_entry(E) || E <- lists:sort(Entries)].

format_entry({Key, Value}) ->
    io_lib:format("epdg_~s ~B\n", [Key, Value]).
