-module(epdg_swm_blocked_transport_tests).
-include_lib("eunit/include/eunit.hrl").

%% KI-175: a Diameter transport whose peer stopped taking data stays blocked
%% in its socket send for good, and every request queued behind it is lost
%% memory. Such a process must be recognised, and nothing else may be: a
%% wrong kill would cut a working SWm connection.

%% A process that blocks in a TCP send (the peer never reads), with
%% InitialCall as its proc_lib initial call and Extra messages queued.
blocked_sender(InitialCall, Extra) ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {recbuf, 4096}]),
    {ok, Port} = inet:port(L),
    Self = self(),
    P = spawn(fun() ->
        put('$initial_call', InitialCall),
        {ok, C} = gen_tcp:connect({127,0,0,1}, Port, [binary, {sndbuf, 4096}]),
        Self ! {connected, self()},
        Chunk = binary:copy(<<0>>, 65536),
        Loop = fun F() -> ok = gen_tcp:send(C, Chunk), F() end,
        Loop()
    end),
    {ok, _A} = gen_tcp:accept(L),
    receive {connected, P} -> ok end,
    [P ! {diameter, {send, x}} || _ <- lists:seq(1, Extra)],
    wait_blocked(P, 100),
    P.

wait_blocked(_P, 0) -> ok;
wait_blocked(P, N) ->
    case erlang:process_info(P, current_function) of
        {current_function, {prim_inet, send, _}} -> ok;
        _ -> timer:sleep(20), wait_blocked(P, N - 1)
    end.

blocked_diameter_transport_with_long_queue_is_found_test() ->
    P = blocked_sender({diameter_tcp, init, 1}, 6000),
    try ?assertMatch({true, N} when N >= 6000, epdg_diameter_swm:blocked_transport(P))
    after exit(P, kill) end.

short_queue_is_left_alone_test() ->
    P = blocked_sender({diameter_sctp, init, 1}, 10),
    try ?assertEqual(false, epdg_diameter_swm:blocked_transport(P))
    after exit(P, kill) end.

other_process_blocked_in_send_is_left_alone_test() ->
    P = blocked_sender({epdg_gtpc_client, init, 1}, 6000),
    try ?assertEqual(false, epdg_diameter_swm:blocked_transport(P))
    after exit(P, kill) end.
