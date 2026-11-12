-module(epdg_gtpc_client_tests).
-include_lib("eunit/include/eunit.hrl").

%% KI-52: the GTP-C client sent every request once and gave up after one
%% timer, so a single lost datagram failed an attach, although the PGW had
%% answered a retransmission's worth later. TS 29.274 section 7.6 asks for
%% retransmission with the same sequence number (T3-RESPONSE, N3-REQUESTS).
%% The client runs against a fake PGW on the loopback with T3 = 50 ms and
%% N3 = 2, so a request is sent at most three times.

-define(T3, 50).
-define(N3, 2).

setup(PgwOpts) ->
    epdg_metrics:init(),
    %% A client of an earlier case must not survive into this one: it
    %% would keep talking to that case's PGW port.
    stop_if_running(epdg_gtpc_client),
    Pgw = fake_pgw:start(PgwOpts),
    Port = fake_pgw:port(Pgw),
    application:load(epdg),
    [application:set_env(epdg, K, V) ||
        {K, V} <- [{gtpc_bind_addr, "127.0.0.1"}, {gtpc_port, 0},
                   {pgw_fqdn, "127.0.0.1"}, {pgw_port, Port},
                   {gtpc_echo_interval_sec, 3600}, {gtpc_echo_timeout_sec, 1},
                   {gtpc_t3_response_ms, ?T3}, {gtpc_n3_requests, ?N3},
                   {gtpc_pending_limit, 16}]],
    Procs = [start(epdg_dns_cache), start(epdg_gtpc_client)],
    {Pgw, Procs}.

start(Mod) ->
    case Mod:start_link() of
        {ok, Pid} -> unlink(Pid), Pid;
        {error, {already_started, Pid}} -> Pid
    end.

stop_if_running(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> catch gen_server:stop(Pid, shutdown, 2000), ok
    end.

teardown({Pgw, _Procs}) ->
    stop_if_running(epdg_gtpc_client),
    fake_pgw:stop(Pgw).

csr_params() ->
    #{imsi => <<"262240000099001">>, apn => <<"ims">>, rat_type => 3,
      pdn_type => 1, ebi => 5, local_c_teid => 1, local_u_teid => 2}.

metric(Key) ->
    case epdg_metrics:get(Key) of
        V when is_integer(V) -> V;
        _                    -> 0
    end.

retransmission_test_() ->
    {foreach, fun() -> ok end, fun(_) -> ok end,
     [fun csr_retransmitted_with_same_seq_after_loss/0,
      fun csr_fails_after_n3_and_the_caller_hears_it_first/0,
      fun delete_session_is_retransmitted_too/0,
      fun pending_calls_fail_when_the_pgw_restarts/0,
      fun restart_seen_in_a_csr_spares_the_session_it_creates/0,
      fun echo_is_retransmitted_before_a_miss_is_counted/0]}.

%% The PGW misses the first Create Session Request; the retransmission is
%% byte-identical (same sequence number) and the attach succeeds.
csr_retransmitted_with_same_seq_after_loss() ->
    S = setup(#{drop_first => 1}),
    Before = metric(gtpc_retransmissions_total),
    try
        {ok, #{cause := 16, pgw_c_fteid := #{teid := 16#1234}, ebi := 5}} =
            epdg_gtpc_client:create_session_request(csr_params()),
        [First, Second] = [R || #{type := 32} = R <- fake_pgw:received(element(1, S))],
        ?assertEqual(maps:get(raw, First), maps:get(raw, Second)),
        ?assertEqual(Before + 1, metric(gtpc_retransmissions_total))
    after teardown(S) end.

%% A PGW that never answers: N3 retransmissions, then {error, timeout}
%% within the client's own budget, before the caller's timeout.
csr_fails_after_n3_and_the_caller_hears_it_first() ->
    S = setup(#{drop_first => 100}),
    try
        T0 = erlang:monotonic_time(millisecond),
        ?assertEqual({error, timeout},
                     epdg_gtpc_client:create_session_request(csr_params())),
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        Budget = ?T3 * (?N3 + 1),
        ?assert(Elapsed >= Budget - 10),
        ?assert(Elapsed < epdg_gtpc_client:call_timeout()),
        Sends = length([R || #{type := 32} = R <- fake_pgw:received(element(1, S))]),
        ?assertEqual(?N3 + 1, Sends)
    after teardown(S) end.

%% The Delete Session Request of a teardown gets the same treatment.
delete_session_is_retransmitted_too() ->
    S = setup(#{drop_first => 1}),
    try
        {ok, #{type := 37}} =
            epdg_gtpc_client:delete_session_request(#{pgw_c_teid => 16#1234, ebi => 5}),
        Dels = [R || #{type := 36} = R <- fake_pgw:received(element(1, S))],
        ?assertEqual(2, length(Dels)),
        [D1, D2] = Dels,
        ?assertEqual(maps:get(seq_num, D1), maps:get(seq_num, D2)),
        ?assertEqual(16#1234, maps:get(teid, D1))
    after teardown(S) end.

%% A Recovery change while a request is pending: the caller is told at
%% once that the PGW restarted, instead of waiting for its timer.
pending_calls_fail_when_the_pgw_restarts() ->
    %% Only Create Session Requests are swallowed; Echo and Delete are answered.
    S = setup(#{drop => #{32 => 100}}),
    {Pgw, _} = S,
    try
        %% Learn the PGW's Recovery value (7) from a first exchange.
        {ok, _} = epdg_gtpc_client:delete_session_request(#{pgw_c_teid => 1, ebi => 5}),
        Self = self(),
        spawn_link(fun() ->
            Self ! {csr, epdg_gtpc_client:create_session_request(csr_params())}
        end),
        timer:sleep(?T3 div 2),
        %% The PGW comes back with another Recovery; the next Echo shows it.
        ok = fake_pgw:set_recovery(Pgw, 9),
        epdg_gtpc_client ! {timeout, make_ref(), echo_tick},
        Res = receive {csr, R} -> R after ?T3 * 2 -> no_answer end,
        ?assertEqual({error, pgw_restarted}, Res),
        ?assertEqual(1, metric(gtpc_peer_restarts_total))
    after teardown(S) end.

%% KI-148: the first message from a restarted PGW-C can be the Create
%% Session Response of a new attach, carrying the new Recovery value. Every
%% session from before the restart is gone and must be told, but the one this
%% response creates is alive: tearing it down cost the UE its fresh tunnel.
restart_seen_in_a_csr_spares_the_session_it_creates() ->
    S = setup(#{}),
    {Pgw, _} = S,
    Reg = start(epdg_ue_registry),
    Self = self(),
    Fsm = fun(Spi, Work) ->
        spawn(fun() ->
            ok = epdg_ue_registry:register(Spi, self(), undefined),
            Res = Work(),
            Got = receive {'$gen_cast', pgw_restart} -> pgw_restart
                  after 200 -> none end,
            Self ! {Spi, Res, Got}
        end)
    end,
    try
        %% Learn the PGW's Recovery value (7) from a first exchange.
        {ok, _} = epdg_gtpc_client:delete_session_request(#{pgw_c_teid => 1, ebi => 5}),
        ok = fake_pgw:set_recovery(Pgw, 9),
        Fsm(1, fun() -> ok end),                     % a session from before
        timer:sleep(20),
        Fsm(2, fun() -> epdg_gtpc_client:create_session_request(csr_params()) end),
        Old = receive {1, _, G1} -> G1 after 1000 -> no_answer end,
        {New, NewGot} = receive {2, R2, G2} -> {R2, G2} after 1000 -> {no_answer, x} end,
        ?assertEqual(pgw_restart, Old),
        ?assertMatch({ok, _}, New),
        ?assertEqual(none, NewGot),
        ?assertEqual(1, metric(gtpc_peer_restarts_total))
    after
        catch gen_server:stop(Reg),
        teardown(S)
    end.

%% Echo: a miss is counted only after the retransmissions went unanswered.
echo_is_retransmitted_before_a_miss_is_counted() ->
    S = setup(#{drop_first => 100}),
    {Pgw, _} = S,
    try
        Before = metric(gtpc_echo_timeouts_total),
        epdg_gtpc_client ! {timeout, make_ref(), echo_tick},
        %% echo_timeout_sec is 1 s per attempt: wait for N3 + 1 sends.
        timer:sleep(1000 * (?N3 + 1) + 300),
        Echoes = length([R || #{type := 1} = R <- fake_pgw:received(Pgw)]),
        ?assertEqual(?N3 + 1, Echoes),
        ?assertEqual(Before + 1, metric(gtpc_echo_timeouts_total))
    after teardown(S) end.
