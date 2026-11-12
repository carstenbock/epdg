%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the SWm RAR answer (KI-46).
%%%
%%% Why it matters: the AAA audits old SWm sessions with a RAR and ends a
%%% session when the ePDG answers 5002. A 5002 for a live session would
%%% end that user's authorization at the AAA and HSS, so only a session
%%% the ePDG positively does not hold may be reported as unknown; when in
%%% doubt the answer must stay 2001.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_swm_rar_tests).

-include_lib("eunit/include/eunit.hrl").

%% A stand-in for a UE FSM: answers get_info calls with Reply.
fake_fsm(Reply) ->
    spawn(fun Loop() ->
        receive
            {'$gen_call', From, get_info} ->
                gen:reply(From, Reply),
                Loop();
            stop ->
                ok
        end
    end).

no_session_for_the_imsi_is_unknown_test() ->
    ?assertEqual(false, epdg_diameter_swm:swm_session_held(<<"s1">>, error)).

same_session_id_is_held_test() ->
    P = fake_fsm({ok, #{swm_session_id => <<"s1">>}}),
    ?assertEqual(true, epdg_diameter_swm:swm_session_held(<<"s1">>, {ok, P})),
    P ! stop.

other_session_of_the_imsi_is_unknown_test() ->
    %% The UE re-attached: the FSM holds a newer SWm session.
    P = fake_fsm({ok, #{swm_session_id => <<"s2">>}}),
    ?assertEqual(false, epdg_diameter_swm:swm_session_held(<<"s1">>, {ok, P})),
    P ! stop.

dead_fsm_is_unsure_not_unknown_test() ->
    P = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertEqual(unsure, epdg_diameter_swm:swm_session_held(<<"s1">>, {ok, P})).
