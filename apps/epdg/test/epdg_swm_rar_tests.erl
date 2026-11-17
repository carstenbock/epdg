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
    ?assertEqual(false, epdg_diameter_swm:swm_session_held(<<"s1">>, [])).

same_session_id_is_held_test() ->
    P = fake_fsm({ok, #{swm_session_id => <<"s1">>}}),
    ?assertEqual(true, epdg_diameter_swm:swm_session_held(<<"s1">>, [P])),
    P ! stop.

other_session_of_the_imsi_is_unknown_test() ->
    %% The UE re-attached: the FSM holds a newer SWm session.
    P = fake_fsm({ok, #{swm_session_id => <<"s2">>}}),
    ?assertEqual(false, epdg_diameter_swm:swm_session_held(<<"s1">>, [P])),
    P ! stop.

dead_fsm_is_unsure_not_unknown_test() ->
    P = spawn(fun() -> ok end),
    timer:sleep(10),
    ?assertEqual(unsure, epdg_diameter_swm:swm_session_held(<<"s1">>, [P])).

%% Multi-PDN (KI-199): a UE with an IMS and an MMS tunnel has two SWm
%% sessions. A RAR for either must be answered as held, or the AAA ends
%% the other PDN connection's authorization.
session_of_any_pdn_connection_is_held_test() ->
    Ims = fake_fsm({ok, #{swm_session_id => <<"s-ims">>}}),
    Mms = fake_fsm({ok, #{swm_session_id => <<"s-mms">>}}),
    ?assertEqual(true, epdg_diameter_swm:swm_session_held(<<"s-ims">>, [Ims, Mms])),
    ?assertEqual(true, epdg_diameter_swm:swm_session_held(<<"s-mms">>, [Ims, Mms])),
    ?assertEqual(false, epdg_diameter_swm:swm_session_held(<<"s-old">>, [Ims, Mms])),
    Ims ! stop, Mms ! stop.

%% An ASR ends only the PDN connection whose SWm session it names: aborting
%% the MMS session must leave VoWiFi up.
asr_ends_only_the_named_session_test() ->
    Ims = fake_fsm({ok, #{swm_session_id => <<"s-ims">>}}),
    Mms = fake_fsm({ok, #{swm_session_id => <<"s-mms">>}}),
    ?assertEqual([Mms], epdg_diameter_swm:asr_targets(<<"s-mms">>, [Ims, Mms])),
    ?assertEqual([], epdg_diameter_swm:asr_targets(<<"s-old">>, [Ims, Mms])),
    Ims ! stop, Mms ! stop.

%% With a single session the ASR ends it even when its Session-Id cannot
%% be confirmed, as before sessions were kept per PDN connection.
asr_with_single_session_ends_it_test() ->
    P = fake_fsm({ok, #{swm_session_id => <<"s2">>}}),
    ?assertEqual([P], epdg_diameter_swm:asr_targets(<<"s1">>, [P])),
    P ! stop.
