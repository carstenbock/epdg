%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the RFC 5685 REDIRECT decision logic in
%%% epdg_ue_fsm: N(REDIRECT_SUPPORTED) detection via find_notify/2 and the
%%% pure drain_action/1 gating matrix.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_fsm_redirect_tests).

-include_lib("eunit/include/eunit.hrl").

%% Notify message types (RFC 5685 §9 / RFC 4555).
-define(N_MOBIKE_SUPPORTED,   16396).
-define(N_REDIRECT_SUPPORTED, 16406).

%%====================================================================
%% find_notify(?N_REDIRECT_SUPPORTED, _) detection
%%====================================================================

find_notify_detects_redirect_supported_test() ->
    Payloads = [notify(?N_MOBIKE_SUPPORTED), notify(?N_REDIRECT_SUPPORTED)],
    ?assert(epdg_ue_fsm:find_notify(?N_REDIRECT_SUPPORTED, Payloads)).

find_notify_absent_when_not_offered_test() ->
    Payloads = [notify(?N_MOBIKE_SUPPORTED)],
    ?assertNot(epdg_ue_fsm:find_notify(?N_REDIRECT_SUPPORTED, Payloads)).

find_notify_empty_payloads_test() ->
    ?assertNot(epdg_ue_fsm:find_notify(?N_REDIRECT_SUPPORTED, [])).

%% A notify payload body per RFC 7296 §3.10: ProtocolId | SPISize | Type ...
notify(NType) ->
    #{type => notify, data => <<0:8, 0:8, NType:16>>}.

%%====================================================================
%% drain_action/1 gating matrix:
%%   {enable on/off} x {target set/empty} x {redirect_supported true/false}
%% Only the all-true combination yields {redirect, _}.
%%====================================================================

drain_action_matrix_test_() ->
    Target = "epdg-b.example.net",
    Gw = {3, <<"epdg-b.example.net">>},
    {foreach,
     fun save_env/0,
     fun restore_env/1,
     [
      {"enable+target+supported -> redirect",
       ?_assertEqual({redirect, Gw}, decide(true, Target, true))},
      {"disabled -> delete_only",
       ?_assertEqual(delete_only, decide(false, Target, true))},
      {"empty target -> delete_only",
       ?_assertEqual(delete_only, decide(true, "", true))},
      {"unsupported UE -> delete_only",
       ?_assertEqual(delete_only, decide(true, Target, false))},
      {"disabled+empty -> delete_only",
       ?_assertEqual(delete_only, decide(false, "", true))},
      {"disabled+unsupported -> delete_only",
       ?_assertEqual(delete_only, decide(false, Target, false))},
      {"empty+unsupported -> delete_only",
       ?_assertEqual(delete_only, decide(true, "", false))},
      {"all-off -> delete_only",
       ?_assertEqual(delete_only, decide(false, "", false))}
     ]}.

decide(Enable, Target, Supported) ->
    application:set_env(epdg, redirect_enable, Enable),
    application:set_env(epdg, redirect_target, Target),
    epdg_ue_fsm:drain_action(epdg_ue_fsm:new_data_for_test(Supported)).

save_env() ->
    {application:get_env(epdg, redirect_enable),
     application:get_env(epdg, redirect_target)}.

restore_env({Enable, Target}) ->
    set_or_unset(redirect_enable, Enable),
    set_or_unset(redirect_target, Target).

set_or_unset(Key, undefined)  -> application:unset_env(epdg, Key);
set_or_unset(Key, {ok, Value}) -> application:set_env(epdg, Key, Value).
