%%%-------------------------------------------------------------------
%%% @doc EUnit tests for classify_register_ue_result/1 in epdg_ue_fsm:
%%% the decision matrix over epdg_gtpu_forwarder:register_ue/1 outcomes
%%% in register_bearer_then_finalize/19. The property under test is that
%%% an attach only ever completes when the bearer is actually registered
%%% (or the forwarder is knowingly absent — degraded / dev mode); every
%%% other outcome must abort the IKE_AUTH with Notify 36
%%% (INTERNAL_ADDRESS_FAILURE) instead of handing the UE a working IPsec
%%% tunnel whose uplink is silently dead.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_fsm_register_tests).

-include_lib("eunit/include/eunit.hrl").

classify_register_ue_result_test_() ->
    Cases = [
        {"successful registration -> attach proceeds",
         {ok, #{local_teid => 16#1000, tun_name => "epdg0"}},
         proceed},
        {"PAA outside every configured pool -> Notify 36",
         {error, ue_ip_outside_configured_pools},
         reject_pool},
        {"forwarder not running (dev mode) -> proceed best-effort",
         {'EXIT', {noproc, {gen_server, call, [epdg_gtpu_forwarder, x]}}},
         degraded},
        {"forwarder call timeout -> proceed best-effort",
         {'EXIT', {timeout, {gen_server, call, [epdg_gtpu_forwarder, x]}}},
         degraded},
        {"unknown {error, _} -> Notify 36, no silent half tunnel",
         {error, invalid_params},
         reject_other},
        {"forwarder crash mid-call -> Notify 36",
         {'EXIT', {{badmatch, x}, [{epdg_gtpu_forwarder, do_register_ue, 2, []}]}},
         reject_other},
        {"unexpected bare return value -> Notify 36",
         ok,
         reject_other}
    ],
    [{Desc, ?_assertEqual(Expected,
                          epdg_ue_fsm:classify_register_ue_result(Result))}
     || {Desc, Result, Expected} <- Cases].
