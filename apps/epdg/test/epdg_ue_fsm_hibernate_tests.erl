-module(epdg_ue_fsm_hibernate_tests).
-include_lib("eunit/include/eunit.hrl").

%% KI-173: every tunnel is one UE FSM that is idle between DPD exchanges.
%% Without hibernation it kept the heap of its attach, and the ePDG grew by
%% 75-125 KB per tunnel; 50,000 tunnels took 6.3 of the pod's 8 GiB. An idle
%% FSM must hibernate, which compacts it to its live state.
idle_ue_fsm_hibernates_test() ->
    epdg_metrics:init(),
    application:load(epdg),
    application:set_env(epdg, ue_hibernate_after_ms, 50),
    {ok, P} = epdg_ue_fsm:start_link(#{peer_ip => {127, 0, 0, 1}, peer_port => 500}),
    unlink(P),
    try
        timer:sleep(300),
        ?assertEqual({current_function, {erlang, hibernate, 3}},
                     erlang:process_info(P, current_function)),
        %% It still answers once woken.
        ?assertEqual({ok, idle}, epdg_ue_fsm:get_state(P))
    after
        exit(P, kill),
        application:unset_env(epdg, ue_hibernate_after_ms)
    end.
