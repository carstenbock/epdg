-module(epdg_config_tests).
-include_lib("eunit/include/eunit.hrl").

gtpc_mode_defaults_to_s2b_test() ->
    os:unsetenv("EPDG_GTPC_MODE"),
    ?assertEqual(s2b, epdg_config:parse_gtpc_mode(os:getenv("EPDG_GTPC_MODE"))).

gtpc_mode_reads_s5s8_test() ->
    ?assertEqual(s5s8, epdg_config:parse_gtpc_mode("s5s8")).

gtpc_mode_unknown_falls_back_to_s2b_test() ->
    ?assertEqual(s2b, epdg_config:parse_gtpc_mode("garbage")).
