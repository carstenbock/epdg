-module(epdg_ue_registry_tests).
-include_lib("eunit/include/eunit.hrl").

%% A UE holds one session per PDN connection (TS 24.302 §6.5.3). Keying
%% sessions by IMSI alone made an MMS tunnel supersede the IMS tunnel and
%% drop VoWiFi (KI-199). EPS bearer IDs identify a bearer within the UE
%% across all its PDN connections (TS 29.274 §7.2.1), so two PDN
%% connections must never share one.

-define(IMSI, <<"262240000099001">>).

registry_test_() ->
    {foreach,
     fun() -> {ok, Pid} = epdg_ue_registry:start_link(), unlink(Pid), Pid end,
     fun(Pid) -> exit(Pid, kill), timer:sleep(10) end,
     [fun two_apns_two_sessions/1,
      fun same_apn_is_replaced/1,
      fun ebis_are_distinct_per_imsi/1,
      fun ebi_claims_die_with_the_session/1]}.

idle() -> spawn(fun() -> receive stop -> ok end end).

two_apns_two_sessions(_) ->
    Ims = idle(), Mms = idle(),
    ok = epdg_ue_registry:register(1, Ims, ?IMSI, <<"ims">>),
    ok = epdg_ue_registry:register(2, Mms, ?IMSI, <<"mms">>),
    [?_assertEqual({ok, Ims}, epdg_ue_registry:lookup_by_imsi_apn(?IMSI, <<"ims">>)),
     ?_assertEqual({ok, Mms}, epdg_ue_registry:lookup_by_imsi_apn(?IMSI, <<"mms">>)),
     ?_assertEqual(lists:sort([Ims, Mms]),
                   lists:sort(epdg_ue_registry:lookup_all_by_imsi(?IMSI)))].

%% A re-attach to the same APN takes over the IMSI+APN entry; when the old
%% session unregisters it must not remove the new one's entry.
same_apn_is_replaced(_) ->
    Old = idle(), New = idle(),
    ok = epdg_ue_registry:register(1, Old, ?IMSI, <<"ims">>),
    ok = epdg_ue_registry:register(2, New, ?IMSI, <<"ims">>),
    ok = epdg_ue_registry:unregister(1),
    [?_assertEqual({ok, New}, epdg_ue_registry:lookup_by_imsi_apn(?IMSI, <<"ims">>)),
     ?_assertEqual([New], epdg_ue_registry:lookup_all_by_imsi(?IMSI))].

ebis_are_distinct_per_imsi(_) ->
    A = idle(), B = idle(),
    {ok, EA} = epdg_ue_registry:claim_ebi(?IMSI, A, lists:seq(5, 15)),
    {ok, EB} = epdg_ue_registry:claim_ebi(?IMSI, B, lists:seq(5, 15)),
    %% Another UE starts from 5 again: the pool is per IMSI.
    {ok, EO} = epdg_ue_registry:claim_ebi(<<"001010000000001">>, B, lists:seq(5, 15)),
    [?_assertEqual(5, EA),
     ?_assertEqual(6, EB),
     ?_assertEqual(5, EO),
     %% Claims are idempotent for their holder and refused to others.
     ?_assertEqual(ok, epdg_ue_registry:claim_ebi_exact(?IMSI, 5, A)),
     ?_assertEqual({error, taken}, epdg_ue_registry:claim_ebi_exact(?IMSI, 5, B))].

ebi_claims_die_with_the_session(_) ->
    A = idle(), B = idle(),
    %% The registry monitors registered sessions and drops their claims
    %% when they die, so a crashed session does not leak bearer IDs.
    ok = epdg_ue_registry:register(1, A, ?IMSI, <<"ims">>),
    {ok, 5} = epdg_ue_registry:claim_ebi(?IMSI, A, lists:seq(5, 15)),
    A ! stop,
    timer:sleep(20),
    Released = epdg_ue_registry:claim_ebi(?IMSI, B, lists:seq(5, 15)),
    %% A full pool is refused instead of handing out a used EBI.
    lists:foreach(fun(E) -> epdg_ue_registry:claim_ebi_exact(?IMSI, E, B) end,
                  lists:seq(5, 15)),
    [?_assertEqual({ok, 5}, Released),
     ?_assertEqual({error, no_free_ebi},
                   epdg_ue_registry:claim_ebi(?IMSI, idle(), lists:seq(5, 15)))].
