-module(epdg_xfrm_sa_gauge_tests).
%% `epdg_xfrm_sa_active' must equal the SAs the kernel holds. Every attach
%% first deletes the UE's previous SAs by SPI (re-dial handling) and most of
%% those deletes find nothing; counting them drove the gauge to minus two per
%% session (KI-59). A fake `ip' on PATH plays the kernel: it answers a delete
%% either silently (removed) or with the kernel's error (nothing to remove).
-include_lib("eunit/include/eunit.hrl").

-define(EPDG_OUTER, {212, 9, 60, 20}).
-define(UE_OUTER,   {93, 204, 201, 107}).

setup(DeleteFinds) ->
    application:set_env(epdg, xfrm_backend, "ip"),
    application:set_env(epdg, xfrm_backend_effective, ip),
    application:set_env(epdg, xfrm_policy_mode, "static"),
    Base = case os:getenv("TMPDIR") of false -> "/tmp"; T -> T end,
    Dir = filename:join(Base, "epdg_sa_gauge_" ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_dir(filename:join(Dir, "keep")),
    Reply = case DeleteFinds of
                true -> "";
                false -> "case \"$*\" in *delete*) echo 'RTNETLINK answers: No such process';; esac\n"
            end,
    ok = file:write_file(filename:join(Dir, "ip"), ["#!/bin/sh\n", Reply]),
    ok = file:change_mode(filename:join(Dir, "ip"), 8#755),
    OldPath = os:getenv("PATH"),
    true = os:putenv("PATH", Dir ++ ":" ++ OldPath),
    catch ets:delete(epdg_metrics_tab),
    epdg_metrics:init(),
    {ok, Pid} = epdg_xfrm:start_link(),
    {Dir, OldPath, Pid}.

cleanup({Dir, OldPath, Pid}) ->
    gen_server:stop(Pid),
    [application:unset_env(epdg, K) || K <- [xfrm_backend, xfrm_backend_effective, xfrm_policy_mode]],
    true = os:putenv("PATH", OldPath),
    _ = [file:delete(F) || F <- filelib:wildcard(filename:join(Dir, "*"))],
    _ = file:del_dir(Dir),
    ok.

sa(Spi) ->
    #{spi => Spi, src_ip => ?EPDG_OUTER, dst_ip => ?UE_OUTER, reqid => 1,
      enc_alg => aes_cbc_256, enc_key => binary:copy(<<16#ab>>, 32),
      auth_alg => hmac_sha256, auth_key => binary:copy(<<16#cd>>, 32)}.

del(Spi) -> #{spi => Spi, src_ip => ?EPDG_OUTER, dst_ip => ?UE_OUTER}.

%% The re-dial deletes before an attach remove nothing: the gauge stays.
deletes_that_remove_nothing_are_not_counted_test() ->
    Ctx = setup(false),
    try
        ok = epdg_xfrm:delete_sa(del(16#1001)),
        ok = epdg_xfrm:delete_sa(del(16#1002)),
        ?assertEqual(0, epdg_metrics:get(xfrm_sa_active)),
        ?assertEqual(0, epdg_metrics:get(xfrm_sa_deleted_total))
    after cleanup(Ctx) end.

%% Attach and detach of one UE: two SAs in, two out, gauge back to zero.
attach_and_detach_leave_the_gauge_at_zero_test() ->
    Ctx = setup(true),
    try
        ok = epdg_xfrm:create_sa(sa(16#2001)),
        ok = epdg_xfrm:create_sa(sa(16#2002)),
        ?assertEqual(2, epdg_metrics:get(xfrm_sa_active)),
        ok = epdg_xfrm:delete_sa(del(16#2001)),
        ok = epdg_xfrm:delete_sa(del(16#2002)),
        ?assertEqual(0, epdg_metrics:get(xfrm_sa_active)),
        ?assertEqual(2, epdg_metrics:get(xfrm_sa_deleted_total))
    after cleanup(Ctx) end.
