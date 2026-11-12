-module(epdg_srccheck_tests).
%% KI-58: in static policy mode a UE may send uplink only from its own inner
%% address. The inbound SA marks what it decrypts; nftables accepts a packet
%% only when `source address . mark' is in the set. So the set must hold
%% exactly the attached UEs' addresses under their own marks, in the byte
%% layout the kernel compares, and lose them with the UE's process.
-include_lib("eunit/include/eunit.hrl").

-define(IF_ID, 16#45500009).
-define(TABLE, "epdg9").
-define(UE4, {10, 46, 0, 5}).
-define(UE6, {16#2001, 16#db8, 1, 2, 0, 0, 0, 7}).

%% Marks stay off bits 0 to 12: Cilium uses 8 to 11 and the node's
%% policy routing bit 12 (`fwmark 0x1000/0x1000 lookup 4000').
marks_leave_the_low_bits_alone_test() ->
    [?assertEqual(0, epdg_srccheck:mark_of_index(I) band 16#1FFF)
     || I <- [1, 2, 4095, 4096, (1 bsl 19) - 1]],
    ?assertEqual(16#FFFFE000, epdg_srccheck:mark_of_index((1 bsl 19) - 1)).

%% An IPv6 UE is matched on its /64, as the PGW grants a prefix.
ipv6_key_covers_the_prefix_test() ->
    {Low, High} = epdg_srccheck:key6(?UE6, 16#2000),
    ?assertEqual(<<16#2001:16, 16#db8:16, 1:16, 2:16, 0:64, 16#2000:32/big>>, Low),
    ?assertEqual(<<16#2001:16, 16#db8:16, 1:16, 2:16, (-1):64, 16#2000:32/big>>, High).

%%--------------------------------------------------------------------
%% Against the kernel (NET_ADMIN and nft; skipped otherwise)
%%--------------------------------------------------------------------

kernel_test_() ->
    case epdg_xfrm_nl:available() andalso os:find_executable("nft") =/= false
         andalso os:cmd("nft list tables 2>&1") =:= os:cmd("nft list tables 2>/dev/null") of
        true ->
            [{"netlink backend", {setup, fun() -> start(netlink) end, fun stop/1,
                                  fun checks/1}},
             {"ip backend", {setup, fun() -> start(ip) end, fun stop/1,
                             fun checks/1}}];
        false ->
            {"source check kernel tests skipped: no NET_ADMIN or no nft", fun() -> ok end}
    end.

start(Backend) ->
    catch ets:delete(epdg_metrics_tab),
    epdg_metrics:init(),
    application:set_env(epdg, xfrm_backend_effective, Backend),
    application:set_env(epdg, xfrm_policy_mode, "static"),
    application:set_env(epdg, xfrm_source_check, "true"),
    application:set_env(epdg, xfrm_if, #{id => ?IF_ID, name => "epdgx9"}),
    {ok, Pid} = epdg_srccheck:start_link(),
    unlink(Pid),
    Pid.

stop(Pid) ->
    gen_server:stop(Pid),
    [application:unset_env(epdg, K)
     || K <- [xfrm_backend_effective, xfrm_policy_mode, xfrm_source_check, xfrm_if]].

ue() -> spawn(fun() -> receive stop -> ok end end).

%% `nft get element' asks the kernel with nft's own encoding, so a byte
%% order mistake in our keys shows here.
present(Set, Key) ->
    Cmd = lists:flatten(io_lib:format("nft get element inet ~s ~s '{ ~s }' >/dev/null 2>&1; echo $?",
                                      [?TABLE, Set, Key])),
    string:trim(os:cmd(Cmd)) =:= "0".

key(Addr, Mark) -> lists:flatten(io_lib:format("~s . 0x~.16B", [Addr, Mark])).

wait_gone(Set, Key, 0) -> not present(Set, Key);
wait_gone(Set, Key, N) ->
    case present(Set, Key) of
        false -> true;
        true -> timer:sleep(50), wait_gone(Set, Key, N - 1)
    end.

checks(_Pid) ->
    fun() ->
        ?assert(epdg_srccheck:enabled()),
        Ue = ue(),
        Mark = epdg_srccheck:claim(Ue, ?UE4, ?UE6, undefined),
        ?assert(is_integer(Mark)),
        ?assertEqual(0, Mark band 16#1FFF),
        %% the UE's own address and prefix under its own mark, nothing else
        ?assert(present("ue4", key("10.46.0.5", Mark))),
        ?assert(present("ue6", key("2001:db8:1:2::99", Mark))),
        ?assertNot(present("ue4", key("10.46.0.6", Mark))),
        ?assertNot(present("ue4", key("10.46.0.5", Mark + 16#2000))),
        ?assertNot(present("ue6", key("2001:db8:1:3::1", Mark))),
        %% a MOBIKE move or restore of the same session keeps its mark
        ?assertEqual(Mark, epdg_srccheck:claim(Ue, ?UE4, ?UE6, undefined)),
        %% a restored session gets the mark its surviving SA writes
        Restored = ue(),
        ?assertEqual(16#7770000 band 16#FFFFE000,
                     epdg_srccheck:claim(Restored, {10, 46, 0, 9}, undefined,
                                         16#7770000 band 16#FFFFE000)),
        %% the elements go with the UE process
        Ue ! stop, Restored ! stop,
        ?assert(wait_gone("ue4", key("10.46.0.5", Mark), 40)),
        ?assert(wait_gone("ue6", key("2001:db8:1:2::99", Mark), 40)),
        ?assertEqual(0, epdg_metrics:get(nft_errors_total))
    end.
