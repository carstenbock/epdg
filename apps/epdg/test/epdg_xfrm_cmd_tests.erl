-module(epdg_xfrm_cmd_tests).
-include_lib("eunit/include/eunit.hrl").

%% What `ip xfrm' actually receives, asserted after /bin/sh has split the words.
%%
%% Every silent data-plane break this module has produced was a malformed
%% command string rather than bad logic: unquoted `cbc(aes)' aborting the shell
%% before `ip' was spawned, a hard-coded 96-bit ICV on hmac(sha256), reversed
%% espinudp ports, and a missing `flag af-unspec' that made the kernel drop
%% every inner-IPv6 packet with XfrmInStateMismatch. An assertion on the string
%% built inside the BEAM cannot see the first of those, so these tests put a
%% shim named `ip' on PATH and record its argv, one word per line — the words
%% the kernel-facing tool really got.
%%
%% Values are from the 2026-08-19 09:53 lab session on epdg-lab01 (IPv4v6 PDN,
%% NAT-T, outer IPv4 / inner IPv6), so a failure names a configuration that was
%% actually observed.

-define(EPDG_OUTER, {212, 9, 60, 20}).
-define(UE_OUTER,   {93, 204, 201, 107}).
-define(SPI,        16#05974942).
-define(REQID,      1186832296).
-define(UE_NAT_PORT, 23830).

%%====================================================================
%% Fixture: a fake `ip' on PATH that logs its argv
%%====================================================================

xfrm_cmd_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun sa_add_sets_af_unspec_flag/1,
      fun sa_add_algorithm_names_survive_the_shell/1,
      fun sa_add_auth_trunc_length_follows_algorithm/1,
      fun sa_add_encap_ports_follow_direction/1,
      fun policy_add_uses_update_not_add/1]}.

setup() ->
    Base = case os:getenv("TMPDIR") of false -> "/tmp"; T -> T end,
    Dir  = filename:join(Base, "epdg_xfrm_cmd_"
                         ++ integer_to_list(erlang:unique_integer([positive]))),
    ok  = filelib:ensure_dir(filename:join(Dir, "keep")),
    Log = filename:join(Dir, "argv.log"),
    %% One line per argv word, then a `--' terminator per invocation. Nothing on
    %% stdout: run_cmd/1 reads any output at all as a failure.
    ok = file:write_file(filename:join(Dir, "ip"),
                         ["#!/bin/sh\n",
                          "for a in \"$@\"; do printf '%s\\n' \"$a\" >> ", Log, "; done\n",
                          "printf '%s\\n' -- >> ", Log, "\n"]),
    ok = file:change_mode(filename:join(Dir, "ip"), 8#755),
    OldPath = os:getenv("PATH"),
    true = os:putenv("PATH", Dir ++ ":" ++ OldPath),
    %% inc/1 falls back to ets:insert on a missing counter, which still needs
    %% the table to exist.
    epdg_metrics:init(),
    {ok, Pid} = epdg_xfrm:start_link(),
    {Dir, Log, OldPath, Pid}.

cleanup({Dir, _Log, OldPath, Pid}) ->
    gen_server:stop(Pid),
    true = os:putenv("PATH", OldPath),
    _ = [file:delete(F) || F <- filelib:wildcard(filename:join(Dir, "*"))],
    _ = file:del_dir(Dir),
    ok.

%%====================================================================
%% Tests
%%====================================================================

%% An SA added without this flag gets x->sel.family pinned to the SA's own
%% (outer) family in xfrm_state_construct/1. xfrm_policy_ok/5 then rejects every
%% inner packet of the other family with XfrmInStateMismatch, before the
%% netfilter FORWARD hook — so an IPv4v6 PDN loses all IPv6 uplink silently.
sa_add_sets_af_unspec_flag(Ctx) ->
    ok = epdg_xfrm:create_sa(base_sa()),
    Argv = one_invocation(Ctx),
    [?_assert(has_seq(Argv, ["flag", "af-unspec"])),
     ?_assert(has_seq(Argv, ["mode", "tunnel"])),
     ?_assert(has_seq(Argv, ["reqid", integer_to_list(?REQID)]))].

%% `cbc(aes)' and `hmac(sha256)' contain shell metacharacters. If the quoting
%% regresses, /bin/sh aborts with a syntax error and `ip' is never spawned: IKE
%% completes and the kernel drops every ESP packet for want of a state.
sa_add_algorithm_names_survive_the_shell(Ctx) ->
    ok = epdg_xfrm:create_sa(base_sa()),
    Argv = one_invocation(Ctx),
    [?_assert(lists:member("cbc(aes)", Argv)),
     ?_assert(lists:member("hmac(sha256)", Argv))].

%% `ip xfrm ... auth ALGO KEY' defaults to a 96-bit ICV for every algorithm,
%% which is wrong for the SHA-2 family (RFC 4868). The truncation length must
%% follow the negotiated integrity transform.
sa_add_auth_trunc_length_follows_algorithm(Ctx) ->
    ok = epdg_xfrm:create_sa(base_sa()),
    ok = epdg_xfrm:create_sa((base_sa())#{auth_alg => hmac_sha1,
                                          spi => ?SPI + 1}),
    [Sha256, Sha1] = invocations(Ctx),
    [?_assert(has_seq(Sha256, ["hmac(sha256)"])),
     ?_assertEqual("128", word_after_key(Sha256)),
     ?_assert(has_seq(Sha1, ["hmac(sha1)"])),
     ?_assertEqual("96", word_after_key(Sha1))].

%% encap espinudp maps positionally to encap_sport / encap_dport, and the kernel
%% builds the outbound UDP header from sport -> dport. One fixed ordering for
%% both directions emitted downlink ESP from the wrong port, which a
%% port-translating NAT then dropped.
sa_add_encap_ports_follow_direction(Ctx) ->
    Nat = (base_sa())#{nat_t => true,
                       peer_udp_port => ?UE_NAT_PORT,
                       peer_outer_ip => ?UE_OUTER},
    ok = epdg_xfrm:create_sa(Nat#{sa_dir => out}),
    ok = epdg_xfrm:create_sa(Nat#{sa_dir => in, spi => ?SPI + 1}),
    [Out, In] = invocations(Ctx),
    UePort = integer_to_list(?UE_NAT_PORT),
    [?_assert(has_seq(Out, ["espinudp", "4500", UePort])),
     ?_assert(has_seq(In,  ["espinudp", UePort, "4500"]))].

%% `add' is create-exclusive and returned EEXIST for a UE re-dialling onto the
%% same inner IP, leaving the policy template bound to the deleted Child SA.
policy_add_uses_update_not_add(Ctx) ->
    ok = epdg_xfrm:create_policy(#{src => "fd00:230:babe:9c::/64",
                                   dst => "::/0",
                                   direction => in,
                                   tmpl_src => ?UE_OUTER,
                                   tmpl_dst => ?EPDG_OUTER,
                                   reqid => ?REQID}),
    Argv = one_invocation(Ctx),
    [?_assert(has_seq(Argv, ["policy", "update"])),
     ?_assert(has_seq(Argv, ["dir", "in"])),
     ?_assert(has_seq(Argv, ["reqid", integer_to_list(?REQID)]))].

%%====================================================================
%% Helpers
%%====================================================================

base_sa() ->
    #{spi      => ?SPI,
      src_ip   => ?EPDG_OUTER,
      dst_ip   => ?UE_OUTER,
      reqid    => ?REQID,
      enc_alg  => aes_cbc_256,
      enc_key  => binary:copy(<<16#ab>>, 32),
      auth_alg => hmac_sha256,
      auth_key => binary:copy(<<16#cd>>, 32)}.

one_invocation(Ctx) ->
    [Argv] = invocations(Ctx),
    Argv.

%% argv.log holds every word the shim was called with, `--'-terminated per
%% invocation.
invocations({_Dir, Log, _OldPath, _Pid}) ->
    {ok, Bin} = file:read_file(Log),
    Words = string:lexemes(binary_to_list(Bin), "\n"),
    split_on("--", Words, [], []).

split_on(_Sep, [], [], Acc) -> lists:reverse(Acc);
split_on(_Sep, [], Cur, Acc) -> lists:reverse([lists:reverse(Cur) | Acc]);
split_on(Sep, [Sep | Rest], Cur, Acc) ->
    split_on(Sep, Rest, [], [lists:reverse(Cur) | Acc]);
split_on(Sep, [W | Rest], Cur, Acc) ->
    split_on(Sep, Rest, [W | Cur], Acc).

has_seq(Words, Seq) ->
    lists:any(fun(N) -> lists:prefix(Seq, lists:nthtail(N, Words)) end,
              lists:seq(0, length(Words) - 1)).

%% The truncation length is the word right after the hex auth key.
word_after_key(Words) ->
    hd(lists:nthtail(1, lists:dropwhile(
        fun("0x" ++ _) -> false; (_) -> true end,
        lists:dropwhile(fun("auth-trunc") -> false; (_) -> true end, Words)))).
