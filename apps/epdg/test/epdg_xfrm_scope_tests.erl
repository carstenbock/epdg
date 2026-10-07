-module(epdg_xfrm_scope_tests).
-include_lib("eunit/include/eunit.hrl").

%% The ePDG must only ever look at ITS OWN slice of the host's XFRM state.
%%
%% On a hostNetwork node the kernel SAD/SPD is shared with the IMS IPsec
%% gateway. During an IMS-AKA load test the gateway held ~39,000 SAs on
%% volte-ims-1; the ePDG read the complete `ip xfrm state list' output into
%% the BEAM on every reconciler sweep and at session restore, and was
%% OOM-killed in a loop by state that was never its own. The gateway is
%% sized for millions of SAs, so the contract under test is:
%%
%%   * SAs: every dump carries an address filter (`src'/`dst' become
%%     XFRMA_ADDRESS_FILTER, i.e. the kernel does the filtering) — an
%%     unfiltered dump must never be issued;
%%   * policies (no kernel filter exists): foreign blocks are dropped in the
%%     pipeline, before they reach the BEAM;
%%   * whatever a listing returns, state without this pod's outer address is
%%     never a deletion candidate for the reconciler.
%%
%% As in epdg_xfrm_cmd_tests a shim named `ip' is put on PATH. It answers
%% like a busy shared node: an unfiltered state dump returns the gateway's
%% SAs, and the policy dump is dominated by the gateway's policies.

-define(LOCAL,   {46, 225, 197, 146}).   %% this pod's IKE VIP
-define(SIBLING, {46, 225, 197, 147}).   %% the other ePDG pod's VIP
-define(UE,      {93, 204, 201, 107}).
-define(FOREIGN_POLICIES, 5000).

%%====================================================================
%% Fixture
%%====================================================================

xfrm_scope_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun sa_dumps_are_address_filtered/1,
      fun foreign_policies_never_reach_the_beam/1]}.

setup() ->
    Base = case os:getenv("TMPDIR") of false -> "/tmp"; T -> T end,
    Dir  = filename:join(Base, "epdg_xfrm_scope_"
                         ++ integer_to_list(erlang:unique_integer([positive]))),
    ok  = filelib:ensure_dir(filename:join(Dir, "keep")),
    Log = filename:join(Dir, "argv.log"),
    F   = fun(Name) -> filename:join(Dir, Name) end,
    ok = file:write_file(F("sa_in"),  own_sa_in()),
    ok = file:write_file(F("sa_out"), own_sa_out()),
    ok = file:write_file(F("sa_all"), [gateway_sas(), own_sa_in(), own_sa_out()]),
    ok = file:write_file(F("pol_all"), host_policy_dump()),
    ok = file:write_file(F("ip"),
        ["#!/bin/sh\n",
         "printf '%s\\n' \"$*\" >> ", Log, "\n",
         "case \"$*\" in\n",
         "  'xfrm state list dst 46.225.197.146 proto esp') cat ", F("sa_in"), " ;;\n",
         "  'xfrm state list src 46.225.197.146 proto esp') cat ", F("sa_out"), " ;;\n",
         "  'xfrm state list'*) cat ", F("sa_all"), " ;;\n",
         "  'xfrm policy list') cat ", F("pol_all"), " ;;\n",
         "esac\n"]),
    ok = file:change_mode(F("ip"), 8#755),
    OldPath = os:getenv("PATH"),
    true = os:putenv("PATH", Dir ++ ":" ++ OldPath),
    {Dir, Log, OldPath}.

cleanup({Dir, _Log, OldPath}) ->
    true = os:putenv("PATH", OldPath),
    _ = [file:delete(F) || F <- filelib:wildcard(filename:join(Dir, "*"))],
    _ = file:del_dir(Dir),
    ok.

invocations(Log) ->
    {ok, Bin} = file:read_file(Log),
    string:lexemes(binary_to_list(Bin), "\n").

%%====================================================================
%% Shared-node fixtures
%%====================================================================

own_sa_in() ->
    "src 93.204.201.107 dst 46.225.197.146\n"
    "\tproto esp spi 0x05974942 reqid 93800770 mode tunnel\n"
    "\treplay-window 32 flag af-unspec\n"
    "\tenc cbc(aes) 0x0011223344556677\n"
    "\tsel src 0.0.0.0/0 dst 0.0.0.0/0\n".

own_sa_out() ->
    "src 46.225.197.146 dst 93.204.201.107\n"
    "\tproto esp spi 0xc91f55b2 reqid 93800770 mode tunnel\n"
    "\treplay-window 32 flag af-unspec\n"
    "\tenc cbc(aes) 0x99aabb\n"
    "\tsel src 0.0.0.0/0 dst 0.0.0.0/0\n".

%% Gm SAs of the IPsec gateway (transport mode, P-CSCF VIP <-> UE).
gateway_sas() ->
    [io_lib:format(
       "src 10.46.~B.~B dst 46.225.197.153\n"
       "\tproto esp spi 0x~8.16.0b reqid 0 mode transport\n"
       "\treplay-window 32\n"
       "\tauth-trunc hmac(sha1) 0x00112233445566778899aabbccddeeff00112233 96\n"
       "\tenc cbc(aes) 0x00112233445566778899aabbccddeeff\n"
       "\tsel src 0.0.0.0/0 dst 0.0.0.0/0\n",
       [N div 250, N rem 250 + 1, 16#10000 + N])
     || N <- lists:seq(1, 1000)].

own_policies() ->
    "src 10.46.0.34/32 dst 0.0.0.0/0\n"
    "\tdir fwd priority 0\n"
    "\ttmpl src 93.204.201.107 dst 46.225.197.146\n"
    "\t\tproto esp reqid 93800770 mode tunnel\n"
    "src 10.46.0.34/32 dst 0.0.0.0/0\n"
    "\tdir in priority 0\n"
    "\ttmpl src 93.204.201.107 dst 46.225.197.146\n"
    "\t\tproto esp reqid 93800770 mode tunnel\n"
    "src 0.0.0.0/0 dst 10.46.0.34/32\n"
    "\tdir out priority 0\n"
    "\ttmpl src 46.225.197.146 dst 93.204.201.107\n"
    "\t\tproto esp reqid 93800770 mode tunnel\n".

%% The gateway's per-port IMS policies, the sibling ePDG pod's per-UE
%% policy, an address that merely STARTS with ours, and a socket policy —
%% with our own three policies split across the middle and the very end, so
%% a filter that only handles the first or last block fails.
host_policy_dump() ->
    Gateway = [io_lib:format(
                 "src 10.46.~B.~B/32 dst 10.0.1.5/32 proto udp sport ~B dport 6100\n"
                 "\tdir ~s priority 1024\n"
                 "\ttmpl src 0.0.0.0 dst 0.0.0.0\n"
                 "\t\tproto esp spi 0x~8.16.0b reqid 0 mode transport\n",
                 [N div 250, N rem 250 + 1, 5000 + N,
                  case N rem 2 of 0 -> "in"; 1 -> "out" end, 16#10000 + N])
               || N <- lists:seq(1, ?FOREIGN_POLICIES)],
    {Head, Tail} = lists:split(?FOREIGN_POLICIES div 2, Gateway),
    [Fwd, In, Out] = policy_blocks(own_policies()),
    [Head, Fwd, In,
     "src 10.46.0.99/32 dst 0.0.0.0/0\n"
     "\tdir fwd priority 0\n"
     "\ttmpl src 198.51.100.9 dst 46.225.197.147\n"
     "\t\tproto esp reqid 4242 mode tunnel\n"
     "src 10.46.0.98/32 dst 0.0.0.0/0\n"
     "\tdir fwd priority 0\n"
     "\ttmpl src 198.51.100.9 dst 46.225.197.14\n"
     "\t\tproto esp reqid 4243 mode tunnel\n"
     "src 0.0.0.0/0 dst 0.0.0.0/0\n"
     "\tsocket in priority 0\n",
     Tail, Out].

%% own_policies/0 as three 4-line blocks.
policy_blocks(Text) ->
    Lines = string:split(Text, "\n", all),
    [lists:append([L ++ "\n" || L <- lists:sublist(Lines, I, 4)])
     || I <- [1, 5, 9]].

%%====================================================================
%% Tests
%%====================================================================

%% WHY: an unfiltered `ip xfrm state list' hands every SA on the node to the
%% BEAM. Both dumps must carry this pod's address so the kernel filters; the
%% result is our SA pair and nothing of the gateway's.
sa_dumps_are_address_filtered({_Dir, Log, _}) ->
    SAs = epdg_xfrm:list_sas(?LOCAL),
    Calls = invocations(Log),
    [?_assertEqual(["xfrm state list dst 46.225.197.146 proto esp",
                    "xfrm state list src 46.225.197.146 proto esp"],
                   lists:sort(Calls)),
     ?_assertEqual(
        lists:sort([#{src => ?UE, dst => ?LOCAL,
                      spi => 16#05974942, reqid => 93800770},
                    #{src => ?LOCAL, dst => ?UE,
                      spi => 16#c91f55b2, reqid => 93800770}]),
        lists:sort(SAs))].

%% WHY: the SPD cannot be filtered by the kernel, so the dump of a shared
%% node is dominated by the gateway. What crosses into the BEAM must be our
%% own blocks only — a few hundred bytes out of a dump of several hundred
%% kilobytes — independent of how many foreign policies exist.
foreign_policies_never_reach_the_beam({Dir, _Log, _}) ->
    {ok, Dump} = file:read_file(filename:join(Dir, "pol_all")),
    Reached = os:cmd(epdg_xfrm:policy_list_cmd(?LOCAL)),
    Pols = epdg_xfrm:list_policies(?LOCAL),
    [?_assert(byte_size(Dump) > 500000),
     ?_assertEqual(own_policies(), Reached),
     ?_assertEqual([fwd, in, out], [maps:get(dir, P) || P <- Pols]),
     ?_assert(lists:all(fun(#{tmpl_src := S, tmpl_dst := D}) ->
                                S =:= ?LOCAL orelse D =:= ?LOCAL
                        end, Pols))].

%%====================================================================
%% Reconciler ownership (pure)
%%====================================================================

%% WHY: the reconciler DELETES what it is handed and nobody claims. If a
%% listing ever returns foreign state (an iproute2/kernel that ignores the
%% address filter), the gateway's Gm SAs and a sibling pod's SAs must still
%% not become candidates: no live ePDG session will ever claim them, so they
%% would all be deleted after one grace period.
reconciler_never_owns_foreign_sas_test() ->
    Own     = [#{src => ?UE, dst => ?LOCAL, spi => 1, reqid => 1},
               #{src => ?LOCAL, dst => ?UE, spi => 2, reqid => 1}],
    Gateway = [#{src => {10,46,0,N}, dst => {46,225,197,153},
                 spi => 16#10000 + N, reqid => 0} || N <- lists:seq(1, 200)],
    Sibling = [#{src => ?UE, dst => ?SIBLING, spi => 3, reqid => 3}],
    ?assertEqual(Own, epdg_xfrm_reconciler:owned_sas(
                        Gateway ++ Own ++ Sibling, ?LOCAL)).

%% Same for policies; additionally a policy with our address but reqid 0
%% was not installed by the ePDG (it always sets reqid = inbound SPI).
reconciler_never_owns_foreign_policies_test() ->
    Pol = fun(TS, TD, R) ->
                  #{src => "10.46.0.34/32", dst => "0.0.0.0/0", dir => fwd,
                    tmpl_src => TS, tmpl_dst => TD, reqid => R}
          end,
    Own = Pol(?UE, ?LOCAL, 93800770),
    ?assertEqual([Own],
                 epdg_xfrm_reconciler:owned_policies(
                   [Pol({0,0,0,0}, {0,0,0,0}, 0),      %% gateway, transport
                    Pol(undefined, undefined, 0),      %% no template
                    Own,
                    Pol(?UE, ?SIBLING, 4242),          %% sibling ePDG pod
                    Pol(?UE, ?LOCAL, 0)],              %% ours by address only
                   ?LOCAL)).
