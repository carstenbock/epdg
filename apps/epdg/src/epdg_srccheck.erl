%%%-------------------------------------------------------------------
%%% @doc Inner source address check for static XFRM policy mode (KI-58).
%%%
%%% In static mode one wildcard inbound and forward policy per XFRM
%%% interface replaced the per-UE policies whose selector `src <UE>/32'
%%% made the kernel drop inner packets with another UE's address
%%% (RFC 7296 §2.9 traffic selectors, TS 33.402 §8.2). The per-UE policies
%%% went because every policy insert flushes the route cache (KI-53).
%%%
%%% The check is back without a flush (ADR-0042):
%%%   * each UE session gets a mark; its inbound SA writes the mark into
%%%     every packet it decrypts (XFRMA_SET_MARK, bits 13 to 31);
%%%   * table `inet epdg<id>' checks `saddr . mark' of each packet from
%%%     the XFRM interface against a set holding one element per UE (its
%%%     IPv4 address, its IPv6 /64) and drops the rest. Set updates do not
%%%     flush the route cache (measured on volte-ims-1, see KI-58).
%%%
%%% The chain runs at priority -300, before conntrack and the node's
%%% mangle rules (which rewrite bit 12 of the mark for policy routing),
%%% and gives an accepted packet its original low mark bits back, so
%%% nothing after it sees a difference. Bits 0 to 12 stay clear: Cilium
%%% uses bits 8 to 11, the node's policy routing bit 12.
%%%
%%% A mark belongs to the UE's FSM process. This server monitors it, so
%%% the element and the mark go away with the process however it ends.
%%%
%%% Off (claim/4 returns undefined, SAs carry no mark, no table) unless
%%% EPDG_XFRM_SOURCE_CHECK is true, the policy mode is static and the
%%% XFRM interface is in use. When the table cannot be created the check
%%% stays off and that is logged; a UE whose element cannot be added still
%%% gets its mark, so its packets are dropped rather than let through
%%% unchecked.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_srccheck).
-behaviour(gen_server).

-export([start_link/0, claim/4, enabled/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
-ifdef(TEST).
-export([ruleset/2, key4/2, key6/2, mark_of_index/1]).
-endif.

-define(SERVER, ?MODULE).
-define(MARK_SHIFT, 13).
-define(MARK_MASK, 16#FFFFE000).
-define(MAX_INDEX, (1 bsl (32 - ?MARK_SHIFT)) - 1).
-define(UE6_PREFIX_LEN, 64).
-define(DROPS_INTERVAL_MS, 15000).

-record(st, {table      :: string() | undefined,
             backend    :: netlink | ip,
             next = 1   :: pos_integer(),
             by_pid = #{} :: #{pid() => {integer(), [elem()], reference()}},
             by_mark = #{} :: #{integer() => pid()}}).

-type elem() :: {ue4 | ue6, binary(), binary() | undefined}.

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% The mark for the inbound SA of the UE session owned by Pid, or undefined
%% when the check is off. Idempotent per Pid (a MOBIKE move or a restore
%% gets the same mark). Preferred: the mark a restored session had before
%% the restart, which its surviving kernel SA still writes.
-spec claim(pid(), inet:ip4_address() | undefined, inet:ip6_address() | undefined,
            integer() | undefined) -> integer() | undefined.
claim(Pid, Ip4, Ip6, Preferred) ->
    case whereis(?SERVER) of
        undefined -> undefined;
        _ -> gen_server:call(?SERVER, {claim, Pid, Ip4, Ip6, Preferred}, 10000)
    end.

-spec enabled() -> boolean().
enabled() ->
    case whereis(?SERVER) of
        undefined -> false;
        _ -> gen_server:call(?SERVER, enabled)
    end.

%%====================================================================
%% gen_server
%%====================================================================

init([]) ->
    process_flag(trap_exit, true),
    Backend = case epdg_config:get(xfrm_backend_effective, netlink) of
                  ip -> ip;
                  _ -> netlink
              end,
    St0 = #st{backend = Backend,
              next = 1 + rand:uniform(?MAX_INDEX - 1)},
    case wanted() of
        {true, #{id := IfId, name := IfName}} ->
            Table = "epdg" ++ integer_to_list(IfId band 16#FFFF),
            case nft_script(ruleset(Table, IfName)) of
                ok ->
                    logger:notice("Source check: table inet ~s on ~s", [Table, IfName]),
                    erlang:send_after(?DROPS_INTERVAL_MS, self(), read_drops),
                    {ok, St0#st{table = Table}};
                {error, Reason} ->
                    epdg_metrics:inc(nft_errors_total),
                    logger:error("Source check OFF: table inet ~s could not be created "
                                 "(~p); UEs are not bound to their inner address", [Table, Reason]),
                    {ok, St0}
            end;
        {false, Why} ->
            logger:info("Source check off: ~s", [Why]),
            {ok, St0}
    end.

handle_call(enabled, _From, St) ->
    {reply, St#st.table =/= undefined, St};
handle_call({claim, _Pid, _Ip4, _Ip6, _Pref}, _From, #st{table = undefined} = St) ->
    {reply, undefined, St};
handle_call({claim, Pid, Ip4, Ip6, Pref}, _From, St) ->
    Elems = elems(Ip4, Ip6),
    case maps:get(Pid, St#st.by_pid, undefined) of
        {Mark, Elems, _} ->
            {reply, Mark, St};
        {Mark, Old, Ref} ->
            %% Same session, other addresses: swap the elements.
            _ = setelem(del, Old, Mark, St),
            _ = setelem(add, Elems, Mark, St),
            {reply, Mark, St#st{by_pid = (St#st.by_pid)#{Pid => {Mark, Elems, Ref}}}};
        undefined ->
            case allocate(Pref, St) of
                {ok, Mark, St1} ->
                    _ = setelem(add, Elems, Mark, St1),
                    Ref = erlang:monitor(process, Pid),
                    St2 = St1#st{by_pid = (St1#st.by_pid)#{Pid => {Mark, Elems, Ref}},
                                 by_mark = (St1#st.by_mark)#{Mark => Pid}},
                    epdg_metrics:gauge_set(xfrm_source_check_elements, map_size(St2#st.by_pid)),
                    {reply, Mark, St2};
                full ->
                    %% Cannot happen below 524,287 sessions per instance.
                    epdg_metrics:inc(nft_errors_total),
                    logger:error("Source check: no free mark"),
                    {reply, undefined, St}
            end
    end;
handle_call(_Req, _From, St) ->
    {reply, {error, unknown_call}, St}.

handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info({'DOWN', _Ref, process, Pid, _}, St) ->
    case maps:take(Pid, St#st.by_pid) of
        {{Mark, Elems, _}, ByPid} ->
            _ = setelem(del, Elems, Mark, St),
            St1 = St#st{by_pid = ByPid, by_mark = maps:remove(Mark, St#st.by_mark)},
            epdg_metrics:gauge_set(xfrm_source_check_elements, map_size(ByPid)),
            {noreply, St1};
        error ->
            {noreply, St}
    end;
handle_info(read_drops, #st{table = Table} = St) when Table =/= undefined ->
    case drops(Table) of
        {ok, N} -> epdg_metrics:gauge_set(xfrm_source_check_drops_total, N);
        _ -> ok
    end,
    erlang:send_after(?DROPS_INTERVAL_MS, self(), read_drops),
    {noreply, St};
handle_info(_Info, St) ->
    {noreply, St}.

%% The table goes with the process: a successor recreates it empty.
terminate(_Reason, #st{table = undefined}) ->
    ok;
terminate(_Reason, #st{table = Table}) ->
    _ = nft_script("delete table inet " ++ Table ++ "\n"),
    ok.

code_change(_Old, St, _Extra) ->
    {ok, St}.

%%====================================================================
%% Internal
%%====================================================================

wanted() ->
    Check = epdg_config:get(xfrm_source_check, "true") =/= "false",
    Static = epdg_config:get(xfrm_policy_mode, "static") =:= "static",
    If = epdg_config:get(xfrm_if, undefined),
    case {Check, Static, If} of
        {false, _, _} -> {false, "EPDG_XFRM_SOURCE_CHECK=false"};
        {_, false, _} -> {false, "per-ue policy mode (the policies check the source)"};
        {_, _, #{id := Id, name := _}} when is_integer(Id), Id > 0 -> {true, If};
        _ -> {false, "no XFRM interface"}
    end.

%% Created atomically: `table' + `delete table' first makes the script work
%% whether or not a previous incarnation left the table behind.
ruleset(Table, IfName) ->
    lists:flatten(io_lib:format(
      "table inet ~s\n"
      "delete table inet ~s\n"
      "table inet ~s {\n"
      "  set ue4 { type ipv4_addr . mark; }\n"
      "  set ue6 { type ipv6_addr . mark; flags interval; }\n"
      "  chain pre {\n"
      "    type filter hook prerouting priority -300; policy accept;\n"
      "    iifname != \"~s\" accept\n"
      "    meta mark & 0x~.16B == 0 accept\n"
      "    ip saddr . meta mark & 0x~.16B @ue4 meta mark set meta mark & 0x~.16B accept\n"
      "    ip6 saddr . meta mark & 0x~.16B @ue6 meta mark set meta mark & 0x~.16B accept\n"
      "    counter drop\n"
      "  }\n"
      "}\n",
      [Table, Table, Table, IfName,
       ?MARK_MASK, ?MARK_MASK, bnot ?MARK_MASK band 16#FFFFFFFF,
       ?MARK_MASK, bnot ?MARK_MASK band 16#FFFFFFFF])).

mark_of_index(I) -> I bsl ?MARK_SHIFT.

allocate(Pref, St) when is_integer(Pref), Pref band (bnot ?MARK_MASK) =:= 0, Pref > 0 ->
    case maps:is_key(Pref, St#st.by_mark) of
        false -> {ok, Pref, St};
        true -> allocate(undefined, St)
    end;
allocate(_, St) ->
    find_free(St#st.next, ?MAX_INDEX, St).

find_free(_, 0, _St) ->
    full;
find_free(I, Left, St) ->
    Mark = mark_of_index(I),
    Next = case I >= ?MAX_INDEX of true -> 1; false -> I + 1 end,
    case maps:is_key(Mark, St#st.by_mark) of
        false -> {ok, Mark, St#st{next = Next}};
        true -> find_free(Next, Left - 1, St)
    end.

elems(Ip4, Ip6) ->
    [{ue4, Ip4} || Ip4 =/= undefined] ++ [{ue6, Ip6} || Ip6 =/= undefined].

%% Concatenated set keys: each field padded to 4 bytes, addresses in
%% network order. The mark is the kernel's u32 register (host order) in the
%% hash set; in the interval (pipapo) set nft keeps every field big-endian
%% and its rule converts the packet's mark the same way.
key4({A, B, C, D}, Mark) -> <<A, B, C, D, Mark:32/native>>.

key6({_, _, _, _, _, _, _, _} = Ip6, Mark) ->
    <<P:?UE6_PREFIX_LEN, _/bitstring>> = ip6_bin(Ip6),
    Low = <<P:?UE6_PREFIX_LEN, 0:(128 - ?UE6_PREFIX_LEN)>>,
    High = <<P:?UE6_PREFIX_LEN, (-1):(128 - ?UE6_PREFIX_LEN)>>,
    {<<Low/binary, Mark:32/big>>, <<High/binary, Mark:32/big>>}.

ip6_bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

setelem(Op, Elems, Mark, #st{table = Table, backend = netlink}) ->
    R4 = [{key4(Ip, Mark), undefined} || {ue4, Ip} <- Elems],
    R6 = [key6(Ip, Mark) || {ue6, Ip} <- Elems],
    report(Op, Mark, [epdg_xfrm_nl:nft_setelem(Op, Table, "ue4", R4),
                      epdg_xfrm_nl:nft_setelem(Op, Table, "ue6", R6)]);
setelem(Op, Elems, Mark, #st{table = Table, backend = ip}) ->
    Verb = case Op of add -> "add"; del -> "delete" end,
    Lines = [io_lib:format("~s element inet ~s ~s { ~s . 0x~.16B }\n",
                           [Verb, Table, Set, Addr, Mark])
             || {Set, Addr} <- [{"ue4", inet:ntoa(Ip)} || {ue4, Ip} <- Elems] ++
                               [{"ue6", prefix6(Ip)} || {ue6, Ip} <- Elems]],
    report(Op, Mark, [nft_script(lists:flatten(Lines))]).

prefix6(Ip6) ->
    <<P:?UE6_PREFIX_LEN, _/bitstring>> = ip6_bin(Ip6),
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> =
        <<P:?UE6_PREFIX_LEN, 0:(128 - ?UE6_PREFIX_LEN)>>,
    inet:ntoa({A, B, C, D, E, F, G, H}) ++ "/" ++ integer_to_list(?UE6_PREFIX_LEN).

report(Op, Mark, Results) ->
    case [R || R <- Results, R =/= ok] of
        [] -> ok;
        Errors ->
            epdg_metrics:inc(nft_errors_total),
            logger:error("Source check: ~p of the elements of mark 0x~.16B failed: ~p",
                         [Op, Mark, Errors]),
            error
    end.

nft_script("") ->
    ok;
nft_script(Script) ->
    File = filename:join(tmp_dir(), "epdg-nft-" ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = file:write_file(File, Script),
    Out = os:cmd("nft -f " ++ File ++ " 2>&1"),
    _ = file:delete(File),
    case Out of
        "" -> ok;
        _ -> {error, string:trim(Out)}
    end.

tmp_dir() ->
    case os:getenv("TMPDIR") of false -> "/tmp"; D -> D end.

drops(Table) ->
    Out = os:cmd("nft list chain inet " ++ Table ++ " pre 2>&1"),
    case re:run(Out, "counter packets ([0-9]+) bytes [0-9]+ drop",
                [{capture, all_but_first, list}]) of
        {match, [N]} -> {ok, list_to_integer(N)};
        _ -> error
    end.
