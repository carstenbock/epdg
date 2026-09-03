%%%-------------------------------------------------------------------
%%% @doc Redis-backed UE session store (opt-in).
%%%
%%% Persists a per-session snapshot so established VoWiFi sessions
%%% survive a pod crash (BEAM crash, OOM-kill, node failure): at the
%%% next startup epdg_session_restore re-spawns a UE FSM per stored
%%% entry and adopts (same node) or re-installs (rescheduled) the
%%% kernel XFRM state. Planned drains are NOT covered on purpose — the
%%% drain path redirects UEs to a healthy pod and terminate/3 deletes
%%% the entry.
%%%
%%% Storage layout: one Redis hash per session,
%%%   key    <EPDG_REDIS_KEY_PREFIX>:session:<responder-spi-hex>
%%%   fields "session"    -> versioned term_to_binary snapshot map
%%%          "message_id" -> next responder message-id, updated after
%%%                          every responder-initiated IKE send so a
%%%                          restored session's DPD stays inside the
%%%                          peer's RFC 7296 §2.3 window
%%% Keys carry a 48 h TTL (refreshed on every full write) so entries of
%%% a pod identity that never returns cannot accumulate forever.
%%%
%%% The snapshot contains the session's IKE and ESP key material — the
%%% same secrets the kernel already holds in XFRM. The store is
%%% expected to be the in-chart, cluster-internal Redis; do not point
%%% it at a shared/exposed instance.
%%%
%%% All writes are fire-and-forget casts so signalling latency never
%%% depends on Redis; a lost write degrades to at worst a stale
%%% snapshot, which the restore path resolves via DPD.
%%%
%%% Disabled (EPDG_SESSION_STORE_ENABLED=false, the default): start/0
%%% returns `ignore', every API call is a no-op.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_session_store).

-behaviour(gen_server).

-export([start_link/0, enabled/0,
         put_session/2, update_message_id/2, delete_session/1,
         list_sessions/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
%% Pure snapshot codec, exported for the EUnit suite
%% (epdg_session_store_tests) and epdg_session_restore.
-export([encode_snapshot/1, decode_snapshot/1, session_key/1]).

-define(SERVER, ?MODULE).
-define(SNAPSHOT_VERSION, 1).
-define(KEY_TTL_SEC, 172800).            %% 48 h
-define(SCAN_COUNT, <<"100">>).

-record(state, {conn :: pid() | undefined}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    case enabled() of
        true  -> gen_server:start_link({local, ?SERVER}, ?MODULE, [], []);
        false -> ignore
    end.

-spec enabled() -> boolean().
enabled() ->
    epdg_config:get(session_store_enabled, false) =:= true.

%% Full snapshot write (entering established, bearer changes, MOBIKE
%% move). RSPI keys the entry; the snapshot map comes from
%% epdg_ue_fsm:session_snapshot/1.
-spec put_session(non_neg_integer(), map()) -> ok.
put_session(RSPI, Snapshot) ->
    cast_if_enabled({put_session, RSPI, Snapshot}).

%% Lightweight message-id update after a responder-initiated IKE send
%% (DPD probe, MOBIKE COOKIE2). Persisted AFTER the send on purpose: a
%% crash between send and persist restores a one-BEHIND counter, and
%% re-using an id the UE already answered degrades to an RFC 7296 §2.1
%% retransmission (the UE re-sends its cached response). Persisting
%% ahead of the send would instead restore a one-AHEAD counter, whose
%% next request the UE drops as out-of-window — killing the session.
-spec update_message_id(non_neg_integer(), non_neg_integer()) -> ok.
update_message_id(RSPI, MsgId) ->
    cast_if_enabled({update_message_id, RSPI, MsgId}).

%% Orderly teardown (any terminate/3): forget the session. A crashed
%% pod never runs this — that is exactly the point.
-spec delete_session(non_neg_integer()) -> ok.
delete_session(RSPI) ->
    cast_if_enabled({delete_session, RSPI}).

%% All stored sessions of THIS pod (scoped by key prefix), for the
%% startup restore. Returns snapshots with the persisted message_id
%% already folded in.
-spec list_sessions() -> {ok, [map()]} | {error, term()}.
list_sessions() ->
    case enabled() of
        false -> {ok, []};
        true  -> gen_server:call(?SERVER, list_sessions, 15000)
    end.

cast_if_enabled(Msg) ->
    case enabled() of
        true  -> gen_server:cast(?SERVER, Msg);
        false -> ok
    end.

%%====================================================================
%% Snapshot codec (pure)
%%====================================================================

-spec encode_snapshot(map()) -> binary().
encode_snapshot(Snapshot) when is_map(Snapshot) ->
    term_to_binary(Snapshot#{v => ?SNAPSHOT_VERSION}).

-spec decode_snapshot(binary()) -> {ok, map()} | {error, term()}.
decode_snapshot(Bin) when is_binary(Bin) ->
    try binary_to_term(Bin, [safe]) of
        #{v := ?SNAPSHOT_VERSION} = Map -> {ok, Map};
        #{v := Other}                   -> {error, {unknown_version, Other}};
        _                               -> {error, not_a_snapshot}
    catch
        _:_ -> {error, undecodable}
    end;
decode_snapshot(_) ->
    {error, undecodable}.

-spec session_key(non_neg_integer()) -> binary().
session_key(RSPI) ->
    iolist_to_binary([key_prefix(), ":session:",
                      io_lib:format("~16.16.0b", [RSPI])]).

key_prefix() ->
    case epdg_config:get(redis_key_prefix, "epdg") of
        B when is_binary(B) -> B;
        L when is_list(L)   -> list_to_binary(L)
    end.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    process_flag(trap_exit, true),
    self() ! connect,
    {ok, #state{conn = undefined}}.

handle_call(list_sessions, _From, #state{conn = undefined} = State) ->
    {reply, {error, redis_unavailable}, State};
handle_call(list_sessions, _From, #state{conn = C} = State) ->
    {reply, do_list_sessions(C), State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, #state{conn = undefined} = State) ->
    %% Not connected: drop the write (fire-and-forget contract). The
    %% worst case is a stale/missing snapshot, resolved via DPD after a
    %% restore.
    epdg_metrics:inc(session_store_errors_total),
    {noreply, State};
handle_cast({put_session, RSPI, Snapshot}, #state{conn = C} = State) ->
    Key = session_key(RSPI),
    MsgId = maps:get(message_id, Snapshot, 0),
    Cmds = [[<<"HSET">>, Key,
             <<"session">>, encode_snapshot(Snapshot),
             <<"message_id">>, integer_to_binary(MsgId)],
            [<<"EXPIRE">>, Key, integer_to_binary(?KEY_TTL_SEC)]],
    pipeline(C, Cmds),
    {noreply, State};
handle_cast({update_message_id, RSPI, MsgId}, #state{conn = C} = State) ->
    q(C, [<<"HSET">>, session_key(RSPI),
          <<"message_id">>, integer_to_binary(MsgId)]),
    {noreply, State};
handle_cast({delete_session, RSPI}, #state{conn = C} = State) ->
    q(C, [<<"DEL">>, session_key(RSPI)]),
    {noreply, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(connect, State) ->
    Host = epdg_config:get(redis_host, "127.0.0.1"),
    Port = epdg_config:get(redis_port, 6379),
    Db   = epdg_config:get(redis_db, 0),
    case eredis:start_link([{host, Host}, {port, Port}, {database, Db},
                            {connect_timeout, 5000},
                            {reconnect_sleep, 500}]) of
        {ok, Conn} ->
            logger:notice("Session store: connected to redis ~s:~B db=~B "
                          "prefix=~s", [Host, Port, Db, key_prefix()]),
            {noreply, State#state{conn = Conn}};
        {error, Reason} ->
            logger:warning("Session store: redis connect failed ~s:~B: ~p "
                           "— retrying", [Host, Port, Reason]),
            erlang:send_after(1000, self(), connect),
            {noreply, State}
    end;
handle_info({'EXIT', Pid, Reason}, #state{conn = Pid} = State) ->
    logger:warning("Session store: redis connection died: ~p — reconnecting",
                   [Reason]),
    erlang:send_after(500, self(), connect),
    {noreply, State#state{conn = undefined}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{conn = undefined}) -> ok;
terminate(_Reason, #state{conn = C}) ->
    catch eredis:stop(C),
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% Internal
%%====================================================================

q(C, Cmd) ->
    Reply = try eredis:q(C, Cmd, 5000)
            catch Class:Reason ->
                {error, {exception, Class, Reason}}
            end,
    bump(Reply),
    Reply.

pipeline(C, Cmds) ->
    Replies = try eredis:qp(C, Cmds, 5000)
              catch Class:Reason ->
                  {error, {exception, Class, Reason}}
              end,
    bump(Replies),
    Replies.

bump({error, Reason}) ->
    logger:warning("Session store: redis command failed: ~p", [Reason]),
    epdg_metrics:inc(session_store_writes_total),
    epdg_metrics:inc(session_store_errors_total);
bump(Replies) when is_list(Replies) ->
    epdg_metrics:inc(session_store_writes_total),
    case [E || {error, _} = E <- Replies] of
        []      -> ok;
        [E | _] ->
            logger:warning("Session store: redis pipeline error: ~p", [E]),
            epdg_metrics:inc(session_store_errors_total)
    end;
bump(_Ok) ->
    epdg_metrics:inc(session_store_writes_total).

%% SCAN this pod's session keys, then HGETALL each. Undecodable or
%% version-mismatched entries are deleted on the spot (they can only
%% get staler).
do_list_sessions(C) ->
    Pattern = iolist_to_binary([key_prefix(), ":session:*"]),
    case scan_keys(C, <<"0">>, Pattern, []) of
        {ok, Keys} ->
            Sessions = lists:filtermap(
                         fun(Key) -> load_session(C, Key) end, Keys),
            {ok, Sessions};
        {error, _} = E ->
            E
    end.

scan_keys(C, Cursor, Pattern, Acc) ->
    case eredis:q(C, [<<"SCAN">>, Cursor, <<"MATCH">>, Pattern,
                      <<"COUNT">>, ?SCAN_COUNT], 5000) of
        {ok, [Next, Keys]} ->
            Acc1 = Keys ++ Acc,
            case Next of
                <<"0">> -> {ok, Acc1};
                _       -> scan_keys(C, Next, Pattern, Acc1)
            end;
        {error, _} = E ->
            E
    end.

load_session(C, Key) ->
    case eredis:q(C, [<<"HGETALL">>, Key], 5000) of
        {ok, KVs} ->
            Fields = pairs_to_map(KVs),
            case decode_snapshot(maps:get(<<"session">>, Fields, <<>>)) of
                {ok, Snapshot} ->
                    %% The separately-updated message_id wins over the
                    %% one frozen into the snapshot blob.
                    MsgId = case maps:get(<<"message_id">>, Fields,
                                          undefined) of
                        undefined -> maps:get(message_id, Snapshot, 0);
                        B         -> binary_to_integer(B)
                    end,
                    {true, Snapshot#{message_id => MsgId}};
                {error, Reason} ->
                    logger:warning("Session store: dropping undecodable "
                                   "entry ~s: ~p", [Key, Reason]),
                    catch eredis:q(C, [<<"DEL">>, Key], 5000),
                    false
            end;
        {error, Reason} ->
            logger:warning("Session store: HGETALL ~s failed: ~p",
                           [Key, Reason]),
            false
    end.

pairs_to_map(KVs) ->
    pairs_to_map(KVs, #{}).

pairs_to_map([K, V | Rest], Acc) ->
    pairs_to_map(Rest, Acc#{K => V});
pairs_to_map(_, Acc) ->
    Acc.
