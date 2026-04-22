%%%-------------------------------------------------------------------
%%% @doc UE session registry backed by ETS.
%%% Maps responder SPI → UE FSM pid, and IMSI → SPI for reverse lookup.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_registry).

-behaviour(gen_server).

-export([start_link/0,
         register/3, unregister/1,
         register_initiator/3, lookup_by_initiator/2, unregister_initiator/2,
         lookup_by_spi/1, lookup_by_imsi/1,
         count/0, all/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(TAB_SPI,  epdg_spi_tab).
-define(TAB_IMSI, epdg_imsi_tab).
-define(TAB_INIT, epdg_initiator_tab).  %% {PeerIP, ISPI} -> Pid (dedup IKE_SA_INIT retransmits)

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec register(non_neg_integer(), pid(), binary() | undefined) -> ok.
register(SPI, Pid, IMSI) ->
    gen_server:call(?SERVER, {register, SPI, Pid, IMSI}).

-spec unregister(non_neg_integer()) -> ok.
unregister(SPI) ->
    gen_server:call(?SERVER, {unregister, SPI}).

-spec register_initiator(inet:ip_address(), non_neg_integer(), pid()) -> ok.
register_initiator(PeerIP, ISPI, Pid) ->
    ets:insert(?TAB_INIT, {{PeerIP, ISPI}, Pid}),
    ok.

-spec lookup_by_initiator(inet:ip_address(), non_neg_integer()) ->
    {ok, pid()} | error.
lookup_by_initiator(PeerIP, ISPI) ->
    case ets:lookup(?TAB_INIT, {PeerIP, ISPI}) of
        [{_, Pid}] ->
            case is_process_alive(Pid) of
                true  -> {ok, Pid};
                false ->
                    ets:delete(?TAB_INIT, {PeerIP, ISPI}),
                    error
            end;
        [] -> error
    end.

-spec unregister_initiator(inet:ip_address(), non_neg_integer()) -> ok.
unregister_initiator(PeerIP, ISPI) ->
    ets:delete(?TAB_INIT, {PeerIP, ISPI}),
    ok.

-spec lookup_by_spi(non_neg_integer()) -> {ok, pid()} | error.
lookup_by_spi(SPI) ->
    case ets:lookup(?TAB_SPI, SPI) of
        [{_, Pid, _}] -> {ok, Pid};
        [] -> error
    end.

-spec lookup_by_imsi(binary()) -> {ok, pid()} | error.
lookup_by_imsi(IMSI) ->
    case ets:lookup(?TAB_IMSI, IMSI) of
        [{_, SPI}] ->
            lookup_by_spi(SPI);
        [] ->
            error
    end.

-spec count() -> non_neg_integer().
count() ->
    ets:info(?TAB_SPI, size).

-spec all() -> [{non_neg_integer(), pid(), binary() | undefined}].
all() ->
    ets:tab2list(?TAB_SPI).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    ets:new(?TAB_SPI,  [named_table, public, set, {read_concurrency, true}]),
    ets:new(?TAB_IMSI, [named_table, public, set, {read_concurrency, true}]),
    ets:new(?TAB_INIT, [named_table, public, set, {read_concurrency, true},
                        {write_concurrency, true}]),
    {ok, #{}}.

handle_call({register, SPI, Pid, IMSI}, _From, State) ->
    MRef = erlang:monitor(process, Pid),
    ets:insert(?TAB_SPI, {SPI, Pid, IMSI}),
    case IMSI of
        undefined -> ok;
        _ -> ets:insert(?TAB_IMSI, {IMSI, SPI})
    end,
    NewState = State#{SPI => MRef, Pid => SPI},
    {reply, ok, NewState};

handle_call({unregister, SPI}, _From, State) ->
    do_unregister(SPI, State),
    NewState = maps:remove(SPI, State),
    {reply, ok, NewState};

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', _MRef, process, Pid, _Reason}, State) ->
    case maps:find(Pid, State) of
        {ok, SPI} ->
            do_unregister(SPI, State),
            {noreply, maps:without([Pid, SPI], State)};
        error ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal
%%====================================================================

do_unregister(SPI, State) ->
    case ets:lookup(?TAB_SPI, SPI) of
        [{_, _Pid, IMSI}] ->
            ets:delete(?TAB_SPI, SPI),
            case IMSI of
                undefined -> ok;
                _ -> ets:delete(?TAB_IMSI, IMSI)
            end,
            case maps:find(SPI, State) of
                {ok, MRef} -> erlang:demonitor(MRef, [flush]);
                error -> ok
            end;
        [] ->
            ok
    end.
