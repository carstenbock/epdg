%%%-------------------------------------------------------------------
%%% @doc GTP-C v2 client for S2b interface toward PGW-C/SMF.
%%% Handles Create/Delete/Modify Session for VoWiFi PDN connectivity.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_gtpc_client).

-behaviour(gen_server).

-export([start_link/0,
         create_session_request/1, delete_session_request/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(GTP_C_PORT, 2123).

-record(state, {
    socket    :: gen_udp:socket() | undefined,
    local_ip  :: inet:ip_address(),
    pgw_ip    :: inet:ip_address(),
    pgw_port  :: inet:port_number(),
    seq_num   :: non_neg_integer(),
    pending   :: #{non_neg_integer() => {term(), reference()}}
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec create_session_request(map()) -> {ok, map()} | {error, term()}.
create_session_request(Params) ->
    gen_server:call(?SERVER, {create_session, Params}, 30000).

-spec delete_session_request(map()) -> {ok, map()} | {error, term()}.
delete_session_request(Params) ->
    gen_server:call(?SERVER, {delete_session, Params}, 30000).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    BindAddr = parse_ip(epdg_config:get(gtpc_bind_addr, "0.0.0.0")),
    Port     = epdg_config:get(gtpc_port, ?GTP_C_PORT),
    PgwAddr  = parse_ip(epdg_config:get(pgw_addr, "127.0.0.1")),
    PgwPort  = epdg_config:get(pgw_port, ?GTP_C_PORT),

    InetFamily = case BindAddr of
        {_,_,_,_,_,_,_,_} -> inet6;
        _ -> inet
    end,
    case gen_udp:open(Port, [binary, {ip, BindAddr}, {active, true}, {reuseaddr, true}, InetFamily]) of
        {ok, Socket} ->
            {ok, {LIP, _}} = inet:sockname(Socket),
            logger:info("GTP-C S2b on ~p:~p → PGW ~p:~p",
                        [LIP, Port, PgwAddr, PgwPort]),
            {ok, #state{socket = Socket, local_ip = LIP,
                        pgw_ip = PgwAddr, pgw_port = PgwPort,
                        seq_num = 0, pending = #{}}};
        {error, Reason} ->
            {stop, {gtpc_bind_failed, Reason}}
    end.

handle_call({create_session, Params}, From, State) ->
    {noreply, send_create_session(Params, From, State)};
handle_call({delete_session, Params}, From, State) ->
    {noreply, send_delete_session(Params, From, State)};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, _Sock, _FromIP, _FromPort, Data}, State) ->
    {noreply, handle_response(Data, State)};

handle_info({timeout, Ref, {seq_timeout, SeqNum}},
            #state{pending = Pending} = State) ->
    case maps:find(SeqNum, Pending) of
        {ok, {From, Ref}} ->
            gen_server:reply(From, {error, timeout}),
            epdg_metrics:inc(gtpc_timeouts_total),
            {noreply, State#state{pending = maps:remove(SeqNum, Pending)}};
        _ ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{socket = S}) ->
    case S of undefined -> ok; _ -> gen_udp:close(S) end,
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Create Session Request (GTPv2 type 32)
%%====================================================================

send_create_session(Params, From,
                    #state{socket = Socket, seq_num = Seq,
                           local_ip = LIP, pgw_ip = PgwIP,
                           pgw_port = PgwPort, pending = Pending} = State) ->
    IMSI    = maps:get(imsi, Params, <<>>),
    MSISDN  = maps:get(msisdn, Params, <<>>),
    APN     = maps:get(apn, Params, <<"ims">>),

    Msg = epdg_gtpc_codec:encode_create_session_request(#{
        seq_num    => Seq,
        imsi       => IMSI,
        msisdn     => MSISDN,
        apn        => APN,
        rat_type   => 3,
        local_ip   => LIP
    }),

    gen_udp:send(Socket, PgwIP, PgwPort, Msg),
    epdg_metrics:inc(gtpc_requests_total),

    Ref = erlang:start_timer(30000, self(), {seq_timeout, Seq}),
    State#state{
        seq_num = (Seq + 1) band 16#FFFFFF,
        pending = Pending#{Seq => {From, Ref}}
    }.

%%====================================================================
%% Delete Session Request (GTPv2 type 36)
%%====================================================================

send_delete_session(Params, From,
                    #state{socket = Socket, seq_num = Seq,
                           pgw_ip = PgwIP, pgw_port = PgwPort,
                           pending = Pending} = State) ->
    PgwTEID = maps:get(pgw_teid, Params, 0),
    EBI     = maps:get(ebi, Params, 5),

    Msg = epdg_gtpc_codec:encode_delete_session_request(#{
        seq_num  => Seq,
        teid     => PgwTEID,
        ebi      => EBI
    }),

    gen_udp:send(Socket, PgwIP, PgwPort, Msg),

    Ref = erlang:start_timer(30000, self(), {seq_timeout, Seq}),
    State#state{
        seq_num = (Seq + 1) band 16#FFFFFF,
        pending = Pending#{Seq => {From, Ref}}
    }.

%%====================================================================
%% Response handling
%%====================================================================

handle_response(Data, #state{pending = Pending} = State) ->
    case epdg_gtpc_codec:decode_header(Data) of
        {ok, #{seq_num := Seq} = Decoded} ->
            case maps:find(Seq, Pending) of
                {ok, {From, Ref}} ->
                    erlang:cancel_timer(Ref),
                    gen_server:reply(From, {ok, Decoded}),
                    epdg_metrics:inc(gtpc_responses_total),
                    State#state{pending = maps:remove(Seq, Pending)};
                error ->
                    State
            end;
        {error, _} ->
            State
    end.

%%====================================================================
%% Internal
%%====================================================================

parse_ip(Str) when is_list(Str) ->
    case inet:parse_address(Str) of
        {ok, IP} -> IP;
        {error, _} ->
            case inet:getaddr(Str, inet) of
                {ok, IP} -> IP;
                {error, _} ->
                    case inet:getaddr(Str, inet6) of
                        {ok, IP6} -> IP6;
                        {error, Reason} -> error({resolve_failed, Str, Reason})
                    end
            end
    end;
parse_ip(T) when is_tuple(T) -> T.
