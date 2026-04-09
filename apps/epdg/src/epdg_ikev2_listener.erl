%%%-------------------------------------------------------------------
%%% @doc IKEv2 UDP listener (RFC 7296).
%%% Binds UDP 500 (IKE) and 4500 (NAT-T), dispatches to UE FSMs.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_listener).

-behaviour(gen_server).

-export([start_link/0, send/3, get_local_ip/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
    socket_500  :: gen_udp:socket() | undefined,
    socket_4500 :: gen_udp:socket() | undefined,
    local_ip    :: inet:ip_address()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec send(inet:ip_address(), inet:port_number(), binary()) -> ok | {error, term()}.
send(IP, Port, Data) ->
    gen_server:call(?SERVER, {send, IP, Port, Data}).

-spec get_local_ip() -> inet:ip_address().
get_local_ip() ->
    gen_server:call(?SERVER, get_local_ip).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    BindAddr = parse_ip(epdg_config:get(ike_bind_addr, "0.0.0.0")),
    Port     = epdg_config:get(ike_port, 500),
    NATTPort = epdg_config:get(ike_natt_port, 4500),

    InetFamily = ip_family(BindAddr),
    Opts = [binary, {ip, BindAddr}, {active, true}, {reuseaddr, true}, InetFamily]
           ++ ipv6_opts(InetFamily),

    case gen_udp:open(Port, Opts) of
        {ok, S500} ->
            case gen_udp:open(NATTPort, Opts) of
                {ok, S4500} ->
                    logger:info("IKEv2 listening on ~p:~p / ~p:~p (~p)",
                                [BindAddr, Port, BindAddr, NATTPort, InetFamily]),
                    {ok, #state{socket_500 = S500, socket_4500 = S4500,
                                local_ip = BindAddr}};
                {error, R} ->
                    gen_udp:close(S500),
                    {stop, {natt_bind_failed, R}}
            end;
        {error, R} ->
            {stop, {ike_bind_failed, R}}
    end.

handle_call({send, IP, Port, Data}, _From,
            #state{socket_500 = S500, socket_4500 = S4500} = State) ->
    Sock = case Port of
        500 -> S500;
        _   -> S4500
    end,
    SendData = case Port of
        4500 -> <<0,0,0,0, Data/binary>>;
        _    -> Data
    end,
    {reply, gen_udp:send(Sock, IP, Port, SendData), State};

handle_call(get_local_ip, _From, #state{local_ip = IP} = State) ->
    {reply, IP, State};

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Sock, FromIP, FromPort, Data},
            #state{socket_500 = S500, socket_4500 = S4500} = State) ->
    RecvPort = case Sock of
        S500  -> 500;
        S4500 -> 4500;
        _     -> 0
    end,
    %% Strip NAT-T non-ESP marker (4 zero bytes on port 4500)
    IKEData = case {RecvPort, Data} of
        {4500, <<0,0,0,0, Rest/binary>>} -> Rest;
        _ -> Data
    end,
    handle_ikev2_packet(IKEData, FromIP, FromPort, RecvPort),
    epdg_metrics:inc(ikev2_packets_received_total),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{socket_500 = S500, socket_4500 = S4500}) ->
    close_if_open(S500),
    close_if_open(S4500),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Internal
%%====================================================================

handle_ikev2_packet(Data, FromIP, FromPort, _RecvPort) ->
    case epdg_ikev2_codec:decode_header(Data) of
        {ok, #{initiator_spi := ISPI, responder_spi := RSPI,
               exchange_type := ExType} = Header} ->
            logger:debug("IKEv2 ~p from ~p:~p ISPI=~.16B",
                         [ExType, FromIP, FromPort, ISPI]),
            dispatch(ISPI, RSPI, Header, Data, FromIP, FromPort);
        {error, Reason} ->
            logger:warning("IKEv2 decode error: ~p from ~p:~p",
                           [Reason, FromIP, FromPort])
    end.

dispatch(_ISPI, 0, Header, Data, FromIP, FromPort) ->
    %% RSPI=0 → new IKE SA
    case epdg_ue_sup:start_ue_fsm(#{peer_ip => FromIP,
                                     peer_port => FromPort}) of
        {ok, Pid} ->
            epdg_ue_fsm:handle_ikev2(Pid, Header, Data);
        {error, Reason} ->
            logger:error("Failed to start UE FSM: ~p", [Reason])
    end;
dispatch(_ISPI, RSPI, Header, Data, _FromIP, _FromPort) ->
    case epdg_ue_registry:lookup_by_spi(RSPI) of
        {ok, Pid} ->
            epdg_ue_fsm:handle_ikev2(Pid, Header, Data);
        error ->
            logger:warning("IKEv2 for unknown RSPI ~.16B", [RSPI])
    end.

close_if_open(undefined) -> ok;
close_if_open(Sock) -> gen_udp:close(Sock).

parse_ip(Str) when is_list(Str) ->
    {ok, IP} = inet:parse_address(Str),
    IP;
parse_ip(T) when is_tuple(T) ->
    T.

ip_family({_, _, _, _}) -> inet;
ip_family({_, _, _, _, _, _, _, _}) -> inet6;
ip_family(_) -> inet.

ipv6_opts(inet6) -> [{ipv6_v6only, true}];
ipv6_opts(_)     -> [].
