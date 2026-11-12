%%%-------------------------------------------------------------------
%%% @doc IKEv2 UDP listener (RFC 7296).
%%% Binds UDP 500 (IKE) and 4500 (NAT-T), dispatches to UE FSMs.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_listener).

-behaviour(gen_server).

-export([start_link/0, send/3, send/4, get_local_ip/0]).
%% Exported for eunit (epdg_ikev2_listener_tests).
-export([invalid_ike_spi_response/1, invalid_spi_allowed/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

%% IKEv2 Encrypted (SK) payload type, RFC 7296 §3.14.
-define(PL_SK, 46).

%% RFC 7296 §3.10.1 INVALID_IKE_SPI.
-define(N_INVALID_IKE_SPI, 4).
%% IKE_SA_INIT exchange type (RFC 7296 §3.1).
-define(EX_IKE_SA_INIT, 34).
%% Unprotected INVALID_IKE_SPI answers per second (RFC 7296 §2.21.4). After
%% a restart every UE of the old tunnels hits this path; the answers are
%% unauthenticated hints, so a cap keeps the ePDG from becoming a
%% reflector for spoofed sources while still telling most phones quickly.
-define(INVALID_SPI_PER_SEC, 100).

-record(state, {
    socket_500  :: gen_udp:socket() | undefined,
    socket_4500 :: gen_udp:socket() | undefined,
    local_ip    :: inet:ip_address(),
    %% {second, answers sent in it} for the INVALID_IKE_SPI rate cap.
    invalid_spi_window = {0, 0} :: {integer(), non_neg_integer()}
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec send(inet:ip_address(), inet:port_number(), binary()) -> ok | {error, term()}.
send(IP, Port, Data) ->
    gen_server:call(?SERVER, {send, IP, Port, auto, Data}).

-spec send(inet:ip_address(), inet:port_number(), 500 | 4500, binary()) -> ok | {error, term()}.
send(IP, Port, FromPort, Data) ->
    gen_server:call(?SERVER, {send, IP, Port, FromPort, Data}).

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
           ++ ipv6_opts(InetFamily) ++ epdg_config:udp_socket_opts(),

    case gen_udp:open(Port, Opts) of
        {ok, S500} ->
            case gen_udp:open(NATTPort, Opts) of
                {ok, S4500} ->
                    %% Enable UDP_ENCAP=UDP_ENCAP_ESPINUDP on the NAT-T
                    %% socket (RFC 3948). Without this the kernel delivers
                    %% ESP-in-UDP frames to this gen_udp socket as plain
                    %% UDP data; with it set the kernel peeks the first
                    %% 4 bytes: zeroes → IKE (delivered to userspace),
                    %% anything else → ESP (stripped and handed to XFRM
                    %% for decryption). Linux: IPPROTO_UDP=17,
                    %% UDP_ENCAP=100, UDP_ENCAP_ESPINUDP=2.
                    case inet:setopts(S4500, [{raw, 17, 100, <<2:32/native>>}]) of
                        ok -> ok;
                        EncapErr ->
                            logger:warning("UDP_ENCAP_ESPINUDP setopt failed on 4500: ~p",
                                           [EncapErr])
                    end,
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

handle_call({send, IP, Port, FromPort, Data}, _From,
            #state{socket_500 = S500, socket_4500 = S4500} = State) ->
    {Sock, LocalPort} = case FromPort of
        500  -> {S500, 500};
        4500 -> {S4500, 4500};
        _    -> case Port of 500 -> {S500, 500}; _ -> {S4500, 4500} end
    end,
    {reply, send_on(Sock, LocalPort, IP, Port, Data), State};

handle_call(get_local_ip, _From, #state{local_ip = IP} = State) ->
    {reply, IP, State};

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(stop_accepting,
            #state{socket_500 = S500, socket_4500 = S4500} = State) ->
    %% Called from `epdg_app:prep_stop/1' during graceful shutdown.
    %% Close the UDP sockets immediately so no new IKE_SA_INIT can land
    %% and spawn a UE FSM during the supervisor walk. The gen_server
    %% itself stays alive until its supervisor shutdown so any in-flight
    %% `send/3' calls still get a reply (with `{error, einval}' once the
    %% socket is gone, which the FSM `catch'es).
    close_if_open(S500),
    close_if_open(S4500),
    logger:info("IKEv2 listener sockets closed (stop_accepting)"),
    {noreply, State#state{socket_500 = undefined, socket_4500 = undefined}};
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
    mirror_if_cleartext(in, IKEData, FromIP, FromPort, RecvPort),
    State1 = case handle_ikev2_packet(IKEData, FromIP, FromPort, RecvPort) of
        {unknown_spi, Header} ->
            unknown_spi(Header, Sock, RecvPort, FromIP, FromPort, State);
        ok ->
            State
    end,
    epdg_metrics:inc(ikev2_packets_received_total),
    {noreply, State1};

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

handle_ikev2_packet(Data, FromIP, FromPort, RecvPort) ->
    case epdg_ikev2_codec:decode_header(Data) of
        {ok, #{initiator_spi := ISPI, responder_spi := RSPI,
               exchange_type := ExType} = Header0} ->
            logger:debug("IKEv2 ~p from ~p:~p ISPI=~.16B",
                         [ExType, FromIP, FromPort, ISPI]),
            %% Carry the UDP source address in the decoded header so the UE
            %% FSM can detect a MOBIKE address change (RFC 4555) without a
            %% wider signature change to the {ikev2, ...} cast.
            %% local_port is the listener port the datagram arrived on: the
            %% IKE_SA_INIT response has to leave from that same port
            %% (RFC 7296 §2.11), see epdg_ue_fsm:sa_init_reply_port/1.
            Header = Header0#{from_ip => FromIP, from_port => FromPort,
                              local_port => RecvPort},
            dispatch(ISPI, RSPI, Header, Data, FromIP, FromPort);
        {error, Reason} ->
            Prefix = case Data of
                <<P:64/binary, _/binary>> -> P;
                _ -> Data
            end,
            logger:warning("IKEv2 decode error: ~p from ~p:~p first_bytes=~w",
                           [Reason, FromIP, FromPort, Prefix])
    end.

dispatch(ISPI, 0, Header, Data, FromIP, FromPort) ->
    %% RSPI=0 → new IKE SA OR IKE_SA_INIT retransmit.
    %% RFC 7296 §2.1: if we already have an FSM for (PeerIP, ISPI), route the
    %% retransmit there instead of spawning a zombie duplicate.
    case epdg_ue_registry:lookup_by_initiator(FromIP, ISPI) of
        {ok, Pid} ->
            epdg_ue_fsm:handle_ikev2(Pid, Header, Data, FromPort);
        error ->
            case epdg_ue_sup:start_ue_fsm(#{peer_ip => FromIP,
                                             peer_port => FromPort}) of
                {ok, Pid} ->
                    epdg_ue_fsm:handle_ikev2(Pid, Header, Data, FromPort);
                {error, Reason} ->
                    logger:error("Failed to start UE FSM: ~p", [Reason])
            end
    end,
    ok;
dispatch(_ISPI, RSPI, Header, Data, _FromIP, FromPort) ->
    case epdg_ue_registry:lookup_by_spi(RSPI) of
        {ok, Pid} ->
            epdg_ue_fsm:handle_ikev2(Pid, Header, Data, FromPort),
            ok;
        error ->
            {unknown_spi, Header}
    end.

%% A message for an IKE SA this ePDG does not know, typically from a UE
%% whose tunnel was lost in an ePDG restart. RFC 7296 §2.21.4: a response
%% MUST NOT be answered; a request MAY be answered with an unprotected
%% INVALID_IKE_SPI, so the UE learns at once that its IKE SA is gone and
%% sets up a new tunnel, instead of waiting for its own DPD to give up
%% (KI-137). The answer leaves from the port the request arrived on, to
%% the address and port it came from (§2.11).
unknown_spi(#{responder_spi := RSPI, is_response := IsResp,
              exchange_type_raw := ExType} = Header,
            Sock, RecvPort, FromIP, FromPort,
            #state{invalid_spi_window = Win} = State) ->
    NowSec = erlang:monotonic_time(second),
    {Outcome, Win1} =
        case IsResp orelse ExType =:= ?EX_IKE_SA_INIT of
            true ->
                {"not answered (response)", Win};
            false ->
                case invalid_spi_allowed(NowSec, Win) of
                    {true, W} ->
                        Resp = invalid_ike_spi_response(Header),
                        _ = send_on(Sock, RecvPort, FromIP, FromPort, Resp),
                        epdg_metrics:inc(ike_invalid_spi_sent_total),
                        {"answered INVALID_IKE_SPI", W};
                    {false, W} ->
                        {"not answered (rate cap)", W}
                end
        end,
    logger:warning("IKEv2 for unknown RSPI ~.16B from ~p:~p, ~s",
                   [RSPI, FromIP, FromPort, Outcome]),
    State#state{invalid_spi_window = Win1}.

%% Rate cap for the unprotected answers: at most ?INVALID_SPI_PER_SEC in
%% one second of monotonic time.
-spec invalid_spi_allowed(integer(), {integer(), non_neg_integer()}) ->
          {boolean(), {integer(), non_neg_integer()}}.
invalid_spi_allowed(NowSec, {NowSec, N}) when N >= ?INVALID_SPI_PER_SEC ->
    {false, {NowSec, N}};
invalid_spi_allowed(NowSec, {NowSec, N}) ->
    {true, {NowSec, N + 1}};
invalid_spi_allowed(NowSec, _Older) ->
    {true, {NowSec, 1}}.

%% RFC 7296 §2.21.4 / §1.5: not cryptographically protected, the IKE SPIs,
%% exchange type and Message ID of the request copied, the Response flag
%% set, the Initiator flag set only if the request came from the original
%% responder, and one Notify payload INVALID_IKE_SPI without SPI or data.
-spec invalid_ike_spi_response(map()) -> binary().
invalid_ike_spi_response(#{initiator_spi := ISPI, responder_spi := RSPI,
                           exchange_type_raw := ExType, message_id := MsgId,
                           is_initiator := ReqFromInitiator}) ->
    Notify = epdg_ikev2_codec:encode_notify_payload(0, ?N_INVALID_IKE_SPI,
                                                     <<>>, <<>>),
    {FirstPL, PayloadBin} = epdg_ikev2_codec:encode_payloads([{notify, Notify}]),
    Flags = case ReqFromInitiator of
        true  -> 16#20;
        false -> 16#20 bor 16#08
    end,
    epdg_ikev2_codec:encode_header(#{initiator_spi     => ISPI,
                                     responder_spi     => RSPI,
                                     next_payload      => FirstPL,
                                     exchange_type_raw => ExType,
                                     flags             => Flags,
                                     message_id        => MsgId,
                                     payload_bin       => PayloadBin}).

%% Send one IKE message; on 4500 with the non-ESP marker (RFC 3948).
send_on(undefined, _LocalPort, _IP, _Port, _Data) ->
    {error, closed};
send_on(Sock, LocalPort, IP, Port, Data) ->
    SendData = case LocalPort of
        4500 -> <<0,0,0,0, Data/binary>>;
        _    -> Data
    end,
    mirror_if_cleartext(out, Data, IP, Port, LocalPort),
    gen_udp:send(Sock, IP, Port, SendData).

%% IKE_SA_INIT is the only exchange that crosses the wire in the clear, so
%% the listener is the right place to mirror it: both directions pass
%% through here with the plaintext already in hand. Every later exchange is
%% SK-protected (RFC 7296 §3.14) and is mirrored from the UE FSM once
%% decrypted — mirroring the ciphertext here would only produce opaque
%% frames, and would duplicate every message in the trace.
%%
%% The check is on the header's Next Payload field rather than the exchange
%% type so anything unencrypted (e.g. an IKE_SA_INIT carrying a COOKIE
%% retry) is mirrored too.
mirror_if_cleartext(Dir, Data, PeerIP, PeerPort, LocalPort) ->
    case epdg_ikev2_trace:enabled() of
        false ->
            ok;
        true ->
            case Data of
                <<_ISPI:8/binary, _RSPI:8/binary, NextPL:8, _Rest/binary>>
                  when NextPL =/= ?PL_SK ->
                    epdg_ikev2_trace:mirror(#{dir        => Dir,
                                              msg        => Data,
                                              peer_ip    => PeerIP,
                                              peer_port  => PeerPort,
                                              local_port => LocalPort});
                _ ->
                    ok
            end
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
