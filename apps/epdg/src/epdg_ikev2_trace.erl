%%%-------------------------------------------------------------------
%%% @doc Plaintext IKEv2 trace mirror.
%%%
%%% Everything after IKE_SA_INIT travels inside an SK payload (RFC 7296
%%% §3.14), so a packet capture on the SWu interface is opaque: it shows
%%% that an IKE_AUTH happened but not the IDi, the EAP round trip, or the
%%% CFG_REPLY that carries the P-CSCF addresses. This module mirrors the
%%% *decrypted* control messages out of the BEAM in a form any pcapng
%%% reader can dissect.
%%%
%%% Wire format is **pcapng** (not classic pcap) streamed over TCP, one
%%% Enhanced Packet Block per IKE message:
%%%
%%%   * `LINKTYPE_RAW' (101) — the block data starts at the IP header, so
%%%     we never have to invent Ethernet addresses.
%%%   * A synthetic IPv4/IPv6 + UDP datagram carrying the plaintext IKE
%%%     message, using the UE's *real* address and port. Preserving those
%%%     is the whole reason for pcapng framing over a plain UDP mirror to
%%%     localhost, which would rewrite them to 127.0.0.1.
%%%   * On port 4500 the 4-byte zero non-ESP marker (RFC 3948) is
%%%     prepended, exactly as on the wire. Wireshark needs it to hand the
%%%     datagram to the ISAKMP dissector instead of treating it as
%%%     UDP-encapsulated ESP.
%%%   * An `opt_comment' option (pcapng option code 1) holding a JSON
%%%     object with the IMSI / APN / SWm session this FSM already knows.
%%%     tshark surfaces it as the `frame.comment' field, so a consumer
%%%     gets subscriber identity without having to re-correlate anything.
%%%
%%% The mirrored message is a faithful rendering of the payload chain but
%%% NOT of the octets that crossed the wire: ciphertext, padding, ICV and
%%% RFC 7383 fragmentation are all gone (fragments are mirrored once,
%%% after reassembly). Byte-exact analysis still needs an interface
%%% capture.
%%%
%%% Off unless `EPDG_IKE_TRACE_ENABLE' is set, and bound to loopback by
%%% default: the stream is decrypted signalling plus subscriber
%%% identifiers, so it must not be casually reachable.
%%%
%%% See the "Plaintext IKEv2 tracing" section of the README for the
%%% consumer side.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_trace).

-behaviour(gen_server).

-export([start_link/0, enabled/0, mirror/1]).

%% Exported for eunit (epdg_ikev2_trace_tests) — pure helpers with no
%% dependency on the running gen_server.
-export([shb/0, idb/0, epb/3, synth_datagram/5, checksum/1,
         encode_meta/1, ike_bytes/1, endpoints/2, meta_of/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

%% Read on every mirror/1 call from every UE FSM, so it has to be cheap.
%% `true' only while tracing is enabled AND at least one subscriber is
%% attached; with nobody listening the mirror costs one persistent_term
%% read and returns. persistent_term:put/2 triggers a global scan, but it
%% only runs on subscriber attach/detach, not per message.
-define(ACTIVE_KEY, {?MODULE, active}).

%% pcapng block types (pcapng spec §4)
-define(BT_SHB, 16#0A0D0D0A).
-define(BT_IDB, 16#00000001).
-define(BT_EPB, 16#00000006).

%% Byte-Order Magic. We emit big-endian throughout (Erlang's binary
%% default), which readers detect from these four bytes.
-define(BOM, 16#1A2B3C4D).

-define(LINKTYPE_RAW, 101).
-define(SNAPLEN, 262144).

%% pcapng options
-define(OPT_ENDOFOPT,     0).
-define(OPT_COMMENT,      1).
-define(OPT_IF_NAME,      2).
-define(OPT_SHB_USERAPPL, 4).
-define(OPT_IF_TSRESOL,   9).

%% IKEv2 exchange types (RFC 7296 §3.1)
-define(EX_IKE_SA_INIT,     34).
-define(EX_IKE_AUTH,        35).
-define(EX_CREATE_CHILD_SA, 36).
-define(EX_INFORMATIONAL,   37).

-define(FLAG_RESPONSE,  16#20).
-define(FLAG_INITIATOR, 16#08).

-define(IPPROTO_UDP, 17).

%% Drop mirrored messages rather than let the mailbox grow without bound
%% when a subscriber stops reading. Tracing is best-effort by design; a
%% wedged tshark must never become backpressure on the signalling plane.
-define(MAX_QUEUE, 512).
-define(SEND_TIMEOUT, 1000).

-record(state, {
    lsock    :: gen_tcp:socket() | undefined,
    acceptor :: pid() | undefined,
    subs = [] :: [gen_tcp:socket()],
    %% Candidate addresses for the ePDG side of the synthetic datagrams,
    %% one per address family. A list because a single address cannot be
    %% right for both: rendering a v6 UE against a v4 local address would
    %% produce a mixed-family datagram.
    local_ips = [] :: [inet:ip_address()]
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Cheap gate for call sites that would otherwise build a payload chain
%% just to throw it away.
-spec enabled() -> boolean().
enabled() ->
    persistent_term:get(?ACTIVE_KEY, false).

%% Mirror one IKE message. Event map:
%%
%%   dir         := in | out          `in' = UE -> ePDG
%%   peer_ip     := inet:ip_address() the UE's outer address
%%   peer_port   := inet:port_number()
%%   local_port  => 500 | 4500        defaults from peer_port
%%   meta        => map()             merged over the derived metadata
%%   and EITHER
%%   msg         => binary()          a complete IKE message, or
%%   header      => map()             a decoded header (epdg_ikev2_codec)
%%   first_inner => non_neg_integer() type of the first inner payload
%%   inner       => binary()          decrypted inner payload chain
%%
%% Asynchronous and never fails: the timestamp is taken here, at the
%% moment the message was actually sent or received, rather than whenever
%% the trace server gets round to encoding it.
-spec mirror(map()) -> ok.
mirror(Ev) when is_map(Ev) ->
    case persistent_term:get(?ACTIVE_KEY, false) of
        false ->
            ok;
        true ->
            gen_server:cast(?SERVER,
                            {mirror, Ev, erlang:system_time(microsecond)})
    end.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    process_flag(trap_exit, true),
    LocalIPs = epdg_config:get(ike_trace_local_addrs, []),
    case epdg_config:get(ike_trace_enable, false) of
        false ->
            logger:info("IKEv2 trace mirror disabled "
                        "(set EPDG_IKE_TRACE_ENABLE=1 to enable)"),
            {ok, #state{local_ips = LocalIPs}};
        true ->
            BindAddr = parse_ip(epdg_config:get(ike_trace_bind_addr,
                                                "127.0.0.1")),
            Port = epdg_config:get(ike_trace_port, 19500),
            Opts = [binary, {ip, BindAddr}, {active, false},
                    {reuseaddr, true}, {packet, raw}, ip_family(BindAddr)],
            case gen_tcp:listen(Port, Opts) of
                {ok, LSock} ->
                    Acceptor = start_acceptor(LSock),
                    logger:notice("IKEv2 trace mirror listening on ~s:~B "
                                  "(pcapng; carries decrypted signalling and "
                                  "IMSIs)",
                                  [inet:ntoa(BindAddr), Port]),
                    {ok, #state{lsock = LSock, acceptor = Acceptor,
                                local_ips = LocalIPs}};
                {error, Reason} ->
                    %% A diagnostic listener must never keep the ePDG from
                    %% serving subscribers, so a taken port degrades to
                    %% "tracing off" instead of failing the boot.
                    logger:error("IKEv2 trace mirror bind failed on port ~p: "
                                 "~p — tracing stays off", [Port, Reason]),
                    {ok, #state{local_ips = LocalIPs}}
            end
    end.

handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast({subscriber, Sock}, #state{subs = Subs} = State) ->
    %% send_timeout + send_timeout_close so a subscriber that stops
    %% reading gets dropped instead of blocking this server.
    catch inet:setopts(Sock, [{active, once},
                              {send_timeout, ?SEND_TIMEOUT},
                              {send_timeout_close, true}]),
    %% Each subscriber may attach at any point in the stream, so the
    %% section header and interface description are per-connection and
    %% cannot be emitted once globally.
    case gen_tcp:send(Sock, [shb(), idb()]) of
        ok ->
            logger:notice("IKEv2 trace subscriber attached (~B total)",
                          [length(Subs) + 1]),
            {noreply, update_subs([Sock | Subs], State)};
        {error, Reason} ->
            logger:warning("IKEv2 trace subscriber handshake failed: ~p",
                           [Reason]),
            catch gen_tcp:close(Sock),
            {noreply, State}
    end;

handle_cast({mirror, _Ev, _Ts}, #state{subs = []} = State) ->
    {noreply, State};
handle_cast({mirror, Ev, Ts}, State) ->
    case erlang:process_info(self(), message_queue_len) of
        {message_queue_len, N} when N > ?MAX_QUEUE ->
            epdg_metrics:inc(ike_trace_dropped_total),
            {noreply, State};
        _ ->
            {noreply, write(Ev, Ts, State)}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({tcp, Sock, _Data}, State) ->
    %% Subscribers are read-only; discard anything they send but keep the
    %% socket active so we still learn about tcp_closed.
    catch inet:setopts(Sock, [{active, once}]),
    {noreply, State};
handle_info({tcp_closed, Sock}, State) ->
    {noreply, drop_sub(Sock, State)};
handle_info({tcp_error, Sock, _Reason}, State) ->
    {noreply, drop_sub(Sock, State)};
handle_info({'EXIT', Pid, Reason},
            #state{acceptor = Pid, lsock = LSock} = State)
  when LSock =/= undefined ->
    logger:warning("IKEv2 trace acceptor exited (~p), restarting", [Reason]),
    {noreply, State#state{acceptor = start_acceptor(LSock)}};
handle_info({'EXIT', _Pid, _Reason}, State) ->
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{lsock = LSock, subs = Subs}) ->
    _ = persistent_term:erase(?ACTIVE_KEY),
    lists:foreach(fun close_quietly/1, [LSock | Subs]),
    ok.

close_quietly(undefined) -> ok;
close_quietly(Sock)      -> catch gen_tcp:close(Sock), ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Subscriber bookkeeping
%%====================================================================

start_acceptor(LSock) ->
    Server = self(),
    spawn_link(fun() -> acceptor_loop(Server, LSock) end).


acceptor_loop(Server, LSock) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} ->
            case gen_tcp:controlling_process(Sock, Server) of
                ok ->
                    gen_server:cast(Server, {subscriber, Sock});
                {error, _} ->
                    catch gen_tcp:close(Sock)
            end,
            acceptor_loop(Server, LSock);
        {error, closed} ->
            ok;
        {error, Reason} ->
            %% Back off rather than spin: the realistic cause is a
            %% transient emfile, and a tight retry loop here would burn a
            %% core for as long as it lasts.
            logger:warning("IKEv2 trace accept failed: ~p", [Reason]),
            timer:sleep(1000),
            acceptor_loop(Server, LSock)
    end.


drop_sub(Sock, #state{subs = Subs} = State) ->
    catch gen_tcp:close(Sock),
    update_subs(lists:delete(Sock, Subs), State).

%% persistent_term:put/2 triggers a global scan of every process heap, so
%% it must only run when the flag actually flips — never per mirrored
%% message. Same for the gauge: a no-op update is skipped.
update_subs(Subs, #state{subs = Subs} = State) ->
    State;
update_subs(Subs, #state{subs = Old} = State) ->
    WasActive = Old =/= [],
    IsActive  = Subs =/= [],
    case IsActive =:= WasActive of
        true  -> ok;
        false -> persistent_term:put(?ACTIVE_KEY, IsActive)
    end,
    epdg_metrics:gauge_set(ike_trace_subscribers, length(Subs)),
    State#state{subs = Subs}.

%%====================================================================
%% Encoding one mirrored message
%%====================================================================

write(Ev, Ts, #state{subs = Subs, local_ips = LocalIPs} = State) ->
    try
        IkeMsg = ike_bytes(Ev),
        {SrcIP, SrcPort, DstIP, DstPort} = endpoints(Ev, LocalIPs),
        Pkt = synth_datagram(SrcIP, SrcPort, DstIP, DstPort, IkeMsg),
        Block = epb(Pkt, Ts, encode_meta(meta_of(Ev, IkeMsg))),
        epdg_metrics:inc(ike_trace_messages_total),
        update_subs(broadcast(Block, Subs, []), State)
    catch Class:Reason:Stack ->
        %% Tracing is a diagnostic; a malformed event must not take the
        %% trace server (and with it the mirror for every other UE) down.
        logger:warning("IKEv2 trace encode failed: ~p:~p ~p",
                       [Class, Reason, Stack]),
        epdg_metrics:inc(ike_trace_dropped_total),
        State
    end.

broadcast(_Block, [], Kept) ->
    lists:reverse(Kept);
broadcast(Block, [Sock | Rest], Kept) ->
    case gen_tcp:send(Sock, Block) of
        ok ->
            broadcast(Block, Rest, [Sock | Kept]);
        {error, Reason} ->
            logger:info("IKEv2 trace subscriber dropped: ~p", [Reason]),
            catch gen_tcp:close(Sock),
            broadcast(Block, Rest, Kept)
    end.

%% Rebuild a complete IKE message from the decrypted inner chain, or take
%% one that is already assembled (IKE_SA_INIT off the listener).
-spec ike_bytes(map()) -> binary().
ike_bytes(#{msg := Msg}) when is_binary(Msg) ->
    Msg;
ike_bytes(#{header := Hdr, first_inner := FirstInner, inner := Inner}) ->
    epdg_ikev2_codec:encode_header(Hdr#{next_payload => FirstInner,
                                        payload_bin  => Inner}).

%% {SrcIP, SrcPort, DstIP, DstPort} for the synthetic datagram.
-spec endpoints(map(), [inet:ip_address()]) ->
    {inet:ip_address(), inet:port_number(),
     inet:ip_address(), inet:port_number()}.
endpoints(#{dir := in, peer_ip := PeerIP, peer_port := PeerPort} = Ev,
          LocalIPs) ->
    {PeerIP, PeerPort,
     local_addr_for(PeerIP, LocalIPs), local_port(Ev, PeerPort)};
endpoints(#{dir := out, peer_ip := PeerIP, peer_port := PeerPort} = Ev,
          LocalIPs) ->
    {local_addr_for(PeerIP, LocalIPs), local_port(Ev, PeerPort),
     PeerIP, PeerPort}.

%% A UE talking to 500 is not behind NAT; anything else reached us on the
%% NAT-T socket. Mirrors the socket choice in epdg_ikev2_listener.
local_port(Ev, 500) -> maps:get(local_port, Ev, 500);
local_port(Ev, _)   -> maps:get(local_port, Ev, 4500).

%% Pick the configured local address of the peer's family. A synthetic
%% datagram has to be single-family, so an address of the wrong family is
%% not usable at all — hence the configured value is a list. With nothing
%% configured for this family the unspecified address stands in, which
%% renders as 0.0.0.0 / :: in the dissector.
local_addr_for(PeerIP, LocalIPs) ->
    Want = tuple_size(PeerIP),
    case [IP || IP <- LocalIPs, tuple_size(IP) =:= Want] of
        [IP | _] -> IP;
        []       -> unspecified(Want)
    end.

unspecified(4) -> {0, 0, 0, 0};
unspecified(8) -> {0, 0, 0, 0, 0, 0, 0, 0}.

%% Metadata derived from the message itself, with the caller's meta map
%% merged on top so an explicit value always wins.
-spec meta_of(map(), binary()) -> map().
meta_of(Ev, <<ISPI:8/binary, RSPI:8/binary, _NextPL:8, _Ver:8,
              ExType:8, Flags:8, MsgId:32, _/binary>>) ->
    Derived = #{dir            => maps:get(dir, Ev, undefined),
                ike_spi_pair   => <<(hex(ISPI))/binary, $:, (hex(RSPI))/binary>>,
                initiator_spi  => hex(ISPI),
                responder_spi  => hex(RSPI),
                exchange_type  => exchange_name(ExType),
                message_id     => MsgId,
                is_response    => (Flags band ?FLAG_RESPONSE) =/= 0,
                from_initiator => (Flags band ?FLAG_INITIATOR) =/= 0},
    maps:merge(Derived, maps:get(meta, Ev, #{}));
meta_of(Ev, _Short) ->
    maps:merge(#{dir => maps:get(dir, Ev, undefined)},
               maps:get(meta, Ev, #{})).

exchange_name(?EX_IKE_SA_INIT)     -> <<"IKE_SA_INIT">>;
exchange_name(?EX_IKE_AUTH)        -> <<"IKE_AUTH">>;
exchange_name(?EX_CREATE_CHILD_SA) -> <<"CREATE_CHILD_SA">>;
exchange_name(?EX_INFORMATIONAL)   -> <<"INFORMATIONAL">>;
exchange_name(N)                   -> integer_to_binary(N).

%% JSON for the pcapng opt_comment. Undefined values are dropped rather
%% than emitted as null, so the ingest side does not end up with a mapping
%% full of empty fields.
-spec encode_meta(map()) -> binary().
encode_meta(Meta) when is_map(Meta) ->
    jsx:encode(maps:from_list([{K, norm(V)}
                               || {K, V} <- maps:to_list(Meta),
                                  V =/= undefined])).

norm(V) when is_boolean(V)                     -> V;
norm(V) when is_binary(V)                      -> V;
norm(V) when is_integer(V)                     -> V;
norm(V) when is_atom(V)                        -> atom_to_binary(V, utf8);
norm(V) when is_tuple(V), tuple_size(V) =:= 4  -> ip_text(V);
norm(V) when is_tuple(V), tuple_size(V) =:= 8  -> ip_text(V);
norm(V) when is_list(V) ->
    case unicode:characters_to_binary(V) of
        B when is_binary(B) -> B;
        _                   -> fmt(V)
    end;
norm(V) -> fmt(V).

fmt(V) -> iolist_to_binary(io_lib:format("~p", [V])).

ip_text(IP) -> iolist_to_binary(inet:ntoa(IP)).

hex(Bin) -> binary:encode_hex(Bin, lowercase).

%%====================================================================
%% pcapng blocks (pcapng spec §4)
%%
%% Every block is: Type(4) | TotalLength(4) | Body | TotalLength(4),
%% where TotalLength counts the 12 bytes of framing as well and the body
%% is padded to a 4-byte boundary.
%%====================================================================

-spec shb() -> binary().
shb() ->
    Body = <<?BOM:32, 1:16, 0:16,
             %% Section Length "unknown" (-1): we are streaming, so the
             %% length is not known when the header goes out.
             16#FFFFFFFFFFFFFFFF:64,
             (opt(?OPT_SHB_USERAPPL, <<"epdg">>))/binary,
             (end_of_opts())/binary>>,
    block(?BT_SHB, Body).

-spec idb() -> binary().
idb() ->
    Body = <<?LINKTYPE_RAW:16, 0:16, ?SNAPLEN:32,
             %% if_tsresol = 6 -> microseconds, matching the
             %% erlang:system_time(microsecond) stamp in the EPBs.
             (opt(?OPT_IF_TSRESOL, <<6>>))/binary,
             (opt(?OPT_IF_NAME, <<"epdg-ike">>))/binary,
             (end_of_opts())/binary>>,
    block(?BT_IDB, Body).

-spec epb(binary(), non_neg_integer(), binary()) -> binary().
epb(Pkt, Micros, Comment) ->
    Len = byte_size(Pkt),
    Body = <<0:32,                                  %% interface id
             (Micros bsr 32):32,                    %% timestamp high
             (Micros band 16#FFFFFFFF):32,          %% timestamp low
             Len:32,                                %% captured length
             Len:32,                                %% original length
             (pad4(Pkt))/binary,
             (opt(?OPT_COMMENT, Comment))/binary,
             (end_of_opts())/binary>>,
    block(?BT_EPB, Body).

block(Type, Body) ->
    Total = 12 + byte_size(Body),
    <<Type:32, Total:32, Body/binary, Total:32>>.

opt(Code, Value) ->
    <<Code:16, (byte_size(Value)):16, (pad4(Value))/binary>>.

end_of_opts() ->
    <<?OPT_ENDOFOPT:16, 0:16>>.

pad4(Bin) ->
    case byte_size(Bin) rem 4 of
        0 -> Bin;
        R -> <<Bin/binary, 0:((4 - R) * 8)>>
    end.

%%====================================================================
%% Synthetic IP/UDP datagram
%%====================================================================

-spec synth_datagram(inet:ip_address(), inet:port_number(),
                     inet:ip_address(), inet:port_number(),
                     binary()) -> binary().
synth_datagram(SrcIP, SrcPort, DstIP, DstPort, IkeMsg) ->
    %% RFC 3948 §2.2: IKE on port 4500 is prefixed with a 4-byte zero
    %% non-ESP marker. Without it Wireshark reads the datagram as
    %% UDP-encapsulated ESP and never reaches the ISAKMP dissector.
    Payload = case SrcPort =:= 4500 orelse DstPort =:= 4500 of
        true  -> <<0:32, IkeMsg/binary>>;
        false -> IkeMsg
    end,
    ok = check_renderable(SrcIP, byte_size(Payload)),
    Udp = udp(SrcIP, DstIP, SrcPort, DstPort, Payload),
    ip(SrcIP, DstIP, Udp).

%% The IPv4 total-length, IPv6 payload-length and UDP length fields are all
%% 16 bits, so a larger datagram cannot be described at all. Erlang would
%% silently truncate the field modulo 65536 and hand the dissector a frame
%% whose length disagrees with its contents, which is worse than no frame:
%% it reads as a genuine capture. Refuse instead — write/3 turns this into
%% a counted `ike_trace_dropped_total'. Only reachable via RFC 7383
%% fragmentation, where the mirror sees the reassembled message.
check_renderable(SrcIP, PayloadLen) ->
    Overhead = case tuple_size(SrcIP) of
        4 -> 20 + 8;   %% IPv4 total length spans the IP header too
        8 -> 8         %% IPv6 payload length starts after the IP header
    end,
    case PayloadLen + Overhead > 16#FFFF of
        true  -> error({ike_message_too_large, PayloadLen});
        false -> ok
    end.

udp(SrcIP, DstIP, SrcPort, DstPort, Payload) ->
    Len = 8 + byte_size(Payload),
    Pseudo = pseudo_header(SrcIP, DstIP, Len),
    Zeroed = <<SrcPort:16, DstPort:16, Len:16, 0:16>>,
    Sum = case checksum([Pseudo, Zeroed, Payload]) of
        %% RFC 768: an all-zero checksum means "not computed", so the
        %% equivalent 0xFFFF is transmitted instead.
        0 -> 16#FFFF;
        S -> S
    end,
    <<SrcPort:16, DstPort:16, Len:16, Sum:16, Payload/binary>>.

pseudo_header({_, _, _, _} = Src, {_, _, _, _} = Dst, UdpLen) ->
    <<(ip_bin(Src))/binary, (ip_bin(Dst))/binary,
      0:8, ?IPPROTO_UDP:8, UdpLen:16>>;
pseudo_header({_, _, _, _, _, _, _, _} = Src,
              {_, _, _, _, _, _, _, _} = Dst, UdpLen) ->
    <<(ip_bin(Src))/binary, (ip_bin(Dst))/binary,
      UdpLen:32, 0:24, ?IPPROTO_UDP:8>>.

ip({_, _, _, _} = Src, {_, _, _, _} = Dst, Udp) ->
    Total = 20 + byte_size(Udp),
    Head  = <<4:4, 5:4, 0:8, Total:16, 0:16, 0:16, 64:8, ?IPPROTO_UDP:8>>,
    Addrs = <<(ip_bin(Src))/binary, (ip_bin(Dst))/binary>>,
    Sum   = checksum([Head, <<0:16>>, Addrs]),
    <<Head/binary, Sum:16, Addrs/binary, Udp/binary>>;
ip({_, _, _, _, _, _, _, _} = Src, {_, _, _, _, _, _, _, _} = Dst, Udp) ->
    %% version(4) | traffic class(8) | flow label(20) | payload len(16)
    %% | next header(8) | hop limit(8)
    <<6:4, 0:8, 0:20, (byte_size(Udp)):16, ?IPPROTO_UDP:8, 64:8,
      (ip_bin(Src))/binary, (ip_bin(Dst))/binary, Udp/binary>>.

ip_bin({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
ip_bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%% 16-bit one's complement Internet checksum (RFC 1071).
-spec checksum(iodata()) -> 0..16#FFFF.
checksum(Data) ->
    (bnot fold(sum16(iolist_to_binary(Data), 0))) band 16#FFFF.

sum16(<<Word:16, Rest/binary>>, Acc) -> sum16(Rest, Acc + Word);
sum16(<<Last:8>>, Acc)               -> Acc + (Last bsl 8);
sum16(<<>>, Acc)                     -> Acc.

fold(Sum) when Sum > 16#FFFF -> fold((Sum band 16#FFFF) + (Sum bsr 16));
fold(Sum)                    -> Sum.

%%====================================================================
%% Misc
%%====================================================================

parse_ip(Str) when is_list(Str) ->
    case inet:parse_address(Str) of
        {ok, IP}    -> IP;
        {error, _}  -> {0, 0, 0, 0}
    end;
parse_ip(T) when is_tuple(T) ->
    T.

ip_family({_, _, _, _})                -> inet;
ip_family({_, _, _, _, _, _, _, _})    -> inet6;
ip_family(_)                           -> inet.
