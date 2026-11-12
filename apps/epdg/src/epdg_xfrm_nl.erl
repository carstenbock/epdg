%%%-------------------------------------------------------------------
%%% @doc XFRM and route programming over netlink, in Erlang.
%%%
%%% Replaces the `ip xfrm' / `ip route' commands of epdg_xfrm: every
%%% command cost a fork of `sh' and `ip' (7 to 12 per attach, KI-42). OTP's
%%% `socket' module opens AF_NETLINK sockets when given the numeric domain,
%%% so no NIF or port program is needed; the messages are the kernel's UAPI
%%% structures (include/uapi/linux/xfrm.h, rtnetlink.h, 6.8), built here
%%% with binary syntax in native byte order and the kernel's alignment.
%%%
%%% One socket per request: open, bind, send, read the acknowledgement (or
%%% the dump), close. The kernel answers a request synchronously, so a
%%% single receive with a timeout is enough; dumps are read until
%%% NLMSG_DONE.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_xfrm_nl).

-export([available/0,
         create_sa/4, delete_sa/1, flush_sa_endpoint/1,
         create_policy/2, delete_policy/2,
         route/4, flush_all/0,
         list_sas/1, list_policies/1, dev_accept_local/2,
         nft_setelem/4]).

-ifdef(TEST).
-export([encode_sa_info/1, encode_policy_info/1, encode_tmpl/1,
         encode_selector/1, parse_cidr/1, format_cidr/2, nla/2,
         decode_sa_info/1, decode_policy/1, nft_setelem_msg/5]).
-endif.

%% Families and protocols
-define(AF_INET,      2).
-define(AF_INET6,    10).
-define(AF_NETLINK,  16).
-define(NETLINK_ROUTE, 0).
-define(NETLINK_XFRM,  6).
-define(IPPROTO_ESP, 50).
-define(UDP_ENCAP_ESPINUDP, 2).

%% nlmsg flags
-define(NLM_F_REQUEST, 16#01).
-define(NLM_F_MULTI,   16#02).
-define(NLM_F_ACK,     16#04).
-define(NLM_F_DUMP,    16#300).
-define(NLM_F_REPLACE, 16#100).
-define(NLM_F_EXCL,    16#200).
-define(NLM_F_CREATE,  16#400).
-define(NLMSG_ERROR, 2).
-define(NLMSG_DONE,  3).

%% xfrm messages
-define(XFRM_MSG_NEWSA,       16#10).
-define(XFRM_MSG_DELSA,       16#11).
-define(XFRM_MSG_GETSA,       16#12).
-define(XFRM_MSG_NEWPOLICY,   16#13).
-define(XFRM_MSG_DELPOLICY,   16#14).
-define(XFRM_MSG_GETPOLICY,   16#15).
-define(XFRM_MSG_UPDPOLICY,   16#19).
-define(XFRM_MSG_FLUSHSA,     16#1c).
-define(XFRM_MSG_FLUSHPOLICY, 16#1d).

%% xfrm attributes
-define(XFRMA_ALG_AUTH,       1).
-define(XFRMA_ALG_CRYPT,      2).
-define(XFRMA_ENCAP,          4).
-define(XFRMA_TMPL,           5).
-define(XFRMA_SRCADDR,       13).
-define(XFRMA_ALG_AEAD,      18).
-define(XFRMA_ALG_AUTH_TRUNC, 20).
-define(XFRMA_REPLAY_ESN_VAL, 23).
-define(XFRMA_ADDRESS_FILTER, 26).
-define(XFRMA_OFFLOAD_DEV,   28).
-define(XFRMA_SET_MARK,      29).
-define(XFRMA_SET_MARK_MASK, 30).
-define(XFRMA_IF_ID,         31).

%% nf_tables over NETLINK_NETFILTER (KI-58 source check)
-define(NETLINK_NETFILTER,      12).
-define(NFNL_SUBSYS_NFTABLES,   10).
-define(NFNL_MSG_BATCH_BEGIN,   16).
-define(NFNL_MSG_BATCH_END,     17).
-define(NFT_MSG_NEWSETELEM,     12).
-define(NFT_MSG_DELSETELEM,     14).
-define(NFPROTO_INET,            1).
-define(NFTA_SET_ELEM_LIST_TABLE,    1).
-define(NFTA_SET_ELEM_LIST_SET,      2).
-define(NFTA_SET_ELEM_LIST_ELEMENTS, 3).
-define(NFTA_LIST_ELEM,              1).
-define(NFTA_SET_ELEM_KEY,           1).
-define(NFTA_SET_ELEM_KEY_END,      10).
-define(NFTA_DATA_VALUE,             1).
-define(NLA_F_NESTED,          16#8000).

-define(XFRM_MODE_TRANSPORT, 0).
-define(XFRM_MODE_TUNNEL,    1).
-define(XFRM_POLICY_ALLOW,   0).
-define(XFRM_STATE_AF_UNSPEC, 32).
-define(XFRM_STATE_ESN,      128).
-define(XFRM_OFFLOAD_INBOUND, 2).
-define(XFRM_OFFLOAD_PACKET,  4).
-define(XFRM_INF, 16#FFFFFFFFFFFFFFFF).

%% rtnetlink
-define(RTM_SETLINK,  19).
-define(RTM_NEWROUTE, 24).
-define(RTM_DELROUTE, 25).
-define(IFLA_AF_SPEC, 26).
-define(IFLA_INET_CONF, 1).
-define(IPV4_DEVCONF_ACCEPT_LOCAL, 23).
-define(RTA_DST,   1).
-define(RTA_OIF,   4).
-define(RTA_TABLE, 15).
-define(RTN_UNICAST,   1).
-define(RTPROT_BOOT,   3).
-define(RT_SCOPE_LINK, 253).

-define(RECV_TIMEOUT_MS, 5000).
-define(DUMP_BUF, 65536).

%%====================================================================
%% API
%%====================================================================

%% Whether this process may change XFRM state (NET_ADMIN). Opening the
%% socket works for anyone; the probe is a delete of an SA that does not
%% exist, which the kernel answers with ESRCH when the caller may write and
%% with EPERM when it may not.
-spec available() -> boolean().
available() ->
    case catch delsa({10, 255, 255, 254}, {10, 255, 255, 253}, 16#7fffffff, ?AF_INET) of
        ok               -> true;
        {error, esrch}   -> true;
        {error, {esrch, _}} -> true;
        _                -> false
    end.

%% Params as epdg_xfrm:create_sa/1 takes them; Offload/Iface/If from the
%% server state and the instance's XFRM interface (#{id, name, local_table}
%% or undefined).
-spec create_sa(map(), none | inline | crypto, string(), map() | undefined) ->
          ok | {error, term()}.
create_sa(#{spi := SPI, src_ip := Src, dst_ip := Dst,
            enc_alg := EncAlg, enc_key := EncKey} = Params, Offload, Iface, If) ->
    Family = family(Src),
    Flags = ?XFRM_STATE_AF_UNSPEC bor
            case maps:get(esn, Params, false) of true -> ?XFRM_STATE_ESN; false -> 0 end,
    Reqid = case maps:get(reqid, Params, 0) of R when is_integer(R), R > 0 -> R; _ -> 0 end,
    Info = encode_sa_info(#{src => Src, dst => Dst, spi => SPI, family => Family,
                            mode => ?XFRM_MODE_TUNNEL, reqid => Reqid, flags => Flags,
                            replay_window => 0}),
    Attrs = [enc_attr(EncAlg, EncKey),
             auth_attr(Params),
             encap_attr(Params, Src),
             esn_attr(Params),
             if_id_attr(If),
             set_mark_attr(Params),
             offload_attr(Offload, Iface, maps:get(sa_dir, Params, in))],
    request(?NETLINK_XFRM, ?XFRM_MSG_NEWSA,
            ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE bor ?NLM_F_EXCL,
            Info, lists:append(Attrs));
create_sa(_, _, _, _) ->
    {error, invalid_params}.

-spec delete_sa(map()) -> ok | {error, term()}.
delete_sa(#{spi := SPI, src_ip := Src, dst_ip := Dst}) ->
    delsa(Src, Dst, SPI, family(Dst));
delete_sa(#{spi := SPI}) ->
    %% The endpoints are unknown: find every SA with that SPI. Rare path
    %% (a session whose outer addresses were lost), so a full dump is
    %% acceptable here, as `ip xfrm state deleteall spi' did.
    case dump(?NETLINK_XFRM, ?XFRM_MSG_GETSA, <<>>, []) of
        {ok, Msgs} ->
            Results = [delsa(S, D, SPI, F)
                       || {?XFRM_MSG_NEWSA, Bin} <- Msgs,
                          #{spi := SPI0, src := S, dst := D, family := F} <- [decode_sa_info(Bin)],
                          SPI0 =:= SPI],
            %% ok only when an SA was removed, as for a delete by address.
            case lists:member(ok, Results) of
                true -> ok;
                false -> {error, esrch}
            end;
        E -> E
    end;
delete_sa(_) ->
    {error, invalid_params}.

%% Every ESP SA between two outer endpoints, regardless of SPI.
-spec flush_sa_endpoint(map()) -> ok | {error, term()}.
flush_sa_endpoint(#{src_ip := Src, dst_ip := Dst}) ->
    Fam = family(Src),
    Filter = nla(?XFRMA_ADDRESS_FILTER, address_filter(Src, Dst, Fam)),
    case dump(?NETLINK_XFRM, ?XFRM_MSG_GETSA, <<>>, [Filter]) of
        {ok, Msgs} ->
            lists:foreach(
              fun({?XFRM_MSG_NEWSA, Bin}) ->
                      case decode_sa_info(Bin) of
                          #{src := Src, dst := Dst, spi := SPI} -> delsa(Src, Dst, SPI, Fam);
                          _ -> ok
                      end;
                 (_) -> ok
              end, Msgs),
            ok;
        E -> E
    end;
flush_sa_endpoint(_) ->
    {error, invalid_params}.

%% Params as epdg_xfrm:create_policy/1 takes them (`src'/`dst' are CIDR
%% strings); the route of the outbound policy is added by the caller
%% through route/4, as before.
-spec create_policy(map(), map() | undefined) -> ok | {error, term()}.
create_policy(#{src := Src, dst := Dst, direction := Dir,
                tmpl_src := TSrc, tmpl_dst := TDst} = Params, If) ->
    Sel = selector_from_cidrs(Src, Dst),
    Reqid = maps:get(reqid, Params, 0),
    Info = encode_policy_info(#{sel => Sel, dir => dir(Dir), priority => 0}),
    Tmpl = encode_tmpl(#{src => TSrc, dst => TDst, reqid => Reqid,
                         mode => ?XFRM_MODE_TUNNEL, family => family(TSrc)}),
    request(?NETLINK_XFRM, ?XFRM_MSG_UPDPOLICY,
            ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
            Info, [nla(?XFRMA_TMPL, Tmpl) | if_id_attr(If)]);
create_policy(_, _) ->
    {error, invalid_params}.

-spec delete_policy(map(), map() | undefined) -> ok | {error, term()}.
delete_policy(#{src := Src, dst := Dst, direction := Dir}, If) ->
    Sel = selector_from_cidrs(Src, Dst),
    Id = <<(encode_selector(Sel))/binary, 0:32, (dir(Dir)):8, 0:24>>,
    request(?NETLINK_XFRM, ?XFRM_MSG_DELPOLICY, ?NLM_F_REQUEST bor ?NLM_F_ACK,
            Id, if_id_attr(If));
delete_policy(_, _) ->
    {error, invalid_params}.

%% `ip route replace|del <Dst> dev <Name> table <Table>' for a UE address
%% (CIDR string) into the instance's local-origin table.
-spec route(replace | del, string(), string(), non_neg_integer()) ->
          ok | {error, term()}.
route(Op, DstCidr, DevName, Table) ->
    case ifindex(DevName) of
        {ok, Ifindex} ->
            {Addr, Plen} = parse_cidr(DstCidr),
            Fam = family(Addr),
            Rtm = <<Fam:8, Plen:8, 0:8, 0:8,
                    (min(Table, 255)):8, ?RTPROT_BOOT:8, ?RT_SCOPE_LINK:8, ?RTN_UNICAST:8,
                    0:32/native>>,
            Attrs = [nla(?RTA_DST, addr_bin_exact(Addr)),
                     nla(?RTA_OIF, <<Ifindex:32/native>>),
                     nla(?RTA_TABLE, <<Table:32/native>>)],
            {Type, Flags} = case Op of
                replace -> {?RTM_NEWROUTE,
                            ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE bor ?NLM_F_REPLACE};
                del     -> {?RTM_DELROUTE, ?NLM_F_REQUEST bor ?NLM_F_ACK}
            end,
            request(?NETLINK_ROUTE, Type, Flags, Rtm, Attrs);
        E -> E
    end.

-spec flush_all() -> ok.
flush_all() ->
    _ = request(?NETLINK_XFRM, ?XFRM_MSG_FLUSHSA, ?NLM_F_REQUEST bor ?NLM_F_ACK,
                <<?IPPROTO_ESP:8, 0:24>>, []),
    _ = request(?NETLINK_XFRM, ?XFRM_MSG_FLUSHPOLICY, ?NLM_F_REQUEST bor ?NLM_F_ACK,
                <<>>, []),
    ok.

%% The ESP SAs with LocalIP as an outer endpoint (kernel-side address
%% filter, one dump per direction), as epdg_xfrm:list_sas/1 returns them.
-spec list_sas(inet:ip_address()) -> [map()].
list_sas(LocalIP) ->
    Fam = family(LocalIP),
    Dumps = [dump(?NETLINK_XFRM, ?XFRM_MSG_GETSA, <<>>,
                  [nla(?XFRMA_ADDRESS_FILTER, F)])
             || F <- [address_filter(LocalIP, any, Fam), address_filter(any, LocalIP, Fam)]],
    lists:usort(lists:append(
      [[#{src => S, dst => D, spi => SPI, reqid => R}
        || {?XFRM_MSG_NEWSA, Bin} <- Msgs,
           #{src := S, dst := D, spi := SPI, reqid := R, proto := ?IPPROTO_ESP}
               <- [decode_sa_info(Bin)]]
       || {ok, Msgs} <- Dumps])).

%% The policies whose first template names LocalIP, as
%% epdg_xfrm:list_policies/1 returns them (CIDR strings for the selector).
-spec list_policies(inet:ip_address()) -> [map()].
list_policies(LocalIP) ->
    case dump(?NETLINK_XFRM, ?XFRM_MSG_GETPOLICY, <<>>, []) of
        {ok, Msgs} ->
            [P || {?XFRM_MSG_NEWPOLICY, Bin} <- Msgs,
                  #{tmpl_src := TS, tmpl_dst := TD} = P <- [decode_policy(Bin)],
                  TS =:= LocalIP orelse TD =:= LocalIP];
        _ -> []
    end.

%%====================================================================
%% Structures (include/uapi/linux/xfrm.h, x86_64 layout)
%%====================================================================

%% struct xfrm_selector, 56 bytes
encode_selector(#{} = S) ->
    Fam = maps:get(family, S, 0),
    <<(addr_bin(maps:get(daddr, S, any)))/binary,
      (addr_bin(maps:get(saddr, S, any)))/binary,
      (maps:get(dport, S, 0)):16/big, (maps:get(dport_mask, S, 0)):16/big,
      (maps:get(sport, S, 0)):16/big, (maps:get(sport_mask, S, 0)):16/big,
      Fam:16/native,
      (maps:get(dprefix, S, 0)):8, (maps:get(sprefix, S, 0)):8,
      (maps:get(proto, S, 0)):8, 0:24,   %% proto, then padding to the int
      0:32/native,                       %% ifindex
      (maps:get(user, S, 0)):32/native>>.

%% struct xfrm_lifetime_cfg, 64 bytes: no byte or packet limit, no timers
lifetime_cfg() ->
    <<?XFRM_INF:64/native, ?XFRM_INF:64/native, ?XFRM_INF:64/native, ?XFRM_INF:64/native,
      0:64, 0:64, 0:64, 0:64>>.

%% struct xfrm_id, 24 bytes
encode_id(Daddr, SPI, Proto) ->
    <<(addr_bin(Daddr))/binary, SPI:32/big, Proto:8, 0:24>>.

%% struct xfrm_usersa_info, 224 bytes
encode_sa_info(#{src := Src, dst := Dst, spi := SPI, family := Fam,
                 mode := Mode, reqid := Reqid, flags := Flags} = M) ->
    Sel = encode_selector(maps:get(sel, M, #{})),
    <<Sel/binary,
      (encode_id(Dst, SPI, ?IPPROTO_ESP))/binary,
      (addr_bin(Src))/binary,
      (lifetime_cfg())/binary,
      0:(32*8),                           %% curlft
      0:(12*8),                           %% stats
      0:32/native,                        %% seq
      Reqid:32/native,
      Fam:16/native, Mode:8, (maps:get(replay_window, M, 0)):8, Flags:8,
      0:56>>.                             %% padding to the 8-byte alignment

%% struct xfrm_userpolicy_info, 168 bytes
encode_policy_info(#{sel := Sel, dir := Dir} = M) ->
    <<(encode_selector(Sel))/binary,
      (lifetime_cfg())/binary,
      0:(32*8),                           %% curlft
      (maps:get(priority, M, 0)):32/native,
      0:32/native,                        %% index
      Dir:8, ?XFRM_POLICY_ALLOW:8, 0:8, 0:8,
      0:32>>.

%% struct xfrm_user_tmpl, 64 bytes
encode_tmpl(#{src := Src, dst := Dst, reqid := Reqid, mode := Mode, family := Fam}) ->
    <<(encode_id(Dst, 0, ?IPPROTO_ESP))/binary,
      Fam:16/native, 0:16,
      (addr_bin(Src))/binary,
      Reqid:32/native,
      Mode:8, 0:8, 0:8, 0:8,
      16#FFFFFFFF:32/native, 16#FFFFFFFF:32/native, 16#FFFFFFFF:32/native>>.

%% struct xfrm_address_filter, 36 bytes; `any' leaves that side open
address_filter(Src, Dst, Fam) ->
    Plen = fun(any) -> 0; (A) -> bits(A) end,
    <<(addr_bin(Src))/binary, (addr_bin(Dst))/binary, Fam:16/native,
      (Plen(Src)):8, (Plen(Dst)):8>>.

%% struct xfrm_algo / xfrm_algo_auth / xfrm_algo_aead
algo_name(Name) ->
    B = list_to_binary(Name),
    <<B/binary, 0:((64 - byte_size(B)) * 8)>>.

enc_attr(EncAlg, Key) ->
    case enc_alg(EncAlg) of
        {aead, Name, IcvBits} ->
            [nla(?XFRMA_ALG_AEAD, <<(algo_name(Name))/binary,
                                    (bit_size(Key)):32/native, IcvBits:32/native,
                                    Key/binary>>)];
        {crypt, Name} ->
            [nla(?XFRMA_ALG_CRYPT, <<(algo_name(Name))/binary,
                                     (bit_size(Key)):32/native, Key/binary>>)]
    end.

auth_attr(Params) ->
    case maps:find(auth_alg, Params) of
        {ok, none} -> [];
        error      -> [];
        {ok, Alg}  ->
            Key = maps:get(auth_key, Params, <<>>),
            [nla(?XFRMA_ALG_AUTH_TRUNC,
                 <<(algo_name(auth_alg(Alg)))/binary, (bit_size(Key)):32/native,
                   (auth_trunc_bits(Alg)):32/native, Key/binary>>)]
    end.

%% struct xfrm_encap_tmpl, 24 bytes; port order follows the SA direction
%% (see the note in epdg_xfrm:do_create_sa/2)
encap_attr(#{nat_t := true} = Params, Src) ->
    LocalPort = maps:get(local_udp_port, Params, 4500),
    PeerPort  = maps:get(peer_udp_port,  Params, 4500),
    PeerOuter = maps:get(peer_outer_ip,  Params, Src),
    {Sport, Dport} = case maps:get(sa_dir, Params, in) of
        out -> {LocalPort, PeerPort};
        _   -> {PeerPort, LocalPort}
    end,
    [nla(?XFRMA_ENCAP, <<?UDP_ENCAP_ESPINUDP:16/native, Sport:16/big, Dport:16/big, 0:16,
                         (addr_bin(PeerOuter))/binary>>)];
encap_attr(_, _) ->
    [].

%% struct xfrm_replay_state_esn with a 128-bit window (bmp_len 4 words)
esn_attr(#{esn := true}) ->
    [nla(?XFRMA_REPLAY_ESN_VAL, <<4:32/native, 0:32, 0:32, 0:32, 0:32, 128:32/native,
                                  0:(4*32)>>)];
esn_attr(_) ->
    [].

if_id_attr(#{id := Id}) when is_integer(Id), Id > 0 -> [nla(?XFRMA_IF_ID, <<Id:32/native>>)];
if_id_attr(_)                                       -> [].

offload_attr(none, _Iface, _Dir) ->
    [];
offload_attr(Mode, Iface, Dir) ->
    case ifindex(Iface) of
        {ok, Idx} ->
            Flags = (case Dir of in -> ?XFRM_OFFLOAD_INBOUND; _ -> 0 end) bor
                    (case Mode of inline -> ?XFRM_OFFLOAD_PACKET; _ -> 0 end),
            [nla(?XFRMA_OFFLOAD_DEV, <<Idx:32/signed-native, Flags:8, 0:24>>)];
        _ -> []
    end.

%% struct xfrm_usersa_id + XFRMA_SRCADDR
delsa(Src, Dst, SPI, Fam) ->
    Id = <<(addr_bin(Dst))/binary, SPI:32/big, Fam:16/native, ?IPPROTO_ESP:8, 0:8>>,
    request(?NETLINK_XFRM, ?XFRM_MSG_DELSA, ?NLM_F_REQUEST bor ?NLM_F_ACK,
            Id, [nla(?XFRMA_SRCADDR, addr_bin(Src))]).

%%====================================================================
%% Decoding
%%====================================================================

%% xfrm_usersa_info -> #{src, dst, spi, reqid, family, mode, proto}
decode_sa_info(<<_Sel:56/binary, DaddrBin:16/binary, SPI:32/big, Proto:8, _:24,
                 SaddrBin:16/binary, _Lft:64/binary, _Cur:32/binary, _Stats:12/binary,
                 _Seq:32, Reqid:32/native, Fam:16/native, Mode:8, _/binary>>) ->
    #{src => bin_addr(SaddrBin, Fam), dst => bin_addr(DaddrBin, Fam),
      spi => SPI, reqid => Reqid, family => Fam, mode => Mode, proto => Proto};
decode_sa_info(_) ->
    #{}.

%% xfrm_userpolicy_info + attributes -> the epdg_xfrm:list_policies/1 map
decode_policy(<<DaddrBin:16/binary, SaddrBin:16/binary,
                _Dport:16, _DportMask:16, _Sport:16, _SportMask:16,
                Fam:16/native, Dplen:8, Splen:8, _Proto:8, _:24, _Ifindex:32, _User:32,
                _Lft:64/binary, _Cur:32/binary, _Prio:32, _Index:32, Dir:8, _:24,
                _:32, Attrs/binary>>) ->
    {TS, TD, Reqid} =
        case [V || {?XFRMA_TMPL, V} <- parse_attrs(Attrs)] of
            [<<TDaddr:16/binary, _SPI:32, _P:8, _:24, TFam:16/native, _:16,
               TSaddr:16/binary, R:32/native, _/binary>> | _] ->
                {bin_addr(TSaddr, TFam), bin_addr(TDaddr, TFam), R};
            _ -> {undefined, undefined, 0}
        end,
    #{src => format_cidr(bin_addr(SaddrBin, Fam), Splen),
      dst => format_cidr(bin_addr(DaddrBin, Fam), Dplen),
      dir => dir_atom(Dir), tmpl_src => TS, tmpl_dst => TD, reqid => Reqid};
decode_policy(_) ->
    #{tmpl_src => undefined, tmpl_dst => undefined}.

parse_attrs(<<Len:16/native, Type:16/native, Rest/binary>>) when Len >= 4 ->
    PLen = Len - 4,
    Pad = (4 - (PLen rem 4)) rem 4,
    case Rest of
        <<V:PLen/binary, _:Pad/binary, Tail/binary>> -> [{Type, V} | parse_attrs(Tail)];
        <<V:PLen/binary, _/binary>>                  -> [{Type, V}]
    end;
parse_attrs(_) ->
    [].

%%====================================================================
%% Netlink transport
%%====================================================================

nl_open(Proto) ->
    case socket:open(?AF_NETLINK, raw, Proto) of
        {ok, S} ->
            %% NETLINK_EXT_ACK (SOL_NETLINK 270, option 11): the kernel
            %% then names the refused field in its error answer.
            _ = catch socket:setopt_native(S, {270, 11}, <<1:32/native>>),
            case socket:bind(S, #{family => ?AF_NETLINK, addr => <<0:16, 0:32, 0:32>>}) of
                ok -> {ok, S};
                E  -> catch socket:close(S), E
            end;
        E -> E
    end.

%% One request, one acknowledgement.
request(Proto, Type, Flags, Payload, Attrs) ->
    case nl_open(Proto) of
        {ok, S} ->
            try
                Seq = erlang:unique_integer([positive]) band 16#7FFFFFFF,
                ok = socket:sendto(S, nlmsg(Type, Flags, Seq, Payload, Attrs),
                                   #{family => ?AF_NETLINK, addr => <<0:16, 0:32, 0:32>>}),
                case socket:recvfrom(S, 0, ?RECV_TIMEOUT_MS) of
                    {ok, {_, Bin}} ->
                        case ack_of(Bin, Seq) of
                            0  -> ok;
                            {Errno, Msg} when is_integer(Errno) ->
                                {error, {errno(Errno), Msg}};
                            Errno when is_integer(Errno) -> {error, errno(Errno)};
                            Other -> {error, Other}
                        end;
                    {error, R} -> {error, R}
                end
            catch C:R2 -> {error, {C, R2}}
            after socket:close(S)
            end;
        {error, R} -> {error, R}
    end.

%% Add or delete nf_tables set elements in one batch. Elements are
%% {Key, KeyEnd} with KeyEnd = undefined for a set without intervals; keys
%% are the concatenated field values, each padded to 4 bytes. A batch is
%% all or nothing in the kernel. Adding an element that exists and deleting
%% one that does not are both ok, so callers can repeat an operation.
-spec nft_setelem(add | del, string(), string(), [{binary(), binary() | undefined}]) ->
          ok | {error, term()}.
nft_setelem(_Op, _Table, _Set, []) ->
    ok;
nft_setelem(Op, Table, Set, Elems) ->
    case nl_open(?NETLINK_NETFILTER) of
        {ok, S} ->
            try
                Seq = erlang:unique_integer([positive]) band 16#3FFFFFFF,
                Msg = nft_setelem_msg(Op, Table, Set, Elems, Seq),
                ok = socket:sendto(S, Msg, #{family => ?AF_NETLINK,
                                             addr => <<0:16, 0:32, 0:32>>}),
                case socket:recvfrom(S, 0, ?RECV_TIMEOUT_MS) of
                    {ok, {_, Bin}} ->
                        case {Op, ack_of(Bin, Seq + 1)} of
                            {_, 0} -> ok;
                            {add, {eexist, _}} -> ok;
                            {add, eexist} -> ok;
                            {del, {enoent, _}} -> ok;
                            {del, enoent} -> ok;
                            {_, {Errno, Text}} when is_integer(Errno) ->
                                {error, {errno(Errno), Text}};
                            {_, Errno} when is_integer(Errno) -> {error, errno(Errno)};
                            {_, Other} -> {error, Other}
                        end;
                    {error, R} -> {error, R}
                end
            catch C:R2 -> {error, {C, R2}}
            after socket:close(S)
            end;
        {error, R} -> {error, R}
    end.

%% BATCH_BEGIN (Seq), the element message (Seq + 1, acknowledged), BATCH_END.
nft_setelem_msg(Op, Table, Set, Elems, Seq) ->
    Type = (?NFNL_SUBSYS_NFTABLES bsl 8) bor
           case Op of add -> ?NFT_MSG_NEWSETELEM; del -> ?NFT_MSG_DELSETELEM end,
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor
            case Op of add -> ?NLM_F_CREATE; del -> 0 end,
    %% struct nfgenmsg: family, version, res_id (big endian)
    BatchHdr = <<0:8, 0:8, ?NFNL_SUBSYS_NFTABLES:16/big>>,
    ElemHdr  = <<?NFPROTO_INET:8, 0:8, 0:16/big>>,
    List = [nla_nested(?NFTA_LIST_ELEM,
                       [nla_nested(?NFTA_SET_ELEM_KEY, [nla(?NFTA_DATA_VALUE, K)]),
                        case E of
                            undefined -> <<>>;
                            _ -> nla_nested(?NFTA_SET_ELEM_KEY_END, [nla(?NFTA_DATA_VALUE, E)])
                        end])
            || {K, E} <- Elems],
    Attrs = [nla(?NFTA_SET_ELEM_LIST_TABLE, <<(list_to_binary(Table))/binary, 0>>),
             nla(?NFTA_SET_ELEM_LIST_SET, <<(list_to_binary(Set))/binary, 0>>),
             nla_nested(?NFTA_SET_ELEM_LIST_ELEMENTS, List)],
    iolist_to_binary([nlmsg(?NFNL_MSG_BATCH_BEGIN, ?NLM_F_REQUEST, Seq, BatchHdr, []),
                      nlmsg(Type, Flags, Seq + 1, ElemHdr, Attrs),
                      nlmsg(?NFNL_MSG_BATCH_END, ?NLM_F_REQUEST, Seq + 2, BatchHdr, [])]).

nla_nested(Type, Children) ->
    nla(Type bor ?NLA_F_NESTED, iolist_to_binary(Children)).

%% A dump: [{Type, Payload}] of every message until NLMSG_DONE.
dump(Proto, Type, Payload, Attrs) ->
    case nl_open(Proto) of
        {ok, S} ->
            try
                Seq = erlang:unique_integer([positive]) band 16#7FFFFFFF,
                ok = socket:sendto(S, nlmsg(Type, ?NLM_F_REQUEST bor ?NLM_F_DUMP, Seq,
                                            Payload, Attrs),
                                   #{family => ?AF_NETLINK, addr => <<0:16, 0:32, 0:32>>}),
                recv_dump(S, [])
            catch C:R -> {error, {C, R}}
            after socket:close(S)
            end;
        {error, R} -> {error, R}
    end.

recv_dump(S, Acc) ->
    case socket:recvfrom(S, 0, ?RECV_TIMEOUT_MS) of
        {ok, {_, Bin}} ->
            case split_msgs(Bin, []) of
                {done, Msgs}     -> {ok, lists:reverse(Msgs ++ Acc)};
                {more, Msgs}     -> recv_dump(S, Msgs ++ Acc);
                {error, _} = E   -> E
            end;
        {error, R} -> {error, R}
    end.

%% Messages of one datagram, newest first; `done' when NLMSG_DONE was among them.
split_msgs(<<Len:32/native, Type:16/native, _Flags:16, _Seq:32, _Pid:32, Rest/binary>>, Acc)
  when Len >= 16 ->
    PLen = Len - 16,
    Aligned = ((Len + 3) div 4) * 4 - 16,
    case {Type, Rest} of
        {?NLMSG_DONE, _} -> {done, Acc};
        {?NLMSG_ERROR, <<Err:32/signed-native, _/binary>>} when Err =/= 0 ->
            {error, errno(-Err)};
        {_, <<P:PLen/binary, _/binary>>} ->
            Tail = case Rest of <<_:Aligned/binary, T/binary>> -> T; _ -> <<>> end,
            split_msgs(Tail, [{Type, P} | Acc]);
        _ -> {more, Acc}
    end;
split_msgs(_, Acc) ->
    {more, Acc}.

nlmsg(Type, Flags, Seq, Payload, Attrs) ->
    Body = iolist_to_binary([pad4(Payload), Attrs]),
    Len = 16 + byte_size(Body),
    <<Len:32/native, Type:16/native, Flags:16/native, Seq:32/native, 0:32/native, Body/binary>>.

%% Mark the packets this SA decrypts (KI-58): bits outside the mask keep
%% the outer packet's mark. Inbound SAs only; the caller decides.
set_mark_attr(#{set_mark := M, set_mark_mask := Mask}) when is_integer(M) ->
    [nla(?XFRMA_SET_MARK, <<M:32/native>>), nla(?XFRMA_SET_MARK_MASK, <<Mask:32/native>>)];
set_mark_attr(_) ->
    [].

nla(Type, Value) when is_binary(Value) ->
    pad4(<<(4 + byte_size(Value)):16/native, Type:16/native, Value/binary>>).

pad4(Bin) ->
    case byte_size(Bin) rem 4 of
        0 -> Bin;
        N -> <<Bin/binary, 0:((4 - N) * 8)>>
    end.

ack_of(<<_Len:32, ?NLMSG_ERROR:16/native, _Flags:16, Seq:32/native, _Pid:32,
         Err:32/signed-native, Rest/binary>>, Seq) ->
    case Err of
        0 -> 0;
        _ ->
            %% struct nlmsgerr: the original message follows, then, with
            %% extended acks, attributes; NLMSGERR_ATTR_MSG (1) is the text.
            Msg = case Rest of
                <<OrigLen:32/native, _/binary>> when byte_size(Rest) > OrigLen ->
                    Aligned = ((OrigLen + 3) div 4) * 4,
                    <<_:Aligned/binary, Attrs/binary>> = Rest,
                    case [V || {1, V} <- parse_attrs(Attrs)] of
                        [T | _] -> binary_to_list(string:trim(T, trailing, [0]));
                        []      -> undefined
                    end;
                _ -> undefined
            end,
            case Msg of undefined -> -Err; _ -> {-Err, Msg} end
    end;
ack_of(<<_Len:32, Type:16/native, _/binary>>, _Seq) ->
    {unexpected_message, Type};
ack_of(_, _) ->
    short_answer.

errno(1)  -> eperm;
errno(2)  -> enoent;
errno(3)  -> esrch;
errno(11) -> eagain;
errno(12) -> enomem;
errno(17) -> eexist;
errno(19) -> enodev;
errno(22) -> einval;
errno(38) -> enosys;
errno(N)  -> {errno, N}.

%%====================================================================
%% Addresses, algorithms, helpers
%%====================================================================

family({_, _, _, _})                 -> ?AF_INET;
family({_, _, _, _, _, _, _, _})     -> ?AF_INET6.

bits({_, _, _, _})             -> 32;
bits({_, _, _, _, _, _, _, _}) -> 128.

%% xfrm_address_t, 16 bytes
addr_bin(any)          -> <<0:128>>;
addr_bin({A, B, C, D}) -> <<A, B, C, D, 0:96>>;
addr_bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

%% The address alone (RTA_DST wants 4 or 16 bytes)
addr_bin_exact({A, B, C, D}) -> <<A, B, C, D>>;
addr_bin_exact(IP6)          -> addr_bin(IP6).

bin_addr(<<A, B, C, D, _/binary>>, ?AF_INET) -> {A, B, C, D};
bin_addr(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>, ?AF_INET6) ->
    {A, B, C, D, E, F, G, H};
bin_addr(_, _) -> undefined.

%% "10.46.0.34/32", "0.0.0.0/0", "cafe:0:46:1::/64", or a bare address
parse_cidr(Str) ->
    {AddrStr, Plen} = case string:split(Str, "/") of
        [A, P] -> {A, list_to_integer(P)};
        [A]    -> {A, undefined}
    end,
    {ok, Addr} = inet:parse_address(AddrStr),
    {Addr, case Plen of undefined -> bits(Addr); _ -> Plen end}.

format_cidr(Addr, Plen) ->
    inet:ntoa(Addr) ++ "/" ++ integer_to_list(Plen).

selector_from_cidrs(SrcCidr, DstCidr) ->
    {SAddr, SPlen} = parse_cidr(SrcCidr),
    {DAddr, DPlen} = parse_cidr(DstCidr),
    #{saddr => SAddr, sprefix => SPlen, daddr => DAddr, dprefix => DPlen,
      family => family(SAddr)}.

dir(in)  -> 0;
dir(out) -> 1;
dir(fwd) -> 2.

dir_atom(0) -> in;
dir_atom(1) -> out;
dir_atom(_) -> fwd.

%% net.ipv4.conf.<dev>.accept_local over rtnetlink (RTM_SETLINK with
%% IFLA_AF_SPEC / AF_INET / IFLA_INET_CONF). /proc/sys is read-only in a
%% hostNetwork pod; this path is not. A packet whose source is one of the
%% node's own addresses is a martian on every interface but lo unless the
%% interface accepts local sources, and that check runs in routing, before
%% netfilter and XFRM, whatever rp_filter says. The IMS IPsec gateway's
%% replies to a UE of a co-located ePDG come back into the ePDG's TUN
%% through the PGW-U with the node's own VIP as source (static policy
%% mode, which has no per-UE host route into the XFRM interface), so the
%% TUN has to accept them (KI-53, run r9: half of the VoWiFi UEs never
%% saw their 401).
-spec dev_accept_local(string(), boolean()) -> ok | {error, term()}.
dev_accept_local(DevName, On) ->
    case ifindex(DevName) of
        {ok, Ifindex} ->
            Val = case On of true -> 1; false -> 0 end,
            Conf = nla(?IFLA_INET_CONF bor ?NLA_F_NESTED,
                       nla(?IPV4_DEVCONF_ACCEPT_LOCAL, <<Val:32/native>>)),
            Inet = nla(?AF_INET bor ?NLA_F_NESTED, Conf),
            Spec = nla(?IFLA_AF_SPEC bor ?NLA_F_NESTED, Inet),
            %% struct ifinfomsg: family, pad, type, index, flags, change
            Ifi = <<0:8, 0:8, 0:16/native, Ifindex:32/native, 0:32/native, 0:32/native>>,
            request(?NETLINK_ROUTE, ?RTM_SETLINK, ?NLM_F_REQUEST bor ?NLM_F_ACK, Ifi, [Spec]);
        E -> E
    end.

ifindex(Name) ->
    case file:read_file("/sys/class/net/" ++ Name ++ "/ifindex") of
        {ok, Bin} -> {ok, binary_to_integer(string:trim(Bin))};
        {error, R} -> {error, {no_such_device, Name, R}}
    end.

%% GCM is an AEAD transform for the kernel: XFRMA_ALG_AEAD with the ICV
%% length, the key followed by the 4-byte salt as IKEv2 derives it.
enc_alg(aes_gcm_128)       -> {aead, "rfc4106(gcm(aes))", 128};
enc_alg(aes_gcm_192)       -> {aead, "rfc4106(gcm(aes))", 128};
enc_alg(aes_gcm_256)       -> {aead, "rfc4106(gcm(aes))", 128};
enc_alg(chacha20_poly1305) -> {aead, "rfc7539esp(chacha20,poly1305)", 128};
enc_alg(_)                 -> {crypt, "cbc(aes)"}.

auth_alg(hmac_sha1)   -> "hmac(sha1)";
auth_alg(aes_xcbc)    -> "xcbc(aes)";
auth_alg(hmac_sha256) -> "hmac(sha256)";
auth_alg(hmac_sha384) -> "hmac(sha384)";
auth_alg(hmac_sha512) -> "hmac(sha512)";
auth_alg(_)           -> "hmac(sha256)".

auth_trunc_bits(hmac_sha1)   -> 96;
auth_trunc_bits(aes_xcbc)    -> 96;
auth_trunc_bits(hmac_sha256) -> 128;
auth_trunc_bits(hmac_sha384) -> 192;
auth_trunc_bits(hmac_sha512) -> 256;
auth_trunc_bits(_)           -> 128.
