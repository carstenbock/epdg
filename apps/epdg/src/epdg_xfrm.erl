%%%-------------------------------------------------------------------
%%% @doc Linux XFRM interface for kernel IPsec SA/SP management.
%%% Uses ip-xfrm commands; production should migrate to gen_netlink.
%%% Supports hardware offload detection (NIC inline / Intel QAT).
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_xfrm).

-behaviour(gen_server).

-export([start_link/0,
         create_sa/1, delete_sa/1, flush_sa_endpoint/1,
         create_policy/1, delete_policy/1,
         get_offload_mode/0, flush_all/0,
         list_sas/0, list_policies/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).
%% Pure `ip xfrm ... list` output parsers, exported for the EUnit suite
%% (epdg_xfrm_list_tests) and for callers that capture the output
%% themselves.
-export([parse_state_list/1, parse_policy_list/1]).

-define(SERVER, ?MODULE).

-record(state, {
    offload_mode :: none | inline | crypto,
    iface        :: string()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec create_sa(map()) -> ok | {error, term()}.
create_sa(Params) ->
    gen_server:call(?SERVER, {create_sa, Params}).

-spec delete_sa(map()) -> ok | {error, term()}.
delete_sa(Params) ->
    gen_server:call(?SERVER, {delete_sa, Params}).

%% Delete ALL ESP SAs matching a (src,dst) endpoint pair, regardless of
%% SPI. Used to make Child SA installation idempotent per UE outer
%% endpoint (see install_child_sas/10 in epdg_ue_fsm).
-spec flush_sa_endpoint(map()) -> ok | {error, term()}.
flush_sa_endpoint(Params) ->
    gen_server:call(?SERVER, {flush_sa_endpoint, Params}).

-spec create_policy(map()) -> ok | {error, term()}.
create_policy(Params) ->
    gen_server:call(?SERVER, {create_policy, Params}).

-spec delete_policy(map()) -> ok | {error, term()}.
delete_policy(Params) ->
    gen_server:call(?SERVER, {delete_policy, Params}).

-spec get_offload_mode() -> none | inline | crypto.
get_offload_mode() ->
    gen_server:call(?SERVER, get_offload_mode).

-spec flush_all() -> ok.
flush_all() ->
    gen_server:call(?SERVER, flush_all).

%% Inventory of the kernel's ESP SAs: one map per SA with the OUTER
%% endpoints, SPI and reqid. Used by epdg_xfrm_reconciler to find
%% orphaned states (no live UE FSM claims the SPI) and by the session
%% restore path to decide adopt-vs-reinstall after a pod restart.
%% Goes through the gen_server so reads serialise with mutations.
-spec list_sas() -> [#{src := inet:ip_address(), dst := inet:ip_address(),
                       spi := non_neg_integer(), reqid := non_neg_integer()}].
list_sas() ->
    gen_server:call(?SERVER, list_sas).

%% Inventory of the kernel's XFRM policies: selector src/dst (CIDR
%% strings, exactly as `ip xfrm policy' prints them so delete_policy/1
%% round-trips), direction, and the first template's outer endpoints +
%% reqid. Socket policies are skipped.
-spec list_policies() -> [#{src := string(), dst := string(),
                            dir := in | out | fwd,
                            tmpl_src := inet:ip_address() | undefined,
                            tmpl_dst := inet:ip_address() | undefined,
                            reqid := non_neg_integer()}].
list_policies() ->
    gen_server:call(?SERVER, list_policies).

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    Iface = epdg_config:get(ipsec_iface, "eth0"),
    OffloadCfg = epdg_config:get(ipsec_offload, "auto"),

    Mode = case OffloadCfg of
        "auto"   -> detect_hw_offload(Iface);
        "none"   -> none;
        "inline" -> inline;
        "crypto" -> crypto;
        _        -> none
    end,

    logger:info("XFRM: offload_mode=~p iface=~s", [Mode, Iface]),
    {ok, #state{offload_mode = Mode, iface = Iface}}.

handle_call({create_sa, Params}, _From, State) ->
    {reply, do_create_sa(Params, State), State};
handle_call({delete_sa, Params}, _From, State) ->
    {reply, do_delete_sa(Params), State};
handle_call({flush_sa_endpoint, Params}, _From, State) ->
    {reply, do_flush_sa_endpoint(Params), State};
handle_call({create_policy, Params}, _From, State) ->
    {reply, do_create_policy(Params), State};
handle_call({delete_policy, Params}, _From, State) ->
    {reply, do_delete_policy(Params), State};
handle_call(get_offload_mode, _From, #state{offload_mode = M} = State) ->
    {reply, M, State};
handle_call(flush_all, _From, State) ->
    os:cmd("ip xfrm state flush 2>/dev/null"),
    os:cmd("ip xfrm policy flush 2>/dev/null"),
    {reply, ok, State};
handle_call(list_sas, _From, State) ->
    Out = os:cmd("ip xfrm state list 2>/dev/null"),
    {reply, parse_state_list(Out), State};
handle_call(list_policies, _From, State) ->
    Out = os:cmd("ip xfrm policy list 2>/dev/null"),
    {reply, parse_policy_list(Out), State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) -> {noreply, State}.
handle_info(_Info, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

%%====================================================================
%% SA management
%%====================================================================

do_create_sa(#{spi := SPI, src_ip := Src, dst_ip := Dst,
               enc_alg := EncAlg, enc_key := EncKey} = Params,
             #state{offload_mode = Offload, iface = Iface}) ->
    %% Algorithm names like `cbc(aes)` and `hmac(sha256)` contain `(` / `)`
    %% which are shell metacharacters. Wrap them in single quotes so that
    %% `os:cmd/1` (which invokes `/bin/sh -c`) passes them verbatim to
    %% `ip xfrm`. Without the quoting the shell aborts with a "syntax
    %% error: unexpected (" before `ip` is ever spawned and the SA silently
    %% never installs — the UE would then complete IKE_AUTH but all ESP
    %% packets would be dropped by the kernel (no matching state).
    %% Use `auth-trunc` with the explicit truncation length mandated by
    %% the IKEv2 integrity transform. `ip xfrm ... auth ALGO KEY` defaults
    %% to a hard-coded 96-bit ICV for every algorithm, which is correct
    %% for `hmac(sha1)` but WRONG for the SHA-2 family:
    %%   AUTH_HMAC_SHA2_256_128 (RFC 4868) wants 128-bit ICV
    %%   AUTH_HMAC_SHA2_384_192                   192-bit ICV
    %%   AUTH_HMAC_SHA2_512_256                   256-bit ICV
    %% With a wrong ICV length the kernel drops every inbound ESP packet
    %% (`XfrmInStateProtoError`) and produces outbound ESP the UE cannot
    %% authenticate — IKE succeeds, data plane silently breaks.
    AuthPart = case maps:find(auth_alg, Params) of
        {ok, none} -> "";
        {ok, AuthAlg} ->
            AuthKey  = maps:get(auth_key, Params, <<>>),
            TruncLen = auth_trunc_bits(AuthAlg),
            io_lib:format(" auth-trunc '~s' 0x~s ~B",
                          [auth_alg_str(AuthAlg), bin2hex(AuthKey), TruncLen]);
        error -> ""
    end,

    %% NAT-T encapsulation (RFC 3948): when the peer is behind a NAT
    %% (detected during IKE_SA_INIT via NAT_DETECTION_*_IP payloads)
    %% ESP packets ride inside UDP/4500. Pass nat_t=true with the UE's
    %% outer UDP source port (the NAT-mapped port) + local UDP port
    %% (4500 unless customised).
    EncapPart = case maps:get(nat_t, Params, false) of
        true ->
            %% `ip xfrm ... encap espinudp <sport> <dport> <oaddr>` maps
            %% positionally to the SA's encap_sport / encap_dport. The
            %% kernel builds the *outbound* UDP header from
            %% encap_sport → encap_dport (esp_output); on input it
            %% de-encapsulates purely by SPI, so the inbound ordering is
            %% cosmetic. The ports MUST therefore follow the SA direction:
            %%   outbound (ePDG → UE): src = our 4500, dst = UE NAT port
            %%   inbound  (UE → ePDG): src = UE NAT port, dst = our 4500
            %% A single fixed ordering for both directions emitted downlink
            %% ESP from the wrong source port to the wrong UE port, which a
            %% port-translating NAT then dropped.
            LocalPort = maps:get(local_udp_port, Params, 4500),
            PeerPort  = maps:get(peer_udp_port,  Params, 4500),
            PeerOuter = maps:get(peer_outer_ip,  Params, Src),
            {Sport, Dport} = case maps:get(sa_dir, Params, in) of
                out -> {LocalPort, PeerPort};
                _   -> {PeerPort, LocalPort}
            end,
            io_lib:format(" encap espinudp ~B ~B ~s",
                          [Sport, Dport, ip_str(PeerOuter)]);
        false -> ""
    end,

    %% reqid binds this SA to its UE-specific XFRM policy template. With
    %% multiple UEs behind one public IP (CGNAT / a shared home router)
    %% the outer (src,dst) tuple is identical, so a reqid-0 wildcard let
    %% the kernel resolve a co-NAT'd UE's outbound SA for the wrong UE. A
    %% unique per-UE reqid keeps each UE's policy bound to its own SA pair
    %% (same model strongSwan / Open5GS use for multi-UE-behind-NAT).
    ReqidPart = case maps:get(reqid, Params, 0) of
        R when is_integer(R), R > 0 -> io_lib:format(" reqid ~B", [R]);
        _ -> ""
    end,

    %% ESN (RFC 4304, negotiated via the IKEv2 ESN transform): set the
    %% XFRM_STATE_ESN flag so the kernel runs 64-bit extended sequence
    %% numbers. iproute2 requires a non-zero replay window together with
    %% the esn flag (it is carried in XFRMA_REPLAY_ESN_VAL); without ESN
    %% we keep the kernel's default replay handling untouched.
    EsnPart = case maps:get(esn, Params, false) of
        true  -> " flag esn replay-window 128";
        false -> ""
    end,

    %% `flag af-unspec' leaves the SA's selector family unset. Without it
    %% the kernel pins x->sel.family to the SA's own family (the OUTER
    %% addresses, IPv4 here) in xfrm_state_construct/1, and every inner
    %% IPv6 packet the SA decrypts is then rejected by xfrm_policy_ok/5
    %% with XfrmInStateMismatch. One SA pair has to carry both families
    %% for an IPv4v6 PDN; family selection belongs to the per-/64 policies,
    %% not the SA. strongSwan sets the same flag unconditionally.
    Cmd = io_lib:format(
        "ip xfrm state add src ~s dst ~s proto esp spi 0x~.16B~s~s "
        "enc '~s' 0x~s~s~s mode tunnel flag af-unspec",
        [ip_str(Src), ip_str(Dst), SPI, ReqidPart, EsnPart,
         enc_alg_str(EncAlg), bin2hex(EncKey), AuthPart, EncapPart]),

    OffloadPart = case Offload of
        inline -> io_lib:format(" offload packet dev ~s", [Iface]);
        crypto -> io_lib:format(" offload crypto dev ~s", [Iface]);
        none   -> ""
    end,

    case run_cmd(lists:flatten([Cmd, OffloadPart])) of
        ok ->
            epdg_metrics:inc(xfrm_sa_created_total),
            epdg_metrics:gauge_inc(xfrm_sa_active),
            ok;
        E -> E
    end;

do_create_sa(_, _) ->
    {error, invalid_params}.

do_delete_sa(#{spi := SPI, src_ip := Src, dst_ip := Dst}) ->
    Cmd = io_lib:format(
        "ip xfrm state delete src ~s dst ~s proto esp spi 0x~.16B",
        [ip_str(Src), ip_str(Dst), SPI]),
    _ = run_cmd(lists:flatten(Cmd)),
    epdg_metrics:inc(xfrm_sa_deleted_total),
    epdg_metrics:gauge_dec(xfrm_sa_active),
    ok;
do_delete_sa(#{spi := SPI}) ->
    Cmd = io_lib:format("ip xfrm state deleteall spi 0x~.16B 2>/dev/null", [SPI]),
    _ = run_cmd(lists:flatten(Cmd)),
    epdg_metrics:inc(xfrm_sa_deleted_total),
    epdg_metrics:gauge_dec(xfrm_sa_active),
    ok;
do_delete_sa(_) ->
    {error, invalid_params}.

%% Purge every ESP SA for a (src,dst) endpoint pair. `ip xfrm state
%% deleteall` filters by the supplied selectors (here src/dst/proto),
%% so this removes any stale SAs left over from a UE IKE_AUTH retransmit
%% or a re-dial whose previous FSM did not tear down cleanly — without
%% needing to know their (random responder) SPIs.
do_flush_sa_endpoint(#{src_ip := Src, dst_ip := Dst}) ->
    Cmd = io_lib:format(
        "ip xfrm state deleteall src ~s dst ~s proto esp 2>/dev/null",
        [ip_str(Src), ip_str(Dst)]),
    _ = run_cmd(lists:flatten(Cmd)),
    ok;
do_flush_sa_endpoint(_) ->
    {error, invalid_params}.

%%====================================================================
%% Policy management
%%====================================================================

do_create_policy(#{src := Src, dst := Dst, direction := Dir,
                   tmpl_src := TSrc, tmpl_dst := TDst} = Params) ->
    %% `update` (create-or-replace), not `add` (create-exclusive): a UE
    %% that re-dials onto the SAME inner IP must REBIND its policy to the
    %% new Child SA's reqid. `add` returned EEXIST ("File exists") and
    %% silently kept the stale template pointing at the old, now-deleted
    %% reqid, which black-holed the downlink. The reqid pins the template
    %% to this UE's SA pair (see do_create_sa/2).
    Reqid = maps:get(reqid, Params, 0),
    Cmd = io_lib:format(
        "ip xfrm policy update src ~s dst ~s dir ~s "
        "tmpl src ~s dst ~s proto esp reqid ~B mode tunnel",
        [Src, Dst, dir_str(Dir), ip_str(TSrc), ip_str(TDst), Reqid]),
    run_cmd(lists:flatten(Cmd));
do_create_policy(_) ->
    {error, invalid_params}.

do_delete_policy(#{src := Src, dst := Dst, direction := Dir}) ->
    Cmd = io_lib:format(
        "ip xfrm policy delete src ~s dst ~s dir ~s",
        [Src, Dst, dir_str(Dir)]),
    run_cmd(lists:flatten(Cmd));
do_delete_policy(_) ->
    {error, invalid_params}.

%%====================================================================
%% Hardware offload detection
%%====================================================================

detect_hw_offload(Iface) ->
    Cmd = io_lib:format("ethtool -k ~s 2>/dev/null | grep esp-hw-offload", [Iface]),
    case os:cmd(lists:flatten(Cmd)) of
        "esp-hw-offload: on" ++ _ -> inline;
        _ ->
            case filelib:is_file("/dev/qat_adf_ctl") of
                true  -> crypto;
                false -> none
            end
    end.

%%====================================================================
%% Helpers
%%====================================================================

run_cmd(Cmd) ->
    case os:cmd(Cmd ++ " 2>&1") of
        ""    -> ok;
        Error -> {error, list_to_binary(Error)}
    end.

enc_alg_str(aes_cbc_128)       -> "cbc(aes)";
enc_alg_str(aes_cbc_192)       -> "cbc(aes)";
enc_alg_str(aes_cbc_256)       -> "cbc(aes)";
enc_alg_str(aes_gcm_128)       -> "rfc4106(gcm(aes))";
enc_alg_str(aes_gcm_192)       -> "rfc4106(gcm(aes))";
enc_alg_str(aes_gcm_256)       -> "rfc4106(gcm(aes))";
enc_alg_str(chacha20_poly1305) -> "rfc7539esp(chacha20,poly1305)";
enc_alg_str(_)                 -> "cbc(aes)".

auth_alg_str(hmac_sha1)   -> "hmac(sha1)";
auth_alg_str(aes_xcbc)    -> "xcbc(aes)";
auth_alg_str(hmac_sha256) -> "hmac(sha256)";
auth_alg_str(hmac_sha384) -> "hmac(sha384)";
auth_alg_str(hmac_sha512) -> "hmac(sha512)";
auth_alg_str(_)           -> "hmac(sha256)".

%% Kernel ICV truncation length (in bits) for each IKEv2 integrity
%% transform, per RFC 4868 / RFC 2404 / RFC 3566.
auth_trunc_bits(hmac_sha1)   -> 96;
auth_trunc_bits(aes_xcbc)    -> 96;
auth_trunc_bits(hmac_sha256) -> 128;
auth_trunc_bits(hmac_sha384) -> 192;
auth_trunc_bits(hmac_sha512) -> 256;
auth_trunc_bits(_)           -> 128.

dir_str(in)  -> "in";
dir_str(out) -> "out";
dir_str(fwd) -> "fwd".

ip_str({A,B,C,D}) ->
    io_lib:format("~B.~B.~B.~B", [A,B,C,D]);
ip_str({A,B,C,D,E,F,G,H}) ->
    inet:ntoa({A,B,C,D,E,F,G,H});
ip_str(S) when is_list(S) -> S;
ip_str(B) when is_binary(B) -> binary_to_list(B).

bin2hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0B", [B]) || <<B>> <= Bin]).

%%====================================================================
%% `ip xfrm ... list` output parsers
%%
%% Both parsers scan line-wise: an SA / policy block starts with an
%% UNINDENTED "src ... dst ..." line, everything indented (tab or
%% space) belongs to the current block. Fields are located by keyword
%% so extra tokens (priority, ptype, flags, if_id, ...) never break
%% the parse. Blocks missing a mandatory field are dropped rather
%% than guessed at — the reconciler must never delete on a misparse.
%%====================================================================

-spec parse_state_list(string()) ->
          [#{src := inet:ip_address(), dst := inet:ip_address(),
             spi := non_neg_integer(), reqid := non_neg_integer()}].
parse_state_list(Output) ->
    Blocks = split_blocks(Output),
    lists:filtermap(fun parse_state_block/1, Blocks).

parse_state_block([Head | Body]) ->
    HeadWords = string:lexemes(Head, " \t"),
    case {parse_addr_after("src", HeadWords),
          parse_addr_after("dst", HeadWords)} of
        {{ok, Src}, {ok, Dst}} ->
            %% "proto esp spi 0x05974942 reqid 93800770 mode tunnel"
            BodyWords = lists:append([string:lexemes(L, " \t") || L <- Body]),
            case {word_after("spi", BodyWords),
                  lists:member("esp", BodyWords)} of
                {{ok, "0x" ++ SpiHex}, true} ->
                    Reqid = case word_after("reqid", BodyWords) of
                        {ok, R} -> to_int(R, 0);
                        error   -> 0
                    end,
                    {true, #{src => Src, dst => Dst,
                             spi => list_to_integer(SpiHex, 16),
                             reqid => Reqid}};
                _ ->
                    false
            end;
        _ ->
            false
    end.

-spec parse_policy_list(string()) ->
          [#{src := string(), dst := string(), dir := in | out | fwd,
             tmpl_src := inet:ip_address() | undefined,
             tmpl_dst := inet:ip_address() | undefined,
             reqid := non_neg_integer()}].
parse_policy_list(Output) ->
    Blocks = split_blocks(Output),
    lists:filtermap(fun parse_policy_block/1, Blocks).

parse_policy_block([Head | Body]) ->
    HeadWords = string:lexemes(Head, " \t"),
    case {word_after("src", HeadWords), word_after("dst", HeadWords)} of
        {{ok, Src}, {ok, Dst}} ->
            BodyLines = [string:lexemes(L, " \t") || L <- Body],
            %% "dir in|out|fwd priority N" — socket policies print
            %% "socket in|out" instead and are skipped here.
            Dir = lists:foldl(
                    fun(Words, undefined) ->
                            case word_after("dir", Words) of
                                {ok, "in"}  -> in;
                                {ok, "out"} -> out;
                                {ok, "fwd"} -> fwd;
                                _           -> undefined
                            end;
                       (_, Acc) -> Acc
                    end, undefined, BodyLines),
            %% First template: "tmpl src A dst B" then
            %% "proto esp reqid N mode tunnel" on the next line.
            {TmplSrc, TmplDst} = first_tmpl(BodyLines),
            Reqid = first_tmpl_reqid(BodyLines),
            case Dir of
                undefined -> false;
                _ ->
                    {true, #{src => Src, dst => Dst, dir => Dir,
                             tmpl_src => TmplSrc, tmpl_dst => TmplDst,
                             reqid => Reqid}}
            end;
        _ ->
            false
    end.

first_tmpl([]) -> {undefined, undefined};
first_tmpl([["tmpl" | Rest] | _]) ->
    S = case parse_addr_after("src", Rest) of
        {ok, A} -> A;
        _       -> undefined
    end,
    D = case parse_addr_after("dst", Rest) of
        {ok, B} -> B;
        _       -> undefined
    end,
    {S, D};
first_tmpl([_ | T]) -> first_tmpl(T).

%% The reqid of the FIRST template, from the first "... reqid N ..."
%% line that follows a "tmpl" line.
first_tmpl_reqid(BodyLines) ->
    first_tmpl_reqid(BodyLines, false).

first_tmpl_reqid([], _SeenTmpl) -> 0;
first_tmpl_reqid([["tmpl" | _] | T], _) -> first_tmpl_reqid(T, true);
first_tmpl_reqid([Words | T], true) ->
    case word_after("reqid", Words) of
        {ok, R} -> to_int(R, 0);
        error   -> first_tmpl_reqid(T, true)
    end;
first_tmpl_reqid([_ | T], false) -> first_tmpl_reqid(T, false).

%% Group output lines into blocks: a block starts at every unindented
%% line, indented lines extend the current block.
split_blocks(Output) ->
    Lines = [L || L <- string:split(Output, "\n", all), string:trim(L) =/= ""],
    lists:reverse(lists:foldl(
      fun([C | _] = Line, Acc) when C =:= $\t; C =:= $\s ->
              case Acc of
                  [Cur | Rest] -> [Cur ++ [Line] | Rest];
                  []           -> []   %% indented line before any block: drop
              end;
         (Line, Acc) ->
              [[Line] | Acc]
      end, [], Lines)).

word_after(_Key, []) -> error;
word_after(Key, [Key, Next | _]) -> {ok, Next};
word_after(Key, [_ | T]) -> word_after(Key, T).

%% The word after Key, parsed as an IP address (SA endpoints and policy
%% templates print bare addresses; selectors print CIDR and would fail
%% here on purpose).
parse_addr_after(Key, Words) ->
    case word_after(Key, Words) of
        {ok, S} ->
            case inet:parse_address(S) of
                {ok, IP} -> {ok, IP};
                _        -> error
            end;
        error -> error
    end.

to_int(S, Default) ->
    case string:to_integer(S) of
        {N, ""} when is_integer(N) -> N;
        _ -> Default
    end.
