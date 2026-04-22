%%%-------------------------------------------------------------------
%%% @doc ETS-backed DNS resolver cache with honest TTL handling.
%%%
%%% Designed for long-lived clients that talk to services identified
%%% by FQDN (Kubernetes ClusterIP addresses can change when a Service
%%% or Pod is rescheduled). Callers look up an FQDN on every send path;
%%% the cache serves the previously-resolved address until its TTL
%%% expires, then falls back to `inet_res:resolve/2` to refresh.
%%%
%%% Callers that detect the peer has gone away (send error, Echo loss,
%%% Recovery-counter bump) must call `invalidate/1` so the next lookup
%%% re-resolves instead of handing out the stale cached value.
%%%
%%% All TTLs are clamped to `[MinTtl, MaxTtl]`. Both default to sensible
%%% values for CoreDNS (min 5 s, max 60 s) but can be overridden per
%%% lookup via the Opts map — callers can therefore tune TTLs per peer.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_dns_cache).

-behaviour(gen_server).

-export([start_link/0, lookup/1, lookup/2, invalidate/1, flush/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(TABLE, ?MODULE).
-define(DEFAULT_MIN_TTL, 5).
-define(DEFAULT_MAX_TTL, 60).
-define(DEFAULT_FAMILY,  inet).

-record(entry, {
    fqdn      :: string(),
    ip        :: inet:ip_address(),
    expires_at:: integer()
}).

%%====================================================================
%% API
%%====================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec lookup(string() | binary()) ->
    {ok, inet:ip_address()} | {error, term()}.
lookup(FQDN) -> lookup(FQDN, #{}).

-spec lookup(string() | binary(), map()) ->
    {ok, inet:ip_address()} | {error, term()}.
lookup(FQDN0, Opts) ->
    FQDN = to_str(FQDN0),
    Now  = erlang:system_time(second),
    case ets_lookup(FQDN) of
        {ok, #entry{ip = IP, expires_at = Exp}} when Exp > Now ->
            {ok, IP};
        _ ->
            resolve_and_cache(FQDN, Opts)
    end.

-spec invalidate(string() | binary()) -> ok.
invalidate(FQDN) ->
    Key = to_str(FQDN),
    catch ets:delete(?TABLE, Key),
    ok.

-spec flush() -> ok.
flush() ->
    catch ets:delete_all_objects(?TABLE),
    ok.

%%====================================================================
%% gen_server callbacks
%%====================================================================

init([]) ->
    ets:new(?TABLE, [named_table, public, set, {keypos, #entry.fqdn},
                     {read_concurrency, true}]),
    {ok, #{}}.

handle_call(_, _, S) -> {reply, ok, S}.
handle_cast(_, S)    -> {noreply, S}.
handle_info(_, S)    -> {noreply, S}.
terminate(_, _)      -> ok.
code_change(_, S, _) -> {ok, S}.

%%====================================================================
%% Internal
%%====================================================================

resolve_and_cache(FQDN, Opts) ->
    Family = maps:get(family, Opts, ?DEFAULT_FAMILY),
    MinTtl = maps:get(min_ttl, Opts, ?DEFAULT_MIN_TTL),
    MaxTtl = maps:get(max_ttl, Opts, ?DEFAULT_MAX_TTL),
    case resolve(FQDN, Family) of
        {ok, IP, Ttl0} ->
            Ttl = clamp(Ttl0, MinTtl, MaxTtl),
            Now = erlang:system_time(second),
            ets:insert(?TABLE,
                       #entry{fqdn = FQDN, ip = IP,
                              expires_at = Now + Ttl}),
            epdg_metrics_safe_inc(gtpc_dns_resolves_total),
            {ok, IP};
        {error, Why} = E ->
            epdg_metrics_safe_inc(gtpc_dns_resolve_errors_total),
            logger:warning("DNS cache: ~p resolve failed: ~p", [FQDN, Why]),
            E
    end.

clamp(N, Lo, _Hi) when N < Lo -> Lo;
clamp(N, _Lo, Hi) when N > Hi -> Hi;
clamp(N, _, _)                -> N.

%% If the FQDN happens to already be an IP literal, don't touch DNS.
resolve(Str, Family) ->
    case inet:parse_address(Str) of
        {ok, IP} ->
            %% No DNS → cache for the max TTL so we don't hammer
            %% inet:parse_address for each send.
            {ok, IP, ?DEFAULT_MAX_TTL};
        {error, _} ->
            resolve_via_dns(Str, Family)
    end.

resolve_via_dns(Str, Family) ->
    ResType = case Family of
        inet6 -> aaaa;
        _     -> a
    end,
    case inet_res:resolve(Str, in, ResType, [], 3000) of
        {ok, Msg} ->
            case pick_answer(Msg, ResType) of
                {ok, IP, Ttl} -> {ok, IP, Ttl};
                Err           -> fallback_getaddr(Str, Family, Err)
            end;
        {error, _} = E ->
            fallback_getaddr(Str, Family, E)
    end.

%% If inet_res can't tell us a TTL (or returns nothing), fall back to
%% inet:getaddr/2 and use the minimum TTL so we keep re-checking.
fallback_getaddr(Str, Family, _Reason) ->
    case inet:getaddr(Str, Family) of
        {ok, IP} -> {ok, IP, ?DEFAULT_MIN_TTL};
        E        -> E
    end.

pick_answer(Msg, ResType) ->
    try
        Answers = inet_dns:msg(Msg, anlist),
        case [{inet_dns:rr(RR, ttl), inet_dns:rr(RR, data)}
              || RR <- Answers,
                 inet_dns:rr(RR, type) =:= ResType] of
            [{Ttl, IP} | _] -> {ok, IP, Ttl};
            [] -> {error, no_answer}
        end
    catch _:_ -> {error, bad_dns_msg}
    end.

ets_lookup(FQDN) ->
    case catch ets:lookup(?TABLE, FQDN) of
        [E = #entry{}] -> {ok, E};
        _              -> none
    end.

to_str(S) when is_list(S)   -> S;
to_str(B) when is_binary(B) -> binary_to_list(B).

epdg_metrics_safe_inc(Metric) ->
    try epdg_metrics:inc(Metric)
    catch _:_ -> ok
    end.
