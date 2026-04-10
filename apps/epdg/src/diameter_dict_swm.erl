%%%-------------------------------------------------------------------
%%% @doc Diameter dictionary proxy for SWm (TS 29.273).
%%% Application-ID 16777264. Delegates encoding/decoding to base
%%% RFC 6733 dictionary; overrides id/0 so the Erlang diameter
%%% framework registers the correct Application-ID for CER/CEA
%%% negotiation and fires peer_up/peer_down callbacks.
%%% @end
%%%-------------------------------------------------------------------
-module(diameter_dict_swm).

-export([name/0, id/0, vendor_id/0, vendor_name/0]).
-export([msg_name/2, msg_header/1, rec2msg/1, msg2rec/1,
         name2rec/1, avp_name/2, avp_arity/1, avp_arity/2,
         avp_header/1, avp/3, grouped_avp/3, enumerated_avp/3,
         empty_value/2, dict/0]).

-define(BASE, diameter_gen_base_rfc6733).

id()          -> 16777264.
vendor_id()   -> 10415.
vendor_name() -> '3GPP'.
name()        -> 'SWm'.

msg_name(CC, R)         -> ?BASE:msg_name(CC, R).
msg_header(N)           -> ?BASE:msg_header(N).
rec2msg(R)              -> ?BASE:rec2msg(R).
msg2rec(M)              -> ?BASE:msg2rec(M).
name2rec(N)             -> ?BASE:name2rec(N).
avp_name(C, V)          -> ?BASE:avp_name(C, V).
avp_arity(M)            -> ?BASE:avp_arity(M).
avp_arity(M, A)         -> ?BASE:avp_arity(M, A).
avp_header(A)           -> ?BASE:avp_header(A).
avp(T, D, A)            -> ?BASE:avp(T, D, A).
grouped_avp(T, D, A)    -> ?BASE:grouped_avp(T, D, A).
enumerated_avp(T, A, V) -> ?BASE:enumerated_avp(T, A, V).
empty_value(M, A)       -> ?BASE:empty_value(M, A).
dict()                  -> ?BASE:dict().
