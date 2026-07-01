%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the RFC 5685 REDIRECT codec helpers in
%%% epdg_ikev2_codec: notify-data byte layout, encode/decode round-trip,
%%% and config-target parsing.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_codec_redirect_tests).

-include_lib("eunit/include/eunit.hrl").

%% RFC 5685 §6 GW Ident Type values.
-define(GW_IPV4, 1).
-define(GW_IPV6, 2).
-define(GW_FQDN, 3).

%%====================================================================
%% encode_redirect_notify_data/3 exact byte layout
%%====================================================================

encode_ipv4_layout_test() ->
    Ident = <<192, 0, 2, 10>>,
    Data = epdg_ikev2_codec:encode_redirect_notify_data(?GW_IPV4, Ident, <<>>),
    %% GW Ident Type (1) | GW Ident Len (1) | GW Identity (4)
    ?assertEqual(<<?GW_IPV4:8, 4:8, 192, 0, 2, 10>>, Data).

encode_ipv6_layout_test() ->
    Ident = <<16#20,16#01,16#0d,16#b8, 0,0,0,0, 0,0,0,0, 0,0,0,1>>,
    Data = epdg_ikev2_codec:encode_redirect_notify_data(?GW_IPV6, Ident, <<>>),
    ?assertEqual(<<?GW_IPV6:8, 16:8, Ident/binary>>, Data),
    %% Type + Len header, then exactly 16 identity octets, no nonce.
    ?assertEqual(18, byte_size(Data)).

encode_fqdn_layout_test() ->
    Fqdn = <<"epdg.example.net">>,
    Data = epdg_ikev2_codec:encode_redirect_notify_data(?GW_FQDN, Fqdn, <<>>),
    Len = byte_size(Fqdn),
    ?assertEqual(<<?GW_FQDN:8, Len:8, Fqdn/binary>>, Data).

%% SA_INIT case (RFC 5685 §5): the client Ni is appended verbatim after the
%% identity, and the length byte still counts only the identity.
encode_fqdn_with_nonce_test() ->
    Fqdn = <<"epdg.example.net">>,
    Nonce = <<1,2,3,4,5,6,7,8>>,
    Data = epdg_ikev2_codec:encode_redirect_notify_data(?GW_FQDN, Fqdn, Nonce),
    Len = byte_size(Fqdn),
    ?assertEqual(<<?GW_FQDN:8, Len:8, Fqdn/binary, Nonce/binary>>, Data),
    ?assertEqual(2 + Len + byte_size(Nonce), byte_size(Data)).

%%====================================================================
%% encode -> decode round-trip
%%====================================================================

roundtrip_ipv4_test() ->
    Ident = <<10, 47, 0, 5>>,
    Data = epdg_ikev2_codec:encode_redirect_notify_data(?GW_IPV4, Ident, <<>>),
    ?assertEqual({ok, {?GW_IPV4, Ident, <<>>}},
                 epdg_ikev2_codec:decode_redirect_notify_data(Data)).

roundtrip_fqdn_with_nonce_test() ->
    Fqdn = <<"pod-b.epdg.svc.cluster.local">>,
    Nonce = crypto:strong_rand_bytes(24),
    Data = epdg_ikev2_codec:encode_redirect_notify_data(?GW_FQDN, Fqdn, Nonce),
    ?assertEqual({ok, {?GW_FQDN, Fqdn, Nonce}},
                 epdg_ikev2_codec:decode_redirect_notify_data(Data)).

decode_rejects_garbage_test() ->
    ?assertMatch({error, _}, epdg_ikev2_codec:decode_redirect_notify_data(<<>>)),
    %% Length byte claims 8 identity octets but only 2 are present.
    ?assertMatch({error, _},
                 epdg_ikev2_codec:decode_redirect_notify_data(<<?GW_IPV4:8, 8:8, 1, 2>>)).

%%====================================================================
%% parse_redirect_target/1
%%====================================================================

parse_ipv4_test() ->
    ?assertEqual({ok, {?GW_IPV4, <<192, 0, 2, 1>>}},
                 epdg_ikev2_codec:parse_redirect_target("192.0.2.1")).

parse_ipv6_test() ->
    {ok, {Type, Ident}} = epdg_ikev2_codec:parse_redirect_target("2001:db8::1"),
    ?assertEqual(?GW_IPV6, Type),
    ?assertEqual(16, byte_size(Ident)),
    ?assertEqual(<<16#20,16#01,16#0d,16#b8, 0,0,0,0, 0,0,0,0, 0,0,0,1>>, Ident).

parse_fqdn_test() ->
    ?assertEqual({ok, {?GW_FQDN, <<"epdg-b.example.net">>}},
                 epdg_ikev2_codec:parse_redirect_target("epdg-b.example.net")).

parse_fqdn_trims_whitespace_test() ->
    ?assertEqual({ok, {?GW_FQDN, <<"epdg-b.example.net">>}},
                 epdg_ikev2_codec:parse_redirect_target("  epdg-b.example.net  ")).

parse_empty_is_error_test() ->
    ?assertMatch({error, _}, epdg_ikev2_codec:parse_redirect_target("")),
    ?assertMatch({error, _}, epdg_ikev2_codec:parse_redirect_target("   ")).

%% The parsed target feeds straight into the notify encoder.
parse_then_encode_test() ->
    {ok, {Type, Ident}} = epdg_ikev2_codec:parse_redirect_target("203.0.113.7"),
    Data = epdg_ikev2_codec:encode_redirect_notify_data(Type, Ident, <<>>),
    ?assertEqual(<<?GW_IPV4:8, 4:8, 203, 0, 113, 7>>, Data).
