%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the IKE_SA_INIT rejection path in epdg_ue_fsm:
%%% an INVALID_KE_PAYLOAD notify must carry the responder's accepted DH
%%% group as a two-octet big-endian integer (RFC 7296 §1.2) and go out
%%% with a zero responder SPI, so a UE that opened with an unsupported
%%% group (2, 5, 17, 18) can retry in one round trip instead of treating
%%% the mismatch as a hard missing-algorithm failure. Also covers the
%%% RFC 7296 §3.4 KE length check: a public value whose size does not
%%% match the agreed group is rejected as malformed.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_fsm_notify_tests).

-include_lib("eunit/include/eunit.hrl").

-define(NOTIFY_INVALID_KE_PAYLOAD, 17).
-define(NOTIFY_NO_PROPOSAL_CHOSEN, 14).

-define(ISPI, 16#0123456789ABCDEF).
-define(RSPI, 16#FEDCBA9876543210).

%%====================================================================
%% Helpers: build IKE_SA_INIT request payload maps (as decoded by
%% decode_payloads/2) with an SA offering MODP-2048 and a KE payload
%% for an arbitrary group.
%%====================================================================

%% Transforms: ENCR AES-CBC-128, PRF HMAC-SHA1, INTEG HMAC-SHA1-96, DH group.
sa_payload(DhGroup) ->
    TBin = <<3:8, 0:8, 12:16, 1:8, 0:8, 12:16, 1:1, 14:15, 128:16,
             3:8, 0:8,  8:16, 2:8, 0:8,  2:16,
             3:8, 0:8,  8:16, 3:8, 0:8,  2:16,
             0:8, 0:8,  8:16, 4:8, 0:8, DhGroup:16>>,
    PropLen = 8 + byte_size(TBin),
    <<0:8, 0:8, PropLen:16, 1:8, 1:8, 0:8, 4:8, TBin/binary>>.

request_payloads(SaDhGroup, KeDhGroup) ->
    request_payloads(SaDhGroup, KeDhGroup, 256).

request_payloads(SaDhGroup, KeDhGroup, KeLen) ->
    [#{type => sa,    data => sa_payload(SaDhGroup)},
     #{type => ke,    data => <<KeDhGroup:16, 0:16,
                                (crypto:strong_rand_bytes(KeLen))/binary>>},
     #{type => nonce, data => crypto:strong_rand_bytes(32)}].

decode_notify(RespBytes) ->
    {ok, #{next_payload := NextPL, payload_data := PayloadBin} = Header} =
        epdg_ikev2_codec:decode_header(RespBytes),
    {ok, [#{type := notify, data := NotifyData}]} =
        epdg_ikev2_codec:decode_payloads(NextPL, PayloadBin),
    <<Proto:8, SPISize:8, NotifyType:16, Rest/binary>> = NotifyData,
    <<_SPI:SPISize/binary, Data/binary>> = Rest,
    {Header, Proto, NotifyType, Data}.

%%====================================================================
%% A request that opened with KE group 2 while the SA offered a group
%% we support (14) yields {invalid_ke_payload, 14}.
%%====================================================================

ke_group_mismatch_selects_group_from_sa_test() ->
    Payloads = request_payloads(14, 2),
    ?assertEqual({error, {invalid_ke_payload, 14}},
                 epdg_ue_fsm:process_sa_init_payloads(Payloads)).

ke_group_match_proceeds_test() ->
    Payloads = request_payloads(14, 14),
    ?assertMatch({ok, #{suite := _, peer_dh_pub := _, nonce_i := _}},
                 epdg_ue_fsm:process_sa_init_payloads(Payloads)).

%%====================================================================
%% RFC 7296 §3.4: the KE public value length is fixed by the group —
%% MODP values are zero-padded to the modulus length. A wrong-length
%% value (like the truncated garbage KEs seen from internet scanners)
%% must be rejected as malformed, not fed into dh_compute.
%%====================================================================

ke_wrong_length_rejected_test() ->
    %% Group 14 agreed, but only 100 bytes of key data.
    Payloads = request_payloads(14, 14, 100),
    ?assertEqual({error, invalid_syntax},
                 epdg_ue_fsm:process_sa_init_payloads(Payloads)),
    %% One byte over is just as malformed.
    Payloads2 = request_payloads(14, 14, 257),
    ?assertEqual({error, invalid_syntax},
                 epdg_ue_fsm:process_sa_init_payloads(Payloads2)).

ke_correct_length_dh15_proceeds_test() ->
    %% MODP-3072: 384-byte public value passes the length check.
    Payloads = request_payloads(15, 15, 384),
    ?assertMatch({ok, #{suite := #{dh := #{id := 15}}}},
                 epdg_ue_fsm:process_sa_init_payloads(Payloads)),
    %% ...and a 256-byte one (group-14 sized) is rejected.
    Short = request_payloads(15, 15, 256),
    ?assertEqual({error, invalid_syntax},
                 epdg_ue_fsm:process_sa_init_payloads(Short)).

%%====================================================================
%% The INVALID_KE_PAYLOAD response: data = <<Group:16>>, responder
%% SPI = 0, message id echoed, response flag set.
%%====================================================================

invalid_ke_notify_layout_test() ->
    Resp = epdg_ue_fsm:build_notify_response(?ISPI, ?RSPI, 0,
                                             {invalid_ke_payload, 14}),
    {Header, Proto, NotifyType, Data} = decode_notify(Resp),
    ?assertEqual(?NOTIFY_INVALID_KE_PAYLOAD, NotifyType),
    ?assertEqual(<<14:16>>, Data),
    ?assertEqual(0, Proto),
    ?assertMatch(#{initiator_spi := ?ISPI,
                   responder_spi := 0,
                   exchange_type := ike_sa_init,
                   message_id := 0,
                   is_response := true}, Header).

invalid_ke_notify_carries_selected_group_test() ->
    %% The group threaded from the UE's own SA proposal wins over the
    %% default (here ECP-256, group 19).
    Resp = epdg_ue_fsm:build_notify_response(?ISPI, ?RSPI, 0,
                                             {invalid_ke_payload, 19}),
    {_, _, ?NOTIFY_INVALID_KE_PAYLOAD, Data} = decode_notify(Resp),
    ?assertEqual(<<19:16>>, Data).

%%====================================================================
%% Other rejection reasons keep their empty data and real RSPI.
%%====================================================================

no_proposal_chosen_unchanged_test() ->
    Resp = epdg_ue_fsm:build_notify_response(?ISPI, ?RSPI, 0,
                                             no_proposal_chosen),
    {Header, _, NotifyType, Data} = decode_notify(Resp),
    ?assertEqual(?NOTIFY_NO_PROPOSAL_CHOSEN, NotifyType),
    ?assertEqual(<<>>, Data),
    ?assertMatch(#{responder_spi := ?RSPI}, Header).
