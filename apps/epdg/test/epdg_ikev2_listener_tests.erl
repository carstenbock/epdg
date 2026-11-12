%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the unprotected INVALID_IKE_SPI answer to a
%%% message for an unknown IKE SA (RFC 7296 §2.21.4, KI-137).
%%%
%%% Why it matters: after an ePDG restart a phone keeps sending DPD and
%%% other requests on its lost IKE SA. The answer only helps if the phone
%%% can match it to that SA: same SPIs and Message ID, a response, not
%%% encrypted, carrying INVALID_IKE_SPI. A wrong flag or a missing copy
%%% makes the phone drop it and wait for its own timeouts again.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ikev2_listener_tests).

-include_lib("eunit/include/eunit.hrl").

-define(INFORMATIONAL, 37).
-define(PL_NOTIFY, 41).

request_header() ->
    {ok, H} = epdg_ikev2_codec:decode_header(
                epdg_ikev2_codec:encode_header(
                  #{initiator_spi => 16#1122334455667788,
                    responder_spi => 16#AF4956A4FC37DA3D,
                    next_payload => 46,
                    exchange_type_raw => ?INFORMATIONAL,
                    flags => 16#08,              % request from the initiator
                    message_id => 7,
                    payload_bin => <<0:32>>})),
    H.

response_copies_spis_and_message_id_test() ->
    Bin = epdg_ikev2_listener:invalid_ike_spi_response(request_header()),
    {ok, R} = epdg_ikev2_codec:decode_header(Bin),
    ?assertEqual(16#1122334455667788, maps:get(initiator_spi, R)),
    ?assertEqual(16#AF4956A4FC37DA3D, maps:get(responder_spi, R)),
    ?assertEqual(7, maps:get(message_id, R)),
    ?assertEqual(?INFORMATIONAL, maps:get(exchange_type_raw, R)),
    ?assertEqual(byte_size(Bin), maps:get(length, R)).

response_is_a_response_from_the_responder_test() ->
    Bin = epdg_ikev2_listener:invalid_ike_spi_response(request_header()),
    {ok, R} = epdg_ikev2_codec:decode_header(Bin),
    ?assert(maps:get(is_response, R)),
    ?assertNot(maps:get(is_initiator, R)).

response_is_unprotected_invalid_ike_spi_notify_test() ->
    Bin = epdg_ikev2_listener:invalid_ike_spi_response(request_header()),
    {ok, #{next_payload := NP, payload_data := PD}} =
        epdg_ikev2_codec:decode_header(Bin),
    %% Not an SK payload: the IKE SA and its keys are gone.
    ?assertEqual(?PL_NOTIFY, NP),
    {ok, [#{type := notify, data := N}]} =
        epdg_ikev2_codec:decode_payloads(NP, PD),
    %% Protocol ID 0, SPI size 0, Notify type 4 (INVALID_IKE_SPI), no data.
    ?assertEqual(<<0:8, 0:8, 4:16>>, N).

rate_cap_test() ->
    W0 = {10, 0},
    {Allowed, WEnd} = lists:foldl(
        fun(_, {Acc, W}) ->
            {Ok, W1} = epdg_ikev2_listener:invalid_spi_allowed(10, W),
            {[Ok | Acc], W1}
        end, {[], W0}, lists:seq(1, 150)),
    %% 100 answers in one second, the rest refused ...
    ?assertEqual(100, length([x || true <- Allowed])),
    %% ... and the next second starts afresh.
    ?assertMatch({true, {11, 1}},
                 epdg_ikev2_listener:invalid_spi_allowed(11, WEnd)).
