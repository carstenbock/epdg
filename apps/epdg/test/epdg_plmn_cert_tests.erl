%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the IKE certificate per home PLMN (ADR-0045)
%%% and for loading a certificate chain.
%%%
%%% A UE checks the ePDG certificate against the ePDG FQDN it derived
%%% from its own IMSI (TS 33.402 §8.2.4.1, TS 23.003 §19.4.2.9.2) and
%%% against the CAs it trusts. Operators of different home PLMNs can use
%%% different CAs, so the ePDG must present each UE the certificate of
%%% that UE's home PLMN, and the IDr must name the same PLMN.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_plmn_cert_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PLATFORM, {"262", "24"}).

%%====================================================================
%% Choosing the home PLMN (shared by IDr and certificate)
%%====================================================================

home_plmn_of_an_additional_plmn_subscriber_test() ->
    ?assertEqual({"262", "22"},
                 epdg_config:home_plmn_for_imsi(<<"262220000000001">>, ?PLATFORM, "262-22")),
    ?assertEqual(platform,
                 epdg_config:home_plmn_for_imsi(<<"262240000000001">>, ?PLATFORM, "262-22")),
    ?assertEqual(platform,
                 epdg_config:home_plmn_for_imsi(undefined, ?PLATFORM, "262-22")).

%% An entry equal to the platform PLMN must not take the platform's own
%% (configured) IDr and certificate away from its subscribers.
home_plmn_prefers_the_platform_on_a_tie_test() ->
    ?assertEqual(platform,
                 epdg_config:home_plmn_for_imsi(<<"262240000000001">>, ?PLATFORM, "262-24")),
    ?assertEqual("epdg.custom.example",
                 epdg_config:ike_id_fqdn_for_imsi(<<"262240000000001">>, "epdg.custom.example",
                                                  ?PLATFORM, "262-24")).

%%====================================================================
%% Loading a chain
%%====================================================================

load_chain_returns_every_certificate_in_file_order_test() ->
    Dir = tmp_dir(),
    #{chain := Chain} = Pki = pki(),
    ?assert(length(Chain) > 2),
    write_pair(Dir, Pki),
    ?assertEqual({ok, Chain},
                 epdg_ikev2_crypto:load_certificate_chain(filename:join(Dir, "tls.crt"))).

load_chain_of_a_single_certificate_test() ->
    Dir = tmp_dir(),
    #{chain := [Own | _]} = pki(),
    File = filename:join(Dir, "single.crt"),
    ok = file:write_file(File, public_key:pem_encode([{'Certificate', Own, not_encrypted}])),
    ?assertEqual({ok, [Own]}, epdg_ikev2_crypto:load_certificate_chain(File)).

load_chain_rejects_a_file_without_certificates_test() ->
    Dir = tmp_dir(),
    File = filename:join(Dir, "empty.crt"),
    ok = file:write_file(File, <<"not a pem\n">>),
    ?assertEqual({error, no_certificate_in_pem}, epdg_ikev2_crypto:load_certificate_chain(File)).

%%====================================================================
%% Choosing the certificate
%%====================================================================

-define(DEFAULT, {[<<"default">>], default_key}).

plmn_with_its_own_certificate_gets_it_test() ->
    Dir = tmp_dir(),
    #{chain := Chain} = Pki = pki(),
    write_pair(filename:join(Dir, "262-22"), Pki),
    {Got, Key} = epdg_ue_fsm:plmn_certificate(Dir, {"262", "22"}, ?DEFAULT),
    ?assertEqual(Chain, Got),
    ?assertNotEqual(default_key, Key).

platform_subscriber_gets_the_default_certificate_test() ->
    Dir = tmp_dir(),
    write_pair(filename:join(Dir, "262-24"), pki()),
    ?assertEqual(?DEFAULT, epdg_ue_fsm:plmn_certificate(Dir, platform, ?DEFAULT)).

plmn_without_its_own_certificate_gets_the_default_test() ->
    Dir = tmp_dir(),
    write_pair(filename:join(Dir, "262-22"), pki()),
    ?assertEqual(?DEFAULT, epdg_ue_fsm:plmn_certificate(Dir, {"262", "25"}, ?DEFAULT)),
    ?assertEqual(?DEFAULT, epdg_ue_fsm:plmn_certificate("", {"262", "22"}, ?DEFAULT)).

%% A broken secret must not stop UEs that do not check the certificate
%% (EAP-only, RFC 5998); the error log names the PLMN.
plmn_with_an_unreadable_certificate_falls_back_to_the_default_test() ->
    Dir = tmp_dir(),
    PlmnDir = filename:join(Dir, "262-22"),
    ok = filelib:ensure_dir(filename:join(PlmnDir, "x")),
    ok = file:write_file(filename:join(PlmnDir, "tls.crt"), <<"garbage">>),
    ok = file:write_file(filename:join(PlmnDir, "tls.key"), <<"garbage">>),
    ?assertEqual(?DEFAULT, epdg_ue_fsm:plmn_certificate(Dir, {"262", "22"}, ?DEFAULT)).

%%====================================================================
%% Helpers
%%====================================================================

%% Own certificate followed by its CA certificates.
pki() ->
    #{server_config := Conf} =
        public_key:pkix_test_data(#{server_chain => #{root => [], intermediates => [[]], peer => []},
                                    client_chain => #{root => [], intermediates => [], peer => []}}),
    Own = proplists:get_value(cert, Conf),
    CaCerts = proplists:get_value(cacerts, Conf),
    {KeyType, KeyDer} = proplists:get_value(key, Conf),
    #{chain => [Own | CaCerts], key => {KeyType, KeyDer, not_encrypted}}.

write_pair(Dir, #{chain := Chain, key := Key}) ->
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    ok = file:write_file(filename:join(Dir, "tls.crt"),
                         public_key:pem_encode([{'Certificate', C, not_encrypted} || C <- Chain])),
    ok = file:write_file(filename:join(Dir, "tls.key"), public_key:pem_encode([Key])).

tmp_dir() ->
    Dir = filename:join([os:getenv("TMPDIR", "/tmp"), "epdg_plmn_cert_tests",
                         integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.
