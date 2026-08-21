%%%-------------------------------------------------------------------
%%% @doc Regression net for the IKE_SA_INIT `proposal #N … transforms=…`
%%% notice: a wide transform set (3 ENCRs × 3 key lengths + 5 INTEGs +
%%% 5 PRFs + 6 DH groups) must survive our formatter and the
%%% logger_formatter config pinned in sys.config with the last token
%%% (`dh:31`) intact. OTP 26 already leaves chars_limit/depth/max_size
%%% unlimited; this test locks that in so a later overlay cannot clip
%%% the diagnostic line customers grep.
%%% @end
%%%-------------------------------------------------------------------
-module(epdg_ue_fsm_proposal_log_tests).

-include_lib("eunit/include/eunit.hrl").

%% Matches apps/epdg/sys.config kernel.logger formatter map.
-define(PINNED_FORMATTER_CFG,
        #{legacy_header => true,
          single_line => false,
          chars_limit => unlimited,
          depth => unlimited,
          max_size => unlimited}).

%%====================================================================
%% Widest realistic IKE SA proposal dump
%%====================================================================

wide_transforms() ->
    Encrs = [#{type => encr, id => E, attrs => #{key_length => KL}}
             || E <- [12, 19, 20], KL <- [128, 192, 256]],
    Integs = [#{type => integ, id => I, attrs => #{}}
              || I <- [2, 5, 12, 13, 14]],
    Prfs = [#{type => prf, id => P, attrs => #{}}
            || P <- [2, 4, 5, 6, 7]],
    Dhs = [#{type => dh, id => G, attrs => #{}}
           || G <- [2, 5, 14, 15, 16, 31]],
    Encrs ++ Integs ++ Prfs ++ Dhs.

log_event({Fmt, Args}) ->
    #{level => notice,
      msg => {Fmt, Args},
      meta => #{time => logger:timestamp(),
                pid => self(),
                gl => group_leader()}}.

format_through(Cfg, Event) ->
    unicode:characters_to_binary(logger_formatter:format(Event, Cfg)).

%%====================================================================
%% Full pipeline: our iolist ~s formatter + pinned logger_formatter.
%% The last DH token must be present; a chars_limit of 80 (the knob
%% that would have produced a mid-token cut like `encr:19/keyle`)
%% is the positive control that the assertion is looking at the
%% formatter output, not a short prefix.
%%====================================================================

wide_proposal_notice_not_truncated_test() ->
    Transforms = wide_transforms(),
    ?assertEqual(25, length(Transforms)),
    {Fmt, Args} = epdg_ue_fsm:format_proposal_notice(1, 1, Transforms),
    %% Contract: transforms stay an iolist (lists:join of io_lib:format
    %% results), interpolated with ~s — not flattened, not ~P/~W.
    ?assertEqual("  proposal #~B proto=~B transforms=~s", Fmt),
    [1, 1, Joined] = Args,
    ?assert(is_list(Joined)),
    Event = log_event({Fmt, Args}),

    Pinned = format_through(?PINNED_FORMATTER_CFG, Event),
    ?assertEqual(nomatch, binary:match(Pinned, <<"...">>)),
    ?assertMatch({_, _}, binary:match(Pinned, <<"dh:31">>)),

    %% Kernel's default handler (no sys.config logger key) uses the
    %% same layout and already passes the line through untruncated.
    {ok, HC} = logger:get_handler_config(default),
    {logger_formatter, DefaultCfg} = maps:get(formatter, HC),
    DefaultOut = format_through(DefaultCfg, Event),
    ?assertMatch({_, _}, binary:match(DefaultOut, <<"dh:31">>)),

    %% Sensitivity: the same event clipped at 80 chars loses dh:31.
    Clipped = format_through(DefaultCfg#{chars_limit => 80, max_size => 80},
                             Event),
    ?assertEqual(80, byte_size(Clipped)),
    ?assertEqual(nomatch, binary:match(Clipped, <<"dh:31">>)).
