-module(epdg_xfrm_reconciler_tests).
-include_lib("eunit/include/eunit.hrl").

%% Tests for the pure sweep planner (epdg_xfrm_reconciler:plan/4).
%%
%% The property that matters: the reconciler must NEVER delete kernel
%% state that a live session claims, and must never delete unclaimed
%% state before it has been continuously unclaimed for a full grace
%% period. Deleting too eagerly tears down a mid-handshake UE (the
%% grace period plus the claim-first ordering in install_child_sas is
%% the protection); deleting too lazily merely leaks — so every rule
%% below errs toward keeping.

-define(GRACE, 30000).

sa(N) -> {sa, {10,0,0,N}, {34,107,29,11}, 16#1000 + N}.

%% A claimed item is never deleted and never accumulates a pending mark
%% (even if a previous sweep had marked it — e.g. the session restore
%% path re-claimed it between sweeps).
claimed_is_kept_and_unmarked_test() ->
    Pending = #{sa(1) => 0},
    {Delete, NewPending} =
        epdg_xfrm_reconciler:plan([{sa(1), true}], Pending, ?GRACE * 2, ?GRACE),
    ?assertEqual([], Delete),
    ?assertEqual(#{}, NewPending).

%% First sighting of an unclaimed item only marks it — a UE FSM that
%% crashed a millisecond ago (or a race with claim registration) must
%% get the full grace period before its kernel state is touched.
unclaimed_new_is_marked_not_deleted_test() ->
    {Delete, NewPending} =
        epdg_xfrm_reconciler:plan([{sa(1), false}], #{}, 1000, ?GRACE),
    ?assertEqual([], Delete),
    ?assertEqual(#{sa(1) => 1000}, NewPending).

%% Continuously unclaimed for >= grace -> deleted, mark dropped.
unclaimed_aged_is_deleted_test() ->
    Pending = #{sa(1) => 1000},
    {Delete, NewPending} =
        epdg_xfrm_reconciler:plan([{sa(1), false}], Pending,
                                  1000 + ?GRACE, ?GRACE),
    ?assertEqual([sa(1)], Delete),
    ?assertEqual(#{}, NewPending).

%% Just under the grace period -> still kept, original first-seen
%% timestamp preserved (age accumulates across sweeps; it does not
%% reset per sweep).
unclaimed_under_grace_keeps_first_seen_test() ->
    Pending = #{sa(1) => 1000},
    {Delete, NewPending} =
        epdg_xfrm_reconciler:plan([{sa(1), false}], Pending,
                                  1000 + ?GRACE - 1, ?GRACE),
    ?assertEqual([], Delete),
    ?assertEqual(#{sa(1) => 1000}, NewPending).

%% An item that vanished from the kernel between sweeps must not keep a
%% stale mark: if the same key reappears later (SPI reuse), its grace
%% period starts over.
vanished_item_forgets_mark_test() ->
    Pending = #{sa(1) => 1000},
    {Delete, NewPending} =
        epdg_xfrm_reconciler:plan([{sa(2), false}], Pending,
                                  2000, ?GRACE),
    ?assertEqual([], Delete),
    ?assertEqual(#{sa(2) => 2000}, NewPending).

%% Mixed sweep: one live session, one aged orphan, one fresh orphan.
mixed_sweep_test() ->
    Pending = #{sa(2) => 0},
    Items = [{sa(1), true}, {sa(2), false}, {sa(3), false}],
    {Delete, NewPending} =
        epdg_xfrm_reconciler:plan(Items, Pending, ?GRACE, ?GRACE),
    ?assertEqual([sa(2)], Delete),
    ?assertEqual(#{sa(3) => ?GRACE}, NewPending).
