%% Length of the IPv6 prefix a PDN connection gets. 3GPP fixes this at /64
%% (TS 23.401 §5.3.1.2.2): the network assigns the prefix, the UE picks its
%% own interface identifier within it. Everything that touches a UE's IPv6
%% inner address — XFRM selectors, CFG_REPLY, handover PAA, GTP-U uplink
%% attribution, pool validation — must derive from this one value.
-define(UE6_PREFIX_LEN, 64).
