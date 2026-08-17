#!/bin/sh
# Integration test for the shared-TUN datapath: registering N UEs with
# the GTP-U forwarder must not change the node's policy-rule count. The
# legacy datapath added 2-4 `ip rule` entries per UE, which disabled the
# kernel FIB fast path and collided route-table ids at scale; the shared
# datapath installs a constant rule set at startup only.
#
# Run inside a running ePDG pod/container on a LAB deployment (the test
# registers and unregisters synthetic bearers on the live forwarder):
#
#   ./scripts/test-shared-tun-scale.sh [num_ues]
#
# Environment:
#   EPDG_BIN     path to the relx start script
#                (default: /app/_build/prod/rel/epdg/bin/epdg)
#   POOL_PREFIX  first two octets of a configured IPv4 UE pool
#                (default: 10.46 — the default ims APN pool)

set -eu

NUM=${1:-1000}
EPDG_BIN=${EPDG_BIN:-/app/_build/prod/rel/epdg/bin/epdg}
POOL_PREFIX=${POOL_PREFIX:-10.46}

rules_now() {
    expr "$(ip rule list | wc -l)" + "$(ip -6 rule list | wc -l)"
}

BEFORE=$(rules_now)

"$EPDG_BIN" eval "
    [A, B] = [list_to_integer(X) || X <- string:split(\"$POOL_PREFIX\", \".\")],
    Base = 16#40000000,
    lists:foreach(fun(I) ->
        Ip = {A, B, I div 250, (I rem 250) + 1},
        {ok, _} = epdg_gtpu_forwarder:register_ue(#{
            pgw_u_teid => I, pgw_u_ip => {127,0,0,1},
            ue_inner_ip => Ip, imsi => <<\"scaletest\">>,
            local_teid_hint => Base + I})
    end, lists:seq(1, $NUM)).
"

AFTER=$(rules_now)

"$EPDG_BIN" eval "
    Base = 16#40000000,
    lists:foreach(fun(I) ->
        ok = epdg_gtpu_forwarder:unregister_ue(Base + I)
    end, lists:seq(1, $NUM)).
"

FINAL=$(rules_now)

echo "ip rules: before=$BEFORE after_register=$AFTER after_unregister=$FINAL"
if [ "$BEFORE" -ne "$AFTER" ] || [ "$BEFORE" -ne "$FINAL" ]; then
    echo "FAIL: rule count changed while registering/unregistering $NUM UEs" >&2
    exit 1
fi
echo "PASS: rule count constant across $NUM UE registrations"
