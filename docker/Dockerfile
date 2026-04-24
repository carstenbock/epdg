FROM erlang:26-alpine

WORKDIR /app
COPY . .

RUN apk add --no-cache bash git build-base wget iproute2 ethtool libcap lksctp-tools linux-headers \
  && adduser -D -u 1000 epdg-user \
  && wget -qO- https://github.com/erlang/rebar3/releases/download/3.23.0/rebar3 \
       | install -m 0755 /dev/stdin /usr/local/bin/rebar3 \
  && rebar3 clean \
  && rebar3 as prod release

# Compile the TUN port-driver helper used by epdg_gtpu_forwarder to
# bridge per-UE TUN devices to the GTP-U socket. The binary is a tiny
# stdio bridge; see apps/epdg/c_src/epdg_tun_port.c for the protocol.
RUN cc -O2 -Wall -Wextra \
        -o /app/_build/prod/rel/epdg/bin/epdg_tun_port \
        /app/apps/epdg/c_src/epdg_tun_port.c

# Diameter identity
ENV EPDG_ORIGIN_REALM="mnc001.mcc001.3gppnetwork.org"

# IKEv2
ENV EPDG_IKE_BIND_ADDR="0.0.0.0"
ENV EPDG_IKE_PORT="500"
ENV EPDG_IKE_NATT_PORT="4500"

# EAP method: aka or aka-prime
ENV EPDG_EAP_METHOD="aka-prime"

# IPsec XFRM offload: auto | none | inline | crypto
ENV EPDG_IPSEC_OFFLOAD="auto"
ENV EPDG_IPSEC_IFACE="eth0"

# GTP-C S2b
ENV EPDG_GTPC_BIND_ADDR="0.0.0.0"
ENV EPDG_GTPC_PORT="2123"
ENV PGW_ADDR=""
ENV PGW_PORT="2123"

# Diameter SWm toward AAA Server via DRA
ENV DRA_HOST="dra-diameter"
ENV DRA_PORT="3868"
ENV DRA_TRANSPORT="tcp"
ENV EPDG_DIAMETER_PORT="3868"

# PLMN
ENV MCC="001"
ENV MNC="01"

# HTTP API
ENV EPDG_API_PORT="8080"

# The XFRM / TUN data plane is driven from Erlang via `os:cmd("ip …")`,
# which execs `/bin/sh -c "ip …"`. We need CAP_NET_ADMIN / CAP_NET_RAW to
# survive across that exec chain. Two approaches were tried:
#
#   (a) `setcap cap_net_admin,cap_net_raw=eip` on beam.smp + uid=1000.
#       File caps on beam give the beam those caps, but on execve() of
#       `/bin/sh` (no file caps, non-root uid) the kernel resets
#       P'(permitted) = (P(inh) & F(inh)) | (F(perm) & bset) = 0, so
#       the `ip` grandchild ends up with CapPrm=CapEff=0.
#   (b) `setcap =ep` on /sbin/ip itself. On this kernel / containerd /
#       overlayfs combination the `security.capability` xattr is
#       preserved by `getcap` but *not* honored at exec time for the
#       non-root user — the `ip` process still starts with CapPrm=0 and
#       `ip xfrm state add` returns `RTNETLINK answers: Operation not
#       permitted`.
#
# The robust path — and the standard pattern for telco pods that drive
# kernel IPsec — is to run the container as root (uid=0) with only
# NET_ADMIN / NET_RAW in the bounding set. For a root process execing a
# "capability-dumb" binary (no file caps xattr) the kernel treats
# F(permitted) as the bounding set, so every child `exec` keeps
# CapPrm=CapEff covering NET_ADMIN + NET_RAW — exactly what `ip xfrm`
# and `ip tuntap` need. The container is still unprivileged (everything
# outside those two caps is dropped via the pod securityContext).
RUN mkdir -p /data

EXPOSE 500/udp 4500/udp 3868 2123/udp 8080

CMD ["/app/_build/prod/rel/epdg/bin/epdg", "foreground"]
