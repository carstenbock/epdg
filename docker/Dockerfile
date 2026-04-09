FROM erlang:26-alpine

WORKDIR /app
COPY . .

RUN apk add --no-cache bash git build-base wget iproute2 ethtool libcap \
  && adduser -D -u 1000 epdg-user \
  && wget -qO- https://github.com/erlang/rebar3/releases/download/3.23.0/rebar3 \
       | install -m 0755 /dev/stdin /usr/local/bin/rebar3 \
  && rebar3 clean \
  && rebar3 as prod release

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

# Grant NET_ADMIN to the release binary so we can manage XFRM without root
RUN setcap cap_net_admin,cap_net_raw=eip /app/_build/prod/rel/epdg/erts-*/bin/beam.smp \
    || true

RUN mkdir -p /data && chown epdg-user:epdg-user /data

EXPOSE 500/udp 4500/udp 3868 2123/udp 8080

USER epdg-user
CMD ["/app/_build/prod/rel/epdg/bin/epdg", "foreground"]
