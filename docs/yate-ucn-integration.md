# ePDG ↔ yate-UCN integration: MME/SGW emulation for VoWiFi

Status: **design / decided, not yet implemented**
Scope: `carstenbock-epdg` (code) + `carstenbock-aaa_server` (unchanged) + `sipgate-deployment` (playbook already exists)

## Context

VoWiFi (untrusted non-3GPP access) on `epdg-lab01.dev.ml01.sipgatewireless.de`, deployed
by the combined playbook `aaa_server_epdg.yml` in `sipgate-deployment`. The PGW/core is
sipgate's existing **yate-UCN**; the HSS is the existing sipgate HSS.

## Problem

`carstenbock-epdg` implements only the standard untrusted-non-3GPP model:

```
UE --SWu (IKEv2/EAP-AKA')--> ePDG --S2b (GTPv2-C, TS 29.274)--> PGW
                              ePDG --SWm--> AAA --SWx--> HSS
```

yate-UCN's PGW does **not** implement the S2b reference point (nor S6b). Evidence in-repo:

- ePDG GTP-C is **S2b-only**: F-TEID interface types 30–33 in `epdg_gtpc_codec.erl`,
  RAT-Type WLAN(3), single anchoring path `epdg_ue_fsm:proceed_with_s2b/15` →
  `epdg_gtpc_client:create_session_request`. `epdg_config.erl` has no MME/S11/S5/S6a knobs.
- yate-UCN authorizes data sessions via its own **HTTP/JSON backend** (`ucn_auth_json.php`,
  see `yateucn-docker/docs/yate-ucn-http-auth.md`), whose `rat_type` enumerates
  1=UTRAN / 2=GERAN / 6=E-UTRAN — **no WLAN** — i.e. it expects the LTE session shape.

## Decision

The ePDG **emulates the LTE control plane (collapsed MME+SGW)** toward yate-UCN's PGW and
creates the PDN session over the **S5/S8** path the PGW already accepts, instead of S2b.
Subscriber authentication is **unchanged**: EAP-AKA' (SWu) → SWm → AAA → SWx → HSS.

This is a **GTP-C-only change ("Tier 1")**. It does **not** require an S6a Diameter client
in the ePDG ("Tier 2", explicitly ruled out below).

### Why Tier 2 (S6a / MME authentication) is NOT needed

Two authorizations are independent:

1. **Subscriber authentication** — EAP-AKA' (SWu) → SWm → AAA → SWx → HSS. Standard, unchanged.
2. **PGW session authorization** — done by yate's PGW itself at Create-Session via its HTTP/JSON
   backend, keyed on IMSI/APN. It does **not** require a prior S6a ULR / MME registration.

Even in a normal 4G attach these are decoupled: the PGW never verifies that an MME ran S6a;
it runs its own authorization. So as long as the UE is authenticated via the AAA path and the
ePDG sends a Create Session the PGW's HTTP auth approves, the bearer comes up. No S6a in the ePDG.

### Consequence: no S6b (PGW ↔ AAA)

Standard S2b VoWiFi has the PGW talk to the AAA over **S6b** (App-Id 16777272): PGW authorization,
APN-Config/AMBR, and the AAA reporting the served-PGW-ID to the HSS via SWx (Server-Assignment-Type
= PGW_UPDATE). The LTE path has no S6b. Therefore:

- The AAA's role shrinks to **SWm** (EAP relay from the ePDG) + **SWx** (to the HSS).
  `aaa_s6b_server.erl` is unused.
- There is **no AAA ↔ yate-UCN Diameter link** → no "secondary Diameter listener" on the UCN.

| S6b function (standard) | Covered in this design by |
|---|---|
| PGW session authorization | yate HTTP auth (per-session, IMSI/APN) |
| APN-Config / AMBR / policy to the PGW | yate HTTP auth response (`kbps_ul`/`kbps_dl`, `policy`) |
| AAA reports served-PGW-ID to the HSS (SWx PGW_UPDATE) | **NOT done — only genuine gap** |

The UE is still registered at the HSS (AAA SWx SAR REGISTRATION at auth time). The served-PGW-FQDN
won't be in the HSS record. Matters only if HSS-initiated detach / served-PGW tracking is required.
Lab: fine. Production: flag.

## Target architecture

```
UE --SWu (IKEv2/EAP-AKA')--> ePDG --SWm (DER/DEA)--> AAA --SWx (MAR/SAR)--> HSS
                              |
                              +-- S5/S8 GTPv2-C (emulated MME+SGW) --> yate-UCN PGW
                                  (yate authorizes via HTTP/JSON, keyed on IMSI/APN)
```

## Tier-1 change scope (`carstenbock-epdg`)

`epdg_gtpc_codec.erl`:
- Add S5/S8 F-TEID interface-type constants (TS 29.274 §8.22): SGW GTP-C = **6**, SGW GTP-U = **4**,
  PGW GTP-C = **7**, PGW GTP-U = **5** (today only S2b 30/31/32/33 exist).
- CSR encoder: emit local control F-TEID as iface **6** (was 30), bearer U-FTEID as iface **4** (was 31)
  and move that bearer F-TEID from **instance 5 → instance 2** (S5/S8-U SGW F-TEID; normatively fixed,
  TS 29.274 Table 7.2.1-2).
- CSR encoder: RAT-Type = **6 (E-UTRAN)** instead of 3 (WLAN).
- CSR encoder: the message must be a **complete, spec-conformant SGW-style CSR**. The existing encoder
  already emits IMSI/MSISDN/MEI/Serving-Network/APN/Selection-Mode/PDN-Type/PAA/APN-AMBR/Bearer-Context
  (+Bearer QoS) — all Conditional IEs whose condition ("E-UTRAN initial attach on S5/S8") our message
  satisfies, so they stay. The only likely **additions** are **ULI** (User-Location-Info) and possibly
  **Indication flags**. (Per TS 29.274 Table 7.2.1-1 only RAT-Type, Sender F-TEID-C, APN and
  Bearer-Contexts are *unconditionally* Mandatory; the rest are Conditional but required for our case —
  a strict PGW may reject if absent.) **Exact final set confirmed by the spike.**
- CSR response decoder: extract PGW F-TEIDs at iface **7/5** (was 32/33).

`epdg_gtpc_client.erl` / `epdg_ue_fsm.erl`:
- Thread RAT-Type 6 and the new interface roles through `create_session_request` /
  `proceed_with_s2b`.
- Make the GTP-C "mode" selectable (`s2b` vs `s5s8`) via an env knob in `epdg_config.erl`
  (e.g. `EPDG_GTPC_MODE`), so the image can target either an S2b SMF (Open5GS) or yate-UCN
  without a fork.

No new Diameter app, no AAA changes, no HSS changes.

## Prior art — this was PROVEN in a lab (the approach is not novel)

In **August 2024** sipgate built exactly this with Alexander Couzens (Osmocom), on this same box
(`edpg-lab01.dev.ml01.sipgatewireless.de`). They **hacked osmo-epdg to use S8 instead of S2b** toward
yate-UCN's PGW and got a real handset (Pixel 7a) onto VoWiFi. Source of truth:
`telco.docs.sipgate.cloud/classic-telco/mobile/vowifi/` (repo `sipgate/telco-docs`,
`pages/classic-telco/mobile/vowifi/index.md`) and `github.com/sipgate/osmo-epdg-ansible`
(`epdg.yml`: `epdg_gtpc_pgw_ip = ucn-ims01`, `epdg_swx_hss_ip = dra01.dev`; gtp_u_kmod `{role, sgsn}`).

**The single critical detail is confirmed:** the doc states (verbatim, translated) — *"Especially
important was changing the F-TEID Instance in the Bearer Context from 5 to 2. Otherwise YateUCN was
unhappy with 'Missing Mandatory IE' on the Create Session Request. The standard also says it should be
Instance 2 — cf. 3GPP TS 29.274, Table 7.2.1-2."* This is exactly the bearer F-TEID instance 5→2 change
in the Tier-1 scope above, and it is what made yate accept the session. The deep-research worry that a
PGW might reject an ePDG-as-SGW session ("Context Not Found"/peer state) **did not occur** — yate
accepted it once the CSR was well-formed.

Other lab facts to carry over:
- MSISDN and IMEI/IMEISV were **faked** — yate did not validate them, so plausible placeholders suffice.
- **IPv4-only** (Pixel 7a); osmo-epdg + kernel GTP lacked IPv6 → `EPDG_IPV6_ENABLED=false` is correct.
- P-CSCF address was **hard-coded in strongSwan** (worked around a bug); IMS/PCO path needs attention.
- Phones were attracted by repointing DNS for `epdg.mnc003/mnc007.mcc262.3gppnetwork.org` to the lab.
- Auth was the same chain we plan: ePDG —SWm→ AAA —SWx→ DRA → dep → HSS (xml), built on sipgate
  feature branches: `sparta-hss@feat/vowifi`, `sparta-yate-adapter@feat/s-wx-interface`,
  `sparta-protocol@feat/vowifi`, `sipgate-deployment@feat/sw-x-interface`.

Note: the osmo-epdg S8 patch itself was never published as a sipgate fork (lab-local), so for
`carstenbock-epdg` we re-implement the same change — but it is **de-risked**: the GTP-C dialect, the
instance-2 fix, and yate's acceptance are all already proven.

## Validation (largely de-risked — confirm, don't gate)

The Aug-2024 lab already proved yate accepts the S8/SGW-style CSR with bearer F-TEID instance 2, so this
is no longer a go/no-go gate. Remaining confirmation for `carstenbock-epdg`: capture the CSR our encoder
emits in `s5s8` mode and diff it against a known-good yate-accepted CSR to confirm the exact IE set
(ULI/Serving-Network/RAT-Type contents) for our codebase.

## Fallback (no new code)

If yate ever balks, point the ePDG at an **S2b-capable SMF (Open5GS)**: keep `EPDG_GTPC_MODE=s2b`
(default, unchanged) and set `PGW_FQDN` to the SMF. The lab notes list "maybe Open5GS for VoWiFi
parallel to YateUCN" as the same idea.

## Deployment status

- `aaa_server_epdg.yml` + `environments/dev/group_vars/epdg_lab.yml` deploy AAA + ePDG on epdg-lab01.
- ePDG `PGW_FQDN` is a flagged TODO pointing at yate-UCN; it won't interwork until Tier-1 lands.
- IKE/SWu, SWm→AAA and SWx→HSS-via-DRA are deployable now.

## Open questions / risks

1. Does yate's PGW accept an S5/S8 CSR directly from a collapsed MME+SGW? (spike)
2. Exact GRX/GTP interface + address for epdg-lab01 ↔ yate (TODO in group_vars).
3. Served-PGW-ID-to-HSS gap acceptable? (lab: yes; production: TBD)
4. Confirm yate expects no key material on the GTP path (EAP-AKA' CK'/IK' are used for the
   IPsec tunnel only; the bearer setup is IMSI/APN-keyed).
