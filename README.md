<div align="center">

# Enhanced PFCP Packet Generator

**Scenario-driven PFCP (N4) traffic generator, fault injector and compliance checker for 5G core testing.**

[![CI](https://github.com/cem8kaya/pfcp_packet_generator/actions/workflows/ci.yml/badge.svg)](https://github.com/cem8kaya/pfcp_packet_generator/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/cem8kaya/pfcp_packet_generator)](LICENSE)
![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
[![Scapy](https://img.shields.io/badge/built%20with-Scapy-orange)](https://scapy.net/)
[![3GPP TS 29.244](https://img.shields.io/badge/3GPP-TS%2029.244-success)](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3111)
[![Tests](https://img.shields.io/badge/tests-116%20passing-brightgreen)](tests)
[![Issues](https://img.shields.io/github/issues/cem8kaya/pfcp_packet_generator)](https://github.com/cem8kaya/pfcp_packet_generator/issues)
[![Last commit](https://img.shields.io/github/last-commit/cem8kaya/pfcp_packet_generator)](https://github.com/cem8kaya/pfcp_packet_generator/commits)
[![Sponsor](https://img.shields.io/badge/sponsor-%E2%9D%A4-ff69b4)](.github/FUNDING.yml)

</div>

---

## Table of contents

- [Why PFCP matters](#why-pfcp-matters)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Command line](#command-line)
  - [Python API](#python-api)
  - [Traffic profiles](#traffic-profiles)
  - [Fault and anomaly injection](#fault-and-anomaly-injection)
  - [Compliance checking](#compliance-checking)
  - [Analysing the output](#analysing-the-output)
- [Project layout](#project-layout)
- [Supported messages and IEs](#supported-messages-and-ies)
- [Enhancement plan status](#enhancement-plan-status)
- [Limitations](#limitations)
- [Testing](#testing)
- [Contributing](#contributing)
- [License and contact](#license-and-contact)

## Why PFCP matters

PFCP (Packet Forwarding Control Protocol, [3GPP TS 29.244](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3111)) is the **N4 interface** protocol between the 5G core's SMF (control plane) and UPF (user plane). Every PDU session, QoS rule, usage report and paging trigger is installed and reported through it, so a PFCP defect can interrupt data services or break charging. Realistic and *deliberately broken* PFCP traffic is therefore essential for functional, interoperability, robustness and security testing of 5G cores, probes and IDS systems.

This tool uses [Scapy](https://scapy.net/) to build spec-aligned PFCP messages and write them to PCAP files.

<img width="518" alt="PFCP packet forwarding model (Navarro do Amaral et al. 2022, fig. 5)" src="https://github.com/user-attachments/assets/77d983c0-9b8b-455e-b9a3-58fd5371edb3">

*Packet forwarding model in PFCP (Navarro do Amaral et al. 2022, fig. 5).*

![Main PFCP procedures (ETSI 2023c, table 7.3-1)](https://github.com/user-attachments/assets/6c2688a0-ed80-49d5-b483-79e6fcec1dea)

*Main PFCP procedures (ETSI 2023c, table 7.3-1).*

## Features

| Area | Highlights |
|---|---|
| **Session lifecycle** | State machine (illegal transitions rejected), consistent SEIDs / sequence numbers, Association, Heartbeat, Session Establishment / Modification / Deletion / Report, PFD Management, Node Report |
| **5G elements** | QFI, S-NSSAI slicing, DNN / network instance, PDU session type, QoS (MBR/GBR/gate status), URSP-derived rules |
| **Usage reporting** | Volume / time / periodic triggers, Query URR, Usage Reports in Report / Modification / Deletion messages |
| **Forwarding** | FORW with outer header creation, DROP, BUFF/NOCP paging path, DUPL, forwarding policy |
| **Resources** | UPF- or CP-allocated F-TEIDs (sequential, random, TEID range), UPF pool with capacity / slice matching / 4 selection strategies |
| **Transport** | IPv4 and IPv6, optional ESP-protected N4, node allow-list authentication |
| **Traffic modelling** | Presets (`embb`, `urllc`, `miot`, `voice`), custom JSON profiles, constant / Poisson / burst timing |
| **Fault injection** | Burst loss, outages, ICMP unreachable, duplication, jitter, corruption, 22 protocol anomalies, stateful failure scenarios, ground-truth log |
| **Compliance** | Header, mandatory IE, cause, rule-consistency and request/response checks on generated or captured PCAPs |

## Installation

```bash
git clone https://github.com/cem8kaya/pfcp_packet_generator.git
cd pfcp_packet_generator
python -m venv .venv && source .venv/bin/activate   # optional
pip install -r requirements.txt
```

Requirements: Python 3.8+, [Scapy](https://scapy.net/) (includes the PFCP contribution), `cryptography` (only for `--ipsec`), `pytest` (tests).

## Usage

### Command line

```bash
python -m pfcp_gen --help
python -m pfcp_gen generate <scenario> [options]
python -m pfcp_gen check <file.pcap>
python -m pfcp_gen inject <file.pcap> --faults <preset|plan.json>
python -m pfcp_gen faults        # list fault presets and anomalies
python -m pfcp_gen profiles      # list traffic profiles
```

**Scenarios:** `lifecycle` `paging` `multi` `slices` `restart` `errors` `usage` `appdetect` `mixed` `flap` `storm` `orphan`

| Option | Meaning |
|---|---|
| `-n, --count N` | Repetitions / session count (scenario dependent) |
| `-o, --output FILE` | Output PCAP (default `pfcp.pcap`) |
| `--profile NAME\|FILE` | `embb` (default), `urllc`, `miot`, `voice`, or a JSON file |
| `--seed N` | Reproducible output |
| `--ipv6` | IPv6 transport and addresses |
| `--ipsec` | Wrap N4 in ESP |
| `--ursp` | Add URSP-derived PDRs |
| `--upfs N` / `--upf-strategy S` | UPF pool size / `round_robin`, `least_loaded`, `weighted`, `random` |
| `--fteid MODE` | `up` (UPF allocates), or CP strategy `sequential`, `random`, `range` |
| `--trusted ID...` | Node ID allow-list (untrusted peers get Cause 64) |
| `--faults PLAN` | Inject faults (preset or JSON) |
| `--fault-log FILE` | Write ground-truth JSON |
| `--check` | Run the compliance checker on the output |

Examples:

```bash
python -m pfcp_gen generate lifecycle -n 5 -o out.pcap --check
python -m pfcp_gen generate paging --profile urllc --upfs 3 --fteid range --seed 42
python -m pfcp_gen generate mixed -n 10 --ipv6 --ipsec
python -m pfcp_gen generate errors -o errors.pcap
python -m pfcp_gen generate mixed -n 10 --faults congested_backhaul --fault-log gt.json -o faulty.pcap
```

### Python API

```python
from pfcp_gen import PFCPSimulator, ComplianceChecker

sim = PFCPSimulator(cp_ip="192.0.2.1", profile="urllc", seed=1)
sim.lifecycle(reports=3, with_paging=True)   # assoc -> session -> usage -> paging -> delete
sim.write("session.pcap")

violations = ComplianceChecker().check_packets(sim.packets)
print(len(violations), "findings")
```

The original stateless `RobustPFCPPacketGenerator` in `pfcp_packet_generator.py` remains available (`python pfcp_packet_generator.py`).

### Traffic profiles

Built-in presets are listed with `python -m pfcp_gen profiles`; examples for custom profiles are in [`profiles/`](profiles). Fields include `qfi` (1..63), `mbr_*`, `gbr_*`, `dnn`, `sst`/`sd`, `volume_threshold`, `time_threshold`, `timing` (`constant`/`poisson`/`burst`) and more. Invalid values (e.g. a 5QI used as QFI, GBR above MBR) are rejected.

```bash
python -m pfcp_gen generate lifecycle --profile profiles/miot.json
```

### Fault and anomaly injection

`pfcp_gen/faults.py` injects faults modelled on real N4 behaviour and writes a **ground-truth log** (time, layer, fault, detail, expected peer behaviour, packet index) so probes, IDS rules and dissectors can be scored.

| Layer | What is injected | Realistic consequence generated |
|---|---|---|
| Network | Gilbert-Elliott burst loss, plain loss, outage windows, duplication, jitter / delay spikes / reordering, bit corruption (stale UDP checksum) | Requester retransmits the identical request every T1 = 3 s up to N1 = 3 (TS 29.244 §7.2.1); an already-answered peer replays its cached response; exhausted retries log `exchange_failed` |
| Network | UPF process down (host up) | ICMP / ICMPv6 port-unreachable instead of silence |
| Protocol, request | missing mandatory / nested IE, invalid QFI, GBR > MBR, zero TEID, bad IE length, unknown SEID | Rejection with the proper Cause (66, 69, 73 + Failed Rule ID, 68, 65) and Offending IE |
| Protocol, request | wrong header length, S-flag mismatch, truncation, unknown message type | Silent discard, then retransmission |
| Protocol, request | wrong PFCP version | Version Not Supported Response |
| Protocol, request | unknown optional IE, duplicate IE, IE reorder, trailing bytes | Tolerated: original response kept (interop tests) |
| Protocol, response | undefined Cause, accepted without UP F-SEID, Recovery Time Stamp jump / regression, wrong sequence / SEID | Unmatched responses force retransmission + replay; others flagged by the checker |
| Scenario | `flap`, `storm`, `orphan` | Heartbeat flapping, signalling storm (Cause 74 + overload timer + retry), silent UPF restart (Cause 65 + re-establish) |

**Presets:** `congested_backhaul` `lossy_link` `upf_process_down` `link_outage` `buggy_peer` `interop_tolerance` `fuzz_framing` `restart_anomalies` `chaos`

Custom plan (`--faults plan.json`):

```json
{
  "name": "my-plan",
  "seed": 7,
  "network": {"loss": 0.02, "jitter_ms": 3, "tap": "receiver"},
  "protocol": [
    {"fault": "missing_mandatory_ie", "probability": 0.1, "messages": [50]},
    {"fault": "rsp_peer_restart", "probability": 0.2, "messages": [2]}
  ]
}
```

For response-side faults, `messages` are *response* types; the logged `message_type` is the exchange's request type. `tap: "receiver"` hides lost packets, as a probe at the receiving side would see.

### Compliance checking

```bash
python -m pfcp_gen check capture.pcap     # exit code 1 on errors
```

Checks: PFCP version / length / S-flag, SEID rules, mandatory IEs per message, defined Cause values, rule consistency (GBR ≤ MBR, QFI 1..63, FORW needs forwarding parameters, unique IDs), IE length integrity, round-trip encoding, request/response pairing.

### Analysing the output

- **Wireshark:** open the PCAP and use the display filter `pfcp`.
- **tshark:** `tshark -r out.pcap -Y pfcp -V`
- **Scapy:** `rdpcap("out.pcap")` for programmatic analysis.
- Fault logs are plain JSON and can be joined with probe output on packet `index`.

## Project layout

| Path | Purpose |
|---|---|
| `pfcp_gen/ies.py` | IE builders (PDR/FAR/QER/URR/BAR, PDI, S-NSSAI, usage report, PFD, IPv4/IPv6) |
| `pfcp_gen/state.py` | Session state machine, F-TEID allocator, UPF pool |
| `pfcp_gen/profiles.py` | Traffic profiles and timing models |
| `pfcp_gen/simulator.py` | Message exchanges and composite scenarios |
| `pfcp_gen/faults.py` | Fault / anomaly injector and failure scenarios |
| `pfcp_gen/security.py` | Node allow-list and ESP protection |
| `pfcp_gen/compliance.py` | TS 29.244 compliance checker |
| `pfcp_gen/__main__.py` | CLI |
| `profiles/*.json` | Example custom traffic profiles |
| `tests/` | Test suite |
| `pfcp_packet_generator.py` | Original stateless generator |

## Supported messages and IEs

**Messages (TS 29.244 §7.4, §7.5):** Heartbeat, PFD Management, Association Setup / Update / Release, Node Report, Session Set Deletion, Version Not Supported, Session Establishment / Modification / Deletion / Report (request and response).

**IEs:** Node ID (IPv4/IPv6/FQDN), F-SEID, F-TEID (incl. CHOOSE), UE IP Address, Create/Update/Remove PDR, FAR, QER, URR, BAR, PDI, SDF Filter, Application ID, Outer Header Creation/Removal, Forwarding Parameters/Policy, MBR/GBR/QFI/Gate Status, Usage Report and measurement IEs, Downlink Data Report, Application Detection Information, PFD contents, Cause, Offending IE, Failed Rule ID, Overload Control Information, Recovery Time Stamp, UP/CP function features, User Plane IP Resource Information, and S-NSSAI (IE 257, implemented here because Scapy lacks it).

## Enhancement plan status

Project board: <https://github.com/users/cem8kaya/projects/4> · Pull request: [#24](https://github.com/cem8kaya/pfcp_packet_generator/pull/24)

| # | Item | Status |
|---|---|---|
| 1 | Complex IEs (Create/Update/Remove PDR, FAR, QER, URR) | ✅ |
| 2 | Session lifecycle state machine | ✅ |
| 3 | Session Report and additional message types | ✅ |
| 4 | QoS handling | ✅ |
| 5 | Usage reporting | ✅ |
| 6 | 5G-specific IEs (QFI, S-NSSAI, DNN) | ✅ |
| 7 | Traffic patterns and timing | ✅ |
| 8 | Network slicing | ✅ |
| 9 | Failure handling and recovery | ✅ |
| 10 | Packet forwarding scenarios | ✅ |
| 11 | Error scenarios | ✅ |
| 12 | F-TEID allocation | ✅ |
| 13 | Buffering and paging | ✅ |
| 14 | UPF selection and load balancing | ✅ |
| 15 | Application detection and control | ✅ |
| 16 | IPv6 support | ✅ |
| 17 | Security (allow-list auth, ESP-protected N4) | ✅ |
| 18 | URSP integration (N4-visible effects) | ✅ |
| 19 | Customizable traffic profiles | ✅ |
| 20 | Compliance checking | ✅ |
| – | Fault and anomaly injector (beyond original plan) | ✅ |

## Limitations

- Control-plane simulation only; no user-plane (GTP-U) traffic.
- PFCP has no native authentication: node authentication is simulated with an allow-list plus optional ESP wrapping (3GPP specifies transport-level protection).
- URSP is a NAS/PCF construct; only its UPF-side consequences appear in PFCP.
- Compliance tables cover Rel-15/16 mandatory IEs, not every conditional rule of TS 29.244; Ethernet PDU sessions, MBS and Rel-17+ IEs are not modelled.
- Fault injection does not causally delay or suppress later messages of a session after an earlier exchange fails; ESP-protected traffic is passed through untouched.
- Output has not been validated against a Wireshark dissector in CI (round-trip through Scapy is tested).

## Testing

```bash
pip install -r requirements.txt
pytest -q tests      # 116 tests, ~1 min
```

CI runs the suite on Python 3.9–3.12 ([workflow](.github/workflows/ci.yml)).

## Contributing

Contributions are welcome. Please open an [issue](https://github.com/cem8kaya/pfcp_packet_generator/issues) to discuss larger changes, keep the existing code style, and include tests for new behaviour (`pytest -q tests` must pass). Pull requests: <https://github.com/cem8kaya/pfcp_packet_generator/pulls>.

## License and contact

Released under the [MIT License](LICENSE). Contact: [cem8kaya@gmail.com](mailto:cem8kaya@gmail.com).

## References

- 3GPP TS 29.244, *Interface between the Control Plane and the User Plane nodes*
- 3GPP TS 23.501 / 23.502, *5G System architecture and procedures*
- Navarro do Amaral et al. (2022); ETSI (2023c)
