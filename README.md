# Enhanced PFCP Packet Generator


## Description

The Enhanced PFCP (Packet Forwarding Control Protocol) Packet Generator is a Python-based tool designed for creating and manipulating PFCP packets. It's primarily used for testing and simulating 5G core network environments. Leveraging the Scapy library, this tool generates various PFCP messages compliant with 3GPP TS 29.244 specifications, offering a flexible and powerful solution for developers and testers working with 5G core network components.


What's the packet forwarding model in PFCP? (Source: Navarro do Amaral et al. 2022, fig. 5)


<img width="518" alt="image" src="https://github.com/user-attachments/assets/77d983c0-9b8b-455e-b9a3-58fd5371edb3">


Which are the main procedures in PFCP? (Source: ETSI 2023c, table 7.3-1.)


![image](https://github.com/user-attachments/assets/6c2688a0-ed80-49d5-b483-79e6fcec1dea)


# Enhanced PFCP Packet Generator

## Description

The Enhanced PFCP (Packet Forwarding Control Protocol) Packet Generator is a Python-based tool designed for creating and manipulating PFCP packets. It's primarily used for testing and simulating 5G core network environments. Leveraging the Scapy library, this tool generates various PFCP messages compliant with 3GPP TS 29.244 specifications, offering a flexible and powerful solution for developers and testers working with 5G core network components.

## Supported Features and 3GPP Notations

### Supported PFCP Message Types

1. Association Setup Request/Response (Section 7.4.4)
2. Session Establishment Request/Response (Section 7.5.3)
3. Session Modification Request/Response (Section 7.5.4)
4. Session Deletion Request/Response (Section 7.5.5)
5. Heartbeat Request/Response (Section 7.4.1)

### Implemented Information Elements (IEs)

1. Node ID (Section 8.2.38)
2. F-SEID (CP/UP F-SEID, Section 8.2.39)
3. PDR (Packet Detection Rule, Section 8.2.41)
4. FAR (Forwarding Action Rule, Section 8.2.42)
5. QER (QoS Enforcement Rule, Section 8.2.68)
6. URR (Usage Reporting Rule, Section 8.2.44)
7. Cause (Section 8.2.1)
8. Recovery Time Stamp (Section 8.2.3)
9. Gate Status (Section 8.2.69)
10. MBR (Maximum Bitrate, Section 8.2.70)
11. GBR (Guaranteed Bitrate, Section 8.2.71)
12. QFI (QoS Flow Identifier, Section 8.2.89)

### Simulated Procedures

1. PFCP Association Setup
2. PFCP Session Establishment
3. PFCP Session Modification
4. PFCP Session Deletion
5. PFCP Heartbeat Procedure

## Supported Features

1. Generation of various PFCP message types
2. Creation of multiple Information Elements (IEs) as per 3GPP standards
3. Enhanced QoS handling with detailed parameters
4. Random generation of SEIDs, PDR IDs, FAR IDs, QER IDs, and URR IDs
5. PCAP file creation for easy analysis and replay of PFCP traffic
6. Robust error handling and detailed logging
7. Strict adherence to 3GPP TS 29.244 specifications
8. Extensible design for future enhancements
9. Customizable source and destination IP addresses for PFCP packets

## Limitations and Simplifications

1. Limited to PFCP protocol simulation only; does not simulate actual user plane traffic
2. Simplified network topology assumed (point-to-point communication between CP and UP functions)
3. Does not include all possible IEs defined in 3GPP TS 29.244; focuses on core elements
4. The legacy `pfcp_packet_generator.py` is stateless; use the `pfcp_gen` package for stateful scenarios
5. Network delay is modelled as a jittered RTT and request retransmission; no real packet loss on the wire
6. PFCP has no native authentication: node authentication is simulated via allow-list + optional ESP wrapping

## Requirements

- Python 3.7+
- Scapy library
- Scapy PFCP contribution (bundled with Scapy)
- `cryptography` (only for `--ipsec`)

Install: `pip install -r requirements.txt`

## Analysis

The generated PCAP files can be analyzed using various tools:

1. Wireshark: Open the PCAP file in Wireshark for detailed packet analysis. Ensure you have the PFCP dissector enabled.
2. tshark: Use command-line tshark for quick analysis or scripting purposes.
3. Scapy: Re-read the PCAP file using Scapy for programmatic analysis or further manipulation.

Example Wireshark filter for PFCP traffic:
```
pfcp
```



## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. Contact : cem8kaya@gmail.com

## Analysis

Use Wireshark or other packet analysis tools to examine the generated PCAP files.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Please ensure your code adheres to the project's coding standards and includes appropriate tests.







## Quick start (`pfcp_gen` package)

```bash
python -m pfcp_gen generate lifecycle -n 5 -o out.pcap --check
python -m pfcp_gen generate paging   --profile urllc --upfs 3 --fteid range
python -m pfcp_gen generate restart  --ipv6
python -m pfcp_gen generate errors   -o errors.pcap
python -m pfcp_gen generate slices -n 3 --ursp --ipsec
python -m pfcp_gen generate lifecycle --profile profiles/miot.json --seed 42
python -m pfcp_gen check out.pcap          # compliance-check any PFCP pcap
python -m pfcp_gen profiles                # list built-in traffic profiles
pytest tests                               # run the test-suite
```

Scenarios: `lifecycle paging multi slices restart errors usage appdetect mixed`.
Python API: `from pfcp_gen import PFCPSimulator` - see `pfcp_gen/simulator.py`.

| Module | Purpose |
|---|---|
| `pfcp_gen/ies.py` | IE builders (PDR/FAR/QER/URR/BAR, PDI, S-NSSAI, usage report, PFD, IPv4/IPv6) |
| `pfcp_gen/state.py` | session state machine, F-TEID allocator, UPF pool |
| `pfcp_gen/profiles.py` | traffic profiles (presets + JSON) and timing models |
| `pfcp_gen/simulator.py` | message exchanges and composite scenarios |
| `pfcp_gen/security.py` | node allow-list and ESP protection |
| `pfcp_gen/compliance.py` | TS 29.244 compliance checker |
| `profiles/*.json` | example custom traffic profiles |

## Enhancement Plan - status

Project board: https://github.com/users/cem8kaya/projects/4

### High Priority (Essential for basic realism)

1. [DONE] Enhance Information Elements (Create/Update/Remove PDR, FAR, QER, URR)
2. [DONE] Realistic Session Lifecycle Simulation - `SessionState` machine (illegal transitions raise `InvalidTransition`), consistent SEIDs/sequence numbers, `PFCPSimulator.lifecycle()`
3. [DONE] Additional Message Types - Session Report Request/Response, Association Update/Release, PFD Management, Node Report, Session Set Deletion, Version Not Supported
4. [DONE] QoS Handling
5. [DONE] Usage Reporting - Create/Update/Query URR, volume/time/periodic triggers, Usage Report in Session Report, Modification and Deletion responses, UR-SEQN
6. [DONE] 5G-Specific Elements - QFI (validated 1..63), PDU session type, DNN, S-NSSAI (IE 257, custom IE since Scapy lacks it), outer-header removal for N3

### Medium Priority (Enhances realism significantly)

7. [DONE] Traffic Patterns and Timing - `constant`, `poisson`, `burst` models; request/response timestamps with jittered RTT
8. [DONE] Network Slicing - S-NSSAI in PDI, per-slice sessions (`slices` scenario), slice-aware UPF selection
9. [DONE] Failure Handling and Recovery - unanswered heartbeats with N1/T1, UPF restart (new Recovery Time Stamp, re-association), CP restart (Session Set Deletion), path failure Node Report, request retransmission
10. [DONE] Packet Forwarding - FORW with outer header creation, DROP, BUFF/NOCP, DUPL, forwarding policy, network instance
11. [DONE] Error Scenarios - 13 scenarios (cause 64-77, Offending IE, Failed Rule ID, overload control, version not supported)
12. [DONE] F-TEID Allocation - UP-allocated (CHOOSE flag + Created PDR), CP-allocated sequential/random/TEID-range (advertised via User Plane IP Resource Information)
13. [DONE] Buffering and Paging - BAR, BUFF+NOCP, Downlink Data Report, resume on service request

### Lower Priority (Adds depth to specific scenarios)

14. [DONE] UPF Selection and Load Balancing - `UpfPool` with capacity, DNN/slice capability matching, round-robin / least-loaded / weighted / random
15. [DONE] Application Detection and Control - PFD Management, Application ID in PDI, Application Detection Information report
16. [DONE] IPv6 Support - IPv6 transport, Node ID, F-SEID, F-TEID, UE IP, outer header creation, user-plane resource info
17. [DONE] Security Features - Node ID allow-list authentication (cause 64 on failure) and ESP-wrapped N4 (`--ipsec`). Note: 3GPP specifies transport-level protection, not a PFCP auth message
18. [DONE] URSP Integration - `UrspRule` mapped to N4-visible effects (traffic descriptor to SDF/App ID, route selection to S-NSSAI/DNN, precedence). URSP itself is a NAS/PCF construct, so only its UPF-side consequences appear in PFCP
19. [DONE] Customizable Traffic Profiles - `TrafficProfile` dataclass, presets (`embb`, `urllc`, `miot`, `voice`), JSON loading with validation
20. [DONE] Compliance Checking - header/length/S-flag rules, mandatory IE tables, cause values, rule consistency (GBR<=MBR, FORW needs forwarding parameters, ...), request/response pairing, PCAP checker

### Known gaps / future work

- Compliance tables cover Rel-15/16 mandatory IEs, not every conditional rule of TS 29.244
- Output has not been validated against a Wireshark dissector in CI (tshark unavailable here); round-trip via Scapy is tested
- Ethernet PDU sessions, MBS and Rel-17+ IEs are not modelled
