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
4. Stateless operation - does not maintain session state between different message generations
5. Does not simulate network delays or packet loss scenarios
6. Limited to IPv4 addressing; IPv6 not currently supported

## Requirements

- Python 3.7+
- Scapy library
- Scapy PFCP contribution

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







## Prioritized PFCP Packet Generator Enhancement Plan for future releases

You can find the Enhancement Plan here : https://github.com/users/cem8kaya/projects/4

### High Priority (Essential for basic realism)

[DONE]1. Enhance Information Elements (IEs):
   - Implement more complex IEs such as Create/Update/Remove PDR, FAR, QER, and URR
   - This forms the core of PFCP functionality

2. Realistic Session Lifecycle Simulation:
   - Implement a state machine for session management
   - Generate sequences of messages reflecting typical session lifecycles

3. Implement Additional Message Types:
   - PFCPSessionReportRequest/Response
   - These are crucial for ongoing session management

[DONE]4. QoS Handling:
   - Implement detailed QoS parameters in QER IEs
   - Essential for simulating real-world traffic management

5. Usage Reporting:
   - Implement realistic usage reporting scenarios
   - Critical for simulating network monitoring and charging

6. 5G-Specific Elements:
   - Implement 5G-specific IEs such as QFI (QoS Flow Identifier)
   - Essential for 5G-specific scenarios

## Medium Priority (Enhances realism significantly)

7. Traffic Patterns and Timing:
   - Implement realistic inter-packet timing and burst patterns
   - Improves the temporal aspect of the simulation

8. Network Slicing Support:
   - Include NSSAI in relevant messages
   - Important for 5G network slicing scenarios

9. Failure Handling and Recovery:
   - Simulate node failures and recovery procedures
   - Implement PFCP heartbeat mechanism

10. Packet Forwarding Simulation:
    - Implement more complex forwarding scenarios in FAR IEs

11. Error Scenarios:
    - Implement various error scenarios and corresponding error handling

12. F-TEID Allocation:
    - Implement realistic F-TEID allocation strategies

13. Buffering and Paging:
    - Simulate downlink data buffering scenarios
    - Implement paging trigger conditions

## Lower Priority (Adds depth to specific scenarios)

14. UPF Selection and Load Balancing:
    - Simulate multiple UPFs with different capabilities

15. Application Detection and Control:
    - Implement Application Detection IEs

16. IPv6 Support:
    - Extend the implementation to support IPv6 addresses

17. Security Features:
    - Implement node authentication procedures

18. URSP (UE Route Selection Policy) Integration:
    - Include URSP-related information in sessions

19. Customizable Traffic Profiles:
    - Allow users to define custom traffic profiles

20. Compliance Checking:
    - Implement checks to ensure generated messages comply with 3GPP specifications
