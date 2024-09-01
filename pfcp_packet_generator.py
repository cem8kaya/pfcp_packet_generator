# PFCP Packet Generator with Request and Response Messages
# Author : cem8kaya@gmail.com


import random
import time
from scapy.all import IP, UDP, wrpcap
from scapy.contrib.pfcp import *

class RobustPFCPPacketGenerator:
    def __init__(self, src_ip, dst_ip):
        """
        Initialize the PFCP Packet Generator.
        
        :param src_ip: Source IP address for PFCP packets
        :param dst_ip: Destination IP address for PFCP packets
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.seq_num = 0

    def get_next_seq_num(self):
        """
        Generate and return the next sequence number for PFCP messages.
        
        :return: Integer representing the next sequence number
        """
        self.seq_num += 1
        return self.seq_num

    def create_pfcp_packet(self, pfcp_layer, src_ip, dst_ip):
        """
        Create a complete PFCP packet with IP and UDP headers.
        
        :param pfcp_layer: The PFCP layer to be encapsulated
        :param src_ip: Source IP address
        :param dst_ip: Destination IP address
        :return: Complete PFCP packet (IP/UDP/PFCP)
        """
        return IP(src=src_ip, dst=dst_ip) / UDP(sport=8805, dport=8805) / pfcp_layer


    def create_node_id_ie(self, ip_address):
        """
        Create a Node ID Information Element.
        
        :param ip_address: IP address to be used as Node ID
        :return: IE_NodeId object
        """
        return IE_NodeId(ipv4=ip_address)


    def create_gate_status_ie(self):
        """
        Create a Gate Status Information Element with safe default values.
        
        :return: IE_GateStatus object
        """
        try:
            # Changed the parameters to match the expected format
            return IE_GateStatus(ul=0, dl=0)
        except Exception as e:
            print(f"Error creating Gate Status IE: {e}")
            return None

    def create_enhanced_qer(self, qer_id):
        """
        Create an enhanced Quality of Service Enforcement Rule (QER) with detailed parameters.
        
        :param qer_id: QER ID
        :return: IE_CreateQER object with enhanced QoS parameters
        """
        try:
            gate_status = self.create_gate_status_ie()
            if gate_status is None:
                return None

            return IE_CreateQER(
                IE_list=[
                    IE_QER_Id(id=qer_id),
                    gate_status,
                    IE_MBR(ul=random.randint(1000000, 1000000000), dl=random.randint(1000000, 1000000000)),
                    IE_GBR(ul=random.randint(500000, 500000000), dl=random.randint(500000, 500000000)),
                    IE_QFI(QFI=random.randint(1, 63))
                ]
            )
        except Exception as e:
            print(f"Error creating enhanced QER: {e}")
            return None

    def generate_association_setup_request_response(self):
        """
        Generate a PFCP Association Setup Request and Response pair.
        
        :return: Tuple of (request, response) PFCP packets
        """
        try:
            seq = self.get_next_seq_num()
            request = PFCP(version=1, S=0, seq=seq) / PFCPAssociationSetupRequest(
                IE_list=[
                    self.create_node_id_ie(self.src_ip),
                    IE_RecoveryTimeStamp(timestamp=int(time.time()))
                ]
            )
            response = PFCP(version=1, S=0, seq=seq) / PFCPAssociationSetupResponse(
                IE_list=[
                    self.create_node_id_ie(self.dst_ip),
                    IE_Cause(cause=1),  # Request accepted
                    IE_RecoveryTimeStamp(timestamp=int(time.time()))
                ]
            )
            return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                    self.create_pfcp_packet(response, self.dst_ip, self.src_ip))
        except Exception as e:
            print(f"Error generating association setup request/response: {e}")
            return None, None

    def generate_session_establishment_request_response(self):
        """
        Generate a PFCP Session Establishment Request and Response pair.
        
        :return: Tuple of (request, response) PFCP packets
        """
        try:
            seq = self.get_next_seq_num()
            cp_seid = random.randint(1, 1000000)
            up_seid = random.randint(1, 1000000)
            
            pdr_id = random.randint(1, 1000)
            far_id = random.randint(1, 1000)
            qer_id = random.randint(1, 1000)
            urr_id = random.randint(1, 1000)

            qer = self.create_enhanced_qer(qer_id)
            if qer is None:
                return None, None

            request = PFCP(version=1, S=1, seq=seq, seid=0) / PFCPSessionEstablishmentRequest(
                IE_list=[
                    self.create_node_id_ie(self.src_ip),
                    IE_FSEID(v4=1, seid=cp_seid, ipv4=self.src_ip),
                    IE_CreatePDR(
                        IE_list=[
                            IE_PDR_Id(id=pdr_id),
                            IE_Precedence(precedence=random.randint(1, 255))
                        ]
                    ),
                    IE_CreateFAR(
                        IE_list=[
                            IE_FAR_Id(id=far_id),
                            IE_ApplyAction(FORW=1)
                        ]
                    ),
                    qer,
                    IE_CreateURR(
                        IE_list=[
                            IE_URR_Id(id=urr_id),
                            IE_MeasurementMethod(VOLUM=1, DURAT=1)
                        ]
                    )
                ]
            )
            response = PFCP(version=1, S=1, seq=seq, seid=cp_seid) / PFCPSessionEstablishmentResponse(
                IE_list=[
                    IE_Cause(cause=1),  # Request accepted
                    IE_FSEID(v4=1, seid=up_seid, ipv4=self.dst_ip)
                ]
            )
            return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                    self.create_pfcp_packet(response, self.dst_ip, self.src_ip))
        except Exception as e:
            print(f"Error generating session establishment request/response: {e}")
            return None, None

    def generate_session_modification_request_response(self):
        """
        Generate a PFCP Session Modification Request and Response pair.
        
        :return: Tuple of (request, response) PFCP packets
        """
        try:
            seq = self.get_next_seq_num()
            seid = random.randint(1, 1000000)
            
            pdr_id = random.randint(1, 1000)
            far_id = random.randint(1, 1000)
            qer_id = random.randint(1, 1000)
            urr_id = random.randint(1, 1000)

            gate_status = self.create_gate_status_ie()
            if gate_status is None:
                return None, None

            request = PFCP(version=1, S=1, seq=seq, seid=seid) / PFCPSessionModificationRequest(
                IE_list=[
                    IE_UpdatePDR(
                        IE_list=[
                            IE_PDR_Id(id=pdr_id),
                            IE_Precedence(precedence=random.randint(1, 255))
                        ]
                    ),
                    IE_UpdateFAR(
                        IE_list=[
                            IE_FAR_Id(id=far_id),
                            IE_ApplyAction(FORW=1)
                        ]
                    ),
                    IE_UpdateQER(
                        IE_list=[
                            IE_QER_Id(id=qer_id),
                            gate_status,
                            IE_MBR(ul=random.randint(1000000, 1000000000), dl=random.randint(1000000, 1000000000)),
                            IE_GBR(ul=random.randint(500000, 500000000), dl=random.randint(500000, 500000000)),
                            IE_QFI(QFI=random.randint(1, 63))
                        ]
                    ),
                    IE_UpdateURR(
                        IE_list=[
                            IE_URR_Id(id=urr_id),
                            IE_MeasurementMethod(VOLUM=1, DURAT=1)
                        ]
                    )
                ]
            )
            response = PFCP(version=1, S=1, seq=seq, seid=seid) / PFCPSessionModificationResponse(
                IE_list=[IE_Cause(cause=1)]  # Request accepted
            )
            return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                    self.create_pfcp_packet(response, self.dst_ip, self.src_ip))
        except Exception as e:
            print(f"Error generating session modification request/response: {e}")
            return None, None

    def generate_session_deletion_request_response(self):
        """
        Generate a PFCP Session Deletion Request and Response pair.
        
        :return: Tuple of (request, response) PFCP packets
        """
        try:
            seq = self.get_next_seq_num()
            seid = random.randint(1, 1000000)
            request = PFCP(version=1, S=1, seq=seq, seid=seid) / PFCPSessionDeletionRequest()
            response = PFCP(version=1, S=1, seq=seq, seid=seid) / PFCPSessionDeletionResponse(
                IE_list=[IE_Cause(cause=1)]  # Request accepted
            )
            return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                    self.create_pfcp_packet(response, self.dst_ip, self.src_ip))
        except Exception as e:
            print(f"Error generating session deletion request/response: {e}")
            return None, None

    def generate_heartbeat_request_response(self):
        """
        Generate a PFCP Heartbeat Request and Response pair.
        
        :return: Tuple of (request, response) PFCP packets
        """
        try:
            seq = self.get_next_seq_num()
            request = PFCP(version=1, S=0, seq=seq) / PFCPHeartbeatRequest(
                IE_list=[IE_RecoveryTimeStamp(timestamp=int(time.time()))]
            )
            response = PFCP(version=1, S=0, seq=seq) / PFCPHeartbeatResponse(
                IE_list=[IE_RecoveryTimeStamp(timestamp=int(time.time()))]
            )
            return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                    self.create_pfcp_packet(response, self.dst_ip, self.src_ip))
        except Exception as e:
            print(f"Error generating heartbeat request/response: {e}")
            return None, None

    def generate_random_packet_pair(self):
        """
        Generate a random PFCP packet pair from the available types.
        
        :return: Tuple of (request, response) PFCP packets
        """
        generators = [
            self.generate_association_setup_request_response,
            self.generate_session_establishment_request_response,
            self.generate_session_modification_request_response,
            self.generate_session_deletion_request_response,
            self.generate_heartbeat_request_response
        ]
        chosen_generator = random.choice(generators)
        print(f"Generating packet pair using: {chosen_generator.__name__}")
        return chosen_generator()

    def generate_pcap(self, num_pairs, filename):
        """
        Generate a PCAP file containing multiple PFCP packet pairs.
        
        :param num_pairs: Number of PFCP packet pairs to generate
        :param filename: Name of the output PCAP file
        """
        packets = []
        for i in range(num_pairs):
            print(f"Generating packet pair {i+1}/{num_pairs}")
            request, response = self.generate_random_packet_pair()
            if request and response:
                packets.extend([request, response])
            else:
                print(f"Failed to generate packet pair {i+1}")
        if packets:
            wrpcap(filename, packets)
            print(f"Generated {len(packets)} packets ({len(packets)//2} pairs) and saved to {filename}")
        else:
            print("No packets were generated. PCAP file was not created.")

if __name__ == "__main__":
    generator = RobustPFCPPacketGenerator("192.0.2.1", "192.0.2.2")
    generator.generate_pcap(10, "robust_pfcp_traffic_v12.pcap")
