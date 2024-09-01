# PFCP Packet Generator with Request and Response Messages
# Author : cem8kaya@gmail.com

import random
import time
from scapy.all import IP, UDP, wrpcap
from scapy.contrib.pfcp import PFCP, IE_NodeId, IE_RecoveryTimeStamp, IE_FSEID, IE_Cause
from scapy.contrib.pfcp import PFCPAssociationSetupRequest, PFCPAssociationSetupResponse
from scapy.contrib.pfcp import PFCPSessionEstablishmentRequest, PFCPSessionEstablishmentResponse
from scapy.contrib.pfcp import PFCPSessionModificationRequest, PFCPSessionModificationResponse
from scapy.contrib.pfcp import PFCPSessionDeletionRequest, PFCPSessionDeletionResponse
from scapy.contrib.pfcp import PFCPHeartbeatRequest, PFCPHeartbeatResponse

class PFCPPacketGenerator:
    def __init__(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.seq_num = 0

    def get_next_seq_num(self):
        self.seq_num += 1
        return self.seq_num

    def create_pfcp_packet(self, pfcp_layer, src_ip, dst_ip):
        return IP(src=src_ip, dst=dst_ip) / UDP(sport=8805, dport=8805) / pfcp_layer

    def create_node_id_ie(self, ip_address):
        return IE_NodeId(id_type=0, id=ip_address.encode())

    def generate_association_setup_request_response(self):
        seq = self.get_next_seq_num()
        request = PFCP(seq=seq) / PFCPAssociationSetupRequest(
            IE_list=[
                self.create_node_id_ie(self.src_ip),
                IE_RecoveryTimeStamp(timestamp=int(time.time()))
            ]
        )
        response = PFCP(seq=seq) / PFCPAssociationSetupResponse(
            IE_list=[
                self.create_node_id_ie(self.dst_ip),
                IE_Cause(cause=1),  # Request accepted
                IE_RecoveryTimeStamp(timestamp=int(time.time()))
            ]
        )
        return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                self.create_pfcp_packet(response, self.dst_ip, self.src_ip))

    def generate_session_establishment_request_response(self):
        seq = self.get_next_seq_num()
        cp_seid = random.randint(1, 1000000)
        up_seid = random.randint(1, 1000000)
        request = PFCP(seq=seq, seid=0) / PFCPSessionEstablishmentRequest(
            IE_list=[
                self.create_node_id_ie(self.src_ip),
                IE_FSEID(v4=1, seid=cp_seid, ipv4=self.src_ip)
            ]
        )
        response = PFCP(seq=seq, seid=cp_seid) / PFCPSessionEstablishmentResponse(
            IE_list=[
                IE_Cause(cause=1),  # Request accepted
                IE_FSEID(v4=1, seid=up_seid, ipv4=self.dst_ip)
            ]
        )
        return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                self.create_pfcp_packet(response, self.dst_ip, self.src_ip))

    def generate_session_modification_request_response(self):
        seq = self.get_next_seq_num()
        seid = random.randint(1, 1000000)
        request = PFCP(seq=seq, seid=seid) / PFCPSessionModificationRequest(
            IE_list=[]
        )
        response = PFCP(seq=seq, seid=seid) / PFCPSessionModificationResponse(
            IE_list=[IE_Cause(cause=1)]  # Request accepted
        )
        return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                self.create_pfcp_packet(response, self.dst_ip, self.src_ip))

    def generate_session_deletion_request_response(self):
        seq = self.get_next_seq_num()
        seid = random.randint(1, 1000000)
        request = PFCP(seq=seq, seid=seid) / PFCPSessionDeletionRequest(
            IE_list=[]
        )
        response = PFCP(seq=seq, seid=seid) / PFCPSessionDeletionResponse(
            IE_list=[IE_Cause(cause=1)]  # Request accepted
        )
        return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                self.create_pfcp_packet(response, self.dst_ip, self.src_ip))

    def generate_heartbeat_request_response(self):
        seq = self.get_next_seq_num()
        request = PFCP(seq=seq) / PFCPHeartbeatRequest(
            IE_list=[IE_RecoveryTimeStamp(timestamp=int(time.time()))]
        )
        response = PFCP(seq=seq) / PFCPHeartbeatResponse(
            IE_list=[IE_RecoveryTimeStamp(timestamp=int(time.time()))]
        )
        return (self.create_pfcp_packet(request, self.src_ip, self.dst_ip),
                self.create_pfcp_packet(response, self.dst_ip, self.src_ip))

    def generate_random_packet_pair(self):
        generators = [
            self.generate_association_setup_request_response,
            self.generate_session_establishment_request_response,
            self.generate_session_modification_request_response,
            self.generate_session_deletion_request_response,
            self.generate_heartbeat_request_response
        ]
        return random.choice(generators)()

    def generate_pcap(self, num_pairs, filename):
        packets = []
        for _ in range(num_pairs):
            request, response = self.generate_random_packet_pair()
            packets.extend([request, response])
        wrpcap(filename, packets)
        print(f"Generated {len(packets)} packets ({num_pairs} pairs) and saved to {filename}")

if __name__ == "__main__":
    from scapy.config import conf
    conf.use_pcap = True
    
    try:
        generator = PFCPPacketGenerator("192.0.2.1", "192.0.2.2")
        generator.generate_pcap(10, "random_pfcp_traffic_with_responses.pcap")
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()
