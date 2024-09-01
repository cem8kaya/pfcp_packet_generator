# Complete PFCP Protocol Implementation
# Author : cem8kaya@gmail.com

import struct
import socket
import enum
import time

# 1. PFCP Message Types (Section 7.2 of 3GPP TS 29.244)
class PFCPMessageType(enum.IntEnum):
    HEARTBEAT_REQUEST = 1
    HEARTBEAT_RESPONSE = 2
    PFD_MANAGEMENT_REQUEST = 3
    PFD_MANAGEMENT_RESPONSE = 4
    ASSOCIATION_SETUP_REQUEST = 5
    ASSOCIATION_SETUP_RESPONSE = 6
    ASSOCIATION_UPDATE_REQUEST = 7
    ASSOCIATION_UPDATE_RESPONSE = 8
    ASSOCIATION_RELEASE_REQUEST = 9
    ASSOCIATION_RELEASE_RESPONSE = 10
    VERSION_NOT_SUPPORTED_RESPONSE = 11
    NODE_REPORT_REQUEST = 12
    NODE_REPORT_RESPONSE = 13
    SESSION_SET_DELETION_REQUEST = 14
    SESSION_SET_DELETION_RESPONSE = 15
    SESSION_ESTABLISHMENT_REQUEST = 50
    SESSION_ESTABLISHMENT_RESPONSE = 51
    SESSION_MODIFICATION_REQUEST = 52
    SESSION_MODIFICATION_RESPONSE = 53
    SESSION_DELETION_REQUEST = 54
    SESSION_DELETION_RESPONSE = 55
    SESSION_REPORT_REQUEST = 56
    SESSION_REPORT_RESPONSE = 57

# 2. Information Element Types (Section 8 of 3GPP TS 29.244)
class IEType(enum.IntEnum):
    CREATE_PDR = 1
    # PDR stands for Packet Detection Rule.
    # This IE is used when creating a new PDR in a PFCP session.
    # It contains information on how to detect specific packets.
    CREATE_FAR = 3
    # FAR stands for Forwarding Action Rule.
    # This IE is used when creating a new FAR in a PFCP session.
    # It specifies what action to take on packets that match a PDR.
    CREATE_URR = 6
    # URR stands for Usage Reporting Rule.
    # This IE is used when creating a new URR in a PFCP session.
    # It defines how to measure and report usage for specific traffic.
    CREATED_PDR = 8
    # This IE is used in responses to indicate that a PDR was successfully created.
    # It may contain additional information about the created PDR.
    UPDATE_PDR = 9  # This IE is used to modify an existing PDR in a PFCP session.
    UPDATE_FAR = 10 # This IE is used to modify an existing FAR in a PFCP session.
    UPDATE_URR = 13 # This IE is used to modify an existing URR in a PFCP session.
    REMOVE_PDR = 14 # This IE is used to request the removal of a PDR from a PFCP session.
    REMOVE_FAR = 15 # This IE is used to request the removal of a FAR from a PFCP session.
    REMOVE_URR = 16 # This IE is used to request the removal of a URR from a PFCP session.
    CAUSE = 19
    SOURCE_INTERFACE = 20
    F_TEID = 21
    NETWORK_INSTANCE = 22
    SDF_FILTER = 23
    APPLICATION_ID = 24
    GATE_STATUS = 25
    MBR = 26
    GBR = 27
    QER_CORRELATION_ID = 28
    PRECEDENCE = 29
    TRANSPORT_LEVEL_MARKING = 30
    VOLUME_THRESHOLD = 31
    TIME_THRESHOLD = 32
    MONITORING_TIME = 33
    SUBSEQUENT_VOLUME_THRESHOLD = 34
    SUBSEQUENT_TIME_THRESHOLD = 35
    INACTIVITY_DETECTION_TIME = 36
    REPORTING_TRIGGERS = 37
    REDIRECT_INFORMATION = 38
    REPORT_TYPE = 39
    OFFENDING_IE = 40
    FORWARDING_POLICY = 41
    DESTINATION_INTERFACE = 42
    UP_FUNCTION_FEATURES = 43
    APPLY_ACTION = 44
    DOWNLINK_DATA_SERVICE_INFORMATION = 45
    DOWNLINK_DATA_NOTIFICATION_DELAY = 46
    DL_BUFFERING_DURATION = 47
    DL_BUFFERING_SUGGESTED_PACKET_COUNT = 48
    PFCPSMREQ_FLAGS = 49
    PFCPSRRSP_FLAGS = 50
    LOAD_CONTROL_INFORMATION = 51
    SEQUENCE_NUMBER = 52
    METRIC = 53
    OVERLOAD_CONTROL_INFORMATION = 54
    TIMER = 55
    PACKET_DETECTION_RULE_ID = 56
    F_SEID = 57
    APPLICATION_ID_PFDS = 58
    PFD = 59
    NODE_ID = 60
    PFD_CONTENTS = 61
    MEASUREMENT_METHOD = 62
    USAGE_REPORT_TRIGGER = 63
    MEASUREMENT_PERIOD = 64
    FQ_CSID = 65
    VOLUME_MEASUREMENT = 66
    DURATION_MEASUREMENT = 67
    APPLICATION_DETECTION_INFORMATION = 68
    TIME_OF_FIRST_PACKET = 69
    TIME_OF_LAST_PACKET = 70
    QUOTA_HOLDING_TIME = 71
    DROPPED_DL_TRAFFIC_THRESHOLD = 72
    VOLUME_QUOTA = 73
    TIME_QUOTA = 74
    START_TIME = 75
    END_TIME = 76
    QUERY_URR = 77
    USAGE_REPORT_SMR = 78
    USAGE_REPORT_SDR = 79
    USAGE_REPORT_SRR = 80
    URR_ID = 81
    LINKED_URR_ID = 82
    DOWNLINK_DATA_REPORT = 83
    OUTER_HEADER_CREATION = 84
    CREATE_BAR = 85
    UPDATE_BAR_SMR = 86
    REMOVE_BAR = 87
    BAR_ID = 88
    CP_FUNCTION_FEATURES = 89
    USAGE_INFORMATION = 90
    APPLICATION_INSTANCE_ID = 91
    FLOW_INFORMATION = 92
    UE_IP_ADDRESS = 93
    PACKET_RATE = 94
    OUTER_HEADER_REMOVAL = 95
    RECOVERY_TIME_STAMP = 96
    DL_FLOW_LEVEL_MARKING = 97
    HEADER_ENRICHMENT = 98
    ERROR_INDICATION_REPORT = 99
    MEASUREMENT_INFORMATION = 100
    NODE_REPORT_TYPE = 101
    USER_PLANE_PATH_FAILURE_REPORT = 102
    REMOTE_GTP_U_PEER = 103
    UR_SEQN = 104
    UPDATE_DUPLICATING_PARAMETERS = 105
    ACTIVATE_PREDEFINED_RULES = 106
    DEACTIVATE_PREDEFINED_RULES = 107
    FAR_ID = 108
    QER_ID = 109
    OCI_FLAGS = 110
    PFCP_ASSOCIATION_RELEASE_REQUEST = 111
    GRACEFUL_RELEASE_PERIOD = 112
    PDN_TYPE = 113
    FAILED_RULE_ID = 114
    TIME_QUOTA_MECHANISM = 115
    USER_PLANE_IP_RESOURCE_INFORMATION = 116
    USER_PLANE_INACTIVITY_TIMER = 117
    AGGREGATED_URRS = 118
    MULTIPLIER = 119
    AGGREGATED_URR_ID = 120
    SUBSEQUENT_VOLUME_QUOTA = 121
    SUBSEQUENT_TIME_QUOTA = 122
    RQI = 123
    QFI = 124
    QUERY_URR_REFERENCE = 125
    ADDITIONAL_USAGE_REPORTS_INFORMATION = 126
    CREATE_TRAFFIC_ENDPOINT = 127
    CREATED_TRAFFIC_ENDPOINT = 128
    UPDATE_TRAFFIC_ENDPOINT = 129
    REMOVE_TRAFFIC_ENDPOINT = 130
    TRAFFIC_ENDPOINT_ID = 131
    ETHERNET_PACKET_FILTER = 132
    MAC_ADDRESS = 133
    C_TAG = 134
    S_TAG = 135
    ETHERTYPE = 136
    PROXYING = 137
    ETHERNET_FILTER_ID = 138
    ETHERNET_FILTER_PROPERTIES = 139
    SUGGESTED_BUFFERING_PACKETS_COUNT = 140
    USER_ID = 141
    ETHERNET_PDU_SESSION_INFORMATION = 142
    ETHERNET_TRAFFIC_INFORMATION = 143
    MAC_ADDRESSES_DETECTED = 144
    MAC_ADDRESSES_REMOVED = 145
    ETHERNET_INACTIVITY_TIMER = 146
    ADDITIONAL_MONITORING_TIME = 147
    EVENT_QUOTA = 148
    EVENT_THRESHOLD = 149
    SUBSEQUENT_EVENT_QUOTA = 150
    SUBSEQUENT_EVENT_THRESHOLD = 151
    TRACE_INFORMATION = 152
    FRAMED_ROUTE = 153
    FRAMED_ROUTING = 154
    FRAMED_IPv6_ROUTE = 155
    EVENT_TIME_STAMP = 156
    AVERAGING_WINDOW = 157
    PAGING_POLICY_INDICATOR = 158
    APN_DNN = 159
    TGPP_INTERFACE_TYPE = 160

# 3. PFCP Header (Section 6 of 3GPP TS 29.244)
class PFCPHeader:
    def __init__(self, message_type, seid=None, sequence_number=0):
        self.version = 1
        self.message_type = message_type
        self.seid = seid
        self.sequence_number = sequence_number

    def encode(self):
        flags = 0x20  # Version 1
        if self.seid is not None:
            flags |= 0x01  # S flag
        header = struct.pack("!BBH", flags, self.message_type, 8)
        if self.seid is not None:
            header += struct.pack("!Q", self.seid)
        header += struct.pack("!I", self.sequence_number)
        return header

    @classmethod
    def decode(cls, data):
        flags, msg_type, length = struct.unpack("!BBH", data[:4])
        seid = None
        if flags & 0x01:
            seid = struct.unpack("!Q", data[4:12])[0]
            seq_num = struct.unpack("!I", data[12:16])[0]
        else:
            seq_num = struct.unpack("!I", data[4:8])[0]
        return cls(msg_type, seid, seq_num)

# 4. Base Information Element class
class IE:
    def __init__(self, ie_type, value):
        self.type = ie_type
        self.value = value

    def encode(self):
        encoded_value = self._encode_value()
        return struct.pack("!HH", self.type, len(encoded_value)) + encoded_value

    def _encode_value(self):
        raise NotImplementedError("Subclasses must implement this method")

    @classmethod
    def decode(cls, data):
        ie_type, length = struct.unpack("!HH", data[:4])
        value = cls._decode_value(data[4:4+length])
        return cls(ie_type, value)

    @classmethod
    def _decode_value(cls, data):
        raise NotImplementedError("Subclasses must implement this method")

# 5. Specific IE classes
class CauseIE(IE):
    def __init__(self, cause):
        super().__init__(IEType.CAUSE, cause)

    def _encode_value(self):
        return struct.pack("!B", self.value)

    @classmethod
    def _decode_value(cls, data):
        return struct.unpack("!B", data)[0]

class F_TEID_IE(IE):
    def __init__(self, teid, ipv4_address=None, ipv6_address=None):
        super().__init__(IEType.F_TEID, (teid, ipv4_address, ipv6_address))

    def _encode_value(self):
        flags = 0
        if self.value[1]:
            flags |= 1  # V4 flag
        if self.value[2]:
            flags |= 2  # V6 flag
        result = struct.pack("!BI", flags, self.value[0])  # TEID
        if self.value[1]:
            result += socket.inet_aton(self.value[1])
        if self.value[2]:
            result += socket.inet_pton(socket.AF_INET6, self.value[2])
        return result

    @classmethod
    def _decode_value(cls, data):
        flags, teid = struct.unpack("!BI", data[:5])
        ipv4_address = None
        ipv6_address = None
        if flags & 1:
            ipv4_address = socket.inet_ntoa(data[5:9])
        if flags & 2:
            ipv6_address = socket.inet_ntop(socket.AF_INET6, data[9:25])
        return (teid, ipv4_address, ipv6_address)

class F_SEID_IE(IE):
    def __init__(self, seid, ip_address):
        super().__init__(IEType.F_SEID, (seid, ip_address))

    def _encode_value(self):
        flags = 2 if ':' in self.value[1] else 1  # IPv6 or IPv4
        result = struct.pack("!BQ", flags, self.value[0])  # SEID
        if flags == 1:
            result += socket.inet_aton(self.value[1])
        else:
            result += socket.inet_pton(socket.AF_INET6, self.value[1])
        return result

    @classmethod
    def _decode_value(cls, data):
        flags = data[0]
        seid = struct.unpack("!Q", data[1:9])[0]
        if flags == 1:
            ip_address = socket.inet_ntoa(data[9:13])
        else:
            ip_address = socket.inet_ntop(socket.AF_INET6, data[9:25])
        return (seid, ip_address)

class NodeIDIE(IE):
    def __init__(self, node_id):
        super().__init__(IEType.NODE_ID, node_id)

    def _encode_value(self):
        if ':' in self.value:
            return b'\x02' + socket.inet_pton(socket.AF_INET6, self.value)
        elif '.' in self.value:
            return b'\x01' + socket.inet_aton(self.value)
        else:
            return b'\x00' + self.value.encode('utf-8')

    @classmethod
    def _decode_value(cls, data):
        node_id_type = data[0]
        if node_id_type == 0:
            return data[1:].decode('utf-8')
        elif node_id_type == 1:
            return socket.inet_ntoa(data[1:5])
        elif node_id_type == 2:
            return socket.inet_ntop(socket.AF_INET6, data[1:17])

class RecoveryTimeStampIE(IE):
    def __init__(self, timestamp):
        super().__init__(IEType.RECOVERY_TIME_STAMP, timestamp)

    def _encode_value(self):
        return struct.pack("!I", self.value)

    @classmethod
    def _decode_value(cls, data):
        return struct.unpack("!I", data)[0]


class PDR:
    def __init__(self, pdr_id, precedence, pdi, far_id):
        self.id = pdr_id
        self.precedence = precedence
        self.pdi = pdi
        self.far_id = far_id

class FAR:
    def __init__(self, far_id, apply_action, forwarding_parameters=None):
        self.id = far_id
        self.apply_action = apply_action
        self.forwarding_parameters = forwarding_parameters

class URR:
    def __init__(self, urr_id, measurement_method, reporting_triggers, measurement_period=None):
        self.id = urr_id
        self.measurement_method = measurement_method
        self.reporting_triggers = reporting_triggers
        self.measurement_period = measurement_period

class CreatePDRIE(IE):
    def __init__(self, pdr):
        super().__init__(IEType.CREATE_PDR, pdr)

    def _encode_value(self):
        # Implement PDR encoding
        pass

    @classmethod
    def _decode_value(cls, data):
        # Implement PDR decoding
        pass

class CreateFARIE(IE):
    def __init__(self, far):
        super().__init__(IEType.CREATE_FAR, far)

    def _encode_value(self):
        # Implement FAR encoding
        pass

    @classmethod
    def _decode_value(cls, data):
        # Implement FAR decoding
        pass

class CreateURRIE(IE):
    def __init__(self, urr):
        super().__init__(IEType.CREATE_URR, urr)

    def _encode_value(self):
        # Implement URR encoding
        pass

    @classmethod
    def _decode_value(cls, data):
        # Implement URR decoding
        pass

class CreatedPDRIE(IE):
    def __init__(self, pdr):
        super().__init__(IEType.CREATED_PDR, pdr)

    def _encode_value(self):
        # Implement created PDR encoding
        pass

    @classmethod
    def _decode_value(cls, data):
        # Implement created PDR decoding
        pass

class UpdatePDRIE(IE):
    def __init__(self, pdr):
        super().__init__(IEType.UPDATE_PDR, pdr)

    def _encode_value(self):
        # Implement PDR update encoding
        pass

    @classmethod
    def _decode_value(cls, data):
        # Implement PDR update decoding
        pass

class UpdateFARIE(IE):
    def __init__(self, far):
        super().__init__(IEType.UPDATE_FAR, far)

    def _encode_value(self):
        # Implement FAR update encoding
        pass

    @classmethod
    def _decode_value(cls, data):
        # Implement FAR update decoding
        pass

class UpdateURRIE(IE):
    def __init__(self, urr):
        super().__init__(IEType.UPDATE_URR, urr)

    def _encode_value(self):
        # Implement URR update encoding
        pass

    @classmethod
    def _decode_value(cls, data):
        # Implement URR update decoding
        pass

class RemovePDRIE(IE):
    def __init__(self, pdr_id):
        super().__init__(IEType.REMOVE_PDR, pdr_id)

    def _encode_value(self):
        return struct.pack("!H", self.value)

    @classmethod
    def _decode_value(cls, data):
        return struct.unpack("!H", data)[0]

class RemoveFARIE(IE):
    def __init__(self, far_id):
        super().__init__(IEType.REMOVE_FAR, far_id)

    def _encode_value(self):
        return struct.pack("!I", self.value)

    @classmethod
    def _decode_value(cls, data):
        return struct.unpack("!I", data)[0]

class RemoveURRIE(IE):
    def __init__(self, urr_id):
        super().__init__(IEType.REMOVE_URR, urr_id)

    def _encode_value(self):
        return struct.pack("!I", self.value)

    @classmethod
    def _decode_value(cls, data):
        return struct.unpack("!I", data)[0]


# 6. PFCP Message
class PFCPMessage:
    def __init__(self, message_type, seid=None, sequence_number=0, ies=None):
        self.header = PFCPHeader(message_type, seid, sequence_number)
        self.ies = ies or []

    def encode(self):
        encoded_ies = b''.join(ie.encode() for ie in self.ies)
        return self.header.encode() + encoded_ies

    @classmethod
    def decode(cls, data):
        header = PFCPHeader.decode(data)
        ies = []
        ie_data = data[16:] if header.seid else data[8:]
        while ie_data:
            ie_type, ie_length = struct.unpack("!HH", ie_data[:4])
            ie_class = IE_TYPES.get(ie_type, IE)
            ies.append(ie_class.decode(ie_data[:4+ie_length]))
            ie_data = ie_data[4+ie_length:]
        return cls(header.message_type, header.seid, header.sequence_number, ies)
    
# 7. PFCP Session
class PFCPSession:
    def __init__(self, cp_seid, up_seid):
        self.cp_seid = cp_seid
        self.up_seid = up_seid
        self.pdrs = {}
        self.fars = {}
        self.urrs = {}

    def add_pdr(self, pdr):
        self.pdrs[pdr.id] = pdr

    def add_far(self, far):
        self.fars[far.id] = far

    def add_urr(self, urr):
        self.urrs[urr.id] = urr

    def update_pdr(self, pdr):
        if pdr.id in self.pdrs:
            self.pdrs[pdr.id].update(pdr)
        else:
            self.add_pdr(pdr)

    def update_far(self, far):
        if far.id in self.fars:
            self.fars[far.id].update(far)
        else:
            self.add_far(far)

    def update_urr(self, urr):
        if urr.id in self.urrs:
            self.urrs[urr.id].update(urr)
        else:
            self.add_urr(urr)

    def remove_pdr(self, pdr_id):
        self.pdrs.pop(pdr_id, None)

    def remove_far(self, far_id):
        self.fars.pop(far_id, None)

    def remove_urr(self, urr_id):
        self.urrs.pop(urr_id, None)

# 8. PFCP Association
class PFCPAssociation:
    def __init__(self, node_id):
        self.node_id = node_id
        self.sessions = {}
        self.recovery_time_stamp = None

    def add_session(self, session):
        self.sessions[session.cp_seid] = session

    def remove_session(self, cp_seid):
        del self.sessions[cp_seid]

# 9. Main PFCP Handler
class PFCPHandler:
    def __init__(self, ip_address):
        self.associations = {}
        self.sequence_number = 0
        self.recovery_time_stamp = int(time.time())
        self.ip_address = ip_address

    def handle_message(self, data):
        message = PFCPMessage.decode(data)
        if message.header.message_type == PFCPMessageType.ASSOCIATION_SETUP_REQUEST:
            return self.handle_association_setup_request(message)
        elif message.header.message_type == PFCPMessageType.SESSION_ESTABLISHMENT_REQUEST:
            return self.handle_session_establishment_request(message)
        elif message.header.message_type == PFCPMessageType.SESSION_MODIFICATION_REQUEST:
            return self.handle_session_modification_request(message)
        elif message.header.message_type == PFCPMessageType.SESSION_DELETION_REQUEST:
            return self.handle_session_deletion_request(message)
        elif message.header.message_type == PFCPMessageType.HEARTBEAT_REQUEST:
            return self.handle_heartbeat_request(message)
        else:
            # Handle other message types or return an error
            return self.create_error_response(message, cause=1)  # Cause: Request rejected (temporarily)

    def handle_association_setup_request(self, message):
        node_id = next(ie for ie in message.ies if isinstance(ie, NodeIDIE)).value
        association = PFCPAssociation(node_id)
        self.associations[node_id] = association
        
        response = PFCPMessage(PFCPMessageType.ASSOCIATION_SETUP_RESPONSE)
        response.ies.append(CauseIE(1))  # Request accepted
        response.ies.append(NodeIDIE(self.ip_address))
        response.ies.append(RecoveryTimeStampIE(self.recovery_time_stamp))
        return response.encode()

    def handle_session_establishment_request(self, message):
        cp_seid = message.header.seid
        up_seid = self.generate_seid()
        session = PFCPSession(cp_seid, up_seid)
        
        for ie in message.ies:
            if isinstance(ie, CreatePDRIE):
                session.add_pdr(ie.value)
            elif isinstance(ie, CreateFARIE):
                session.add_far(ie.value)
            elif isinstance(ie, CreateURRIE):
                session.add_urr(ie.value)

        # Store the session
        node_id = self.get_node_id_from_message(message)
        self.associations[node_id].add_session(session)

        # Create response
        response = PFCPMessage(PFCPMessageType.SESSION_ESTABLISHMENT_RESPONSE, seid=cp_seid)
        response.ies.append(CauseIE(1))  # Request accepted
        response.ies.append(F_SEID_IE(up_seid, self.ip_address))
        
        # Add created PDRs to the response
        for pdr in session.pdrs.values():
            response.ies.append(CreatedPDRIE(pdr))
        
        return response.encode()

    def handle_session_modification_request(self, message):
        cp_seid = message.header.seid
        session = self.get_session_by_cp_seid(cp_seid)
        
        for ie in message.ies:
            if isinstance(ie, UpdatePDRIE):
                session.update_pdr(ie.value)
            elif isinstance(ie, UpdateFARIE):
                session.update_far(ie.value)
            elif isinstance(ie, UpdateURRIE):
                session.update_urr(ie.value)
            elif isinstance(ie, CreatePDRIE):
                session.add_pdr(ie.value)
            elif isinstance(ie, CreateFARIE):
                session.add_far(ie.value)
            elif isinstance(ie, CreateURRIE):
                session.add_urr(ie.value)
            elif isinstance(ie, RemovePDRIE):
                session.remove_pdr(ie.value)
            elif isinstance(ie, RemoveFARIE):
                session.remove_far(ie.value)
            elif isinstance(ie, RemoveURRIE):
                session.remove_urr(ie.value)

        # Create response
        response = PFCPMessage(PFCPMessageType.SESSION_MODIFICATION_RESPONSE, seid=cp_seid)
        response.ies.append(CauseIE(1))  # Request accepted
        
        return response.encode()

    def handle_session_deletion_request(self, message):
        cp_seid = message.header.seid
        session = self.get_session_by_cp_seid(cp_seid)
        
        # Remove the session
        node_id = self.get_node_id_for_session(cp_seid)
        self.associations[node_id].remove_session(cp_seid)

        # Create response
        response = PFCPMessage(PFCPMessageType.SESSION_DELETION_RESPONSE, seid=cp_seid)
        response.ies.append(CauseIE(1))  # Request accepted
        
        return response.encode()

    def handle_heartbeat_request(self, message):
        response = PFCPMessage(PFCPMessageType.HEARTBEAT_RESPONSE)
        response.ies.append(RecoveryTimeStampIE(self.recovery_time_stamp))
        return response.encode()

    def generate_seid(self):
        # Implement a method to generate unique SEIDs
        # This is a simple implementation and should be improved for production use
        return int(time.time() * 1000000)

    def get_session_by_cp_seid(self, cp_seid):
        for association in self.associations.values():
            if cp_seid in association.sessions:
                return association.sessions[cp_seid]
        raise ValueError(f"No session found for CP SEID: {cp_seid}")

    def get_node_id_from_message(self, message):
        node_id_ie = next((ie for ie in message.ies if isinstance(ie, NodeIDIE)), None)
        if node_id_ie is None:
            raise ValueError("NodeID IE not found in message")
        return node_id_ie.value

    def get_node_id_for_session(self, cp_seid):
        for node_id, association in self.associations.items():
            if cp_seid in association.sessions:
                return node_id
        raise ValueError(f"No association found for CP SEID: {cp_seid}")

    def create_error_response(self, message, cause):
        response_type = message.header.message_type + 1  # Assuming response type is always request type + 1
        response = PFCPMessage(response_type, seid=message.header.seid)
        response.ies.append(CauseIE(cause))
        return response.encode()

# 10. Main execution
if __name__ == "__main__":
    handler = PFCPHandler("192.0.2.1")  # Replace with actual IP address
    
    # Set up UDP socket for PFCP communication (port 8805)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 8805))
    
    print("PFCP handler started, listening on port 8805...")
    
    while True:
        data, addr = sock.recvfrom(4096)  # Buffer size of 4096 bytes
        print(f"Received message from {addr}")
        
        try:
            response = handler.handle_message(data)
            if response:
                sock.sendto(response, addr)
                print(f"Sent response to {addr}")
        except Exception as e:
            print(f"Error processing message: {e}")

# Don't forget to add the IE_TYPES dictionary
IE_TYPES = {
    IEType.CAUSE: CauseIE,
    IEType.F_TEID: F_TEID_IE,
    IEType.F_SEID: F_SEID_IE,
    IEType.NODE_ID: NodeIDIE,
    IEType.RECOVERY_TIME_STAMP: RecoveryTimeStampIE,
    IEType.CREATE_PDR: CreatePDRIE,
    IEType.CREATE_FAR: CreateFARIE,
    IEType.CREATE_URR: CreateURRIE,
    IEType.CREATED_PDR: CreatedPDRIE,
    IEType.UPDATE_PDR: UpdatePDRIE,
    IEType.UPDATE_FAR: UpdateFARIE,
    IEType.UPDATE_URR: UpdateURRIE,
    IEType.REMOVE_PDR: RemovePDRIE,
    IEType.REMOVE_FAR: RemoveFARIE,
    IEType.REMOVE_URR: RemoveURRIE,
    }

IE_TYPES.update({
    IEType.CREATE_PDR: CreatePDRIE,
    IEType.CREATE_FAR: CreateFARIE,
    IEType.CREATE_URR: CreateURRIE,
    IEType.CREATED_PDR: CreatedPDRIE,
    IEType.UPDATE_PDR: UpdatePDRIE,
    IEType.UPDATE_FAR: UpdateFARIE,
    IEType.UPDATE_URR: UpdateURRIE,
    IEType.REMOVE_PDR: RemovePDRIE,
    IEType.REMOVE_FAR: RemoveFARIE,
    IEType.REMOVE_URR: RemoveURRIE,
})
