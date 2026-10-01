"""Information Element (IE) builders for TS 29.244.

Thin helpers over ``scapy.contrib.pfcp`` that keep rule construction
(PDR/FAR/QER/URR/BAR, PDI, usage reports, ...) in one place.  Every builder
accepts IPv4 *or* IPv6 addresses where the IE supports both (item 16).
"""
import ipaddress
import struct

from scapy.fields import ByteField, StrFixedLenField
from scapy.contrib import pfcp as _pfcp
from scapy.contrib.pfcp import *  # noqa: F401,F403
from scapy.contrib.pfcp import (IE_Base, ietypecls, IEType)

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
CAUSE_ACCEPTED = 1
CAUSE_REJECTED = 64
CAUSE_SESSION_NOT_FOUND = 65
CAUSE_MANDATORY_IE_MISSING = 66
CAUSE_CONDITIONAL_IE_MISSING = 67
CAUSE_INVALID_LENGTH = 68
CAUSE_MANDATORY_IE_INCORRECT = 69
CAUSE_INVALID_FWD_POLICY = 70
CAUSE_INVALID_FTEID_ALLOC = 71
CAUSE_NO_ESTABLISHED_ASSOCIATION = 72
CAUSE_RULE_FAILURE = 73
CAUSE_CONGESTION = 74
CAUSE_NO_RESOURCES = 75
CAUSE_SERVICE_NOT_SUPPORTED = 76
CAUSE_SYSTEM_FAILURE = 77

# Source / destination interface values (TS 29.244 8.2.2 / 8.2.24)
IFACE_ACCESS, IFACE_CORE, IFACE_N6, IFACE_CP = 0, 1, 2, 3

# Outer Header Removal descriptions (8.2.64)
OHR_GTPU_UDP_IPV4 = 0
OHR_GTPU_UDP_IPV6 = 1
OHR_GTPU_UDP_IP = 6

PFCP_PORT = 8805


# --------------------------------------------------------------------------
# S-NSSAI (IE type 257, TS 29.244 8.2.137) - not shipped with Scapy
# --------------------------------------------------------------------------
class IE_SNSSAI(IE_Base):
    name = "IE S-NSSAI"
    ie_type = 257
    fields_desc = IE_Base.fields_desc + [
        ByteField("sst", 1),
        StrFixedLenField("sd", b"\xff\xff\xff", 3),
    ]


ietypecls[257] = IE_SNSSAI
IEType.setdefault(257, "S-NSSAI")


# --------------------------------------------------------------------------
# Address helpers
# --------------------------------------------------------------------------
def is_ipv6(addr):
    return ipaddress.ip_address(addr).version == 6


def _addr_kwargs(addr, v4_flag="V4", v6_flag="V6", v4_field="ipv4",
                 v6_field="ipv6"):
    if addr is None:
        return {}
    if is_ipv6(addr):
        return {v6_flag: 1, v6_field: addr}
    return {v4_flag: 1, v4_field: addr}


def ip_layer(src, dst):
    """IPv4 or IPv6 header depending on the address family."""
    from scapy.all import IP, IPv6
    return IPv6(src=src, dst=dst) if is_ipv6(src) else IP(src=src, dst=dst)


# --------------------------------------------------------------------------
# Node / session identifiers
# --------------------------------------------------------------------------
def node_id(node):
    """Node ID from IPv4, IPv6 or an FQDN string."""
    try:
        if is_ipv6(node):
            return IE_NodeId(id_type=1, ipv6=node)
        return IE_NodeId(id_type=0, ipv4=node)
    except ValueError:
        return IE_NodeId(id_type=2, id=node)


def fseid(seid, addr):
    return IE_FSEID(seid=seid, **_addr_kwargs(addr, "v4", "v6"))


def fteid(teid, addr):
    return IE_FTEID(TEID=teid, **_addr_kwargs(addr))


def fteid_choose(choose_id=None, v4=True, v6=False):
    """F-TEID requesting UP-function allocation (CH=1, 8.2.3)."""
    kw = dict(CH=1, V4=int(v4), V6=int(v6))
    if choose_id is not None:
        kw.update(CHID=1, choose_id=choose_id)
    return IE_FTEID(**kw)


def ue_ip(addr, source=True):
    kw = _addr_kwargs(addr, "V4", "V6")
    kw["SD"] = 0 if source else 1
    return IE_UE_IP_Address(**kw)


def snssai(sst, sd=None):
    sd_bytes = b"\xff\xff\xff" if sd is None else int(sd).to_bytes(3, "big")
    return IE_SNSSAI(sst=sst, sd=sd_bytes)


# --------------------------------------------------------------------------
# PDI / PDR
# --------------------------------------------------------------------------
def sdf_filter(flow_description):
    return IE_SDF_Filter(FD=1, flow_description=flow_description)


def pdi(source_interface=IFACE_ACCESS, local_fteid=None, ue_address=None,
        network_instance=None, sdf=None, app_id=None, qfi=None, nssai=None):
    ies = [IE_SourceInterface(interface=source_interface)]
    if local_fteid is not None:
        ies.append(local_fteid)
    if network_instance:
        ies.append(IE_NetworkInstance(instance=network_instance))
    if ue_address is not None:
        ies.append(ue_address)
    if sdf:
        ies.append(sdf if isinstance(sdf, IE_Base) else sdf_filter(sdf))
    if app_id:
        ies.append(IE_ApplicationId(id=app_id))
    if qfi is not None:
        ies.append(IE_QFI(QFI=qfi))
    if nssai is not None:
        ies.append(nssai)
    return IE_PDI(IE_list=ies)


def create_pdr(pdr_id, precedence, pdi_ie, far_id=None, qer_ids=(),
               urr_ids=(), outer_header_removal=None):
    ies = [IE_PDR_Id(id=pdr_id), IE_Precedence(precedence=precedence), pdi_ie]
    if outer_header_removal is not None:
        ies.append(IE_OuterHeaderRemoval(header=outer_header_removal))
    if far_id is not None:
        ies.append(IE_FAR_Id(id=far_id))
    ies += [IE_URR_Id(id=u) for u in urr_ids]
    ies += [IE_QER_Id(id=q) for q in qer_ids]
    return IE_CreatePDR(IE_list=ies)


def update_pdr(pdr_id, precedence=None, far_id=None, pdi_ie=None):
    ies = [IE_PDR_Id(id=pdr_id)]
    if precedence is not None:
        ies.append(IE_Precedence(precedence=precedence))
    if pdi_ie is not None:
        ies.append(pdi_ie)
    if far_id is not None:
        ies.append(IE_FAR_Id(id=far_id))
    return IE_UpdatePDR(IE_list=ies)


# --------------------------------------------------------------------------
# FAR - forwarding scenarios (item 10)
# --------------------------------------------------------------------------
def outer_header_creation(teid, addr, port=2152):
    """GTP-U/UDP/IP outer header creation towards a peer (8.2.56)."""
    if is_ipv6(addr):
        return IE_OuterHeaderCreation(GTPUUDPIPV6=1, TEID=teid, ipv6=addr)
    return IE_OuterHeaderCreation(GTPUUDPIPV4=1, TEID=teid, ipv4=addr)


def _policy(identifier):
    return IE_ForwardingPolicy(policy_identifier=identifier)


def create_far(far_id, action="FORW", dest_interface=IFACE_CORE,
               network_instance=None, ohc=None, policy=None, bar_id=None):
    """action: FORW | DROP | BUFF | NOCP | DUPL or '+'-joined combination
    (e.g. ``"BUFF+NOCP"`` for the paging path)."""
    flags = {a: 1 for a in action.split("+")}
    ies = [IE_FAR_Id(id=far_id), IE_ApplyAction(**flags)]
    if flags.get("FORW") or flags.get("DUPL"):
        fp = [IE_DestinationInterface(interface=dest_interface)]
        if network_instance:
            fp.append(IE_NetworkInstance(instance=network_instance))
        if ohc is not None:
            fp.append(ohc)
        if policy:
            fp.append(_policy(policy))
        ies.append(IE_ForwardingParameters(IE_list=fp))
    if bar_id is not None:
        ies.append(IE_BAR_Id(id=bar_id))
    return IE_CreateFAR(IE_list=ies)


def update_far(far_id, action, dest_interface=IFACE_ACCESS, ohc=None,
               bar_id=None):
    flags = {a: 1 for a in action.split("+")}
    ies = [IE_FAR_Id(id=far_id), IE_ApplyAction(**flags)]
    if flags.get("FORW"):
        fp = [IE_DestinationInterface(interface=dest_interface)]
        if ohc is not None:
            fp.append(ohc)
        ies.append(IE_UpdateForwardingParameters(IE_list=fp))
    if bar_id is not None:
        ies.append(IE_BAR_Id(id=bar_id))
    return IE_UpdateFAR(IE_list=ies)


# --------------------------------------------------------------------------
# QER
# --------------------------------------------------------------------------
def create_qer(qer_id, mbr_ul, mbr_dl, gbr_ul=None, gbr_dl=None, qfi=None,
               gate_ul=0, gate_dl=0):
    ies = [IE_QER_Id(id=qer_id), IE_GateStatus(ul=gate_ul, dl=gate_dl),
           IE_MBR(ul=mbr_ul, dl=mbr_dl)]
    if gbr_ul is not None and gbr_dl is not None:
        ies.append(IE_GBR(ul=gbr_ul, dl=gbr_dl))
    if qfi is not None:
        ies.append(IE_QFI(QFI=qfi))
    return IE_CreateQER(IE_list=ies)


def update_qer(qer_id, mbr_ul, mbr_dl, gbr_ul=None, gbr_dl=None, qfi=None):
    ies = [IE_QER_Id(id=qer_id), IE_MBR(ul=mbr_ul, dl=mbr_dl)]
    if gbr_ul is not None and gbr_dl is not None:
        ies.append(IE_GBR(ul=gbr_ul, dl=gbr_dl))
    if qfi is not None:
        ies.append(IE_QFI(QFI=qfi))
    return IE_UpdateQER(IE_list=ies)


# --------------------------------------------------------------------------
# URR / usage reporting (item 5)
# --------------------------------------------------------------------------
def create_urr(urr_id, volume_threshold=None, time_threshold=None,
               period=None, quota_volume=None):
    """Create URR with volume/time measurement and reporting triggers."""
    trig = {}
    ies = [IE_URR_Id(id=urr_id)]
    ies.append(IE_MeasurementMethod(VOLUM=1, DURAT=1))
    if volume_threshold:
        trig["volume_threshold"] = 1
    if time_threshold:
        trig["time_threshold"] = 1
    if period:
        trig["periodic_reporting"] = 1
    ies.append(IE_ReportingTriggers(**trig))
    if period:
        ies.append(IE_MeasurementPeriod(period=period))
    if volume_threshold:
        ies.append(IE_VolumeThreshold(TOVOL=1, total=volume_threshold))
    if time_threshold:
        ies.append(IE_TimeThreshold(threshold=time_threshold))
    return IE_CreateURR(IE_list=ies)


def update_urr(urr_id, volume_threshold=None, time_threshold=None):
    ies = [IE_URR_Id(id=urr_id), IE_MeasurementMethod(VOLUM=1, DURAT=1)]
    if volume_threshold:
        ies.append(IE_VolumeThreshold(TOVOL=1, total=volume_threshold))
    if time_threshold:
        ies.append(IE_TimeThreshold(threshold=time_threshold))
    return IE_UpdateURR(IE_list=ies)


def usage_report(urr_id, seqn, trigger, start, end, ul_bytes, dl_bytes,
                 duration, kind="SRR"):
    """Usage Report IE. kind: SRR (session report), SMR (modification
    response) or SDR (deletion response)."""
    cls = {"SRR": IE_UsageReport_SRR, "SMR": IE_UsageReport_SMR,
           "SDR": IE_UsageReport_SDR}[kind]
    return cls(IE_list=[
        IE_URR_Id(id=urr_id),
        IE_UR_SEQN(number=seqn),
        IE_UsageReportTrigger(**{trigger: 1}),
        IE_StartTime(timestamp=int(start)),
        IE_EndTime(timestamp=int(end)),
        IE_VolumeMeasurement(TOVOL=1, ULVOL=1, DLVOL=1,
                             total=ul_bytes + dl_bytes, uplink=ul_bytes,
                             downlink=dl_bytes),
        IE_DurationMeasurement(duration=int(duration)),
    ])


# --------------------------------------------------------------------------
# BAR / buffering / paging (item 13)
# --------------------------------------------------------------------------
def create_bar(bar_id, notification_delay=10, packet_count=50):
    return IE_Create_BAR(IE_list=[
        IE_BAR_Id(id=bar_id),
        IE_DownlinkDataNotificationDelay(delay=notification_delay),
        IE_SuggestedBufferingPacketsCount(count=packet_count),
    ])


def downlink_data_report(pdr_id, qfi=None, ppi=None):
    svc = {}
    if qfi is not None:
        svc.update(QFII=1, qfi_val=qfi)
    if ppi is not None:
        svc.update(PPI=1, ppi_val=ppi)
    ies = [IE_PDR_Id(id=pdr_id)]
    if svc:
        ies.append(IE_DownlinkDataServiceInformation(**svc))
    return IE_DownlinkDataReport(IE_list=ies)


# --------------------------------------------------------------------------
# Application detection (item 15)
# --------------------------------------------------------------------------
def application_pfd(app_id, flow_descriptions=(), urls=()):
    contents = []
    for fd in flow_descriptions:
        contents.append(IE_PFDContents(FD=1, flow=fd))
    for url in urls:
        contents.append(IE_PFDContents(URL=1, url=url))
    return IE_ApplicationID_PFDs(IE_list=[
        IE_ApplicationId(id=app_id),
        IE_PFDContext(IE_list=contents)])


def application_detection_report(app_id, instance_id, flow):
    return IE_ApplicationDetectionInformation(IE_list=[
        IE_ApplicationId(id=app_id),
        IE_ApplicationInstanceId(id=instance_id),
        IE_FlowInformation(direction=1, flow=flow)])
