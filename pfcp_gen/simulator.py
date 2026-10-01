"""Scenario-driven PFCP simulator.

Covers the enhancement plan: session lifecycle (2), Session Report (3),
usage reporting (5), 5G elements (6), timing (7), slicing (8), failure /
recovery (9), forwarding (10), error scenarios (11), F-TEID allocation
(12), buffering & paging (13), UPF selection (14), application detection
(15), IPv6 (16), security (17), URSP (18), traffic profiles (19).
"""
import random
from dataclasses import dataclass
from typing import List, Optional

from scapy.all import UDP, wrpcap
from scapy.contrib.pfcp import PFCP

from . import ies as I
from .profiles import TrafficProfile, TimingModel, get_profile
from .security import NodeAuthenticator, IpsecProtector
from .state import (Session, SessionManager, SessionState, FteidAllocator,
                    Upf, UpfPool, NoUpfAvailable)

VALID_UPF_FEATURES = {"TREU", "HEEU", "PFDM", "FTUP", "TRST", "DLBD", "DDND",
                      "BUCP", "PFDE", "FRRT", "TRACE", "QUOAC", "UDBC",
                      "PDIU", "EMPU"}

HEARTBEAT_N1 = 3          # retransmissions before declaring path failure
HEARTBEAT_T1 = 5.0        # seconds
REQUEST_T1 = 3.0
REQUEST_N1 = 3


@dataclass
class UrspRule:
    """UE Route Selection Policy rule mapped to its N4-visible effect
    (TS 23.503 6.6.2): traffic descriptor -> SDF filter / app ID in the PDI;
    route selection descriptor -> S-NSSAI, DNN (network instance) and the
    precedence of the resulting PDR."""
    precedence: int
    traffic_descriptor: str = "permit out ip from any to any"
    app_id: Optional[str] = None
    sst: int = 1
    sd: Optional[int] = None
    dnn: str = "internet"


class PFCPSimulator:
    def __init__(self, cp_ip="192.0.2.1", upfs=None, profile="embb",
                 seed=None, ue_pool="10.60.0.0", ue_pool_v6="2001:db8:60::",
                 ipv6=False, auth=None, ipsec=False, ursp_rules=(),
                 fteid_mode="up", start_time=None, upf_strategy="least_loaded"):
        self.rng = random.Random(seed)
        self.cp_ip = cp_ip
        self.profile = (profile if isinstance(profile, TrafficProfile)
                        else get_profile(profile))
        if upfs is None:
            upfs = [Upf("upf-1", "192.0.2.2" if ":" not in cp_ip
                        else "2001:db8::2",
                        dnns=(self.profile.dnn,),
                        slices=((self.profile.sst, self.profile.sd),))]
        for u in upfs:
            bad = set(u.features) - VALID_UPF_FEATURES
            if bad:
                raise ValueError(f"unknown UPF features {sorted(bad)}")
        self.pool = UpfPool(upfs, upf_strategy, self.rng)
        self.sessions = SessionManager(self.rng)
        self.timing = TimingModel.from_profile(self.profile, rng=self.rng,
                                               start=start_time)
        self.auth = auth
        self.ipsec = IpsecProtector() if ipsec else None
        self.ursp_rules = list(ursp_rules)
        self.fteid_mode = fteid_mode
        self.ipv6 = ipv6
        self._ue_base = int(__import__("ipaddress").ip_address(
            ue_pool_v6 if ipv6 else ue_pool))
        self._ue_next = 1
        self.seq = 0
        self.packets = []
        self.cp_recovery = int(self.timing.now) - 3600
        self.up_recovery = {}
        self.associated = set()
        self.log = []

    # ------------------------------------------------------------------
    # plumbing
    # ------------------------------------------------------------------
    def _next_seq(self):
        self.seq = (self.seq % 0xFFFFFF) + 1
        return self.seq

    def _ue_address(self):
        import ipaddress
        a = ipaddress.ip_address(self._ue_base + self._ue_next)
        self._ue_next += 1
        return str(a)

    def _emit(self, layer, src, dst, t):
        pkt = I.ip_layer(src, dst) / UDP(sport=I.PFCP_PORT,
                                         dport=I.PFCP_PORT) / layer
        pkt.time = t
        if self.ipsec:
            pkt = self.ipsec.protect(pkt)
        self.packets.append(pkt)
        return pkt

    def _node_hdr(self, seq):
        return PFCP(version=1, S=0, seq=seq)

    def _sess_hdr(self, seq, seid):
        return PFCP(version=1, S=1, seq=seq, seid=seid)

    def _exchange(self, req, rsp, initiator, responder, t=None,
                  rsp_delay=None):
        """Emit request (initiator->responder) and response."""
        t = self.timing.advance() if t is None else t
        r = self._emit(req, initiator, responder, t)
        if rsp is not None:
            self._emit(rsp, responder, initiator,
                       t + (rsp_delay if rsp_delay is not None else
                            self.timing.response_time(0)))
        self.log.append(type(req.payload).__name__)
        return t

    def _body_name(self, pkt):
        return type(pkt.payload).__name__

    def write(self, filename):
        self.packets.sort(key=lambda p: p.time)
        wrpcap(filename, self.packets)
        return len(self.packets)

    # ------------------------------------------------------------------
    # node-level procedures
    # ------------------------------------------------------------------
    def _up_recovery(self, upf):
        return self.up_recovery.setdefault(upf.name,
                                           int(self.timing.now) - 7200)

    def association_setup(self, upf, initiator="cp", force_cause=None):
        """Association Setup (7.4.4) incl. UP function features and
        User Plane IP Resource Information (F-TEID range advertisement)."""
        seq = self._next_seq()
        cp_feat = I.IE_CPFunctionFeatures(LOAD=1, OVRL=1)
        up_feat = I.IE_UPFunctionFeatures(**{f: 1 for f in upf.features})
        res_kw = dict(V6=1, ipv6=upf.address) if I.is_ipv6(upf.address) \
            else dict(V4=1, ipv4=upf.address)
        alloc = upf.allocator
        if alloc.strategy == "range" and alloc.prefix_bits:
            res_kw.update(TEIDRI=alloc.prefix_bits, teid_range=alloc.prefix)
        res_kw.update(ASSONI=1, network_instance=upf.dnns[0])
        ts_cp, ts_up = self.cp_recovery, self._up_recovery(upf)

        cause = force_cause
        if cause is None:
            cause = (self.auth.association_cause(upf.name, upf.address)
                     if self.auth else I.CAUSE_ACCEPTED)
        if cause == I.CAUSE_ACCEPTED:
            self.associated.add(upf.name)

        if initiator == "cp":
            req = self._node_hdr(seq) / I.PFCPAssociationSetupRequest(IE_list=[
                I.node_id(self.cp_ip), I.IE_RecoveryTimeStamp(timestamp=ts_cp),
                cp_feat])
            rsp_ies = [I.node_id(upf.address), I.IE_Cause(cause=cause),
                       I.IE_RecoveryTimeStamp(timestamp=ts_up)]
            if cause == I.CAUSE_ACCEPTED:
                rsp_ies += [up_feat,
                            I.IE_UserPlaneIPResourceInformation(**res_kw)]
            rsp = self._node_hdr(seq) / I.PFCPAssociationSetupResponse(
                IE_list=rsp_ies)
            self._exchange(req, rsp, self.cp_ip, upf.address)
        else:  # UPF-initiated (e.g. after restart)
            req = self._node_hdr(seq) / I.PFCPAssociationSetupRequest(IE_list=[
                I.node_id(upf.address),
                I.IE_RecoveryTimeStamp(timestamp=ts_up), up_feat,
                I.IE_UserPlaneIPResourceInformation(**res_kw)])
            rsp = self._node_hdr(seq) / I.PFCPAssociationSetupResponse(
                IE_list=[I.node_id(self.cp_ip), I.IE_Cause(cause=cause),
                         I.IE_RecoveryTimeStamp(timestamp=ts_cp)])
            self._exchange(req, rsp, upf.address, self.cp_ip)
        return cause

    def association_update(self, upf):
        seq = self._next_seq()
        req = self._node_hdr(seq) / I.PFCPAssociationUpdateRequest(IE_list=[
            I.node_id(self.cp_ip), I.IE_CPFunctionFeatures(LOAD=1)])
        rsp = self._node_hdr(seq) / I.PFCPAssociationUpdateResponse(IE_list=[
            I.node_id(upf.address), I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, self.cp_ip, upf.address)

    def association_release(self, upf):
        seq = self._next_seq()
        req = self._node_hdr(seq) / I.PFCPAssociationReleaseRequest(IE_list=[
            I.node_id(self.cp_ip)])
        rsp = self._node_hdr(seq) / I.PFCPAssociationReleaseResponse(IE_list=[
            I.node_id(upf.address), I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, self.cp_ip, upf.address)
        self.associated.discard(upf.name)
        if self.auth:
            self.auth.drop(upf.name, upf.address)

    def heartbeat(self, upf, t=None, answered=True, initiator="cp"):
        """Heartbeat (7.4.2).  ``answered=False`` emits request only."""
        seq = self._next_seq()
        src, dst = ((self.cp_ip, upf.address) if initiator == "cp"
                    else (upf.address, self.cp_ip))
        ts = lambda who: I.IE_RecoveryTimeStamp(  # noqa
            timestamp=self.cp_recovery if who == "cp"
            else self._up_recovery(upf))
        req = self._node_hdr(seq) / I.PFCPHeartbeatRequest(
            IE_list=[ts(initiator)])
        rsp = None
        if answered:
            rsp = self._node_hdr(seq) / I.PFCPHeartbeatResponse(
                IE_list=[ts("up" if initiator == "cp" else "cp")])
        return self._exchange(req, rsp, src, dst, t=t)

    def pfd_management(self, upf, apps):
        """PFD Management (7.4.3): push application detection filters.
        ``apps`` = {app_id: {"flows": [...], "urls": [...]}}"""
        seq = self._next_seq()
        req = self._node_hdr(seq) / I.PFCPPFDManagementRequest(IE_list=[
            I.application_pfd(a, d.get("flows", ()), d.get("urls", ()))
            for a, d in apps.items()])
        rsp = self._node_hdr(seq) / I.PFCPPFDManagementResponse(
            IE_list=[I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, self.cp_ip, upf.address)

    # ------------------------------------------------------------------
    # session procedures
    # ------------------------------------------------------------------
    def _rules_for(self, s, profile, upf):
        """Build the rule set for a session; returns IE list for Create*."""
        ue = ue_ip_ie = I.ue_ip(s.ue_ip)
        nssai = I.snssai(profile.sst, profile.sd)
        ul_local = (I.fteid_choose() if self.fteid_mode == "up"
                    else I.fteid(s.ul_teid, upf.address))
        ul_pdi = I.pdi(I.IFACE_ACCESS, ul_local, ue,
                       network_instance=profile.dnn, qfi=profile.qfi,
                       nssai=nssai)
        dl_pdi = I.pdi(I.IFACE_CORE, None, I.ue_ip(s.ue_ip, source=False),
                       network_instance=profile.dnn,
                       sdf=profile.flow_description, app_id=profile.app_id,
                       qfi=profile.qfi, nssai=nssai)
        ies = [
            I.create_pdr(1, profile.precedence, ul_pdi, far_id=1,
                         qer_ids=[1], urr_ids=[1],
                         outer_header_removal=I.OHR_GTPU_UDP_IP),
            I.create_pdr(2, profile.precedence, dl_pdi, far_id=2,
                         qer_ids=[1], urr_ids=[1]),
            I.create_far(1, "FORW", I.IFACE_CORE,
                         network_instance=profile.dnn),
            # DL FAR starts dropping until the AN tunnel is known
            I.create_far(2, "DROP"),
            I.create_qer(1, profile.mbr_ul, profile.mbr_dl, profile.gbr_ul,
                         profile.gbr_dl, profile.qfi),
            I.create_urr(1, profile.volume_threshold, profile.time_threshold,
                         period=profile.time_threshold),
        ]
        # URSP-derived additional PDRs (item 18)
        for n, rule in enumerate(self.ursp_rules):
            pid, fid = 10 + n, 10 + n
            ies.append(I.create_pdr(
                pid, rule.precedence,
                I.pdi(I.IFACE_ACCESS, None, I.ue_ip(s.ue_ip),
                      network_instance=rule.dnn, sdf=rule.traffic_descriptor,
                      app_id=rule.app_id, nssai=I.snssai(rule.sst, rule.sd)),
                far_id=fid, qer_ids=[1], urr_ids=[1]))
            ies.append(I.create_far(fid, "FORW", I.IFACE_CORE,
                                    network_instance=rule.dnn))
            s.pdr_ids.append(pid)
            s.far_ids.append(fid)
        s.pdr_ids += [1, 2]
        s.far_ids += [1, 2]
        s.qer_ids, s.urr_ids = [1], [1]
        return ies

    def session_establishment(self, profile=None, upf=None, reject_cause=None,
                              ue_address=None):
        """Session Establishment (7.5.2).  Returns the Session or None."""
        profile = profile or self.profile
        if upf is None:
            upf = self.pool.select(profile.dnn, (profile.sst, profile.sd))
        s = self.sessions.create(upf, ue_address or self._ue_address())
        s.transition(SessionState.ESTABLISHING)
        s.ul_teid = upf.allocator.allocate()
        seq = self._next_seq()
        req = self._sess_hdr(seq, 0) / I.PFCPSessionEstablishmentRequest(
            IE_list=[I.node_id(self.cp_ip), I.fseid(s.cp_seid, self.cp_ip),
                     *self._rules_for(s, profile, upf),
                     I.IE_PDNType(pdn_type=2 if I.is_ipv6(s.ue_ip) else 1),
                     I.IE_APN_DNN(apn_dnn=profile.dnn)])
        if reject_cause is not None:
            rsp = self._sess_hdr(seq, s.cp_seid) / \
                I.PFCPSessionEstablishmentResponse(IE_list=[
                    I.node_id(upf.address), I.IE_Cause(cause=reject_cause)])
            self._exchange(req, rsp, self.cp_ip, upf.address)
            s.transition(SessionState.DELETED)
            self.pool.release(upf)
            return None
        created = []
        if self.fteid_mode == "up":
            created.append(I.IE_CreatedPDR(IE_list=[
                I.IE_PDR_Id(id=1), I.fteid(s.ul_teid, upf.address)]))
        rsp = self._sess_hdr(seq, s.cp_seid) / \
            I.PFCPSessionEstablishmentResponse(IE_list=[
                I.node_id(upf.address), I.IE_Cause(cause=I.CAUSE_ACCEPTED),
                I.fseid(s.up_seid, upf.address), *created])
        t = self._exchange(req, rsp, self.cp_ip, upf.address)
        s.transition(SessionState.ESTABLISHED)
        s.start_time = s.last_report_time = t
        return s

    def session_modification(self, s, kind="activate_dl", profile=None):
        """Session Modification (7.5.4).  kinds:
        activate_dl  - gNB tunnel known: DL FAR -> FORW with outer header
        qos          - update QER (MBR/GBR/QFI) and URR thresholds
        buffer       - AN release: DL FAR -> BUFF+NOCP, BAR created (paging)
        resume       - service request: DL FAR -> FORW again
        duplicate    - enable DUPL (traffic mirroring)
        remove_rule  - remove PDR/FAR of the extra rule
        query_usage  - Query URR, response carries Usage Report
        """
        profile = profile or self.profile
        s.transition(SessionState.MODIFYING)
        upf = s.upf
        seq = self._next_seq()
        rsp_ies = [I.IE_Cause(cause=I.CAUSE_ACCEPTED)]
        t = self.timing.advance()
        if kind in ("activate_dl", "resume"):
            s.dl_teid = s.dl_teid or self.rng.randint(1, 2 ** 32 - 1)
            gnb = self._gnb_addr()
            ies = [I.update_far(2, "FORW", I.IFACE_ACCESS,
                                ohc=I.outer_header_creation(s.dl_teid, gnb))]
            if kind == "resume":
                ies.append(I.IE_PFCPSMReqFlags(DROBU=0))
                s.buffering = False
        elif kind == "qos":
            ies = [I.update_qer(1, self.rng.randint(1_000_000, 10 ** 9),
                                self.rng.randint(1_000_000, 10 ** 9),
                                profile.gbr_ul, profile.gbr_dl, profile.qfi),
                   I.update_urr(1, profile.volume_threshold * 2,
                                profile.time_threshold)]
        elif kind == "buffer":
            s.bar_id = 1
            ies = [I.update_far(2, "BUFF+NOCP", bar_id=1),
                   I.IE_Create_BAR(IE_list=I.create_bar(1).IE_list)]
            s.buffering = True
        elif kind == "duplicate":
            ies = [I.IE_UpdateFAR(IE_list=[
                I.IE_FAR_Id(id=1), I.IE_ApplyAction(FORW=1, DUPL=1)])]
        elif kind == "remove_rule":
            extra = [p for p in s.pdr_ids if p >= 10]
            if not extra:
                raise ValueError("no extra rule to remove")
            ies = [I.IE_RemovePDR(IE_list=[I.IE_PDR_Id(id=extra[-1])]),
                   I.IE_RemoveFAR(IE_list=[I.IE_FAR_Id(id=extra[-1])])]
            s.pdr_ids.remove(extra[-1])
            s.far_ids.remove(extra[-1])
        elif kind == "query_usage":
            ies = [I.IE_QueryURR(IE_list=[I.IE_URR_Id(id=1)])]
            rsp_ies.append(self._usage(s, "IMMER", t, kind="SMR"))
        else:
            raise ValueError(f"unknown modification kind {kind}")
        req = self._sess_hdr(seq, s.up_seid) / \
            I.PFCPSessionModificationRequest(IE_list=ies)
        rsp = self._sess_hdr(seq, s.cp_seid) / \
            I.PFCPSessionModificationResponse(IE_list=rsp_ies)
        self._exchange(req, rsp, self.cp_ip, upf.address, t=t)
        s.transition(SessionState.ESTABLISHED)

    def session_deletion(self, s):
        """Session Deletion (7.5.6) - response carries final usage."""
        s.transition(SessionState.DELETING)
        seq = self._next_seq()
        t = self.timing.advance()
        req = self._sess_hdr(seq, s.up_seid) / I.PFCPSessionDeletionRequest()
        rsp = self._sess_hdr(seq, s.cp_seid) / I.PFCPSessionDeletionResponse(
            IE_list=[I.IE_Cause(cause=I.CAUSE_ACCEPTED),
                     self._usage(s, "TERMR", t, kind="SDR")])
        self._exchange(req, rsp, self.cp_ip, s.upf.address, t=t)
        s.transition(SessionState.DELETED)
        s.upf.allocator.release(s.ul_teid)
        self.pool.release(s.upf)

    # -- usage reporting --------------------------------------------------
    def _accumulate(self, s, t):
        elapsed = max(t - s.last_report_time, 0.001)
        p = self.profile
        j = lambda: self.rng.uniform(0.5, 1.5)  # noqa
        s.ul_bytes += int(p.ul_rate_bps / 8 * elapsed * j())
        s.dl_bytes += int(p.dl_rate_bps / 8 * elapsed * j())

    def _usage(self, s, trigger, t, kind="SRR"):
        self._accumulate(s, t)
        seqn = s.urr_seqn.get(1, 0)
        s.urr_seqn[1] = seqn + 1
        ie = I.usage_report(1, seqn, trigger, s.last_report_time, t,
                            s.ul_bytes, s.dl_bytes, t - s.start_time, kind)
        s.last_report_time = t
        s.ul_bytes = s.dl_bytes = 0
        return ie

    def usage_report(self, s, trigger=None):
        """Session Report Request carrying a Usage Report (7.5.8),
        trigger chosen from thresholds when not given."""
        p = self.profile
        t = self.timing.advance()
        self._accumulate(s, t)
        if trigger is None:
            if s.ul_bytes + s.dl_bytes >= p.volume_threshold:
                trigger = "VOLTH"
            elif t - s.last_report_time >= p.time_threshold:
                trigger = "TIMTH"
            else:
                trigger = "PERIO"
        # _usage accumulates again for the (tiny) remaining interval
        ur = self._usage(s, trigger, t)
        seq = self._next_seq()
        req = self._sess_hdr(seq, s.cp_seid) / I.PFCPSessionReportRequest(
            IE_list=[I.IE_ReportType(USAR=1), ur])
        rsp = self._sess_hdr(seq, s.up_seid) / I.PFCPSessionReportResponse(
            IE_list=[I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, s.upf.address, self.cp_ip, t=t)

    # -- buffering / paging ----------------------------------------------
    def downlink_data_report(self, s):
        """UPF buffered DL data -> notify CP (paging trigger, 7.5.8)."""
        if not s.buffering:
            raise ValueError("session is not buffering")
        seq = self._next_seq()
        req = self._sess_hdr(seq, s.cp_seid) / I.PFCPSessionReportRequest(
            IE_list=[I.IE_ReportType(DLDR=1),
                     I.downlink_data_report(2, s.upf and self.profile.qfi,
                                            ppi=0)])
        rsp = self._sess_hdr(seq, s.up_seid) / I.PFCPSessionReportResponse(
            IE_list=[I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, s.upf.address, self.cp_ip)

    def error_indication_report(self, s):
        seq = self._next_seq()
        req = self._sess_hdr(seq, s.cp_seid) / I.PFCPSessionReportRequest(
            IE_list=[I.IE_ReportType(ERIR=1),
                     I.IE_ErrorIndicationReport(IE_list=[
                         I.fteid(s.dl_teid or s.ul_teid, s.upf.address)])])
        rsp = self._sess_hdr(seq, s.up_seid) / I.PFCPSessionReportResponse(
            IE_list=[I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, s.upf.address, self.cp_ip)

    def application_detection(self, s, app_id="video-stream"):
        """URR-less application start report, delivered as Session Report
        with an Application Detection Information IE."""
        seq = self._next_seq()
        req = self._sess_hdr(seq, s.cp_seid) / I.PFCPSessionReportRequest(
            IE_list=[I.IE_ReportType(USAR=1),
                     I.IE_UsageReport_SRR(IE_list=[
                         I.IE_URR_Id(id=1), I.IE_UR_SEQN(number=s.urr_seqn.get(1, 0)),
                         I.IE_UsageReportTrigger(START=1),
                         I.application_detection_report(
                             app_id, f"{app_id}-1",
                             "permit out ip from any to any")])])
        s.urr_seqn[1] = s.urr_seqn.get(1, 0) + 1
        rsp = self._sess_hdr(seq, s.up_seid) / I.PFCPSessionReportResponse(
            IE_list=[I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, s.upf.address, self.cp_ip)

    def _gnb_addr(self):
        return "2001:db8:100::1" if self.ipv6 else "198.51.100.1"

    # ------------------------------------------------------------------
    # failure handling and recovery (item 9)
    # ------------------------------------------------------------------
    def path_failure_report(self, upf, peer=None):
        """Node Report Request (UPFR): GTP-U path failure towards gNB."""
        seq = self._next_seq()
        peer = peer or self._gnb_addr()
        req = self._node_hdr(seq) / I.PFCPNodeReportRequest(IE_list=[
            I.node_id(upf.address), I.IE_NodeReportType(UPFR=1),
            I.IE_UserPlanePathFailureReport(IE_list=[
                I.IE_RemoteGTP_U_Peer(**(dict(V6=1, ipv6=peer)
                                         if I.is_ipv6(peer)
                                         else dict(V4=1, ipv4=peer)))])])
        rsp = self._node_hdr(seq) / I.PFCPNodeReportResponse(IE_list=[
            I.node_id(self.cp_ip), I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, upf.address, self.cp_ip)

    def upf_restart(self, upf, downtime=30.0):
        """UPF failure & recovery: unanswered heartbeats (N1 retries) ->
        CP declares path failure and purges sessions -> UPF returns with a
        newer Recovery Time Stamp, re-associates, heartbeats resume."""
        t = self.timing.advance()
        for i in range(HEARTBEAT_N1 + 1):
            self.heartbeat(upf, t=t + i * HEARTBEAT_T1, answered=False)
        self.timing.now = t + (HEARTBEAT_N1 + 1) * HEARTBEAT_T1
        for s in self.sessions.sessions.values():
            if s.upf is upf and s.state != SessionState.DELETED:
                s.state = SessionState.DELETED
                self.pool.release(upf)
        self.associated.discard(upf.name)
        self.timing.skip(downtime)
        self.up_recovery[upf.name] = int(self.timing.now)
        self.association_setup(upf, initiator="up")
        self.timing.skip(1.0)
        self.heartbeat(upf)

    def cp_restart(self, upf):
        """CP restart: new recovery timestamp, Session Set Deletion to
        purge stale sessions on the UPF, then fresh association."""
        self.cp_recovery = int(self.timing.now)
        seq = self._next_seq()
        req = self._node_hdr(seq) / I.PFCPSessionSetDeletionRequest(IE_list=[
            I.node_id(self.cp_ip)])
        rsp = self._node_hdr(seq) / I.PFCPSessionSetDeletionResponse(IE_list=[
            I.node_id(upf.address), I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._exchange(req, rsp, self.cp_ip, upf.address)
        for s in self.sessions.sessions.values():
            if s.upf is upf and s.state != SessionState.DELETED:
                s.state = SessionState.DELETED
                self.pool.release(upf)
        self.association_setup(upf)

    def retransmission(self, upf):
        """Request lost: same sequence number retransmitted every T1, then
        answered on the last attempt."""
        seq = self._next_seq()
        t = self.timing.advance()
        for i in range(REQUEST_N1 + 1):   # original + N1 retransmissions
            req = self._node_hdr(seq) / I.PFCPAssociationUpdateRequest(
                IE_list=[I.node_id(self.cp_ip)])
            self._emit(req, self.cp_ip, upf.address, t + i * REQUEST_T1)
        rsp = self._node_hdr(seq) / I.PFCPAssociationUpdateResponse(IE_list=[
            I.node_id(upf.address), I.IE_Cause(cause=I.CAUSE_ACCEPTED)])
        self._emit(rsp, upf.address, self.cp_ip,
                   t + REQUEST_N1 * REQUEST_T1 + 0.002)
        self.timing.now = t + (REQUEST_N1 + 1) * REQUEST_T1

    # ------------------------------------------------------------------
    # error scenarios (item 11)
    # ------------------------------------------------------------------
    ERROR_SCENARIOS = (
        "association_rejected", "no_association", "mandatory_ie_missing",
        "no_resources", "rule_failure", "session_not_found_mod",
        "session_not_found_del", "invalid_fteid", "congestion",
        "service_not_supported", "system_failure", "version_not_supported",
        "unauthorized_node")

    def error_scenario(self, name, upf=None):
        upf = upf or self.pool.upfs[0]
        seq = lambda: self._next_seq()  # noqa
        if name == "association_rejected":
            return self.association_setup(upf, force_cause=I.CAUSE_REJECTED)
        if name == "unauthorized_node":
            saved = self.auth
            self.auth = NodeAuthenticator(trusted=["trusted.example.net"])
            try:
                return self.association_setup(upf)
            finally:
                self.auth = saved
        if name == "no_association":
            self.associated.discard(upf.name)
            return self.session_establishment(
                upf=upf, reject_cause=I.CAUSE_NO_ESTABLISHED_ASSOCIATION)
        if name == "no_resources":
            return self.session_establishment(
                upf=upf, reject_cause=I.CAUSE_NO_RESOURCES)
        if name == "service_not_supported":
            return self.session_establishment(
                upf=upf, reject_cause=I.CAUSE_SERVICE_NOT_SUPPORTED)
        if name == "system_failure":
            return self.session_establishment(
                upf=upf, reject_cause=I.CAUSE_SYSTEM_FAILURE)
        if name == "invalid_fteid":
            return self.session_establishment(
                upf=upf, reject_cause=I.CAUSE_INVALID_FTEID_ALLOC)
        if name == "mandatory_ie_missing":
            n = seq()
            req = self._sess_hdr(n, 0) / I.PFCPSessionEstablishmentRequest(
                IE_list=[I.node_id(self.cp_ip)])      # no F-SEID/PDR/FAR
            rsp = self._sess_hdr(n, 0) / I.PFCPSessionEstablishmentResponse(
                IE_list=[I.node_id(upf.address),
                         I.IE_Cause(cause=I.CAUSE_MANDATORY_IE_MISSING),
                         I.IE_OffendingIE(type=57)])
            return self._exchange(req, rsp, self.cp_ip, upf.address)
        if name == "rule_failure":
            s = self.sessions.create(upf, self._ue_address())
            n = seq()
            req = self._sess_hdr(n, 0) / I.PFCPSessionEstablishmentRequest(
                IE_list=[I.node_id(self.cp_ip),
                         I.fseid(s.cp_seid, self.cp_ip),
                         *self._rules_for(s, self.profile, upf)])
            rsp = self._sess_hdr(n, s.cp_seid) / \
                I.PFCPSessionEstablishmentResponse(IE_list=[
                    I.node_id(upf.address),
                    I.IE_Cause(cause=I.CAUSE_RULE_FAILURE),
                    I.IE_OffendingIE(type=1),
                    I.IE_FailedRuleId(type=0, pdr_id=1)])
            s.state = SessionState.DELETED
            return self._exchange(req, rsp, self.cp_ip, upf.address)
        if name in ("session_not_found_mod", "session_not_found_del"):
            ghost_up, ghost_cp = (self.sessions.new_seid(),
                                  self.sessions.new_seid())
            n = seq()
            if name.endswith("mod"):
                req = self._sess_hdr(n, ghost_up) / \
                    I.PFCPSessionModificationRequest(IE_list=[
                        I.update_far(2, "FORW")])
                rsp = self._sess_hdr(n, ghost_cp) / \
                    I.PFCPSessionModificationResponse(IE_list=[
                        I.IE_Cause(cause=I.CAUSE_SESSION_NOT_FOUND)])
            else:
                req = self._sess_hdr(n, ghost_up) / \
                    I.PFCPSessionDeletionRequest()
                rsp = self._sess_hdr(n, ghost_cp) / \
                    I.PFCPSessionDeletionResponse(IE_list=[
                        I.IE_Cause(cause=I.CAUSE_SESSION_NOT_FOUND)])
            return self._exchange(req, rsp, self.cp_ip, upf.address)
        if name == "congestion":
            n = seq()
            s = self.sessions.create(upf, self._ue_address())
            req = self._sess_hdr(n, 0) / I.PFCPSessionEstablishmentRequest(
                IE_list=[I.node_id(self.cp_ip),
                         I.fseid(s.cp_seid, self.cp_ip),
                         *self._rules_for(s, self.profile, upf)])
            rsp = self._sess_hdr(n, s.cp_seid) / \
                I.PFCPSessionEstablishmentResponse(IE_list=[
                    I.node_id(upf.address),
                    I.IE_Cause(cause=I.CAUSE_CONGESTION),
                    I.IE_OverloadControlInformation(IE_list=[
                        I.IE_SequenceNumber(number=1),
                        I.IE_Metric(metric=80),
                        I.IE_Timer(timer_unit=1, timer_value=30)])])
            s.state = SessionState.DELETED
            return self._exchange(req, rsp, self.cp_ip, upf.address)
        if name == "version_not_supported":
            n = seq()
            req = PFCP(version=2, S=0, seq=n, message_type=1) / \
                I.PFCPHeartbeatRequest(IE_list=[
                    I.IE_RecoveryTimeStamp(timestamp=self.cp_recovery)])
            rsp = PFCP(version=1, S=0, seq=n) / \
                I.PFCPVersionNotSupportedResponse()
            return self._exchange(req, rsp, self.cp_ip, upf.address)
        raise ValueError(f"unknown error scenario {name}")

    # ------------------------------------------------------------------
    # composite scenarios
    # ------------------------------------------------------------------
    def lifecycle(self, reports=3, with_modification=True, with_paging=False,
                  upf=None, profile=None):
        """Full UE session: [assoc] -> establish -> activate DL -> usage
        reports -> (QoS mod) -> (idle/paging) -> delete."""
        profile = profile or self.profile
        upf = upf or self.pool.select(profile.dnn, (profile.sst, profile.sd))
        self.pool.release(upf)       # select() counted it; establishment
        # re-selects explicitly below
        if upf.name not in self.associated:
            if self.association_setup(upf) != I.CAUSE_ACCEPTED:
                return None
            self.heartbeat(upf)
        s = self.session_establishment(profile, upf=self._reserve(upf))
        if s is None:
            return None
        self.session_modification(s, "activate_dl", profile)
        for _ in range(reports):
            self.usage_report(s)
        if with_modification:
            self.session_modification(s, "qos", profile)
        if with_paging:
            self.session_modification(s, "buffer", profile)
            self.downlink_data_report(s)
            self.session_modification(s, "resume", profile)
        self.usage_report(s)
        self.session_deletion(s)
        return s

    def _reserve(self, upf):
        upf.load += 1
        return upf

    def multi_session(self, n, concurrent=True):
        """N sessions across the UPF pool (UPF selection / load balancing);
        interleaved when ``concurrent``."""
        for u in self.pool.upfs:
            if u.name not in self.associated and u.available:
                self.association_setup(u)
        live = []
        for _ in range(n):
            try:
                s = self.session_establishment(self.profile)
            except NoUpfAvailable:
                break
            if s:
                self.session_modification(s, "activate_dl")
                live.append(s)
        for s in live:
            self.usage_report(s)
        for s in live:
            self.session_deletion(s)
        return live

    def slice_sessions(self, slices):
        """One session per (sst, sd, dnn) - network slicing (item 8)."""
        import dataclasses
        out = []
        for sst, sd, dnn in slices:
            p = dataclasses.replace(self.profile, sst=sst, sd=sd, dnn=dnn)
            try:
                s = self.session_establishment(p)
            except NoUpfAvailable:
                continue
            if s:
                self.session_modification(s, "activate_dl", p)
                out.append(s)
        return out
