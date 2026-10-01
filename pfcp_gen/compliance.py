"""Compliance checking (item 20): validate messages against the mandatory
IE tables and structural rules of TS 29.244 (Rel-15/16 subset)."""
from dataclasses import dataclass
from typing import List

from scapy.all import UDP, IP, IPv6, rdpcap, Raw
from scapy.contrib.pfcp import (PFCP, IE_Base, IE_NotImplemented,
                                CauseValues)

from . import ies as I


@dataclass
class Violation:
    severity: str          # error | warning
    message_type: str
    detail: str
    packet_index: int = -1

    def __str__(self):
        return (f"[{self.severity.upper()}] pkt#{self.packet_index} "
                f"{self.message_type}: {self.detail}")


NODE_MESSAGES = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
SESSION_MESSAGES = {50, 51, 52, 53, 54, 55, 56, 57}
REQUESTS = {1, 3, 5, 7, 9, 12, 14, 50, 52, 54, 56}

# message type -> mandatory IE class names (TS 29.244 7.4 / 7.5)
MANDATORY = {
    1: ["IE_RecoveryTimeStamp"], 2: ["IE_RecoveryTimeStamp"],
    5: ["IE_NodeId", "IE_RecoveryTimeStamp"],
    6: ["IE_NodeId", "IE_Cause", "IE_RecoveryTimeStamp"],
    7: ["IE_NodeId"], 8: ["IE_NodeId", "IE_Cause"],
    9: ["IE_NodeId"], 10: ["IE_NodeId", "IE_Cause"],
    4: ["IE_Cause"],
    12: ["IE_NodeId", "IE_NodeReportType"], 13: ["IE_NodeId", "IE_Cause"],
    14: ["IE_NodeId"], 15: ["IE_NodeId", "IE_Cause"],
    50: ["IE_NodeId", "IE_FSEID", "IE_CreatePDR", "IE_CreateFAR"],
    51: ["IE_NodeId", "IE_Cause"],
    53: ["IE_Cause"], 55: ["IE_Cause"],
    56: ["IE_ReportType"], 57: ["IE_Cause"],
}

# response message type -> expected request type
RESPONSE_OF = {2: 1, 4: 3, 6: 5, 8: 7, 10: 9, 13: 12, 15: 14, 51: 50,
               53: 52, 55: 54, 57: 56}


def _walk(ies):
    for ie in ies or []:
        yield ie
        if hasattr(ie, "IE_list"):
            yield from _walk(ie.IE_list)


def _msg_body(p):
    return p.payload if p.payload and not isinstance(p.payload, Raw) else None


def _names(body):
    return {type(ie).__name__ for ie in body.IE_list} if body is not None \
        and hasattr(body, "IE_list") else set()


class ComplianceChecker:
    def __init__(self, strict_ports=True):
        self.strict_ports = strict_ports

    # -- public ---------------------------------------------------------
    def check_pcap(self, path):
        return self.check_packets(rdpcap(path))

    def check_packets(self, packets):
        violations = []
        pending = {}
        for idx, pkt in enumerate(packets):
            violations += self.check_packet(pkt, idx, pending)
        for (seq, mt), idx in pending.items():
            violations.append(Violation(
                "warning", str(mt), f"request seq={seq} has no response",
                idx))
        return violations

    # -- single packet ----------------------------------------------------
    def check_packet(self, pkt, idx=0, pending=None):
        v = []
        pending = pending if pending is not None else {}

        def add(sev, mt, detail):
            v.append(Violation(sev, mt, detail, idx))

        pkt = pkt.__class__(bytes(pkt))     # force full build + dissect
        if UDP not in pkt:
            add("error", "?", "not a UDP packet")
            return v
        udp = pkt[UDP]
        if self.strict_ports and I.PFCP_PORT not in (udp.sport, udp.dport):
            add("error", "?", "neither UDP port is 8805")
        if self.strict_ports and udp.dport != I.PFCP_PORT and \
                udp.sport != I.PFCP_PORT:
            return v
        if PFCP not in pkt:
            add("error", "?", "no PFCP layer")
            return v

        hdr = pkt[PFCP]
        raw = bytes(hdr)
        mt = hdr.message_type
        mname = str(mt)
        if hdr.version != 1:
            add("error", mname, f"version {hdr.version} != 1")
        expected_len = len(raw) - 4
        if hdr.length != expected_len:
            add("error", mname,
                f"length {hdr.length} != actual {expected_len}")
        if mt in NODE_MESSAGES and hdr.S:
            add("error", mname, "node-level message must have S=0")
        if mt in SESSION_MESSAGES and not hdr.S:
            add("error", mname, "session-level message must have S=1")
        if hdr.S and mt != 50 and mt in SESSION_MESSAGES and hdr.seid == 0 \
                and mt in (52, 54, 56):
            add("error", mname, "SEID must be non-zero")
        if mt == 50 and hdr.seid != 0:
            add("error", mname, "Session Establishment Request SEID must be 0")
        if hdr.seq >= 2 ** 24:
            add("error", mname, "sequence number exceeds 24 bits")

        body = _msg_body(hdr)
        if body is None and MANDATORY.get(mt):
            add("error", mname, "message body not dissected")
            return v

        # structural round-trip
        try:
            re = PFCP(raw)
            if bytes(re) != raw:
                add("error", mname, "re-encoding differs from original")
        except Exception as exc:  # pragma: no cover
            add("error", mname, f"cannot re-dissect: {exc}")

        names = _names(body)
        for ie in _walk(getattr(body, "IE_list", [])):
            if isinstance(ie, IE_NotImplemented) or isinstance(ie, Raw):
                add("warning", mname,
                    f"IE type {getattr(ie, 'ietype', '?')} not understood")
            if isinstance(ie, IE_Base) and ie.length is not None and \
                    ie.length != len(bytes(ie)) - 4:
                add("error", mname, f"{type(ie).__name__} bad length")

        for need in MANDATORY.get(mt, []):
            if need not in names:
                add("error", mname, f"missing mandatory {need}")

        # cause
        causes = [ie for ie in getattr(body, "IE_list", [])
                  if type(ie).__name__ == "IE_Cause"]
        accepted = False
        for c in causes:
            if c.cause not in CauseValues:
                add("error", mname, f"undefined cause value {c.cause}")
            accepted = c.cause == I.CAUSE_ACCEPTED
        if mt == 51 and causes and accepted and "IE_FSEID" not in names:
            add("error", mname, "accepted response lacks UP F-SEID")
        if mt in RESPONSE_OF and causes and not accepted and \
                "IE_OffendingIE" not in names and \
                causes[0].cause in (I.CAUSE_MANDATORY_IE_MISSING,
                                    I.CAUSE_CONDITIONAL_IE_MISSING,
                                    I.CAUSE_MANDATORY_IE_INCORRECT):
            add("warning", mname, "error cause without Offending IE")

        # rule-level checks
        v += self._check_rules(body, mname, idx)

        # request/response pairing
        key = (hdr.seq,)
        if mt in REQUESTS:
            pending[(hdr.seq, mt)] = idx
        elif mt in RESPONSE_OF:
            if pending.pop((hdr.seq, RESPONSE_OF[mt]), None) is None:
                add("warning", mname, f"response seq={hdr.seq} has no "
                                      f"matching request")
        return v

    # -- rules ------------------------------------------------------------
    def _check_rules(self, body, mname, idx):
        v = []

        def add(sev, detail):
            v.append(Violation(sev, mname, detail, idx))

        ies = list(_walk(getattr(body, "IE_list", [])))
        by = lambda n: [i for i in ies if type(i).__name__ == n]  # noqa

        def sub(ie, n):
            return [i for i in ie.IE_list if type(i).__name__ == n]

        for kind, idn in (("IE_CreatePDR", "IE_PDR_Id"),
                          ("IE_CreateFAR", "IE_FAR_Id"),
                          ("IE_CreateQER", "IE_QER_Id"),
                          ("IE_CreateURR", "IE_URR_Id")):
            ids = []
            for r in by(kind):
                found = sub(r, idn)
                if not found:
                    add("error", f"{kind} lacks {idn}")
                else:
                    ids.append(found[0].id)
            if len(ids) != len(set(ids)):
                add("error", f"duplicate IDs in {kind}")

        for pdr in by("IE_CreatePDR"):
            if not sub(pdr, "IE_Precedence"):
                add("error", "Create PDR lacks Precedence")
            if not sub(pdr, "IE_PDI"):
                add("error", "Create PDR lacks PDI")
            else:
                pdi = sub(pdr, "IE_PDI")[0]
                if not sub(pdi, "IE_SourceInterface"):
                    add("error", "PDI lacks Source Interface")

        for far in by("IE_CreateFAR"):
            aa = sub(far, "IE_ApplyAction")
            if not aa:
                add("error", "Create FAR lacks Apply Action")
                continue
            a = aa[0]
            if (a.FORW or a.DUPL) and not sub(far, "IE_ForwardingParameters"):
                add("error", "FAR with FORW/DUPL lacks Forwarding "
                             "Parameters")
            if a.FORW and a.DROP:
                add("error", "FAR has both FORW and DROP")
            if a.BUFF and a.DROP:
                add("error", "FAR has both BUFF and DROP")

        for qer in by("IE_CreateQER") + by("IE_UpdateQER"):
            mbr, gbr = sub(qer, "IE_MBR"), sub(qer, "IE_GBR")
            if mbr and gbr and (gbr[0].ul > mbr[0].ul or
                                gbr[0].dl > mbr[0].dl):
                add("error", "GBR exceeds MBR")
            for q in sub(qer, "IE_QFI"):
                if not 1 <= q.QFI <= 63:
                    add("error", f"QFI {q.QFI} outside 1..63")

        for urr in by("IE_CreateURR"):
            if not sub(urr, "IE_MeasurementMethod"):
                add("error", "Create URR lacks Measurement Method")
            if not sub(urr, "IE_ReportingTriggers"):
                add("error", "Create URR lacks Reporting Triggers")
        return v


def summarize(violations):
    errs = [x for x in violations if x.severity == "error"]
    warns = [x for x in violations if x.severity == "warning"]
    return f"{len(errs)} error(s), {len(warns)} warning(s)"
