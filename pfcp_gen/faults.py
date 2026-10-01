"""Fault / anomaly injection grounded in how real N4 links and PFCP peers
misbehave.

Three layers, all producing a *ground-truth log* so a probe, IDS or
dissector can be scored against what was actually injected:

1. Network impairments  (``NetworkProfile``)
   Burst loss (Gilbert-Elliott), blackout windows, duplication, delay /
   jitter / reordering, bit corruption.  Consequences follow TS 29.244
   7.2.1 (retransmission): the requester resends the *same* request every
   T1 up to N1 times; a peer that already answered replays its cached
   response; an unreachable UPF host returns ICMP port-unreachable.
2. Protocol anomalies   (``ProtocolFault`` / ``MUTATORS``)
   Malformed headers and IEs, missing mandatory IEs, invalid values,
   unknown IEs/messages, unknown SEIDs, bad Cause values, recovery
   timestamp jumps ...  The peer's reaction (rejection cause, Version Not
   Supported, silent discard) is generated according to TS 29.244 7.6.
3. Stateful scenarios   (``heartbeat_flap`` / ``signaling_storm`` /
   ``orphan_session``) driven through ``PFCPSimulator``.

Known approximation: when an exchange is delayed or fails, later messages
of the same session are *not* causally shifted or suppressed.
"""
import copy
import dataclasses
import json
import random
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from scapy.all import IP, IPv6, UDP, ICMP, Raw, wrpcap, rdpcap
from scapy.contrib.pfcp import PFCP, IE_NotImplemented
from scapy.layers.inet6 import ICMPv6DestUnreach

from . import ies as I
from .compliance import MANDATORY, REQUESTS, RESPONSE_OF, NODE_MESSAGES, \
    SESSION_MESSAGES, _walk

T1 = 3.0          # request retransmission timer (s)
N1 = 3            # max retransmissions
CAUSE_NAMES = {n: v for n, v in vars(I).items() if n.startswith("CAUSE_")}


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------
@dataclass
class FaultEvent:
    time: float
    layer: str                # network | protocol | scenario
    fault: str
    detail: str
    expected: str             # what a conformant peer / probe should do
    seq: Optional[int] = None
    message_type: Optional[int] = None
    index: int = -1           # packet index in the written capture

    def to_dict(self):
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _relen(p):
    """Drop cached lengths so the whole message re-encodes consistently."""
    p.length = None
    for ie in _walk(getattr(p.payload, "IE_list", [])):
        if hasattr(ie, "IE_list"):          # compound IEs only; leaf IEs
            ie.length = None                # keep their (possibly forced) len
    return p


def _build(p):
    return bytes(_relen(p))


def _ie_type(name_or_cls):
    cls = getattr(I, name_or_cls) if isinstance(name_or_cls, str) \
        else name_or_cls
    return cls.ie_type


def _names(ies):
    return [type(i).__name__ for i in ies]


def _find(ies, name):
    return [i for i in _walk(ies) if type(i).__name__ == name]


def _transport(pkt):
    ip = pkt.getlayer(IPv6) or pkt.getlayer(IP)
    return ip, pkt[UDP]


def _repack(orig, pfcp_bytes, time=None):
    """New IP/UDP packet (valid lengths/checksums) around raw PFCP bytes."""
    ip, udp = _transport(orig)
    ip2, udp2 = ip.copy(), udp.copy()
    ip2.remove_payload()
    udp2.remove_payload()
    for f in ("len", "chksum", "plen"):
        if hasattr(ip2, f):
            try:
                delattr(ip2, f)
            except AttributeError:
                pass
    del udp2.len
    del udp2.chksum
    pkt = ip2 / udp2 / Raw(pfcp_bytes)
    pkt.time = orig.time if time is None else time
    return pkt


def _pfcp_of(pkt):
    return PFCP(bytes(_transport(pkt)[1].payload))


def _clone(pkt, time):
    c = pkt.copy()
    c.time = time
    return c


@dataclass
class Mutation:
    detail: str
    reaction: object = None    # see _reaction()
    raw: Optional[bytes] = None
    unmatched: bool = False    # response the requester cannot match


def _cause_ie(p):
    c = _find(p.payload.IE_list, "IE_Cause")
    return c[0] if c else None


# ---------------------------------------------------------------------------
# Protocol mutators: fn(p, rng) -> Mutation | None   (p = dissected PFCP)
# `side` says which message they apply to.
# ---------------------------------------------------------------------------
def m_missing_mandatory(p, rng):
    cands = [n for n in MANDATORY.get(p.message_type, [])
             if n in _names(p.payload.IE_list)]
    if not cands:
        return None
    n = rng.choice(cands)
    ies = p.payload.IE_list
    ies.remove(_find(ies, n)[0])
    return Mutation(f"removed mandatory {n}",
                    ("cause", I.CAUSE_MANDATORY_IE_MISSING, _ie_type(n)))


def m_missing_nested(p, rng):
    for rule, idn in (("IE_CreatePDR", "IE_PDR_Id"),
                      ("IE_CreateFAR", "IE_FAR_Id"),
                      ("IE_CreateQER", "IE_QER_Id"),
                      ("IE_CreateURR", "IE_URR_Id")):
        rules = _find(p.payload.IE_list, rule)
        if rules:
            r = rng.choice(rules)
            for i in list(r.IE_list):
                if type(i).__name__ == idn:
                    r.IE_list.remove(i)
                    return Mutation(
                        f"{rule} without {idn}",
                        ("cause", I.CAUSE_MANDATORY_IE_MISSING,
                         _ie_type(idn)))
    return None


def m_invalid_qfi(p, rng):
    q = _find(p.payload.IE_list, "IE_QFI")
    if not q:
        return None
    rng.choice(q).QFI = 0
    return Mutation("QFI set to 0 (valid range 1..63)",
                    ("cause", I.CAUSE_MANDATORY_IE_INCORRECT,
                     _ie_type("IE_QFI")))


def m_gbr_exceeds_mbr(p, rng):
    for q in _find(p.payload.IE_list, "IE_CreateQER") + \
            _find(p.payload.IE_list, "IE_UpdateQER"):
        mbr, gbr = _find(q.IE_list, "IE_MBR"), _find(q.IE_list, "IE_GBR")
        if mbr and gbr:
            gbr[0].ul, gbr[0].dl = mbr[0].ul * 2, mbr[0].dl * 2
            qid = _find(q.IE_list, "IE_QER_Id")
            return Mutation("GBR doubled above MBR",
                            ("rule", I.CAUSE_RULE_FAILURE,
                             _ie_type(type(q)), "qer",
                             qid[0].id if qid else 1))
    return None


def m_zero_teid(p, rng):
    for f in _find(p.payload.IE_list, "IE_FTEID"):
        if not f.CH:
            f.TEID = 0
            return Mutation("F-TEID with TEID=0 and CH=0",
                            ("cause", I.CAUSE_MANDATORY_IE_INCORRECT,
                             _ie_type("IE_FTEID")))
    return None


def m_unknown_ie(p, rng):
    t = rng.randint(3000, 3999)
    p.payload.IE_list.append(IE_NotImplemented(ietype=t,
                                               data=bytes(rng.randrange(256)
                                                          for _ in range(6))))
    return Mutation(f"unassigned optional IE type {t} appended",
                    "ignore")


def m_duplicate_ie(p, rng):
    ies = p.payload.IE_list
    if not ies:
        return None
    ies.insert(1, copy.deepcopy(ies[0]))
    return Mutation(f"{type(ies[0]).__name__} duplicated",
                    "ignore")


def m_reorder_ies(p, rng):
    ies = p.payload.IE_list
    if len(ies) < 3:
        return None
    before = _names(ies)
    for _ in range(5):
        rng.shuffle(ies)
        if _names(ies) != before:
            return Mutation("top-level IE order shuffled", "ignore")
    return None


def m_bad_ie_length(p, rng):
    ies = [i for i in p.payload.IE_list if not hasattr(i, "IE_list")]
    if not ies:
        return None
    ie = rng.choice(ies)
    real = len(bytes(copy.deepcopy(ie))) - 4
    delta = rng.choice([-2, -1, 3, 9])
    ie.length = max(0, real + delta)
    return Mutation(f"{type(ie).__name__} length {ie.length} != {real}",
                    ("cause", I.CAUSE_INVALID_LENGTH, _ie_type(type(ie))))


def m_header_length(p, rng):
    raw = bytearray(_build(p))
    real = len(raw) - 4
    bad = max(0, real + rng.choice([-8, -4, 4, 16]))
    raw[2:4] = struct.pack("!H", bad)
    return Mutation(f"header length {bad} != {real}", "drop", bytes(raw))


def m_version(p, rng):
    raw = bytearray(_build(p))
    v = rng.choice([0, 2, 3])
    raw[0] = (raw[0] & 0x1F) | (v << 5)
    return Mutation(f"PFCP version {v}", "version", bytes(raw))


def m_s_flag(p, rng):
    raw = bytearray(_build(p))
    raw[0] ^= 0x01
    return Mutation("S flag inverted (SEID presence mismatch)", "drop",
                    bytes(raw))


def m_unknown_msgtype(p, rng):
    raw = bytearray(_build(p))
    t = rng.choice([16, 40, 99, 200])
    raw[1] = t
    return Mutation(f"unknown message type {t}", "drop", bytes(raw))


def m_unknown_seid(p, rng):
    if p.message_type not in (52, 54):
        return None
    p.seid = rng.randint(1, 2 ** 32)
    return Mutation(f"SEID {p.seid:#x} unknown to the UPF",
                    ("cause", I.CAUSE_SESSION_NOT_FOUND, None, 0))


def m_truncate(p, rng):
    raw = _build(p)
    hdr = 16 if p.S else 8
    if len(raw) <= hdr + 4:
        return None
    cut = rng.randint(hdr, len(raw) - 2)
    return Mutation(f"payload truncated {len(raw)} -> {cut} bytes",
                    "drop", raw[:cut])


def m_trailing_garbage(p, rng):
    raw = _build(p) + bytes(rng.randrange(256)
                            for _ in range(rng.randint(4, 32)))
    return Mutation("trailing bytes beyond header length", "ignore", raw)


# --- response side ---
def m_rsp_reserved_cause(p, rng):
    c = _cause_ie(p)
    if c is None:
        return None
    c.cause = rng.choice([0, 100, 200])
    return Mutation(f"Cause set to undefined value {c.cause}")


def m_rsp_accept_no_fseid(p, rng):
    if p.message_type != 51:
        return None
    f = _find(p.payload.IE_list, "IE_FSEID")
    if not f:
        return None
    p.payload.IE_list.remove(f[0])
    return Mutation("accepted response without UP F-SEID")


def m_rsp_restart(p, rng):
    ts = _find(p.payload.IE_list, "IE_RecoveryTimeStamp")
    if not ts:
        return None
    ts[0].timestamp += rng.randint(600, 86400)
    return Mutation("Recovery Time Stamp jumped forward (peer restarted "
                    "without notice)")


def m_rsp_regress(p, rng):
    ts = _find(p.payload.IE_list, "IE_RecoveryTimeStamp")
    if not ts:
        return None
    ts[0].timestamp = max(0, ts[0].timestamp - rng.randint(600, 86400))
    return Mutation("Recovery Time Stamp moved backwards")


def m_rsp_wrong_seq(p, rng):
    p.seq = (p.seq + rng.randint(1, 50)) & 0xFFFFFF
    return Mutation(f"response sequence number changed to {p.seq}",
                    unmatched=True)


def m_rsp_wrong_seid(p, rng):
    if not p.S:
        return None
    p.seid = rng.randint(1, 2 ** 32)
    return Mutation("response SEID does not match any session",
                    unmatched=True)


@dataclass
class MutatorInfo:
    fn: Callable
    side: str                      # request | response
    scope: str                     # node | session | any
    expected: str


MUTATORS: Dict[str, MutatorInfo] = {
    "missing_mandatory_ie": MutatorInfo(
        m_missing_mandatory, "request", "any",
        "reject with Cause 66 + Offending IE"),
    "missing_nested_ie": MutatorInfo(
        m_missing_nested, "request", "session",
        "reject with Cause 66 + Offending IE"),
    "invalid_qfi": MutatorInfo(
        m_invalid_qfi, "request", "session",
        "reject with Cause 69 + Offending IE (QFI)"),
    "gbr_exceeds_mbr": MutatorInfo(
        m_gbr_exceeds_mbr, "request", "session",
        "reject with Cause 73 + Failed Rule ID"),
    "zero_teid": MutatorInfo(
        m_zero_teid, "request", "session",
        "reject with Cause 69 + Offending IE (F-TEID)"),
    "unknown_ie": MutatorInfo(
        m_unknown_ie, "request", "any",
        "unknown optional IE ignored; request accepted"),
    "duplicate_ie": MutatorInfo(
        m_duplicate_ie, "request", "any",
        "duplicate ignored; request accepted"),
    "reorder_ies": MutatorInfo(
        m_reorder_ies, "request", "any",
        "IE order is not significant; request accepted"),
    "bad_ie_length": MutatorInfo(
        m_bad_ie_length, "request", "any",
        "reject with Cause 68 (invalid length)"),
    "header_length": MutatorInfo(
        m_header_length, "request", "any",
        "silently discarded; requester retransmits (T1/N1)"),
    "version": MutatorInfo(
        m_version, "request", "any",
        "Version Not Supported Response (type 11)"),
    "s_flag": MutatorInfo(
        m_s_flag, "request", "any",
        "silently discarded; requester retransmits"),
    "unknown_message_type": MutatorInfo(
        m_unknown_msgtype, "request", "any",
        "silently discarded; requester retransmits"),
    "unknown_seid": MutatorInfo(
        m_unknown_seid, "request", "session",
        "reject with Cause 65 (session context not found), SEID 0"),
    "truncated": MutatorInfo(
        m_truncate, "request", "any",
        "silently discarded; requester retransmits"),
    "trailing_garbage": MutatorInfo(
        m_trailing_garbage, "request", "any",
        "extra bytes ignored; request accepted"),
    "rsp_reserved_cause": MutatorInfo(
        m_rsp_reserved_cause, "response", "any",
        "requester treats as failure; probe flags undefined Cause"),
    "rsp_accept_without_fseid": MutatorInfo(
        m_rsp_accept_no_fseid, "response", "session",
        "requester cannot address session; probe flags missing F-SEID"),
    "rsp_peer_restart": MutatorInfo(
        m_rsp_restart, "response", "node",
        "requester detects restart (Recovery TS increased) and purges "
        "sessions"),
    "rsp_recovery_regress": MutatorInfo(
        m_rsp_regress, "response", "node",
        "Recovery TS must never decrease; flag as anomaly"),
    "rsp_wrong_seq": MutatorInfo(
        m_rsp_wrong_seq, "response", "any",
        "response not matched; requester retransmits, peer replays"),
    "rsp_wrong_seid": MutatorInfo(
        m_rsp_wrong_seid, "response", "session",
        "response not matched; requester retransmits, peer replays"),
}


def _reaction(rsp_pkt, req_p, reaction):
    """Rewrite the paired response according to the peer's reaction."""
    if reaction in (None, "ignore"):
        return rsp_pkt
    if reaction == "version":
        r = PFCP(version=1, S=0, seq=req_p.seq,
                 message_type=11) / I.PFCPVersionNotSupportedResponse()
        return _repack(rsp_pkt, bytes(r))
    if rsp_pkt is None:
        return None
    rp = _pfcp_of(rsp_pkt)
    body = rp.payload
    kind = reaction[0]
    ies = []
    nid = [i for i in body.IE_list if type(i).__name__ == "IE_NodeId"]
    ies += nid
    ies.append(I.IE_Cause(cause=reaction[1]))
    off = reaction[2]
    if off is not None:
        ies.append(I.IE_OffendingIE(type=off))
    if kind == "rule":
        ies.append(I.IE_FailedRuleId(type=2, qer_id=reaction[4]))
    body.IE_list = ies
    if kind == "cause" and len(reaction) > 3 and rp.S:
        rp.seid = reaction[3]
    return _repack(rsp_pkt, _build(rp))


# ---------------------------------------------------------------------------
# Network model
# ---------------------------------------------------------------------------
@dataclass
class NetworkProfile:
    # Gilbert-Elliott burst loss. loss=p for plain Bernoulli.
    loss: float = 0.0
    p_good_bad: float = 0.0          # enter burst
    p_bad_good: float = 0.3          # leave burst
    loss_bad: float = 0.6
    blackouts: List[List[float]] = field(default_factory=list)
    # [offset_s_from_first_packet, duration_s]
    icmp_unreachable: bool = False   # host up, PFCP process down
    duplicate: float = 0.0
    corrupt: float = 0.0             # bit flips, checksum left stale
    delay_spike: float = 0.0         # probability of a latency spike
    spike_ms: float = 80.0
    reorder: float = 0.0             # probability a packet overtakes
    reorder_ms: float = 30.0
    jitter_ms: float = 0.0
    retransmit: bool = True
    tap: str = "sender"              # sender | receiver (drop lost pkts)

    def __post_init__(self):
        for n in ("loss", "p_good_bad", "p_bad_good", "loss_bad",
                  "duplicate", "corrupt", "delay_spike", "reorder"):
            if not 0.0 <= getattr(self, n) <= 1.0:
                raise ValueError(f"{n} must be within [0, 1]")
        if self.tap not in ("sender", "receiver"):
            raise ValueError("tap must be 'sender' or 'receiver'")


@dataclass
class ProtocolFault:
    fault: str
    probability: float = 0.05
    # Message types the fault applies to; None = any.  For response-side
    # faults these are *response* types (e.g. 51), and the logged
    # FaultEvent.message_type is always the exchange's request type.
    messages: Optional[List[int]] = None

    def __post_init__(self):
        if self.fault not in MUTATORS:
            raise ValueError(f"unknown protocol fault {self.fault!r}; "
                             f"choose from {sorted(MUTATORS)}")
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError("probability must be within [0, 1]")


@dataclass
class FaultPlan:
    name: str = "custom"
    network: NetworkProfile = field(default_factory=NetworkProfile)
    protocol: List[ProtocolFault] = field(default_factory=list)
    seed: Optional[int] = None

    @classmethod
    def from_dict(cls, d):
        unknown = set(d) - {"name", "network", "protocol", "seed"}
        if unknown:
            raise ValueError(f"unknown plan keys {sorted(unknown)}")
        return cls(d.get("name", "custom"),
                   NetworkProfile(**d.get("network", {})),
                   [ProtocolFault(**p) for p in d.get("protocol", [])],
                   d.get("seed"))

    @classmethod
    def from_file(cls, path):
        with open(path) as fh:
            return cls.from_dict(json.load(fh))

    def to_dict(self):
        return dataclasses.asdict(self)


def _P(*names, p=0.05):
    return [ProtocolFault(n, p) for n in names]


FAULT_PRESETS = {
    # Congested/long backhaul: bursty loss, jitter, occasional reordering
    "congested_backhaul": FaultPlan("congested_backhaul", NetworkProfile(
        p_good_bad=0.02, p_bad_good=0.25, loss_bad=0.5, loss=0.002,
        jitter_ms=4, delay_spike=0.03, spike_ms=120, reorder=0.02,
        duplicate=0.003)),
    # Flaky transport/NIC: plain loss + duplicates + corruption
    "lossy_link": FaultPlan("lossy_link", NetworkProfile(
        loss=0.08, duplicate=0.02, corrupt=0.02, jitter_ms=2)),
    # UPF process crashed: ICMP port-unreachable during outage
    "upf_process_down": FaultPlan("upf_process_down", NetworkProfile(
        blackouts=[[5.0, 25.0]], icmp_unreachable=True)),
    # Transport outage / fibre cut: silence, no ICMP
    "link_outage": FaultPlan("link_outage", NetworkProfile(
        blackouts=[[5.0, 20.0]])),
    # Peer implementation bugs on the control path
    "buggy_peer": FaultPlan("buggy_peer", NetworkProfile(), _P(
        "missing_mandatory_ie", "missing_nested_ie", "invalid_qfi",
        "gbr_exceeds_mbr", "zero_teid", "bad_ie_length", "unknown_seid",
        "rsp_reserved_cause", "rsp_accept_without_fseid", p=0.1)),
    # Interop: things a robust peer must tolerate without failing
    "interop_tolerance": FaultPlan("interop_tolerance", NetworkProfile(),
                                   _P("unknown_ie", "duplicate_ie",
                                      "reorder_ies", "trailing_garbage",
                                      p=0.2)),
    # Parser stress: malformed framing
    "fuzz_framing": FaultPlan("fuzz_framing", NetworkProfile(), _P(
        "header_length", "version", "s_flag", "unknown_message_type",
        "truncated", p=0.1)),
    # Undetected restarts / bad recovery timestamps
    "restart_anomalies": FaultPlan("restart_anomalies", NetworkProfile(),
                                   _P("rsp_peer_restart",
                                      "rsp_recovery_regress",
                                      "rsp_wrong_seq", "rsp_wrong_seid",
                                      p=0.3)),
    # Kitchen sink for robustness testing
    "chaos": FaultPlan("chaos", NetworkProfile(
        loss=0.01, p_good_bad=0.01, p_bad_good=0.3, loss_bad=0.5,
        duplicate=0.01, corrupt=0.01, delay_spike=0.02, jitter_ms=3,
        reorder=0.01), [ProtocolFault(n, 0.02) for n in sorted(MUTATORS)]),
}


def get_plan(name_or_path):
    if name_or_path in FAULT_PRESETS:
        return copy.deepcopy(FAULT_PRESETS[name_or_path])
    return FaultPlan.from_file(name_or_path)


# ---------------------------------------------------------------------------
# Injector
# ---------------------------------------------------------------------------
class _LossModel:
    def __init__(self, prof, rng, t0):
        self.p, self.rng, self.t0 = prof, rng, t0
        self.bad = False

    def blackout(self, t):
        return any(self.t0 + s <= t < self.t0 + s + d
                   for s, d in self.p.blackouts)

    def lost(self, t):
        if self.blackout(t):
            return True
        p = self.p
        if p.p_good_bad:
            if self.bad:
                self.bad = self.rng.random() >= p.p_bad_good
            else:
                self.bad = self.rng.random() < p.p_good_bad
            if self.bad and self.rng.random() < p.loss_bad:
                return True
        return self.rng.random() < p.loss


class FaultInjector:
    def __init__(self, plan, seed=None):
        self.plan = plan if isinstance(plan, FaultPlan) else get_plan(plan)
        self.rng = random.Random(seed if seed is not None else
                                 self.plan.seed)
        self.events: List[FaultEvent] = []
        self._pkt_events = []      # (pkt, event) to resolve indices

    # -- logging ---------------------------------------------------------
    def _log(self, pkt, layer, fault, detail, expected, seq=None, mt=None):
        ev = FaultEvent(float(pkt.time) if pkt is not None else 0.0,
                        layer, fault, detail, expected, seq, mt)
        self.events.append(ev)
        if pkt is not None:
            self._pkt_events.append((pkt, ev))
        return ev

    # -- public ----------------------------------------------------------
    def apply(self, packets):
        """Returns (new_packets_sorted, events)."""
        self.events, self._pkt_events = [], []
        packets = list(packets)
        if not packets:
            return [], []
        t0 = min(float(p.time) for p in packets)
        self.loss = _LossModel(self.plan.network, self.rng, t0)

        groups = defaultdict(lambda: {"req": [], "rsp": [], "other": []})
        out = []
        for p in packets:
            try:
                d = _pfcp_of(p)
            except Exception:
                out.append(p)
                continue
            mt = d.message_type
            if mt in REQUESTS:
                groups[d.seq]["req"].append((p, d))
            elif mt in RESPONSE_OF or mt == 11:
                groups[d.seq]["rsp"].append((p, d))
            else:
                out.append(p)
        for seq, g in sorted(groups.items(),
                             key=lambda kv: min(float(x[0].time) for x in
                                                kv[1]["req"] + kv[1]["rsp"])):
            if len(g["req"]) == 1 and len(g["rsp"]) <= 1:
                out += self._exchange(seq, g["req"][0],
                                      g["rsp"][0] if g["rsp"] else None)
            else:   # already retransmitted / odd shape: pass through
                out += [x[0] for x in g["req"] + g["rsp"]]
        if self.plan.network.tap == "receiver":
            out = [p for p in out if not getattr(p, "_lost", False)]
        out.sort(key=lambda p: float(p.time))
        idx = {id(p): i for i, p in enumerate(out)}
        for p, ev in self._pkt_events:
            ev.index = idx.get(id(p), -1)
        self.events.sort(key=lambda e: e.time)
        return out, self.events

    def write(self, packets, pcap, log=None):
        out, events = self.apply(packets)
        wrpcap(pcap, out)
        if log:
            with open(log, "w") as fh:
                json.dump({"plan": self.plan.to_dict(),
                           "events": [e.to_dict() for e in events]}, fh,
                          indent=2)
        return out, events

    # -- protocol layer ----------------------------------------------------
    def _pick(self, d, side):
        for pf in self.plan.protocol:
            info = MUTATORS[pf.fault]
            if info.side != side:
                continue
            scope = info.scope
            mt = d.message_type
            if scope == "node" and mt not in NODE_MESSAGES:
                continue
            if scope == "session" and mt not in SESSION_MESSAGES:
                continue
            if pf.messages and mt not in pf.messages:
                continue
            if self.rng.random() < pf.probability:
                yield pf.fault, info

    def _mutate(self, pkt, d, side):
        """Apply the first applicable mutator on a fresh dissection.
        Returns (raw_bytes, Mutation, name, info) or None."""
        for name, info in self._pick(d, side):
            work = _pfcp_of(pkt)
            try:
                res = info.fn(work, self.rng)
            except AttributeError:      # body has no IE list (e.g. Del Req)
                continue
            if res is not None:
                raw = res.raw if res.raw is not None else _build(work)
                return raw, res, name, info
        return None

    # -- exchange ----------------------------------------------------------
    def _exchange(self, seq, req, rsp):
        net = self.plan.network
        rng = self.rng
        req_pkt, req_d = req
        rsp_pkt = rsp[0] if rsp else None
        t_req = float(req_pkt.time)
        rtt = max(float(rsp_pkt.time) - t_req, 0.0005) if rsp_pkt else 0.002
        discard = False
        unmatched = False
        out = []

        m = self._mutate(req_pkt, req_d, "request")
        if m:
            raw, res, name, info = m
            req_pkt = _repack(req_pkt, raw)
            self._log(req_pkt, "protocol", name, res.detail, info.expected,
                      seq, req_d.message_type)
            if res.reaction == "drop":
                discard = True
                rsp_pkt = None
            else:
                rsp_pkt = _reaction(rsp_pkt, req_d, res.reaction)

        clean_rsp = rsp_pkt
        if rsp_pkt is not None:
            rm = self._mutate(rsp_pkt, _pfcp_of(rsp_pkt), "response")
            if rm:
                raw, res, name, info = rm
                rsp_pkt = _repack(rsp_pkt, raw)
                unmatched = res.unmatched
                self._log(rsp_pkt, "protocol", name, res.detail,
                          info.expected, seq, req_d.message_type)

        # transmit with loss / retransmission
        attempts = (N1 + 1) if net.retransmit else 1
        good_rsp = rsp_pkt
        delivered_once = False
        for k in range(attempts):
            t = t_req + k * T1
            shift = self._shift(t)
            rq = _clone(req_pkt, t + shift)
            if k:
                self._log(rq, "network", "retransmission",
                          f"request retransmitted (attempt {k + 1}, "
                          f"T1={T1}s)",
                          "peer processes duplicate; replays cached "
                          "response if already answered", seq,
                          req_d.message_type)
            out.append(rq)
            verdict = self._verdict(rq, req_d.message_type, seq, "request")
            if verdict == "corrupt":
                out[-1] = self._corrupt(rq)
            if verdict in ("lost", "corrupt") or discard:
                if verdict == "lost" and self.loss.blackout(t) and \
                        net.icmp_unreachable and not discard:
                    out.append(self._icmp(rq, t + shift + rtt * 0.5, seq,
                                          req_d.message_type))
                rq._lost = True if verdict == "lost" else False
                if verdict == "corrupt":
                    out[-1]._lost = False
                continue
            self._dup(rq, seq, req_d.message_type, out, rtt, good_rsp)
            if good_rsp is None:
                delivered_once = True
                break          # no response expected (e.g. unanswered HB)
            jitter = abs(rng.gauss(0, net.jitter_ms / 1000.0)) \
                if net.jitter_ms else 0.0
            if unmatched and k == 0:
                # wrong seq/SEID: requester ignores it, retransmits
                out.append(_clone(good_rsp, t + shift + rtt + jitter))
                continue
            send = _clone(clean_rsp if unmatched else good_rsp,
                          t + shift + rtt + jitter)
            out.append(send)
            rv = self._verdict(send, req_d.message_type, seq, "response")
            if rv == "corrupt":
                out[-1] = self._corrupt(send)
                continue
            if rv == "lost":
                send._lost = True
                continue
            delivered_once = True
            break
        if not delivered_once and (rsp_pkt is not None or discard):
            self._log(out[-1], "network", "exchange_failed",
                      f"no valid response after {attempts} attempts",
                      "requester declares peer unreachable; for "
                      "Heartbeat this is a path failure", seq,
                      req_d.message_type)
        return out

    # -- network primitives ------------------------------------------------
    def _shift(self, t):
        net, rng = self.plan.network, self.rng
        s = 0.0
        if net.jitter_ms:
            s += abs(rng.gauss(0, net.jitter_ms / 1000.0))
        if net.delay_spike and rng.random() < net.delay_spike:
            s += rng.lognormvariate(0, 0.5) * net.spike_ms / 1000.0
        if net.reorder and rng.random() < net.reorder:
            s += rng.uniform(0.5, 1.5) * net.reorder_ms / 1000.0
        return s

    def _verdict(self, pkt, mt, seq, direction):
        net = self.plan.network
        t = float(pkt.time)
        if self.loss.lost(t):
            kind = "blackout" if self.loss.blackout(t) else "loss"
            self._log(pkt, "network", f"{direction}_{kind}",
                      f"{direction} dropped in transit"
                      + (" (outage window)" if kind == "blackout" else ""),
                      "sender waits T1 then retransmits (TS 29.244 7.2.1)"
                      if direction == "request" else
                      "requester retransmits; responder replays cached "
                      "response", seq, mt)
            return "lost"
        if net.corrupt and self.rng.random() < net.corrupt:
            self._log(pkt, "network", f"{direction}_corruption",
                      "payload bit flips, UDP checksum stale",
                      "receiver discards (bad checksum); sender "
                      "retransmits", seq, mt)
            return "corrupt"
        return "ok"

    def _corrupt(self, pkt):
        raw = bytearray(bytes(pkt))
        hdr = 28 if pkt.haslayer(IP) else 48
        if len(raw) <= hdr:
            return pkt
        for _ in range(self.rng.randint(1, 3)):
            i = self.rng.randrange(hdr, len(raw))
            raw[i] ^= 1 << self.rng.randrange(8)
        cls = IPv6 if pkt.haslayer(IPv6) else IP
        new = cls(bytes(raw))
        new.time = pkt.time
        new._lost = False
        self._pkt_events = [(new if pp is pkt else pp, ev)
                            for pp, ev in self._pkt_events]
        return new

    def _dup(self, rq, seq, mt, out, rtt, rsp):
        net = self.plan.network
        if not (net.duplicate and self.rng.random() < net.duplicate):
            return False
        dt = self.rng.uniform(0.0001, 0.002)
        d = _clone(rq, float(rq.time) + dt)
        out.append(d)
        self._log(d, "network", "duplicate_request",
                  "request duplicated by the network",
                  "peer replays cached response; must not re-execute",
                  seq, mt)
        if rsp is not None:
            out.append(_clone(rsp, float(d.time) + rtt))
        return True

    def _icmp(self, rq, t, seq, mt):
        ip, udp = _transport(rq)
        raw = bytes(rq)
        if rq.haslayer(IPv6):
            icmp = IPv6(src=ip.dst, dst=ip.src) / \
                ICMPv6DestUnreach(code=4) / Raw(raw[:1232])
        else:
            hl = ip.ihl * 4 if ip.ihl else 20
            icmp = IP(src=ip.dst, dst=ip.src) / ICMP(type=3, code=3) / \
                Raw(raw[:hl + 8])
        icmp.time = t
        self._log(icmp, "network", "icmp_port_unreachable",
                  "UPF host up but nothing listening on UDP/8805",
                  "requester should treat peer as down immediately "
                  "rather than wait for N1 retransmissions", seq, mt)
        return icmp


# ---------------------------------------------------------------------------
# Stateful scenarios (use PFCPSimulator internals)
# ---------------------------------------------------------------------------
def _log_scn(sim, events, fault, detail, expected, t=None):
    if events is not None:
        events.append(FaultEvent(sim.timing.now if t is None else t,
                                 "scenario", fault, detail, expected))


def heartbeat_flap(sim, upf, cycles=3, lost_per_cycle=2, events=None):
    """Intermittent loss of heartbeats: each cycle the request is
    retransmitted (same sequence number, T1 apart) and finally answered, so
    the path must NOT be declared down (lost_per_cycle <= N1)."""
    if lost_per_cycle > N1:
        raise ValueError("lost_per_cycle must be <= N1 for a flap")
    for _ in range(cycles):
        seq = sim._next_seq()
        t = sim.timing.advance()
        for k in range(lost_per_cycle + 1):
            req = sim._node_hdr(seq) / I.PFCPHeartbeatRequest(IE_list=[
                I.IE_RecoveryTimeStamp(timestamp=sim.cp_recovery)])
            sim._emit(req, sim.cp_ip, upf.address, t + k * T1)
        rsp = sim._node_hdr(seq) / I.PFCPHeartbeatResponse(IE_list=[
            I.IE_RecoveryTimeStamp(timestamp=sim._up_recovery(upf))])
        sim._emit(rsp, upf.address, sim.cp_ip,
                  t + lost_per_cycle * T1 + 0.002)
        _log_scn(sim, events, "heartbeat_flap",
                 f"{lost_per_cycle} heartbeat(s) lost then answered",
                 "path stays up; no session purge", t)
        sim.timing.now = t + (lost_per_cycle + 1) * T1


def signaling_storm(sim, upf, n=60, window=2.0, capacity=30, events=None):
    """Mass session (re-)establishment, e.g. after a CP/AMF-SMF restart or
    mass UE re-attach.  The UPF accepts ``capacity`` sessions then answers
    Cause 74 (congestion, with Overload Control Information); the CP backs
    off for the advertised timer and retries the rejected ones."""
    from .profiles import TimingModel
    saved = sim.timing
    sim.timing = TimingModel("constant", window / max(n, 1),
                             start=saved.now, rng=sim.rng, rtt=saved.rtt)
    t_start = sim.timing.now
    rejected = 0
    live = []
    for i in range(n):
        if i < capacity:
            s = sim.session_establishment(upf=sim._reserve(upf))
            if s:
                live.append(s)
        else:
            sim.session_establishment(upf=sim._reserve(upf),
                                      reject_cause=I.CAUSE_CONGESTION)
            rejected += 1
    _log_scn(sim, events, "signaling_storm",
             f"{n} establishments in {window}s; {rejected} rejected with "
             f"Cause 74", "CP honours Overload Control timer and retries",
             t_start)
    backoff_until = sim.timing.now + 30.0          # Overload Control timer
    sim.timing = TimingModel("constant", 0.05, start=backoff_until,
                             rng=sim.rng, rtt=saved.rtt)
    for _ in range(rejected):
        s = sim.session_establishment(upf=sim._reserve(upf))
        if s:
            live.append(s)
    saved.now = sim.timing.now
    sim.timing = saved
    return live


def orphan_session(sim, upf, events=None):
    """UPF restarted without the CP noticing (heartbeats lost / not yet
    due).  The CP modifies a session the UPF no longer knows: Cause 65.
    The CP then drops its state, sees the new Recovery Time Stamp in the
    next heartbeat, and re-establishes."""
    if upf.name not in sim.associated:
        sim.association_setup(upf)
    s = sim.session_establishment(upf=sim._reserve(upf))
    sim.session_modification(s, "activate_dl")
    sim.timing.skip(20.0)
    sim.up_recovery[upf.name] = int(sim.timing.now)       # silent restart
    seq = sim._next_seq()
    t = sim.timing.advance()
    req = sim._sess_hdr(seq, s.up_seid) / \
        I.PFCPSessionModificationRequest(IE_list=[
            I.update_far(2, "FORW", ohc=I.outer_header_creation(
                s.dl_teid or 1, sim._gnb_addr()))])
    rsp = sim._sess_hdr(seq, 0) / I.PFCPSessionModificationResponse(
        IE_list=[I.IE_Cause(cause=I.CAUSE_SESSION_NOT_FOUND)])
    sim._exchange(req, rsp, sim.cp_ip, upf.address, t=t)
    _log_scn(sim, events, "orphan_session",
             "UPF restarted silently; session context lost",
             "CP deletes local state, heartbeat reveals new Recovery TS, "
             "session re-established", t)
    s.state = type(s.state).DELETED
    sim.pool.release(upf)
    sim.heartbeat(upf)
    sim.association_setup(upf, initiator="up")
    new = sim.session_establishment(upf=sim._reserve(upf))
    if new:
        sim.session_modification(new, "activate_dl")
    return s, new
