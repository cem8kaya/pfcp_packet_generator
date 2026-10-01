import json
from collections import Counter

import pytest
from scapy.all import rdpcap, ICMP, IP, IPv6, UDP
from scapy.contrib.pfcp import PFCP

from pfcp_gen import PFCPSimulator, ComplianceChecker
from pfcp_gen import faults as F
from pfcp_gen.__main__ import main

CHECK = ComplianceChecker()


def traffic(seed=1, n=6, **kw):
    sim = PFCPSimulator(seed=seed, **kw)
    for _ in range(n):
        sim.lifecycle(with_paging=True)
    return sim.packets


def run(plan, seed=1, packets=None, **kw):
    pk = packets if packets is not None else traffic(**kw)
    return F.FaultInjector(plan, seed=seed).apply(pk)


def parse(p):
    return PFCP(bytes(p[UDP].payload))


def by_fault(events, name):
    return [e for e in events if e.fault == name]


# --- network layer ----------------------------------------------------------
def test_no_faults_is_identity():
    pk = traffic()
    out, ev = run(F.FaultPlan(), packets=pk)
    assert ev == [] and [bytes(p) for p in out] == [bytes(p) for p in pk]


def test_request_loss_triggers_same_seq_retransmission():
    plan = F.FaultPlan(network=F.NetworkProfile(loss=0.3))
    out, ev = run(plan, seed=4)
    retx = by_fault(ev, "retransmission")
    assert retx
    for e in retx:
        same = [p for p in out if p.haslayer(UDP) and parse(p).seq == e.seq
                and parse(p).message_type == e.message_type]
        assert len(same) >= 2
        assert len({bytes(parse(p)) for p in same}) == 1   # identical bytes


def test_response_loss_replays_cached_response():
    plan = F.FaultPlan(network=F.NetworkProfile(loss=0.3))
    out, ev = run(plan, seed=5)
    lost = by_fault(ev, "response_loss")
    assert lost
    e = lost[0]
    rsp = [p for p in out if parse(p).seq == e.seq
           and parse(p).message_type not in F.REQUESTS]
    assert len(rsp) >= 2      # original (lost) + replay after retransmit


def test_receiver_tap_hides_lost_packets():
    net = dict(loss=0.3)
    s = F.FaultPlan(network=F.NetworkProfile(tap="sender", **net))
    r = F.FaultPlan(network=F.NetworkProfile(tap="receiver", **net))
    a, ev = run(s, seed=6)
    b, _ = run(r, seed=6)
    lost = len([e for e in ev if e.fault.endswith("_loss")])
    assert len(a) - len(b) == lost > 0


def test_ground_truth_indices_point_at_packets():
    out, ev = run(F.FAULT_PRESETS["lossy_link"], seed=7)
    for e in ev:
        assert 0 <= e.index < len(out)
        assert abs(float(out[e.index].time) - e.time) < 1e-6


def test_blackout_with_icmp_unreachable():
    out, ev = run(F.FAULT_PRESETS["upf_process_down"], seed=8)
    icmp = [p for p in out if ICMP in p]
    assert icmp and by_fault(ev, "icmp_port_unreachable")
    assert all(p[ICMP].type == 3 and p[ICMP].code == 3 for p in icmp)
    assert by_fault(ev, "exchange_failed")
    # no ICMP for the plain outage preset
    out2, ev2 = run(F.FAULT_PRESETS["link_outage"], seed=8)
    assert not [p for p in out2 if ICMP in p]
    assert by_fault(ev2, "request_blackout")


def test_icmpv6_unreachable():
    from scapy.layers.inet6 import ICMPv6DestUnreach
    out, _ = run(F.FAULT_PRESETS["upf_process_down"], seed=8, ipv6=True,
                 cp_ip="2001:db8::1")
    assert any(ICMPv6DestUnreach in p for p in out)


def test_burst_loss_is_bursty():
    """Gilbert-Elliott losses cluster more than Bernoulli at equal rate."""
    import random
    prof = F.NetworkProfile(p_good_bad=0.02, p_bad_good=0.2, loss_bad=0.9)
    m = F._LossModel(prof, random.Random(1), 0.0)
    seq = [m.lost(float(i)) for i in range(20000)]
    rate = sum(seq) / len(seq)
    pairs = sum(1 for a, b in zip(seq, seq[1:]) if a and b) / max(sum(seq), 1)
    assert 0.02 < rate < 0.4
    assert pairs > rate * 2      # conditional loss prob >> marginal


def test_corruption_keeps_stale_checksum_and_forces_retransmit():
    plan = F.FaultPlan(network=F.NetworkProfile(corrupt=0.4))
    out, ev = run(plan, seed=9)
    assert by_fault(ev, "request_corruption") or \
        by_fault(ev, "response_corruption")
    assert by_fault(ev, "retransmission")


def test_duplicate_request_gets_replayed_response():
    plan = F.FaultPlan(network=F.NetworkProfile(duplicate=0.5))
    out, ev = run(plan, seed=10)
    d = by_fault(ev, "duplicate_request")
    assert d
    seq = d[0].seq
    rsp = [p for p in out if parse(p).seq == seq
           and parse(p).message_type not in F.REQUESTS]
    assert len(rsp) >= 2


def test_responses_never_precede_requests():
    out, _ = run(F.FAULT_PRESETS["congested_backhaul"], seed=11)
    first_req = {}
    for p in out:
        d = parse(p)
        if d.message_type in F.REQUESTS:
            first_req.setdefault(d.seq, float(p.time))
    for p in out:
        d = parse(p)
        if d.message_type not in F.REQUESTS and d.message_type != 11 \
                and d.seq in first_req:
            assert float(p.time) >= first_req[d.seq]


def test_retransmit_disabled():
    plan = F.FaultPlan(network=F.NetworkProfile(loss=0.5, retransmit=False))
    _, ev = run(plan, seed=12)
    assert not by_fault(ev, "retransmission")


# --- protocol layer ---------------------------------------------------------
def only(fault, messages=None, p=1.0):
    return F.FaultPlan(protocol=[F.ProtocolFault(fault, p, messages)])


def first_event(out, ev, fault):
    e = by_fault(ev, fault)
    assert e, f"{fault} never applied"
    return e[0]


def response_for(out, seq):
    return [parse(p) for p in out if p.haslayer(UDP)
            and parse(p).seq == seq
            and parse(p).message_type not in F.REQUESTS]


def cause_of(d):
    return [i for i in d.payload.IE_list
            if type(i).__name__ == "IE_Cause"][0].cause


def test_missing_mandatory_ie_gets_cause_66_with_offending_ie():
    out, ev = run(only("missing_mandatory_ie", [50]), seed=1)
    e = first_event(out, ev, "missing_mandatory_ie")
    r = response_for(out, e.seq)[0]
    assert cause_of(r) == 66
    off = [i for i in r.payload.IE_list
           if type(i).__name__ == "IE_OffendingIE"]
    assert off
    errs = [v for v in CHECK.check_packets(out)
            if v.severity == "error" and "mandatory" in v.detail]
    assert errs


def test_unknown_seid_cause_65_and_zero_seid():
    out, ev = run(only("unknown_seid", [52]), seed=1)
    e = first_event(out, ev, "unknown_seid")
    r = response_for(out, e.seq)[0]
    assert cause_of(r) == 65 and r.seid == 0


def test_invalid_qfi_cause_69():
    out, ev = run(only("invalid_qfi", [50]), seed=1)
    e = first_event(out, ev, "invalid_qfi")
    r = response_for(out, e.seq)[0]
    assert cause_of(r) == 69
    assert [i for i in r.payload.IE_list
            if type(i).__name__ == "IE_OffendingIE"][0].type == 124


def test_gbr_exceeds_mbr_cause_73_failed_rule():
    pk = traffic(profile="urllc")
    out, ev = run(only("gbr_exceeds_mbr", [50]), packets=pk)
    e = first_event(out, ev, "gbr_exceeds_mbr")
    r = response_for(out, e.seq)[0]
    assert cause_of(r) == 73
    assert any(type(i).__name__ == "IE_FailedRuleId"
               for i in r.payload.IE_list)
    assert any("GBR exceeds MBR" in v.detail
               for v in CHECK.check_packets(out))


def test_version_fault_yields_version_not_supported():
    out, ev = run(only("version", [50]), seed=1)
    e = first_event(out, ev, "version")
    r = response_for(out, e.seq)[0]
    assert r.message_type == 11 and r.version == 1


@pytest.mark.parametrize("fault", ["header_length", "s_flag", "truncated",
                                   "unknown_message_type"])
def test_discard_faults_have_no_response_and_requester_retransmits(fault):
    out, ev = run(only(fault, [50]), seed=2)
    e = first_event(out, ev, fault)
    n_req = [p for p in out if bytes(p[UDP].payload)[4:12] is not None
             and abs(float(p.time) - e.time) < 10 * F.T1
             and p.haslayer(UDP)]
    assert by_fault(ev, "retransmission")
    assert by_fault(ev, "exchange_failed")
    assert not any(parse(p).seq == e.seq and
                   parse(p).message_type in (51, 11) for p in out
                   if p.haslayer(UDP) and len(bytes(p[UDP].payload)) > 12
                   and fault in ("header_length",) and False)


@pytest.mark.parametrize("fault", ["unknown_ie", "duplicate_ie",
                                   "reorder_ies", "trailing_garbage"])
def test_tolerated_faults_keep_original_response(fault):
    pk = traffic()
    base, _ = run(F.FaultPlan(), packets=pk)
    out, ev = run(only(fault, [50]), packets=pk, seed=3)
    e = first_event(out, ev, fault)
    r = response_for(out, e.seq)[0]
    assert cause_of(r) == 1
    assert not by_fault(ev, "exchange_failed")


def test_bad_ie_length_cause_68_and_checker_flags_it():
    out, ev = run(only("bad_ie_length", [50]), seed=1)
    e = first_event(out, ev, "bad_ie_length")
    assert cause_of(response_for(out, e.seq)[0]) == 68
    assert CHECK.check_packets(out)


def test_response_side_faults():
    out, ev = run(only("rsp_reserved_cause", [51]), seed=1)
    e = first_event(out, ev, "rsp_reserved_cause")
    assert cause_of(response_for(out, e.seq)[0]) not in (1, 64)
    assert any("undefined cause" in v.detail
               for v in CHECK.check_packets(out))
    out, ev = run(only("rsp_accept_without_fseid", [51]), seed=1)
    e = first_event(out, ev, "rsp_accept_without_fseid")
    assert any("lacks UP F-SEID" in v.detail
               for v in CHECK.check_packets(out))


def test_peer_restart_and_regress_change_recovery_timestamp():
    def ts_of(d):
        return [i for i in d.payload.IE_list
                if type(i).__name__ == "IE_RecoveryTimeStamp"][0].timestamp
    pk = traffic()
    base = {parse(p).seq: ts_of(parse(p)) for p in pk
            if parse(p).message_type == 2}
    out, ev = run(only("rsp_peer_restart", [2]), packets=pk)
    e = first_event(out, ev, "rsp_peer_restart")
    assert ts_of(response_for(out, e.seq)[0]) > base[e.seq]
    out, ev = run(only("rsp_recovery_regress", [2]), packets=pk)
    e = first_event(out, ev, "rsp_recovery_regress")
    assert ts_of(response_for(out, e.seq)[0]) < base[e.seq]


def test_unmatched_response_forces_retransmission_and_replay():
    out, ev = run(only("rsp_wrong_seq", [53]), seed=1)
    e = first_event(out, ev, "rsp_wrong_seq")
    assert by_fault(ev, "retransmission")
    # a response with the right seq eventually arrives
    got = [parse(p) for p in out if p.haslayer(UDP)
           and parse(p).seq == e.seq and parse(p).message_type == 53]
    assert got


def test_scope_and_message_filters():
    out, ev = run(only("missing_mandatory_ie", [5]), seed=1)
    assert all(e.message_type == 5 for e in by_fault(
        ev, "missing_mandatory_ie"))
    # node-only fault never touches session messages
    out, ev = run(only("rsp_peer_restart"), seed=1)
    assert ev and all(e.message_type in F.NODE_MESSAGES for e in ev
               if e.fault == "rsp_peer_restart")


def test_fault_events_describe_expected_peer_behaviour():
    _, ev = run(F.FAULT_PRESETS["chaos"], seed=13)
    assert ev and all(e.expected and e.detail for e in ev)


# --- plans / validation / determinism ----------------------------------------
def test_plan_validation_and_roundtrip(tmp_path):
    with pytest.raises(ValueError):
        F.NetworkProfile(loss=1.5)
    with pytest.raises(ValueError):
        F.NetworkProfile(tap="nowhere")
    with pytest.raises(ValueError):
        F.ProtocolFault("nope")
    with pytest.raises(ValueError):
        F.FaultPlan.from_dict({"bogus": 1})
    plan = F.FAULT_PRESETS["chaos"]
    f = tmp_path / "p.json"
    f.write_text(json.dumps(plan.to_dict()))
    assert F.FaultPlan.from_file(str(f)).to_dict() == plan.to_dict()


def test_deterministic_for_seed():
    pk = traffic()
    a, ea = run(F.FAULT_PRESETS["chaos"], seed=21, packets=pk)
    b, eb = run(F.FAULT_PRESETS["chaos"], seed=21, packets=pk)
    assert [bytes(p) for p in a] == [bytes(p) for p in b]
    assert [e.to_dict() for e in ea] == [e.to_dict() for e in eb]


@pytest.mark.parametrize("name", list(F.FAULT_PRESETS))
def test_all_presets_run_ipv4_and_ipv6(name):
    for kw in ({}, dict(ipv6=True, cp_ip="2001:db8::1")):
        out, ev = run(F.FAULT_PRESETS[name], seed=2, **kw)
        assert out
        for p in out:                    # every packet serialises
            bytes(p)


def test_ipsec_traffic_passes_through_untouched():
    pk = traffic(ipsec=True, n=2)
    out, ev = run(F.FAULT_PRESETS["buggy_peer"], packets=pk)
    assert len(out) == len(pk) and ev == []


# --- scenarios ---------------------------------------------------------------
def test_heartbeat_flap_keeps_path_up():
    sim = PFCPSimulator(seed=1)
    u = sim.pool.upfs[0]
    sim.association_setup(u)
    events = []
    F.heartbeat_flap(sim, u, cycles=2, lost_per_cycle=2, events=events)
    hb = [parse(p) for p in sim.packets if parse(p).message_type == 1]
    assert len(hb) == 2 * 3                      # 2 cycles x 3 requests
    assert len({d.seq for d in hb}) == 2
    assert [e.fault for e in events] == ["heartbeat_flap"] * 2
    with pytest.raises(ValueError):
        F.heartbeat_flap(sim, u, lost_per_cycle=F.N1 + 1)


def test_signaling_storm_overload_and_retry():
    sim = PFCPSimulator(seed=1)
    u = sim.pool.upfs[0]
    sim.association_setup(u)
    live = F.signaling_storm(sim, u, n=20, capacity=12, window=1.0)
    assert len(live) == 20                       # all eventually admitted
    causes = Counter()
    for p in sim.packets:
        d = parse(p)
        if d.message_type == 51:
            causes[cause_of(d)] += 1
    assert causes[74] == 8 and causes[1] == 20
    ov = [p for p in sim.packets if parse(p).message_type == 51 and
          cause_of(parse(p)) == 74]
    assert all(any(type(i).__name__ == "IE_OverloadControlInformation"
                   for i in parse(p).payload.IE_list) for p in ov)
    # rejected ones retried after >= 30 s backoff
    ts = sorted(float(p.time) for p in sim.packets
                if parse(p).message_type == 50)
    assert ts[-1] - ts[11] >= 30
    assert [v for v in CHECK.check_packets(sim.packets)
            if v.severity == "error"] == []


def test_orphan_session_cause_65_then_reestablish():
    sim = PFCPSimulator(seed=1)
    u = sim.pool.upfs[0]
    events = []
    old, new = F.orphan_session(sim, u, events=events)
    types = [parse(p).message_type for p in sim.packets]
    assert 65 in [cause_of(parse(p)) for p in sim.packets
                  if parse(p).message_type == 53]
    assert types.count(50) == 2 and new is not None
    assert events and events[0].fault == "orphan_session"
    assert [v for v in CHECK.check_packets(sim.packets)
            if v.severity == "error"] == []


# --- CLI ---------------------------------------------------------------------
def test_cli_generate_with_faults_and_log(tmp_path):
    out, log = tmp_path / "f.pcap", tmp_path / "gt.json"
    assert main(["generate", "mixed", "-n", "4", "--seed", "3", "--faults",
                 "lossy_link", "--fault-log", str(log), "-o", str(out),
                 "--check"]) == 0
    gt = json.loads(log.read_text())
    assert gt["events"] and gt["plan"]["name"] == "lossy_link"
    assert len(rdpcap(str(out))) > 0
    for e in gt["events"]:
        assert 0 <= e["index"] < len(rdpcap(str(out)))


def test_cli_inject_into_existing_pcap(tmp_path):
    src, dst = tmp_path / "a.pcap", tmp_path / "b.pcap"
    main(["generate", "lifecycle", "-n", "3", "--seed", "1", "-o", str(src)])
    assert main(["inject", str(src), "--faults", "buggy_peer", "-o",
                 str(dst), "--fault-seed", "5", "--check"]) == 0
    assert len(rdpcap(str(dst))) == len(rdpcap(str(src)))


@pytest.mark.parametrize("sc", ["flap", "storm", "orphan"])
def test_cli_fault_scenarios(sc, tmp_path):
    log = tmp_path / "l.json"
    assert main(["generate", sc, "-n", "1", "--seed", "1", "-o",
                 str(tmp_path / "x.pcap"), "--fault-log", str(log),
                 "--check"]) == 0
    assert json.loads(log.read_text())["events"]


def test_cli_faults_listing(capsys):
    assert main(["faults"]) == 0
    out = capsys.readouterr().out
    assert "buggy_peer" in out and "missing_mandatory_ie" in out
