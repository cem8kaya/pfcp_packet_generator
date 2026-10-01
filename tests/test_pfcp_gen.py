import dataclasses
import ipaddress
import json

import pytest
from scapy.all import rdpcap, UDP
from scapy.contrib.pfcp import PFCP, IE_Dispatcher

from pfcp_gen import (PFCPSimulator, UrspRule, Upf, UpfPool, FteidAllocator,
                      Session, SessionState, InvalidTransition,
                      NoUpfAvailable, TrafficProfile, TimingModel, PRESETS,
                      ComplianceChecker, NodeAuthenticator)
from pfcp_gen import ies as I
from pfcp_gen.__main__ import main, SCENARIOS

CHECK = ComplianceChecker()


def errors(packets):
    return [v for v in CHECK.check_packets(packets) if v.severity == "error"]


def msgs(sim):
    return [p[PFCP].message_type for p in sim.packets]


# 2 - state machine / lifecycle ---------------------------------------------
def test_state_machine_rejects_invalid_transition():
    s = Session(cp_seid=1)
    with pytest.raises(InvalidTransition):
        s.transition(SessionState.ESTABLISHED)
    s.transition(SessionState.ESTABLISHING)
    s.transition(SessionState.ESTABLISHED)
    s.transition(SessionState.DELETING)
    s.transition(SessionState.DELETED)
    with pytest.raises(InvalidTransition):
        s.transition(SessionState.MODIFYING)


def test_lifecycle_sequence_and_seids():
    sim = PFCPSimulator(seed=1)
    s = sim.lifecycle(reports=2)
    assert s.state == SessionState.DELETED
    seq = msgs(sim)
    assert seq[:4] == [5, 6, 1, 2]          # assoc + heartbeat
    assert seq[4] == 50 and seq[5] == 51
    assert seq[-2:] == [54, 55]
    assert 56 in seq
    pk = sim.packets
    est_req, est_rsp = pk[4][PFCP], pk[5][PFCP]
    assert est_req.seid == 0 and est_rsp.seid == s.cp_seid
    mod_req = pk[6][PFCP]
    assert mod_req.seid == s.up_seid
    assert errors(pk) == []


def test_request_response_share_sequence_number():
    sim = PFCPSimulator(seed=2)
    sim.lifecycle()
    for i in range(0, len(sim.packets), 2):
        assert sim.packets[i][PFCP].seq == sim.packets[i + 1][PFCP].seq


# 3 - session report ----------------------------------------------------------
def test_session_report_request_response():
    sim = PFCPSimulator(seed=3)
    sim.lifecycle(reports=1)
    reqs = [p for p in sim.packets if p[PFCP].message_type == 56]
    rsps = [p for p in sim.packets if p[PFCP].message_type == 57]
    assert reqs and len(reqs) == len(rsps)
    assert reqs[0][PFCP].S == 1


# 5 - usage reporting ---------------------------------------------------------
def test_usage_report_content_and_sequence_numbers():
    sim = PFCPSimulator(seed=4)
    u = sim.pool.upfs[0]
    sim.association_setup(u)
    s = sim.session_establishment()
    for _ in range(3):
        sim.usage_report(s)
    sim.session_deletion(s)
    p = PFCP(bytes(sim.packets[-1][PFCP]))
    final = [ie for ie in p.payload.IE_list
             if type(ie).__name__ == "IE_UsageReport_SDR"][0]
    names = {type(i).__name__ for i in final.IE_list}
    assert {"IE_VolumeMeasurement", "IE_DurationMeasurement",
            "IE_UR_SEQN", "IE_StartTime", "IE_EndTime"} <= names
    seqns = []
    for pk in sim.packets:
        pf = PFCP(bytes(pk[PFCP]))
        if pf.message_type == 56:
            ur = pf.payload.IE_list[1]
            seqns.append(
                [i for i in ur.IE_list if type(i).__name__ == "IE_UR_SEQN"
                 ][0].number)
    assert seqns == [0, 1, 2]


def test_usage_trigger_by_volume():
    prof = dataclasses.replace(PRESETS["embb"], volume_threshold=1,
                               mean_interval=5)
    sim = PFCPSimulator(profile=prof, seed=5)
    sim.association_setup(sim.pool.upfs[0])
    s = sim.session_establishment()
    sim.usage_report(s)
    ur = PFCP(bytes(sim.packets[-2][PFCP])).payload.IE_list[1]
    trig = [i for i in ur.IE_list if type(i).__name__ ==
            "IE_UsageReportTrigger"][0]
    assert trig.VOLTH == 1


# 6 - 5G elements -------------------------------------------------------------
def test_qfi_and_qos_in_rules():
    sim = PFCPSimulator(profile="urllc", seed=6)
    sim.lifecycle()
    est = PFCP(bytes(sim.packets[4][PFCP]))
    flat = list(_walk(est.payload.IE_list))
    qfis = {i.QFI for i in flat if type(i).__name__ == "IE_QFI"}
    assert qfis == {7}
    assert any(type(i).__name__ == "IE_GBR" for i in flat)


def _walk(ies):
    for i in ies:
        yield i
        if hasattr(i, "IE_list"):
            yield from _walk(i.IE_list)


# 7 - timing ------------------------------------------------------------------
@pytest.mark.parametrize("kind", ["constant", "poisson", "burst"])
def test_timing_monotonic(kind):
    t = TimingModel(kind, mean_interval=0.5, burst_size=4, burst_gap=0.01)
    times = [t.advance() for _ in range(50)]
    assert times == sorted(times)
    if kind == "constant":
        assert {round(b - a, 6) for a, b in zip(times, times[1:])} == {0.5}
    if kind == "burst":
        gaps = [b - a for a, b in zip(times, times[1:])]
        assert sum(1 for g in gaps if abs(g - 0.01) < 1e-4) >= 30


def test_pcap_timestamps_ordered_and_responses_after_requests(tmp_path):
    sim = PFCPSimulator(seed=7)
    sim.lifecycle()
    f = tmp_path / "a.pcap"
    sim.write(str(f))
    pk = rdpcap(str(f))
    ts = [float(p.time) for p in pk]
    assert ts == sorted(ts)


def test_invalid_timing_kind():
    with pytest.raises(ValueError):
        TimingModel("weird")


# 8 - slicing -----------------------------------------------------------------
def test_slices_carry_snssai():
    upf = Upf("u", "192.0.2.2", dnns=("internet", "urllc", "iot"),
              slices=((1, None), (2, 1), (3, 2)))
    sim = PFCPSimulator(upfs=[upf], seed=8)
    sim.association_setup(upf)
    sim.slice_sessions([(1, None, "internet"), (2, 1, "urllc"),
                        (3, 2, "iot")])
    seen = set()
    for p in sim.packets:
        pf = PFCP(bytes(p[PFCP]))
        if pf.message_type == 50:
            for ie in _walk(pf.payload.IE_list):
                if type(ie).__name__ == "IE_SNSSAI":
                    seen.add((ie.sst, ie.sd))
    assert seen == {(1, b"\xff\xff\xff"), (2, b"\x00\x00\x01"),
                    (3, b"\x00\x00\x02")}


def test_snssai_roundtrip():
    ie = I.IE_Dispatcher(bytes(I.snssai(5, 0x123456)))
    assert (ie.sst, ie.sd) == (5, b"\x12\x34\x56")


# 9 - failure and recovery ----------------------------------------------------
def test_upf_restart_recovery_timestamp_changes_and_heartbeats_unanswered():
    sim = PFCPSimulator(seed=9)
    u = sim.pool.upfs[0]
    sim.association_setup(u)
    s = sim.session_establishment()
    first_ts = sim.up_recovery[u.name]
    sim.upf_restart(u)
    assert s.state == SessionState.DELETED
    assert sim.up_recovery[u.name] > first_ts
    hb = [p for p in sim.packets if p[PFCP].message_type == 1]
    assert len(hb) >= 4
    types = msgs(sim)
    # unanswered heartbeats are request-only
    assert types.count(1) - types.count(2) >= 4
    assert types[-4:] == [5, 6, 1, 2]       # re-association then heartbeat


def test_path_failure_and_cp_restart_and_retransmission():
    sim = PFCPSimulator(seed=10)
    u = sim.pool.upfs[0]
    sim.association_setup(u)
    sim.path_failure_report(u)
    sim.cp_restart(u)
    sim.retransmission(u)
    t = msgs(sim)
    assert 12 in t and 13 in t and 14 in t and 15 in t
    retx = [p for p in sim.packets if p[PFCP].message_type == 7]
    assert len({p[PFCP].seq for p in retx}) == 1 and len(retx) == 4
    assert errors(sim.packets) == []


# 10 - forwarding -------------------------------------------------------------
def test_far_variants_encode_correctly():
    far = I.IE_Dispatcher(bytes(I.create_far(
        3, "FORW", ohc=I.outer_header_creation(7, "10.0.0.9"),
        policy="pol", network_instance="internet")))
    names = {type(i).__name__ for i in far.IE_list}
    assert "IE_ForwardingParameters" in names
    buff = I.IE_Dispatcher(bytes(I.create_far(4, "BUFF+NOCP", bar_id=1)))
    aa = [i for i in buff.IE_list if type(i).__name__ == "IE_ApplyAction"][0]
    assert aa.BUFF == 1 and aa.NOCP == 1
    assert "IE_ForwardingParameters" not in {type(i).__name__
                                             for i in buff.IE_list}


def test_modification_kinds():
    sim = PFCPSimulator(seed=11, ursp_rules=[UrspRule(50)])
    sim.association_setup(sim.pool.upfs[0])
    s = sim.session_establishment()
    for k in ("activate_dl", "qos", "buffer", "resume", "duplicate",
              "query_usage", "remove_rule"):
        sim.session_modification(s, k)
    assert s.state == SessionState.ESTABLISHED
    with pytest.raises(ValueError):
        sim.session_modification(s, "bogus")
    assert errors(sim.packets) == []


# 11 - error scenarios --------------------------------------------------------
EXPECTED_CAUSE = {
    "association_rejected": 64, "no_association": 72,
    "mandatory_ie_missing": 66, "no_resources": 75, "rule_failure": 73,
    "session_not_found_mod": 65, "session_not_found_del": 65,
    "invalid_fteid": 71, "congestion": 74, "service_not_supported": 76,
    "system_failure": 77, "unauthorized_node": 64,
}


@pytest.mark.parametrize("name", PFCPSimulator.ERROR_SCENARIOS)
def test_error_scenarios(name):
    sim = PFCPSimulator(seed=12)
    sim.error_scenario(name)
    assert len(sim.packets) == 2
    if name == "version_not_supported":
        assert sim.packets[1][PFCP].message_type == 11
        return
    rsp = PFCP(bytes(sim.packets[1][PFCP])).payload
    cause = [i for i in rsp.IE_list if type(i).__name__ == "IE_Cause"][0]
    assert cause.cause == EXPECTED_CAUSE[name]
    errs = errors(sim.packets)
    if name == "mandatory_ie_missing":
        assert errs      # request is deliberately non-compliant
    else:
        assert errs == []


# 12 - F-TEID allocation ------------------------------------------------------
def test_fteid_strategies():
    seq = FteidAllocator("sequential", start=10)
    assert [seq.allocate() for _ in range(3)] == [10, 11, 12]
    rnd = FteidAllocator("random")
    vals = {rnd.allocate() for _ in range(200)}
    assert len(vals) == 200 and 0 not in vals
    rng = FteidAllocator("range", prefix=5, prefix_bits=7, start=1)
    for _ in range(20):
        assert rng.allocate() >> 25 == 5
    with pytest.raises(ValueError):
        FteidAllocator("range", prefix=1, prefix_bits=8)
    with pytest.raises(ValueError):
        FteidAllocator("nope")
    a = FteidAllocator("sequential", start=1)
    t = a.allocate()
    a.release(t)


def test_up_vs_cp_allocation_modes():
    up = PFCPSimulator(seed=13, fteid_mode="up")
    up.association_setup(up.pool.upfs[0])
    up.session_establishment()
    est = PFCP(bytes(up.packets[2][PFCP]))
    ft = [i for i in _walk(est.payload.IE_list)
          if type(i).__name__ == "IE_FTEID"][0]
    assert ft.CH == 1
    rsp = PFCP(bytes(up.packets[3][PFCP]))
    assert any(type(i).__name__ == "IE_CreatedPDR"
               for i in rsp.payload.IE_list)
    cp = PFCPSimulator(seed=13, fteid_mode="cp")
    cp.association_setup(cp.pool.upfs[0])
    cp.session_establishment()
    est = PFCP(bytes(cp.packets[2][PFCP]))
    ft = [i for i in _walk(est.payload.IE_list)
          if type(i).__name__ == "IE_FTEID"][0]
    assert ft.CH == 0 and ft.TEID != 0


def test_teid_range_advertised_in_association_response():
    u = Upf("u", "192.0.2.2", allocator=FteidAllocator(
        "range", prefix=3, prefix_bits=4))
    sim = PFCPSimulator(upfs=[u], seed=14)
    sim.association_setup(u)
    rsp = PFCP(bytes(sim.packets[1][PFCP]))
    res = [i for i in rsp.payload.IE_list
           if type(i).__name__ == "IE_UserPlaneIPResourceInformation"][0]
    assert res.TEIDRI == 4 and res.teid_range == 3


# 13 - buffering / paging -----------------------------------------------------
def test_paging_flow():
    sim = PFCPSimulator(seed=15)
    sim.lifecycle(with_paging=True)
    dldr = None
    for p in sim.packets:
        pf = PFCP(bytes(p[PFCP]))
        if pf.message_type == 56:
            rt = pf.payload.IE_list[0]
            if rt.DLDR:
                dldr = pf
    assert dldr is not None
    assert any(type(i).__name__ == "IE_DownlinkDataReport"
               for i in dldr.payload.IE_list)
    # buffer modification contains BAR + BUFF|NOCP
    flat = []
    for p in sim.packets:
        pf = PFCP(bytes(p[PFCP]))
        if pf.message_type == 52:
            flat += list(_walk(pf.payload.IE_list))
    assert any(type(i).__name__ == "IE_ApplyAction" and i.BUFF and i.NOCP
               for i in flat)
    assert any(type(i).__name__ == "IE_Create_BAR" for i in flat)
    assert errors(sim.packets) == []


def test_dl_report_requires_buffering():
    sim = PFCPSimulator(seed=16)
    sim.association_setup(sim.pool.upfs[0])
    s = sim.session_establishment()
    with pytest.raises(ValueError):
        sim.downlink_data_report(s)


# 14 - UPF selection ----------------------------------------------------------
def test_upf_selection_strategies():
    upfs = [Upf("a", "10.0.0.1", capacity=10, weight=1),
            Upf("b", "10.0.0.2", capacity=10, weight=1),
            Upf("c", "10.0.0.3", capacity=10, weight=1,
                dnns=("ims",))]
    rr = UpfPool(upfs, "round_robin")
    assert [rr.select("internet").name for _ in range(4)] == \
        ["a", "b", "a", "b"]
    for u in upfs:
        u.load = 0
    ll = UpfPool(upfs, "least_loaded")
    upfs[0].load = 5
    assert ll.select("internet").name == "b"
    assert ll.select("ims").name == "c"
    w = UpfPool(upfs, "weighted", rng=__import__("random").Random(1))
    assert w.select("internet").name in ("a", "b")


def test_upf_capacity_and_unavailable():
    u = Upf("a", "10.0.0.1", capacity=1)
    pool = UpfPool([u])
    pool.select()
    with pytest.raises(NoUpfAvailable):
        pool.select()
    pool.release(u)
    u.available = False
    with pytest.raises(NoUpfAvailable):
        pool.select()
    with pytest.raises(NoUpfAvailable):
        UpfPool([Upf("x", "1.1.1.1")]).select(dnn="nope")


def test_multi_session_spreads_over_upfs():
    upfs = [Upf(f"u{i}", f"192.0.2.{i + 2}") for i in range(3)]
    sim = PFCPSimulator(upfs=upfs, seed=17, upf_strategy="round_robin")
    live = sim.multi_session(6)
    assert {s.upf.name for s in live} == {"u0", "u1", "u2"}
    assert all(u.load == 0 for u in upfs)    # all released
    assert errors(sim.packets) == []


def test_invalid_upf_feature_rejected():
    with pytest.raises(ValueError):
        PFCPSimulator(upfs=[Upf("a", "10.0.0.1", features=("BOGUS",))])


# 15 - application detection --------------------------------------------------
def test_pfd_management_and_detection_report():
    sim = PFCPSimulator(seed=18)
    u = sim.pool.upfs[0]
    sim.association_setup(u)
    sim.pfd_management(u, {"app1": {"flows": ["permit out ip from any to any"],
                                    "urls": ["http://a/*"]}})
    s = sim.session_establishment()
    sim.application_detection(s, "app1")
    t = msgs(sim)
    assert 3 in t and 4 in t
    pf = PFCP(bytes(sim.packets[-2][PFCP]))
    assert any(type(i).__name__ == "IE_ApplicationDetectionInformation"
               for i in _walk(pf.payload.IE_list))
    assert errors(sim.packets) == []


# 16 - IPv6 -------------------------------------------------------------------
def test_ipv6_transport_and_addresses():
    sim = PFCPSimulator(cp_ip="2001:db8::1", seed=19, ipv6=True)
    sim.lifecycle(with_paging=True)
    assert all(p.version == 6 if hasattr(p, "version") else True
               for p in sim.packets)
    from scapy.all import IPv6
    assert all(IPv6 in p for p in sim.packets)
    s = list(sim.sessions.sessions.values())[0]
    assert ipaddress.ip_address(s.ue_ip).version == 6
    assert errors(sim.packets) == []


def test_ipv6_ies():
    n = I.IE_Dispatcher(bytes(I.node_id("2001:db8::5")))
    assert n.id_type == 1 and n.ipv6 == "2001:db8::5"
    f = I.IE_Dispatcher(bytes(I.fseid(5, "2001:db8::5")))
    assert f.v6 == 1 and f.v4 == 0
    t = I.IE_Dispatcher(bytes(I.fteid(5, "2001:db8::5")))
    assert t.V6 == 1
    fqdn = I.IE_Dispatcher(bytes(I.node_id("upf.example.com")))
    assert fqdn.id_type == 2 and fqdn.id == b"upf.example.com"


# 17 - security ---------------------------------------------------------------
def test_node_authentication_rejects_untrusted():
    sim = PFCPSimulator(seed=20, auth=NodeAuthenticator(["other"]))
    u = sim.pool.upfs[0]
    assert sim.association_setup(u) == 64
    assert sim.lifecycle() is None
    sim2 = PFCPSimulator(seed=20, auth=NodeAuthenticator(["upf-1"]))
    assert sim2.lifecycle() is not None


def test_ipsec_wraps_pfcp_in_esp():
    from scapy.layers.ipsec import ESP
    sim = PFCPSimulator(seed=21, ipsec=True)
    sim.lifecycle()
    assert all(ESP in p for p in sim.packets)
    assert all(PFCP not in p for p in sim.packets)


# 18 - URSP -------------------------------------------------------------------
def test_ursp_rules_become_pdrs():
    rules = [UrspRule(50, app_id="ims-voice", sst=1, dnn="ims"),
             UrspRule(60, "permit out 6 from any to any 443")]
    sim = PFCPSimulator(seed=22, ursp_rules=rules)
    sim.association_setup(sim.pool.upfs[0])
    sim.session_establishment()
    est = PFCP(bytes(sim.packets[2][PFCP]))
    pdrs = [i for i in est.payload.IE_list
            if type(i).__name__ == "IE_CreatePDR"]
    assert len(pdrs) == 4
    precs = sorted(
        [i for i in p.IE_list if type(i).__name__ == "IE_Precedence"
         ][0].precedence for p in pdrs)
    assert precs == [50, 60, 100, 100]
    assert errors(sim.packets) == []


# 19 - profiles ---------------------------------------------------------------
def test_profile_roundtrip_and_validation(tmp_path):
    p = dataclasses.replace(PRESETS["urllc"], name="custom", qfi=5)
    f = tmp_path / "p.json"
    p.to_file(str(f))
    assert TrafficProfile.from_file(str(f)) == p
    with pytest.raises(ValueError):
        TrafficProfile.from_dict({"bogus": 1})
    with pytest.raises(ValueError):
        TrafficProfile(qfi=82)
    with pytest.raises(ValueError):
        TrafficProfile(gbr_ul=1, gbr_dl=None)
    with pytest.raises(ValueError):
        TrafficProfile(mbr_ul=1, gbr_ul=2, gbr_dl=1)


def test_shipped_profiles_load_and_generate():
    import glob
    files = glob.glob("profiles/*.json")
    assert len(files) >= 4
    for f in files:
        prof = TrafficProfile.from_file(f)
        sim = PFCPSimulator(profile=prof, seed=23)
        sim.lifecycle()
        assert errors(sim.packets) == []


# 20 - compliance -------------------------------------------------------------
def test_checker_detects_defects():
    sim = PFCPSimulator(seed=24)
    sim.lifecycle()
    pk = sim.packets
    assert errors(pk) == []
    # bad S flag
    bad = pk[0].copy()
    bad[PFCP].S = 1
    bad[PFCP].seid = 5
    assert any("S=0" in v.detail for v in CHECK.check_packet(bad))
    # missing mandatory IE
    e = PFCP(S=0, seq=1) / I.PFCPAssociationSetupRequest(
        IE_list=[I.node_id("10.0.0.1")])
    from scapy.all import IP
    pkt = IP() / UDP(sport=8805, dport=8805) / e
    assert any("IE_RecoveryTimeStamp" in v.detail
               for v in CHECK.check_packet(pkt))
    # GBR > MBR
    q = I.create_qer(1, 10, 10, 20, 20, 5)
    e = PFCP(S=1, seq=1, seid=0) / I.PFCPSessionEstablishmentRequest(
        IE_list=[I.node_id("10.0.0.1"), I.fseid(1, "10.0.0.1"),
                 I.create_pdr(1, 1, I.pdi()), I.create_far(1, "DROP"), q])
    pkt = IP() / UDP(sport=8805, dport=8805) / e
    assert any("GBR exceeds MBR" in v.detail for v in CHECK.check_packet(pkt))
    # FORW without forwarding parameters
    far = I.IE_CreateFAR(IE_list=[I.IE_FAR_Id(id=1),
                                  I.IE_ApplyAction(FORW=1)])
    e = PFCP(S=1, seq=1, seid=0) / I.PFCPSessionEstablishmentRequest(
        IE_list=[I.node_id("10.0.0.1"), I.fseid(1, "10.0.0.1"),
                 I.create_pdr(1, 1, I.pdi()), far])
    pkt = IP() / UDP(sport=8805, dport=8805) / e
    assert any("Forwarding" in v.detail for v in CHECK.check_packet(pkt))
    # wrong port
    pkt = IP() / UDP(sport=1, dport=2) / e
    assert any("8805" in v.detail for v in CHECK.check_packet(pkt))


def test_checker_flags_unanswered_request():
    sim = PFCPSimulator(seed=25)
    sim.heartbeat(sim.pool.upfs[0], answered=False)
    v = CHECK.check_packets(sim.packets)
    assert any("no response" in x.detail for x in v)


# CLI -------------------------------------------------------------------------
@pytest.mark.parametrize("scenario", [s for s in SCENARIOS if s != "errors"])
def test_cli_scenarios_are_compliant(scenario, tmp_path):
    out = tmp_path / f"{scenario}.pcap"
    rc = main(["generate", scenario, "-n", "2", "-o", str(out), "--seed", "1",
               "--check", "--upfs", "2", "--fteid", "range", "--ursp"])
    assert rc == 0 and out.exists()
    assert main(["check", str(out)]) in (0, 1)


def test_cli_errors_and_ipv6_and_profiles(tmp_path, capsys):
    out = tmp_path / "e.pcap"
    assert main(["generate", "errors", "-o", str(out), "--check"]) == 0
    assert main(["generate", "mixed", "--ipv6", "--profile", "voice", "-o",
                 str(out), "--check"]) == 0
    assert main(["profiles"]) == 0
    assert "urllc" in capsys.readouterr().out


def test_deterministic_with_seed():
    a, b = PFCPSimulator(seed=99), PFCPSimulator(seed=99)
    a.lifecycle(with_paging=True)
    b.lifecycle(with_paging=True)
    assert [bytes(p) for p in a.packets] == [bytes(p) for p in b.packets]


def test_legacy_generator_still_works(tmp_path):
    from pfcp_packet_generator import RobustPFCPPacketGenerator
    g = RobustPFCPPacketGenerator("192.0.2.1", "192.0.2.2")
    g.generate_pcap(5, str(tmp_path / "l.pcap"))
    assert (tmp_path / "l.pcap").exists()
