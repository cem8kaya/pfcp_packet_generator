"""Command line: ``python -m pfcp_gen {generate,check,profiles} ...``"""
import argparse
import sys

from . import faults
from .compliance import ComplianceChecker, summarize
from .profiles import PRESETS, get_profile
from .simulator import PFCPSimulator, UrspRule
from .state import Upf, FteidAllocator

SCENARIOS = ("lifecycle", "paging", "multi", "slices", "restart", "errors",
             "usage", "appdetect", "mixed", "flap", "storm", "orphan")


def _build_upfs(n, ipv6, profile, strategy):
    upfs = []
    for i in range(n):
        addr = f"2001:db8::{i + 2:x}" if ipv6 else f"192.0.2.{i + 2}"
        kind = strategy if strategy in ("sequential", "random", "range") \
            else "sequential"
        alloc = FteidAllocator(kind, prefix=i + 1,
                               prefix_bits=7 if kind == "range" else 0)
        upfs.append(Upf(f"upf-{i + 1}", addr, capacity=1000, weight=i + 1,
                        dnns=(profile.dnn, "internet"),
                        slices=((profile.sst, profile.sd), (1, None),
                                (2, None), (3, None)),
                        allocator=alloc))
    return upfs


def run_scenario(sim, name, count):
    upf = sim.pool.upfs[0]
    if name == "lifecycle":
        for _ in range(count):
            sim.lifecycle()
    elif name == "paging":
        for _ in range(count):
            sim.lifecycle(with_paging=True)
    elif name == "multi":
        sim.multi_session(count)
    elif name == "slices":
        sim.slice_sessions([(1, None, "internet"), (2, 1, "urllc"),
                            (3, 2, "iot")][:max(count, 1)])
    elif name == "restart":
        sim.lifecycle()
        sim.upf_restart(upf)
        sim.path_failure_report(upf)
        sim.cp_restart(upf)
    elif name == "errors":
        sim.association_setup(upf)
        for e in PFCPSimulator.ERROR_SCENARIOS:
            sim.error_scenario(e, upf)
    elif name == "usage":
        sim.association_setup(upf)
        s = sim.session_establishment()
        sim.session_modification(s, "activate_dl")
        for _ in range(count):
            sim.usage_report(s)
        sim.session_modification(s, "query_usage")
        sim.session_deletion(s)
    elif name == "appdetect":
        sim.association_setup(upf)
        sim.pfd_management(upf, {"video-stream": {
            "flows": ["permit out 6 from any to any 443"],
            "urls": ["https://video.example.com/*"]}})
        s = sim.session_establishment()
        sim.session_modification(s, "activate_dl")
        sim.application_detection(s)
        sim.usage_report(s)
        sim.session_deletion(s)
    elif name == "flap":
        sim.association_setup(upf)
        faults.heartbeat_flap(sim, upf, cycles=max(count, 1),
                              events=sim.fault_events)
    elif name == "storm":
        sim.association_setup(upf)
        faults.signaling_storm(sim, upf, n=max(count, 1) * 20,
                               capacity=max(count, 1) * 10,
                               events=sim.fault_events)
    elif name == "orphan":
        faults.orphan_session(sim, upf, events=sim.fault_events)
    elif name == "mixed":
        sim.association_setup(upf)
        for _ in range(count):
            sim.lifecycle(with_paging=sim.rng.random() < 0.3)
            sim.heartbeat(upf)
        sim.association_release(upf)


def cmd_generate(a):
    profile = get_profile(a.profile)
    upfs = _build_upfs(a.upfs, a.ipv6, profile, a.fteid)
    ursp = [UrspRule(50, app_id="ims-voice", sst=1, dnn="ims"),
            UrspRule(60, "permit out 6 from any to any 443", sst=1,
                     dnn="internet")] if a.ursp else ()
    auth = None
    if a.trusted:
        from .security import NodeAuthenticator
        auth = NodeAuthenticator(a.trusted)
    sim = PFCPSimulator(cp_ip="2001:db8::1" if a.ipv6 else "192.0.2.1",
                        upfs=upfs, profile=profile, seed=a.seed,
                        ipv6=a.ipv6, ipsec=a.ipsec, ursp_rules=ursp,
                        upf_strategy=a.upf_strategy, auth=auth,
                        fteid_mode="up" if a.fteid != "cp" else "cp")
    sim.fault_events = []
    run_scenario(sim, a.scenario, a.count)
    if a.faults:
        return _write_with_faults(sim.packets, a, sim.fault_events)
    n = sim.write(a.output)
    print(f"{n} packets written to {a.output}")
    if a.fault_log and sim.fault_events:
        _dump_log(a.fault_log, None, sim.fault_events)
        print(f"ground truth: {a.fault_log}")
    if a.check and not a.ipsec:
        v = ComplianceChecker().check_packets(sim.packets)
        for x in v:
            print(x)
        print("compliance:", summarize(v))
        if a.scenario != "errors" and any(x.severity == "error" for x in v):
            return 1
    return 0


def _dump_log(path, plan, events):
    import json
    with open(path, "w") as fh:
        json.dump({"plan": plan.to_dict() if plan else None,
                   "events": [e.to_dict() for e in events]}, fh, indent=2)


def _write_with_faults(packets, a, scenario_events=()):
    plan = faults.get_plan(a.faults)
    inj = faults.FaultInjector(plan, seed=a.fault_seed
                               if a.fault_seed is not None else a.seed)
    out, events = inj.write(packets, a.output)
    events = sorted(list(events) + list(scenario_events),
                    key=lambda e: e.time)
    if a.fault_log:
        _dump_log(a.fault_log, plan, events)
    from collections import Counter
    print(f"{len(packets)} -> {len(out)} packets written to {a.output} "
          f"(plan: {plan.name})")
    for k, v in sorted(Counter((e.layer, e.fault) for e in events).items()):
        print(f"  {k[0]:9} {k[1]:26} x{v}")
    if a.fault_log:
        print(f"ground truth: {a.fault_log}")
    if a.check:
        viol = ComplianceChecker().check_packets(out)
        print("compliance after injection:", summarize(viol))
    return 0


def cmd_inject(a):
    from scapy.all import rdpcap
    return _write_with_faults(rdpcap(a.pcap), a)


def cmd_faults(a):
    print("presets:")
    for n, p in faults.FAULT_PRESETS.items():
        print(f"  {n:20} protocol faults: {len(p.protocol)}")
    print("\nprotocol faults (name: side - expected peer behaviour):")
    for n, m in faults.MUTATORS.items():
        print(f"  {n:26} {m.side:8} {m.expected}")
    return 0


def cmd_check(a):
    v = ComplianceChecker().check_pcap(a.pcap)
    for x in v:
        print(x)
    print("compliance:", summarize(v))
    return 1 if any(x.severity == "error" for x in v) else 0


def cmd_profiles(a):
    for name, p in PRESETS.items():
        print(f"{name:6} qfi={p.qfi:<3} dnn={p.dnn:9} sst={p.sst} "
              f"timing={p.timing}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pfcp_gen")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="generate a PCAP from a scenario")
    g.add_argument("scenario", choices=SCENARIOS)
    g.add_argument("-n", "--count", type=int, default=3)
    g.add_argument("-o", "--output", default="pfcp.pcap")
    g.add_argument("--profile", default="embb",
                   help="preset name (embb|urllc|miot|voice) or JSON path")
    g.add_argument("--seed", type=int)
    g.add_argument("--ipv6", action="store_true")
    g.add_argument("--ipsec", action="store_true",
                   help="wrap N4 in ESP (item 17)")
    g.add_argument("--ursp", action="store_true",
                   help="add URSP-derived PDRs (item 18)")
    g.add_argument("--upfs", type=int, default=1)
    g.add_argument("--upf-strategy", default="least_loaded",
                   choices=("round_robin", "least_loaded", "weighted",
                            "random"))
    g.add_argument("--fteid", default="up",
                   choices=("up", "cp", "sequential", "random", "range"),
                   help="up=UPF-allocated (CH flag); others=CP allocation "
                        "strategy")
    g.add_argument("--trusted", nargs="*", help="Node ID allow-list")
    g.add_argument("--check", action="store_true",
                   help="run compliance check on the output")
    g.add_argument("--faults", help="fault preset name or JSON plan "
                   "(see `faults` subcommand)")
    g.add_argument("--fault-log", help="write ground-truth JSON here")
    g.add_argument("--fault-seed", type=int)
    g.set_defaults(fn=cmd_generate)
    i = sub.add_parser("inject", help="inject faults into an existing PCAP")
    i.add_argument("pcap")
    i.add_argument("-o", "--output", default="pfcp_faulty.pcap")
    i.add_argument("--faults", required=True)
    i.add_argument("--fault-log")
    i.add_argument("--fault-seed", type=int)
    i.add_argument("--seed", type=int)
    i.add_argument("--check", action="store_true")
    i.set_defaults(fn=cmd_inject)
    f = sub.add_parser("faults", help="list fault presets and anomalies")
    f.set_defaults(fn=cmd_faults)
    c = sub.add_parser("check", help="compliance-check an existing PCAP")
    c.add_argument("pcap")
    c.set_defaults(fn=cmd_check)
    p = sub.add_parser("profiles", help="list built-in traffic profiles")
    p.set_defaults(fn=cmd_profiles)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
