"""Command line: ``python -m pfcp_gen {generate,check,profiles} ...``"""
import argparse
import sys

from .compliance import ComplianceChecker, summarize
from .profiles import PRESETS, get_profile
from .simulator import PFCPSimulator, UrspRule
from .state import Upf, FteidAllocator

SCENARIOS = ("lifecycle", "paging", "multi", "slices", "restart", "errors",
             "usage", "appdetect", "mixed")


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
    run_scenario(sim, a.scenario, a.count)
    n = sim.write(a.output)
    print(f"{n} packets written to {a.output}")
    if a.check and not a.ipsec:
        v = ComplianceChecker().check_packets(sim.packets)
        for x in v:
            print(x)
        print("compliance:", summarize(v))
        if a.scenario != "errors" and any(x.severity == "error" for x in v):
            return 1
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
    g.set_defaults(fn=cmd_generate)
    c = sub.add_parser("check", help="compliance-check an existing PCAP")
    c.add_argument("pcap")
    c.set_defaults(fn=cmd_check)
    p = sub.add_parser("profiles", help="list built-in traffic profiles")
    p.set_defaults(fn=cmd_profiles)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
