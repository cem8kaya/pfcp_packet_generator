"""Traffic profiles (item 19) and inter-packet timing / bursts (item 7)."""
import json
import random
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple


@dataclass
class TrafficProfile:
    """Describes the QoS, usage and timing characteristics of a UE flow.
    Fully user-definable: build in code, or ``TrafficProfile.from_file``
    with a JSON document (see ``profiles/*.json``)."""
    name: str = "default"
    qfi: int = 9
    mbr_ul: int = 100_000_000          # bit/s
    mbr_dl: int = 100_000_000
    gbr_ul: Optional[int] = None
    gbr_dl: Optional[int] = None
    dnn: str = "internet"
    sst: int = 1
    sd: Optional[int] = None
    app_id: Optional[str] = None
    flow_description: str = "permit out ip from any to assigned"
    volume_threshold: int = 10_000_000       # bytes
    time_threshold: int = 60                 # seconds
    ul_rate_bps: float = 2_000_000           # mean generated usage
    dl_rate_bps: float = 10_000_000
    timing: str = "poisson"                  # constant | poisson | burst
    mean_interval: float = 1.0               # seconds between messages
    burst_size: int = 5
    burst_gap: float = 0.01
    precedence: int = 100

    def __post_init__(self):
        if not 1 <= self.qfi <= 63:
            raise ValueError(f"QFI {self.qfi} outside 1..63 (TS 29.244 "
                             "8.2.89; 5QI values are not QFIs)")
        if (self.gbr_ul is None) != (self.gbr_dl is None):
            raise ValueError("gbr_ul and gbr_dl must be set together")
        if self.is_gbr and (self.gbr_ul > self.mbr_ul or
                            self.gbr_dl > self.mbr_dl):
            raise ValueError("GBR must not exceed MBR")
        if self.timing not in ("constant", "poisson", "burst"):
            raise ValueError(f"unknown timing model {self.timing}")
        if not 0 <= self.sst <= 255:
            raise ValueError("sst must fit in one octet")

    @classmethod
    def from_dict(cls, d):
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown profile keys: {sorted(unknown)}")
        return cls(**d)

    @classmethod
    def from_file(cls, path):
        with open(path) as fh:
            return cls.from_dict(json.load(fh))

    def to_file(self, path):
        with open(path, "w") as fh:
            json.dump(asdict(self), fh, indent=2)

    @property
    def is_gbr(self):
        return self.gbr_ul is not None and self.gbr_dl is not None


PRESETS = {
    "embb": TrafficProfile(name="embb", qfi=9, dnn="internet", sst=1,
                           mbr_ul=100_000_000, mbr_dl=1_000_000_000),
    "urllc": TrafficProfile(name="urllc", qfi=7, dnn="urllc", sst=2,
                            mbr_ul=10_000_000, mbr_dl=10_000_000,
                            gbr_ul=5_000_000, gbr_dl=5_000_000,
                            timing="constant", mean_interval=0.1,
                            volume_threshold=1_000_000, time_threshold=10),
    "miot": TrafficProfile(name="miot", qfi=9, dnn="iot", sst=3,
                           mbr_ul=100_000, mbr_dl=100_000,
                           ul_rate_bps=5_000, dl_rate_bps=1_000,
                           timing="burst", mean_interval=30, burst_size=3,
                           volume_threshold=100_000, time_threshold=300),
    "voice": TrafficProfile(name="voice", qfi=1, dnn="ims", sst=1,
                            mbr_ul=128_000, mbr_dl=128_000,
                            gbr_ul=64_000, gbr_dl=64_000,
                            app_id="ims-voice", timing="constant",
                            mean_interval=0.02, volume_threshold=500_000,
                            time_threshold=30),
}


def get_profile(name_or_path):
    if name_or_path in PRESETS:
        return PRESETS[name_or_path]
    return TrafficProfile.from_file(name_or_path)


class TimingModel:
    """Produces monotonically increasing message timestamps."""

    def __init__(self, kind="poisson", mean_interval=1.0, burst_size=5,
                 burst_gap=0.01, start=None, rng=None, rtt=0.002):
        if kind not in ("constant", "poisson", "burst"):
            raise ValueError(f"unknown timing model {kind}")
        self.kind = kind
        self.mean = mean_interval
        self.burst_size = burst_size
        self.burst_gap = burst_gap
        self.rtt = rtt
        self.rng = rng or random.Random()
        self.now = start if start is not None else 1_700_000_000.0
        self._in_burst = 0

    @classmethod
    def from_profile(cls, p, **kw):
        return cls(p.timing, p.mean_interval, p.burst_size, p.burst_gap, **kw)

    def next_gap(self):
        if self.kind == "constant":
            return self.mean
        if self.kind == "poisson":
            return self.rng.expovariate(1.0 / self.mean)
        # burst: burst_size back-to-back messages, then an exponential pause
        if self._in_burst > 0:
            self._in_burst -= 1
            return self.burst_gap
        self._in_burst = self.burst_size - 1
        return self.rng.expovariate(1.0 / self.mean)

    def advance(self):
        """Time of the next exchange (request)."""
        self.now += self.next_gap()
        return self.now

    def response_time(self, t):
        """Response timestamp: request time + jittered RTT."""
        return t + self.rtt * self.rng.uniform(0.5, 1.5)

    def skip(self, seconds):
        self.now += seconds
