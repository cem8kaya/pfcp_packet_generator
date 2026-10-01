"""Session state machine (item 2), F-TEID allocation (item 12) and UPF
selection / load balancing (item 14)."""
import enum
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# --------------------------------------------------------------------------
# Session state machine
# --------------------------------------------------------------------------
class SessionState(enum.Enum):
    IDLE = "idle"
    ESTABLISHING = "establishing"
    ESTABLISHED = "established"
    MODIFYING = "modifying"
    DELETING = "deleting"
    DELETED = "deleted"


class InvalidTransition(Exception):
    pass


_TRANSITIONS = {
    SessionState.IDLE: {SessionState.ESTABLISHING},
    SessionState.ESTABLISHING: {SessionState.ESTABLISHED, SessionState.DELETED},
    SessionState.ESTABLISHED: {SessionState.MODIFYING, SessionState.DELETING,
                               SessionState.ESTABLISHED},
    SessionState.MODIFYING: {SessionState.ESTABLISHED},
    SessionState.DELETING: {SessionState.DELETED, SessionState.ESTABLISHED},
    SessionState.DELETED: set(),
}


@dataclass
class Session:
    cp_seid: int
    up_seid: int = 0
    ue_ip: Optional[str] = None
    upf: Optional["Upf"] = None
    state: SessionState = SessionState.IDLE
    ul_teid: int = 0
    dl_teid: int = 0
    pdr_ids: List[int] = field(default_factory=list)
    far_ids: List[int] = field(default_factory=list)
    qer_ids: List[int] = field(default_factory=list)
    urr_ids: List[int] = field(default_factory=list)
    bar_id: Optional[int] = None
    urr_seqn: Dict[int, int] = field(default_factory=dict)
    ul_bytes: int = 0
    dl_bytes: int = 0
    start_time: float = 0.0
    last_report_time: float = 0.0
    buffering: bool = False

    def transition(self, new_state):
        if new_state not in _TRANSITIONS[self.state]:
            raise InvalidTransition(
                f"{self.state.value} -> {new_state.value} not allowed "
                f"(session cp_seid={self.cp_seid:#x})")
        self.state = new_state


class SessionManager:
    """Tracks sessions so that generated sequences are self-consistent
    (right SEIDs in headers, no modification of deleted sessions, ...)."""

    def __init__(self, rng=None):
        self.rng = rng or random.Random()
        self.sessions: Dict[int, Session] = {}
        self._used_seids = set()

    def new_seid(self):
        while True:
            seid = self.rng.randint(1, 2 ** 32 - 1)
            if seid not in self._used_seids:
                self._used_seids.add(seid)
                return seid

    def create(self, upf=None, ue_ip=None):
        s = Session(cp_seid=self.new_seid(), up_seid=self.new_seid(),
                    upf=upf, ue_ip=ue_ip)
        self.sessions[s.cp_seid] = s
        return s

    def active(self):
        return [s for s in self.sessions.values()
                if s.state == SessionState.ESTABLISHED]

    def drop_all(self):
        """Node failure: all sessions on the failed node vanish."""
        for s in self.sessions.values():
            s.state = SessionState.DELETED


# --------------------------------------------------------------------------
# F-TEID allocation
# --------------------------------------------------------------------------
class FteidAllocator:
    """Strategies:
      * ``sequential`` - monotonically increasing from the pool start
      * ``random``     - uniformly random, collision-free
      * ``range``      - TEID range with a fixed prefix (TEID Range
        Indication, TS 29.244 8.2.82 - top ``prefix_bits`` (1..7) identify the
        UPF instance)
    """

    def __init__(self, strategy="sequential", start=0x1000, prefix=0,
                 prefix_bits=0, rng=None):
        if strategy not in ("sequential", "random", "range"):
            raise ValueError(f"unknown F-TEID strategy {strategy}")
        if strategy == "range" and not 1 <= prefix_bits <= 7:
            raise ValueError("range strategy needs 1 <= prefix_bits <= 7 "
                             "(TEID Range Indication is 3 bits)")
        if strategy == "range" and prefix >> prefix_bits:
            raise ValueError("prefix does not fit in prefix_bits")
        self.strategy = strategy
        self.prefix = prefix
        self.prefix_bits = prefix_bits
        self.rng = rng or random.Random()
        self._next = start
        self._used = set()

    def allocate(self):
        suffix_bits = 32 - self.prefix_bits
        while True:
            if self.strategy == "random":
                teid = self.rng.randint(1, 2 ** 32 - 1)
            else:
                teid = self._next
                self._next += 1
                if self.strategy == "range":
                    teid = (self.prefix << suffix_bits) | (
                        teid & ((1 << suffix_bits) - 1))
            if teid and teid not in self._used:
                self._used.add(teid)
                return teid

    def release(self, teid):
        self._used.discard(teid)


# --------------------------------------------------------------------------
# UPF pool
# --------------------------------------------------------------------------
@dataclass
class Upf:
    name: str
    address: str
    capacity: int = 1000          # max sessions
    weight: int = 1
    dnns: tuple = ("internet",)
    slices: tuple = ((1, None),)  # (sst, sd)
    features: tuple = ("FTUP", "DLBD", "TRST")
    load: int = 0
    available: bool = True
    allocator: FteidAllocator = None

    def __post_init__(self):
        if self.allocator is None:
            self.allocator = FteidAllocator()

    def supports(self, dnn=None, slice_=None):
        return ((dnn is None or dnn in self.dnns) and
                (slice_ is None or slice_ in self.slices))


class NoUpfAvailable(Exception):
    pass


class UpfPool:
    """Selects a UPF by capability then by strategy:
    ``round_robin`` | ``least_loaded`` | ``weighted`` | ``random``."""

    def __init__(self, upfs, strategy="least_loaded", rng=None):
        self.upfs = list(upfs)
        self.strategy = strategy
        self.rng = rng or random.Random()
        self._rr = 0

    def select(self, dnn=None, slice_=None):
        cands = [u for u in self.upfs
                 if u.available and u.load < u.capacity
                 and u.supports(dnn, slice_)]
        if not cands:
            raise NoUpfAvailable(f"no UPF for dnn={dnn} slice={slice_}")
        if self.strategy == "round_robin":
            upf = cands[self._rr % len(cands)]
            self._rr += 1
        elif self.strategy == "least_loaded":
            upf = min(cands, key=lambda u: u.load / u.capacity)
        elif self.strategy == "weighted":
            upf = self.rng.choices(cands, [u.weight for u in cands])[0]
        elif self.strategy == "random":
            upf = self.rng.choice(cands)
        else:
            raise ValueError(f"unknown strategy {self.strategy}")
        upf.load += 1
        return upf

    def release(self, upf):
        upf.load = max(0, upf.load - 1)
