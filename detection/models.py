"""detection/models.py — Shared dataclasses and enums.

Import from here in the resolver, parsers, dashboard, and ML code.
This file has zero internal imports so circular dependencies are impossible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Action(str, Enum):
    ALLOW = "allow"
    ALERT = "alert"
    BLOCK = "block"


class Reason(str, Enum):
    CLEAN = "clean"
    ALLOWLIST = "allowlist"
    BLACKLIST = "blacklist"
    THREAT_INTEL = "threat_intel"
    DGA = "dga"
    TUNNELING = "tunneling"
    FAST_FLUX = "fast_flux"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class ParsedDomain:
    """Output of normalize().  Computed once per query, reused everywhere.

    Attributes:
        full:       Lowercase, dot-stripped FQDN.
                    "Www.Evil.com." becomes "www.evil.com"
        registered: Registered domain via tldextract.
                    "www.evil.com" becomes "evil.com"
        subdomain:  Everything left of the registered domain.
                    "a.b.evil.com" becomes "a.b"
    """
    full: str
    registered: str
    subdomain: str


@dataclass
class Verdict:
    action: Action
    reason: Reason
    score: float
    detail: str = ""
    sub_scores: dict[str, float] = field(default_factory=dict)


@dataclass
class DNSRecord:
    """Universal input.  Both live resolver and passive parsers produce this.

    Timestamp ownership: the CALLER sets it at the moment of observation.
      Live resolver  -> time.time() when the packet arrives
      PCAP parser    -> capture timestamp from the pcap header
      Zeek parser    -> the ts column from dns.log
    The DB writer never overwrites it.
    """
    timestamp: float
    src_ip: str
    query: str
    qtype: str
    answers: list[str] = field(default_factory=list)
    ttls: list[int] = field(default_factory=list)


@dataclass
class Event:
    record: DNSRecord
    verdict: Verdict
    cache_hit: bool = False
    latency_ms: float = 0.0
    id: Optional[int] = None


@dataclass
class BlacklistHit:
    reason: Reason
    source: str
    detail: str
