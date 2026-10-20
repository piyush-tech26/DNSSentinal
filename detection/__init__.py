"""detection — DNS threat detection pipeline.

Public API:
    from detection import score, Action, Reason, DNSRecord, Verdict, Event
    from detection import TunnelTracker, normalize
"""

from detection.models import (
    Action,
    Reason,
    ParsedDomain,
    Verdict,
    DNSRecord,
    Event,
    BlacklistHit,
)
from detection.engine import (
    score,
    normalize,
    TunnelTracker,
    reload_blocklist_source,
    reload_intel_source,
    load_blocklist_file,
)

__all__ = [
    "score", "normalize", "TunnelTracker",
    "Action", "Reason", "ParsedDomain", "Verdict",
    "DNSRecord", "Event", "BlacklistHit",
    "reload_blocklist_source", "reload_intel_source", "load_blocklist_file",
]
