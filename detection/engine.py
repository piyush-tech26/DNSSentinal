"""detection/engine.py — Full detection pipeline.

Single entry point:  score(record, tracker=None) -> Verdict

RESOLVER INTEGRATION NOTES:
    1. Treat Action.ALERT the same as Action.ALLOW — forward the query
       upstream and return the real answer.  Only Action.BLOCK triggers
       a refusal response.
    2. For Reason.MALFORMED, return DNS rcode FORMERR (rcode 1), not
       NXDOMAIN.  The query itself is invalid, not the domain.
    3. Do NOT cache tunneling verdicts by domain.  A tunneling block
       depends on one client's behaviour; caching by domain would block
       innocent clients.  Cache only domain-level verdicts (blacklist,
       threat intel, DGA).
    4. Single-label names like "printer" or "wpad" pass normalize()
       with registered == "printer" and subdomain == "".  The resolver
       should answer these locally rather than forwarding upstream.
    5. Once the real ONNX DGA model is loaded, measure its latency.
       If it exceeds ~1 ms, wrap the call in asyncio.run_in_executor.

PASSIVE ANALYSIS NOTE:
    Sort records by timestamp before feeding them to score().  The
    tunneling window assumes time-ordered input.

DEPLOYMENT NOTE:
    Set TUNNEL_BLOCK_ENABLED = False initially.  Run in alert-only
    mode against real campus traffic (Zeek logs or PCAPs) for at
    least a day.  Check the dashboard for false positives from AV
    lookups, spam-list checks, and CDN hash queries.  Add exempt
    domains to _TUNNEL_EXEMPT_DOMAINS as needed, then enable blocking.
"""

from __future__ import annotations

import functools
import ipaddress
import logging
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from math import log2
from typing import Optional
from urllib.parse import urlparse

from detection.models import (
    Action, Reason, ParsedDomain, Verdict,
    DNSRecord, BlacklistHit,
)

log = logging.getLogger("detection")

#  POLICY THRESHOLDS AND FLAGS
# =====================================================================

DGA_BLOCK_THRESHOLD = 0.85
DGA_ALERT_THRESHOLD = 0.60
TUNNEL_ALERT_THRESHOLD = 0.70

TUNNEL_BLOCK_ENABLED = os.getenv("TUNNEL_BLOCK_ENABLED", "false").lower() == "true"

#  ENTROPY HELPER
# =====================================================================

@functools.lru_cache(maxsize=8192) #caches the results of previous calls for up to 8,192 distinct argument combinations
#If the same subdomain appears repeatedly, the engine can reuse the calculated entropy instead of recalculating it.
def _string_entropy(s: str) -> float:
    """Shannon entropy of a string in bits."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * log2(c / length) for c in freq.values())

#  ALLOWLIST
# =====================================================================

_ALLOWLIST: frozenset[str] = frozenset({
    "google.com", "www.google.com", "dns.google",
    "googleapis.com", "gstatic.com",
    "cloudflare.com", "cloudflare-dns.com", "one.one.one.one",
    "apple.com", "icloud.com", "apple-dns.net",
    "github.com",
    "youtube.com", "ytimg.com",
    "facebook.com", "fbcdn.net",
    "netflix.com",
})


#  TUNNEL EXEMPT DOMAINS
# =====================================================================

_TUNNEL_EXEMPT_DOMAINS: frozenset[str] = frozenset({
    "eset.com", "kaspersky.com", "kaspersky-labs.com",
    "avast.com", "avg.com", "bitdefender.com",
    "mcafee.com", "symantec.com", "norton.com",
    "sophos.com", "trendmicro.com", "clamav.net",
    "malwarebytes.com", "f-secure.com", "fortinet.com",
    "spamhaus.org", "barracuda.com", "spamcop.net",
    "sorbs.net", "uribl.com", "surbl.org",
    "windowsupdate.com", "msftncsi.com", "msftconnecttest.com",
    "digicert.com", "globalsign.com", "letsencrypt.org",
})
# Why this? For example, security software often performs automated lookups using changing identifiers. 
# Those queries may look unusual even though they are legitimate.

#  BLACKLIST + THREAT INTEL
# =====================================================================

_BLOCKLIST_SOURCES: dict[str, frozenset[str]] = {
    "static:test": frozenset({
        "malware.test",
        "evil.example.com",
        "phishing-login.xyz",
        "c2-server.bad",
        "xk3j9qpzt.com",
        "dga-botnet-123.net",
    }),
}

_INTEL_SOURCES: dict[str, frozenset[str]] = {}

# Lock around copy-and-rebind so concurrent reloads don't
# lose each other's updates.  Readers still don't need the lock
# because they iterate over a snapshot of the dict reference.
_reload_lock = threading.Lock()

def _blacklist_match(parsed: ParsedDomain) -> Optional[BlacklistHit]:
    """Check full name and parent domains (2+ labels) against all sources."""
    labels = parsed.full.split(".")
    suffixes = [".".join(labels[i:]) for i in range(len(labels) - 1)]

    bl = _BLOCKLIST_SOURCES
    for source_name, domains in bl.items():
        for suffix in suffixes:
            if suffix in domains:
                return BlacklistHit(
                    Reason.BLACKLIST, source_name,
                    "Static blocklist (%s): %s" % (source_name, suffix),
                )

    ti = _INTEL_SOURCES
    for source_name, domains in ti.items():
        for suffix in suffixes:
            if suffix in domains:
                return BlacklistHit(
                    Reason.THREAT_INTEL, source_name,
                    "Threat intel (%s): %s" % (source_name, suffix),
                )

    return None

def reload_blocklist_source(source: str, domains: frozenset[str]) -> None:
    """Replace one blocklist source entirely (atomic rebind under lock)."""
    global _BLOCKLIST_SOURCES
    with _reload_lock:
        new = dict(_BLOCKLIST_SOURCES)
        new[source] = domains
        _BLOCKLIST_SOURCES = new

def reload_intel_source(source: str, domains: frozenset[str]) -> None:
    """Replace one threat-intel source entirely (atomic rebind under lock)."""
    global _INTEL_SOURCES
    with _reload_lock:
        new = dict(_INTEL_SOURCES)
        new[source] = domains
        _INTEL_SOURCES = new

def _is_ip_address(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _parse_blocklist_line(line: str) -> Optional[str]:
    """Parse one line from plain, hosts, CSV, URL, or commented formats."""
    for marker in (" #", "\t#"):
        idx = line.find(marker)
        if idx != -1:
            line = line[:idx]
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if line.startswith(("http://", "https://")):
        try:
            host = urlparse(line).hostname
            if host and "." in host and not _is_ip_address(host):
                return host.lower()
        except Exception:
            pass
        return None

    parts = line.split()
    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
        domain = parts[1].lower()
        if "." in domain and not _is_ip_address(domain):
            return domain
        return None

    if "," in line:
        domain = line.split(",")[0].strip().lower()
        if "." in domain and not _is_ip_address(domain):
            return domain
        return None

    domain = line.lower()
    if "." in domain and not _is_ip_address(domain):
        return domain
    return None


def load_blocklist_file(path: str, source: str = "file") -> int:
    """Load domains from a file into a named source (atomic swap)."""
    domains: set[str] = set()
    with open(path) as f:
        for line in f:
            domain = _parse_blocklist_line(line)
            if domain:
                domains.add(domain)
    reload_blocklist_source(source, frozenset(domains))
    return len(domains)


#  DGA STUB
# =====================================================================

_dga_model = None # model to be trained

def _predict_dga(parsed: ParsedDomain) -> float:
    """Return DGA probability (0.0-1.0) for the registered domain label.

    Input: the second-level label only ("evil" from "evil.com").
    Stub returns 0.0.
    """
    return 0.0


#  TUNNELING
# =====================================================================

@dataclass
class TunnelResult:
    """Internal return type from TunnelTracker.check()."""
    single_score: float     # Suspicion score calculated from current query alone
    window_blocks: bool     # Whether the traffic window detector wants to block
    window_alerts: bool     # Whether the traffic window detector wants to alert
    window_score: float     # Suspicion score calculated from accumulated query pattern
    detail: str             # Human readable explanation of the detection


class TunnelTracker:
    """Stateful tunneling window tracker with LRU eviction."""
    # Stateless detector evaluates only the current query while Stateful detector remembers earlier queries
    # and uses them to analyze subsequent behaviour.
    _EXEMPT_SUFFIXES = ("in-addr.arpa", "ip6.arpa") # These are used for IPv4 and IPv6 reverse lookups.

    def __init__( #these are starting heuristics, we will tune them against representative DNS traffic.
        self,
        window_seconds: int = 300,
        unique_subs_threshold: int = 50,
        avg_entropy_threshold: float = 3.5,
        max_entries_per_key: int = 120,
        max_keys: int = 10_000,
    ):
        self._lock = threading.Lock() # prevents concurrent operations from modifying these shared structures simultaneously
        self._windows: OrderedDict[tuple[str, str], deque] = OrderedDict() # stores a queue of recent queries for each tracking key
        self._counts: dict[tuple[str, str], dict[str, int]] = {} # counts how frequently each subdomain string appears within that key's window
        self._ent_sums: dict[tuple[str, str], float] = {} # tracks the sum of the entropy values for the distinct subdomain strings currently present
        self.window_seconds = window_seconds
        self.unique_subs_threshold = unique_subs_threshold
        self.avg_entropy_threshold = avg_entropy_threshold
        self.max_entries = max_entries_per_key
        self.max_keys = max_keys

    def check(self, record: DNSRecord, parsed: ParsedDomain) -> TunnelResult:
        """Analyse one query for tunneling signals.  Thread-safe."""
        sub = parsed.subdomain

        if not sub:
            return TunnelResult(0.0, False, False, 0.0, "")

        if parsed.full.endswith(self._EXEMPT_SUFFIXES):
            return TunnelResult(0.0, False, False, 0.0, "")

        if parsed.registered in _TUNNEL_EXEMPT_DOMAINS:
            return TunnelResult(0.0, False, False, 0.0, "")

        # -- Stateless per-query heuristic ----------------------------
        length_score = min(len(sub) / 60.0, 1.0)
        label_score = min((sub.count(".") + 1) / 8.0, 1.0)
        entropy_score = min(_string_entropy(sub) / 4.5, 1.0)

        single_score = (
            0.4 * length_score + 0.2 * label_score + 0.4 * entropy_score
        )

        if record.qtype.upper() in ("TXT", "NULL"):
            single_score = min(single_score + 0.15, 1.0)

        single_score = round(single_score, 4)

        # -- Stateful window ------------------------------------------
        window_blocks = False
        window_alerts = False
        window_score = 0.0
        detail = ""

        key = (record.src_ip, parsed.registered)
        sub_ent = _string_entropy(sub)

        with self._lock:
            if key in self._windows:
                self._windows.move_to_end(key)
            else:
                self._windows[key] = deque()
                self._counts[key] = {}
                self._ent_sums[key] = 0.0

            dq = self._windows[key]
            counts = self._counts[key]

            dq.append((record.timestamp, sub))
            if counts.get(sub, 0) == 0:
                self._ent_sums[key] += sub_ent
            counts[sub] = counts.get(sub, 0) + 1

            cutoff = record.timestamp - self.window_seconds
            while dq and (dq[0][0] < cutoff or len(dq) > self.max_entries):
                _, old_sub = dq.popleft()
                counts[old_sub] -= 1
                if counts[old_sub] == 0:
                    del counts[old_sub]
                    self._ent_sums[key] -= _string_entropy(old_sub)

            unique_subs = len(counts)

            if unique_subs == 0:
                self._ent_sums[key] = 0.0
                avg_ent = 0.0
            else:
                avg_ent = max(0.0, self._ent_sums[key] / unique_subs)

            if unique_subs >= self.unique_subs_threshold:
                if avg_ent >= self.avg_entropy_threshold:
                    if TUNNEL_BLOCK_ENABLED:
                        window_blocks = True
                        # compute a real block score instead of
                        # falling back to a hard-coded 0.9 in score().
                        window_score = min(
                            0.85 + 0.15 * (
                                unique_subs / (self.unique_subs_threshold * 2)
                            ),
                            1.0,
                        )
                        detail = (
                            "Tunnel: %d unique subs, avg entropy %.1f "
                            "from %s to %s"
                            % (unique_subs, avg_ent, record.src_ip,
                               parsed.registered)
                        )
                    else:
                        window_alerts = True
                        window_score = min(
                            0.6 + 0.3 * (avg_ent / 4.5), 0.85
                        )
                        detail = (
                            "Tunnel (block disabled): %d unique subs, "
                            "avg entropy %.1f from %s to %s"
                            % (unique_subs, avg_ent, record.src_ip,
                               parsed.registered)
                        )
                else:
                    window_alerts = True
                    window_score = min(
                        max(0.4 + 0.2 * (avg_ent / self.avg_entropy_threshold),
                            0.4),
                        0.6,
                    )
                    detail = (
                        "Tunnel alert: %d unique subs, low entropy %.1f "
                        "from %s to %s"
                        % (unique_subs, avg_ent, record.src_ip,
                           parsed.registered)
                    )
            elif unique_subs >= self.unique_subs_threshold * 0.5:
                if avg_ent >= self.avg_entropy_threshold:
                    window_alerts = True
                    window_score = min(
                        unique_subs / self.unique_subs_threshold, 0.7
                    )
                    detail = (
                        "Tunnel alert: %d unique subs, avg entropy %.1f "
                        "from %s to %s"
                        % (unique_subs, avg_ent, record.src_ip,
                           parsed.registered)
                    )

            while len(self._windows) > self.max_keys:
                old_key, _ = self._windows.popitem(last=False)
                del self._counts[old_key]
                del self._ent_sums[old_key]

        return TunnelResult(
            single_score, window_blocks, window_alerts,
            window_score, detail,
        )

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self._counts.clear()
            self._ent_sums.clear()


_live_tracker = TunnelTracker()

#  NORMALIZATION
# =====================================================================

try:
    import tldextract
    _tld_cache = os.getenv("TLDEXTRACT_CACHE_DIR", "/tmp/tldextract_cache")
    _EXTRACT = tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
        cache_dir=_tld_cache,
    )
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False
    log.warning(
        "tldextract not installed — using two-label heuristic. "
        "Breaks on .co.in, .ac.in, .co.uk.  pip install tldextract"
    )


def normalize(raw_query: str) -> Optional[ParsedDomain]:
    """Lowercase, strip trailing dot, extract registered + subdomain.

    Returns None for malformed queries: empty, bare dot, exceeding
    DNS length limits (253 total, 63 per label), or containing
    empty labels (e.g. "a..b.com").
    """
    full = raw_query.lower().strip().rstrip(".")

    if not full or full == ".":
        return None

    # DNS length validation
    if len(full) > 253:
        return None
    labels = full.split(".")
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return None

    if _HAS_TLDEXTRACT:
        ext = _EXTRACT(full)
        if not ext.domain:
            if ext.suffix:
                return ParsedDomain(full=full,registered=full,subdomain="")
            return None
        registered = ("%s.%s" % (ext.domain, ext.suffix) if ext.suffix else ext.domain)
        subdomain = ext.subdomain
    else:
        if len(labels) <= 2:
            registered = full
            subdomain = ""
        else:
            registered = ".".join(labels[-2:])
            subdomain = ".".join(labels[:-2])

    return ParsedDomain(full=full, registered=registered, subdomain=subdomain)

#  LOGGING
# =====================================================================

_malformed_last_log: dict[str, float] = {}
_MALFORMED_LOG_CAP = 5000

_block_last_log: dict[str, float] = {}
_BLOCK_LOG_COOLDOWN = 60.0


def _log_malformed(src_ip: str, query: str) -> None:
    now = time.time()
    if len(_malformed_last_log) > _MALFORMED_LOG_CAP:
        _malformed_last_log.clear()
    if now - _malformed_last_log.get(src_ip, 0.0) > 60.0:
        log.warning("Malformed query from %s: %r", src_ip, query)
        _malformed_last_log[src_ip] = now


def _log_block(reason: str, domain: str, detail: str) -> None:
    now = time.time()
    if now - _block_last_log.get(domain, 0.0) > _BLOCK_LOG_COOLDOWN:
        log.info("BLOCK [%s] %s — %s", reason, domain, detail)
        _block_last_log[domain] = now
    else:
        log.debug("BLOCK [%s] %s", reason, domain)
    if len(_block_last_log) > 10_000:
        _block_last_log.clear()

#  MAIN PIPELINE
# =====================================================================

def score(
    record: DNSRecord,
    tracker: Optional[TunnelTracker] = None,
) -> Verdict:
    """Run the full detection pipeline on a single DNS record.

    Resolver behaviour:
        BLOCK + MALFORMED  -> return FORMERR (rcode 1)
        BLOCK + other      -> return NXDOMAIN or sinkhole
        ALERT              -> forward normally, log for dashboard
        ALLOW              -> forward normally

    Caching: cache domain-level verdicts only, never tunneling.
    Passive: sort records by timestamp before calling in a loop.
    """
    if tracker is None:
        tracker = _live_tracker

    parsed = normalize(record.query)
    sub: dict[str, float] = {}

    if parsed is None:
        _log_malformed(record.src_ip, record.query)
        return Verdict(
            Action.BLOCK, Reason.MALFORMED, 0.0,
            "Malformed query: %r" % record.query, sub,
        )

    # 1. Allowlist
    if parsed.full in _ALLOWLIST:
        return Verdict(
            Action.ALLOW, Reason.ALLOWLIST, 0.0,
            "Allowlisted: %s" % parsed.full, sub,
        )

    # 2-3. Blacklist + Threat Intel
    hit = _blacklist_match(parsed)
    if hit is not None:
        sub["blacklist"] = 1.0
        _log_block(hit.reason.value, parsed.full, hit.detail)
        return Verdict(
            Action.BLOCK, hit.reason, 1.0,
            "[%s] %s" % (hit.source, hit.detail), sub,
        )
    sub["blacklist"] = 0.0

    # 4. DGA
    dga = _predict_dga(parsed)
    sub["dga"] = dga
    if dga >= DGA_BLOCK_THRESHOLD:
        _log_block("DGA", parsed.full, "score=%.2f" % dga)
        return Verdict(
            Action.BLOCK, Reason.DGA, dga,
            "DGA %.2f >= %.2f" % (dga, DGA_BLOCK_THRESHOLD), sub,
        )

    # 5. Tunneling
    tr = tracker.check(record, parsed)
    sub["tunnel"] = max(tr.single_score, tr.window_score)

    if tr.window_blocks:
        _log_block("TUNNEL", parsed.full, tr.detail)
        return Verdict(
            # use the real window_score computed in the tracker
            Action.BLOCK, Reason.TUNNELING, tr.window_score,
            tr.detail, sub,
        )

    # 6. ALERT tier
    alert_candidates: list[tuple[float, Reason]] = []
    if dga >= DGA_ALERT_THRESHOLD:
        alert_candidates.append((dga, Reason.DGA))
    if tr.single_score >= TUNNEL_ALERT_THRESHOLD:
        alert_candidates.append((tr.single_score, Reason.TUNNELING))
    if tr.window_alerts:
        alert_candidates.append((tr.window_score, Reason.TUNNELING))

    if alert_candidates:
        top_score, dominant = max(alert_candidates, key=lambda c: c[0])
        log.debug("ALERT [%s] %s score=%.2f", dominant.value, parsed.full, top_score)
        return Verdict(
            Action.ALERT, dominant, top_score,
            "Suspicious (%s): %.2f" % (dominant.value, top_score), sub,
        )

    # 7. Clean
    highest = max(dga, tr.single_score)
    return Verdict(
        Action.ALLOW, Reason.CLEAN, highest,
        "No threats detected", sub,
    )
