"""Internal normalized data model.

recon2win owns *recon metadata*; this workspace owns *analysis metadata*.
The line between them is deliberate — a JS asset references its recon2win
source (url, http status, content type, provenance) but adds only fields
that describe analysis (sha256, framework, analysis_status, candidates).

Everything is a plain dataclass with ``to_dict`` so the JSON artifacts in
``output/`` stay stable and diff-friendly; the JSON Schemas in ``schemas/``
are the authority on shape.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# JS asset — one row per JavaScript reference discovered by recon2win.
# --------------------------------------------------------------------------
@dataclass
class JSAsset:
    asset_id: str                      # js_000001 (stable within a target)
    target: str                        # example.com (the recon2win target dir)
    host: str                          # app.example.com
    url: str                           # https://app.example.com/static/app.js
    source: str = "recon2win"          # always recon2win at ingest time
    provenance: list[str] = field(default_factory=list)  # tools that saw it
    status_code: Optional[int] = None  # from recon2win jsluice_js_detail
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    # --- analysis metadata (owned by this workspace) ---
    sha256: Optional[str] = None
    size: Optional[int] = None
    local_path: Optional[str] = None   # raw/ path once acquired
    framework: Optional[str] = None
    bundler: Optional[str] = None
    source_map: Optional[bool] = None
    source_map_url: Optional[str] = None
    minified: Optional[bool] = None
    third_party: bool = False          # known vendor lib / CDN → library noise
    analysis_status: str = "pending"   # pending|acquired|parsed|analyzed|error
    parse_error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Endpoint — an API call/route resolved out of JS.
# --------------------------------------------------------------------------
@dataclass
class Endpoint:
    endpoint_id: str
    asset_id: str
    method: str                        # GET/POST/… or "" when unknown
    url_template: str                  # baseURL + "/users/" + id  → app-relative or absolute
    kind: str = "rest"                 # rest|graphql|websocket
    dynamic: bool = False              # contains unresolved concatenation
    parameters: list[str] = field(default_factory=list)
    auth_hint: Optional[str] = None    # bearer|cookie|apikey|none|unknown
    interesting: bool = False          # admin/internal/debug/auth path
    object_ids: list[str] = field(default_factory=list)  # client-controlled id segments
    sensitive_op: bool = False         # mutating/privileged verb or path
    location: Optional[dict] = None    # {line, col}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Data-flow record — SOURCE → transform → sanitize → SINK.
# --------------------------------------------------------------------------
@dataclass
class DataFlow:
    flow_id: str
    asset_id: str
    source: str                        # e.g. location.hash
    source_kind: str                   # dom|storage|postmessage|url|network
    sink: str                          # e.g. innerHTML
    sink_kind: str                     # dom-xss|eval|open-redirect|proto|...
    transforms: list[str] = field(default_factory=list)
    attacker_controlled: str = "unknown"   # yes|no|unknown
    sanitization: str = "unknown"          # none|weak|known-safe|unknown
    source_location: Optional[dict] = None
    sink_location: Optional[dict] = None
    evidence: Optional[str] = None     # short code snippet

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Vulnerability candidate.
# --------------------------------------------------------------------------
CANDIDATE_STATES = (
    "NEW", "TRIAGED", "INVESTIGATING",
    "VERIFICATION_REQUIRED", "VERIFIED", "FALSE_POSITIVE",
)


@dataclass
class Exploitability:
    """Structured exploitability reasoning (mission §15).

    Every candidate must answer *why* it may be exploitable, not merely that
    a pattern exists. These fields are derived statically from the candidate
    + its evidence and drive the final priority/rank. They are hypotheses to
    verify, never confirmations.
    """
    who_controls: str = "unknown"      # attacker|authenticated-user|same-origin|unknown
    auth_required: str = "unknown"     # none|authenticated|privileged|unknown
    boundary: str = "unknown"          # which security boundary is crossed
    impact: str = "unknown"            # info|low|medium|high|critical
    exploitability: str = "unknown"    # low|medium|high
    user_interaction: str = "unknown"  # none|victim-visits-link|victim-authenticated|unknown
    cross_origin: str = "unknown"      # yes|no|unknown
    reachability: str = "unknown"      # reachable|conditional|dead-code|unknown
    why_interesting: str = ""
    why_not_fp: str = ""               # why this is not obviously a false positive
    missing_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Candidate:
    id: str                            # JS-CAND-001
    type: str                          # DOM-XSS|PROTOTYPE-POLLUTION|...
    priority: str                      # P1|P2|P3
    severity: str                      # info|low|medium|high|critical
    confidence: float                  # 0..1
    asset_id: str
    url: str
    title: str
    source: Optional[str] = None
    sink: Optional[str] = None
    attacker_controlled: str = "unknown"
    sanitization: str = "unknown"
    evidence: Optional[str] = None
    location: Optional[dict] = None
    flow_id: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None            # HTTP method for API/BOLA candidates
    object_id: Optional[str] = None         # client-controlled object identifier
    verification_status: str = "NEW"
    rank_score: float = 0.0
    exploitability: Optional[Exploitability] = None
    chain_ids: list[str] = field(default_factory=list)  # attack chains it joins
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# --------------------------------------------------------------------------
# Attack chain — correlated observations across candidates (mission §14).
# --------------------------------------------------------------------------
@dataclass
class AttackChain:
    chain_id: str                      # CHAIN-001
    name: str                          # human label
    impact: str                        # potential privilege escalation / ...
    confidence: float                  # 0..1
    priority: str                      # P1|P2|P3
    observations: list[str] = field(default_factory=list)   # candidate ids
    relationships: list[str] = field(default_factory=list)  # human edges
    rationale: str = ""
    verification: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
