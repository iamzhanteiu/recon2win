"""utils — domain validation, IO helpers, result factory.

All other modules import `make_result` from here so the response shape stays
consistent with the spec.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional

# RFC 1035 / 1123 — pragmatic domain pattern, not a full parser.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$"
)


# ----------------------------------------------------------------------
# Validation
# ----------------------------------------------------------------------
def validate_domain(domain: str) -> str:
    """Return a cleaned lowercased domain or raise ValueError."""
    if domain is None:
        raise ValueError("domain is required")
    d = domain.strip().lower()
    # strip scheme / path if the user pastes a URL
    d = re.sub(r"^https?://", "", d)
    d = d.split("/", 1)[0]
    # Strip leading wildcard labels. HackerOne WILDCARD scope is written as
    # "*.example.com"; recon runs against the registrable root, so the "*."
    # prefix is meaningless to the pipeline (and would fail the regex).
    # Handles nested wildcards like "*.*.example.com" too.
    d = re.sub(r"^(?:\*\.)+", "", d)
    if not DOMAIN_RE.match(d):
        raise ValueError(f"invalid domain: {domain!r}")
    return d


# ----------------------------------------------------------------------
# Filesystem layout
# ----------------------------------------------------------------------
def create_output_structure(domain: str, root: str = "outputs") -> Path:
    """Create the standard folder tree under ``<root>/<domain>/``.

    Layout (v2 — grouped by stage for ``raw/`` and ``findings/``):

        <root>/<domain>/
            raw/                     # tool outputs grouped by stage
                subdomain/           # subfinder.txt, amass.txt, chaos.txt
                content_discovery/   # katana_urls.txt, urlfinder_urls.txt
                dirsearch/           # dirsearch_raw.txt, merged_wordlists.txt
                waymore/             # waymore_raw.txt
                arjun/               # input_subset.txt
            processed/               # cleaned + merged artefacts, flat
            findings/                # nuclei only, grouped by kind
                default/             # nuclei.json, nuclei.txt
                dynamic/             # nuclei.json, nuclei.txt
            logs/                    # commands.log, stages.json, <stage>.log
            tests_input/             # reserved for future sample inputs
            report/                  # final_report.{html,md,json}
    """
    base = Path(root) / domain
    for sub in (
        "raw",
        "raw/subdomain",
        "raw/content_discovery",
        "raw/dirsearch",
        "raw/waymore",
        "raw/arjun",
        "processed",
        "findings",
        "findings/default",
        "findings/endpoints",
        "findings/dynamic",
        "logs",
        "tests_input",
        "report",
    ):
        (base / sub).mkdir(parents=True, exist_ok=True)
    return base


def raw_dir(output_dir: Path, stage: str) -> Path:
    """Return ``<output_dir>/raw/<stage>/`` and create it if missing.

    Centralises the per-stage raw subfolder convention so callers don't
    accidentally write to the old flat ``raw/`` root. Raises if *stage*
    is not a known subfolder (catches typos at write time).
    """
    valid = {"subdomain", "content_discovery", "dirsearch", "waymore", "arjun",
             "nuclei_dynamic"}
    if stage not in valid:
        raise ValueError(
            f"unknown raw subfolder {stage!r} — valid options: {sorted(valid)}"
        )
    d = output_dir / "raw" / stage
    d.mkdir(parents=True, exist_ok=True)
    return d


def findings_dir(output_dir: Path, kind: str) -> Path:
    """Return ``<output_dir>/findings/<kind>/`` and create it if missing.

    ``kind`` is one of ``"default"``, ``"endpoints"`` or ``"dynamic"``
    (the three nuclei scan modes).
    """
    valid = {"default", "endpoints", "dynamic"}
    if kind not in valid:
        raise ValueError(
            f"unknown findings subfolder {kind!r} — valid options: {sorted(valid)}"
        )
    d = output_dir / "findings" / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


# ----------------------------------------------------------------------
# IO helpers
# ----------------------------------------------------------------------
def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    for ln in path.read_text(errors="ignore").splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def write_lines(path: Path, lines: Iterable[str]) -> int:
    """Write unique non-empty lines. Returns the number written."""
    seen: set[str] = set()
    cleaned: List[str] = []
    for ln in lines:
        if ln is None:
            continue
        s = str(ln).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        cleaned.append(s)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(cleaned) + ("\n" if cleaned else ""), encoding="utf-8")
    return len(cleaned)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(errors="ignore") or "null")
    except json.JSONDecodeError:
        return None


def safe_append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")


# ----------------------------------------------------------------------
# Result factory — every stage must return a dict shaped like this.
# ----------------------------------------------------------------------
def make_result(
    stage: str,
    status: str,
    input_path: Optional[Path | str] = None,
    outputs: Optional[List[Path | str]] = None,
    count: int = 0,
    error: Optional[str] = None,
    extra: Optional[dict] = None,
) -> dict:
    res: dict[str, Any] = {
        "stage": stage,
        "status": status,
        "input": str(input_path) if input_path else None,
        "outputs": [str(p) for p in (outputs or [])],
        "count": count,
        "error": error,
    }
    if extra:
        res["extra"] = extra
    return res


def now_iso() -> str:
    # timezone-aware UTC, ISO 8601 with trailing 'Z' for portability.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------
# Subdomain prioritisation — score + cap before feeding the next stage.
# ----------------------------------------------------------------------
# When subfinder / amass / chaos collectively return tens of thousands of
# subdomains (apple.com pulls 45k+ via cert-transparency logs, mostly
# bot/crawler/push-sandbox noise), feeding the *full* list into httpx_alive
# means the timeout (default 600s) blows past before all hosts are
# probed — so ``alive.txt`` never gets written and every downstream stage
# skips with "no alive hosts".
#
# ``prioritize_subdomains`` scores each subdomain for "recon value" and
# keeps the top ``max_count``. Heuristics:
#   * ROOT DOMAIN (single label) → always kept (the apex itself)
#   * HIGH-VALUE PREFIXES (www/api/admin/auth/...) → huge bonus
#   * KNOWN BUG-BOUNTY TECH (jenkins/gitlab/jira/wordpress/...) → bonus
#   * BOT/CRAWLER/PUSH INFRA (applebot, courier.push, sandbox.*) → penalty
#   * SHORTER names (fewer labels) → mild bonus — ``foo.com`` over
#     ``some.deeply.nested.subdomain.of.foo.com``
#
# Tweak ``_SUBDOMAIN_HIGH_VALUE`` / ``_SUBDOMAIN_NOISE`` below as you
# learn what works for your targets; the unit tests pin the behaviour
# for the common cases.
_SUBDOMAIN_HIGH_VALUE: frozenset[str] = frozenset({
    # Web entry points
    "www", "api", "app", "web", "site", "home", "portal",
    # Auth / admin
    "admin", "auth", "login", "sso", "oauth", "saml",
    "account", "accounts", "identity", "id",
    # Dev / infra often misconfigured
    "dev", "stage", "staging", "test", "qa", "uat", "sandbox",
    "preprod", "demo", "lab", "internal",
    # Mail / messaging
    "mail", "smtp", "imap", "pop", "webmail", "mx",
    # Network entry
    "vpn", "remote", "gateway", "gw", "proxy", "edge",
    # Common SaaS / dashboards
    "crm", "erp", "jira", "confluence", "wiki",
    "gitlab", "github", "bitbucket", "gitea",
    "grafana", "kibana", "prometheus", "nagios",
    "jenkins", "ci", "cd", "build", "deploy",
    "k8s", "kubernetes", "rancher", "argocd", "flux",
    "jumpserver", "bastion",
    # Storage / data
    "db", "mysql", "postgres", "redis", "es", "elastic",
    "s3", "minio", "backup",
    # Container / cloud
    "docker", "registry", "artifactory", "nexus", "harbor",
    # ─────────────────────────────────────────────────────────────────
    # Added 2026-06-25 — modern dev/data tools that frequently show up
    # on real targets and have a history of CVEs:
    #   hasura   → GraphQL engine (CVE-2023-43325 etc.)
    #   airflow  → Apache Airflow (CVE-2020-11978, CVE-2023-49996)
    #   superset → Apache Superset (CVE-2023-27524, CVE-2024-34693)
    #   metabase → business intel (CVE-2023-38611, CVE-2023-49797)
    #   jupyter  → JupyterHub/Notebook (auth-bypass CVEs)
    #   vault    → HashiCorp Vault (info-disclosure CVEs)
    #   backstage → CNCF Backstage (CVE-2024-26176)
    #   argocd   → already covered (GitOps)
    #   discourse → forum software (auth-bypass CVEs)
    #   mattermost → chat platform (auth-bypass CVEs)
    # ─────────────────────────────────────────────────────────────────
    "hasura", "airflow", "superset", "metabase",
    "jupyter", "vault", "backstage", "discourse",
    "mattermost", "rocket", "rocketchat",
    "ghost", "strapi", "directus", "ghost-cms",
    "rancher", "argocd",
    # Misc
    "shop", "store", "blog", "crm", "help", "support",
})

_SUBDOMAIN_NOISE: tuple[str, ...] = (
    # CDN / infra we can't usefully probe
    "bot", "crawler", "spider", "scanner",
    # Sandbox / staging infra we can't usually reach
    "sandbox", "test-", "tmp", "temp",
    # Specific Apple patterns (would not match other targets)
    "applebot", "courier.push", "isoproxy",
)

_SUBDOMAIN_BOUNTY_TECH: tuple[str, ...] = (
    "jenkins", "gitlab", "jira", "confluence",
    "wordpress", "wp-", "drupal", "magento",
    "tomcat", "weblogic", "websphere",
    "grafana", "kibana", "prometheus",
    "sonarqube", "nexus", "artifactory",
    "phpmyadmin", "adminer",
)


def score_subdomain(sub: str) -> int:
    """Higher score = more interesting for a recon scan.

    Pure helper — no I/O, fully unit-testable. Used by
    :func:`prioritize_subdomains` and exported so callers can ask
    "why is this host ranked where it is?".
    """
    s = sub.lower().strip(".")
    if not s:
        return -10_000
    # The apex itself (``example.com`` → 1 label) is mandatory.
    if s.count(".") <= 0:
        return 10_000
    first, _, rest = s.partition(".")
    score = 0

    # APEX BONUS — single-label host MUST rank #1, above even
    # the high-value prefixes (``www``, ``api``, ``admin``, ...).
    # Without this bonus, ``www.example.com`` (1000 + depth 40)
    # outranks ``example.com`` (depth 60) — wrong, the apex is the
    # crown jewel of any recon scan.
    if s.count(".") == 1:
        score += 5000

    # 1) HIGH-VALUE PREFIX — exact match is huge, partial is moderate.
    if first in _SUBDOMAIN_HIGH_VALUE:
        score += 1000
    elif any(kw in first for kw in _SUBDOMAIN_HIGH_VALUE):
        score += 500

    # 2) KNOWN BUG-BOUNTY TECH — substring match anywhere in the host.
    # ``jenkins.foo.com`` and ``ci.jenkins.foo.com`` both score.
    if any(tech in s for tech in _SUBDOMAIN_BOUNTY_TECH):
        score += 800

    # 3) NOISE — bot/crawler/sandbox infra. Heavily penalise.
    if any(bad in s for bad in _SUBDOMAIN_NOISE):
        score -= 1000

    # 4) SHORTER IS BETTER — fewer labels = closer to the apex.
    #    ``foo.com`` (1 dot) scores higher than
    #    ``a.b.c.d.foo.com`` (4 dots). Mild effect.
    dot_count = s.count(".")
    score += max(0, 80 - dot_count * 20)

    # 5) Numeric / random-looking labels are usually auto-generated.
    #    Penalise lightly so they sort lower than hand-picked names.
    if any(ch.isdigit() for ch in first) and len(first) >= 6:
        score -= 100

    # 6) Random long hex / uuid-looking hostnames are noise.
    if len(first) >= 24 and all(c in "0123456789abcdef" for c in first):
        score -= 500

    return score


def prioritize_subdomains(
    subdomains: list[str], max_count: int = 5000,
) -> list[str]:
    """Score + cap a subdomain list before passing it downstream.

    Returns the top ``max_count`` hosts ordered by ``score_subdomain``
    (highest first). Order of equal-score hosts is stable (Python's
    sort is stable), so the original discovery order is preserved
    within a tier.

    Why this matters in practice:
      * ``apple.com`` returns ~45k hosts from cert-transparency logs.
        ~95% of them are bot/push/sandbox infra we can't usefully
        probe. Without a cap, ``httpx_alive`` blows its 600s timeout
        and every downstream stage silently skips with "no alive hosts".
      * With a cap of 5000 (default), the *interesting* hosts
        (root, www/api/admin/auth, tech-detected CMS/CI, etc.) are
        always kept and httpx finishes comfortably within budget.

    Set ``max_count=0`` to skip the cap (return the full list,
    score-ordered). The full list is *never* lost — callers that
    need it can pass the input directly.
    """
    if max_count is None or max_count <= 0:
        # No cap. Sort by score anyway so the user gets a stable,
        # interesting-first ordering for free.
        return sorted(subdomains, key=lambda s: -score_subdomain(s))

    # Dedupe (case-insensitive on host) before scoring — many
    # sources return overlapping results.
    seen: set[str] = set()
    unique: list[str] = []
    for s in subdomains:
        key = s.lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(s)

    ranked = sorted(unique, key=lambda s: -score_subdomain(s))
    return ranked[:max_count]  # when max_count > len(ranked), no-op
