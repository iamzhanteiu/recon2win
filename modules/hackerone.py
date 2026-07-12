"""hackerone — optional: pull program list + in-scope assets from the H1 Hacker API.

Lets the operator pick a target from their HackerOne programs instead of
copy-pasting scope from the website. Only assets flagged
``eligible_for_submission`` are returned, so out-of-scope hosts never enter
the recon pipeline.

Credentials (HTTP Basic — API token *identifier* is the username, token
*value* is the password) are read in this order of precedence:

    1. env vars   H1_API_USERNAME / H1_API_TOKEN
    2. config     hackerone.api_username / hackerone.api_token
                  (put these in config.local.yml — git-ignored)

Generate a token at https://hackerone.com/settings/api_token/edit
API docs: https://api.hackerone.com/getting-started-hacker-api/
"""
from __future__ import annotations

import os
from typing import Optional
from urllib.parse import urlsplit

import requests

API_BASE = "https://api.hackerone.com/v1/hackers"

# Asset types that make sense to feed into domain-based recon. Everything
# else (CIDR, source code, mobile app IDs, hardware, …) is ignored by the
# root-domain extractor.
DOMAIN_ASSET_TYPES = {"URL", "WILDCARD"}


class H1Error(RuntimeError):
    """Auth / network / API problems — main.py catches this to print a clean message."""


# ----------------------------------------------------------------------
# Credentials
# ----------------------------------------------------------------------
def get_credentials(cfg: Optional[dict] = None) -> tuple[str, str]:
    """Return ``(username, token)`` or raise :class:`H1Error`.

    env vars win over config so an operator can override a stored token
    for a one-off run without editing files.
    """
    h1 = (cfg or {}).get("hackerone", {}) or {}
    username = os.environ.get("H1_API_USERNAME") or h1.get("api_username")
    token = os.environ.get("H1_API_TOKEN") or h1.get("api_token")
    if not username or not token:
        raise H1Error(
            "HackerOne API credentials not found. Set H1_API_USERNAME and "
            "H1_API_TOKEN env vars, or add hackerone.api_username / "
            "hackerone.api_token to config.local.yml."
        )
    return str(username), str(token)


# ----------------------------------------------------------------------
# HTTP — paginated GET following JSON:API ``links.next``
# ----------------------------------------------------------------------
def _get_paginated(
    url: str, auth: tuple[str, str], *, timeout: int = 30, max_pages: int = 100,
) -> list[dict]:
    """Follow ``links.next`` until exhausted; return the concatenated ``data``."""
    items: list[dict] = []
    pages = 0
    while url and pages < max_pages:
        try:
            resp = requests.get(
                url, auth=auth,
                headers={"Accept": "application/json"}, timeout=timeout,
            )
        except requests.RequestException as e:  # network / DNS / TLS
            raise H1Error(f"network error talking to HackerOne: {e}") from e
        if resp.status_code == 401:
            raise H1Error(
                "HackerOne API returned 401 Unauthorized — check your API token."
            )
        if resp.status_code == 429:
            raise H1Error("HackerOne API rate limit hit (429) — try again shortly.")
        if resp.status_code != 200:
            raise H1Error(
                f"HackerOne API error {resp.status_code}: {resp.text[:200]}"
            )
        try:
            body = resp.json()
        except ValueError as e:
            raise H1Error(f"invalid JSON from HackerOne: {e}") from e
        items.extend(body.get("data", []) or [])
        url = ((body.get("links") or {}).get("next")) or None
        pages += 1
    return items


# ----------------------------------------------------------------------
# API calls (network)
# ----------------------------------------------------------------------
def list_programs(username: str, token: str, *, timeout: int = 30) -> list[dict]:
    """Return ``[{handle, name, submission_state}, …]`` for accessible programs."""
    raw = _get_paginated(f"{API_BASE}/programs", (username, token), timeout=timeout)
    out: list[dict] = []
    for item in raw:
        attrs = item.get("attributes", {}) or {}
        handle = attrs.get("handle")
        if handle:
            out.append({
                "handle": handle,
                "name": attrs.get("name") or handle,
                "submission_state": attrs.get("submission_state"),
            })
    return out


def get_structured_scopes(
    username: str, token: str, handle: str, *, timeout: int = 30,
) -> list[dict]:
    """Return the raw structured_scope objects for ``handle``."""
    url = f"{API_BASE}/programs/{handle}/structured_scopes"
    return _get_paginated(url, (username, token), timeout=timeout)


# ----------------------------------------------------------------------
# Pure helpers — parsing / filtering (no I/O, unit-testable)
# ----------------------------------------------------------------------
def parse_scopes(raw_scopes: list[dict], *, in_scope_only: bool = True) -> list[dict]:
    """Flatten raw structured_scopes to ``[{asset_type, asset_identifier, ...}]``.

    With ``in_scope_only`` (default) only assets flagged
    ``eligible_for_submission`` are kept — that is what "in scope" means on
    HackerOne, and it keeps out-of-scope hosts out of the recon pipeline.
    """
    out: list[dict] = []
    for item in raw_scopes or []:
        attrs = item.get("attributes", {}) or {}
        if in_scope_only and not attrs.get("eligible_for_submission", False):
            continue
        out.append({
            "asset_type": attrs.get("asset_type", "") or "",
            "asset_identifier": (attrs.get("asset_identifier") or "").strip(),
            "eligible_for_bounty": bool(attrs.get("eligible_for_bounty", False)),
        })
    return out


def _asset_to_host(asset_type: str, identifier: str) -> str:
    """Reduce a URL / WILDCARD asset identifier to a bare hostname.

    ``*.example.com`` → ``example.com``; ``https://app.example.com/x`` →
    ``app.example.com``. Returns "" for anything unparseable.
    """
    ident = (identifier or "").strip()
    if not ident:
        return ""
    if asset_type == "WILDCARD":
        if ident.startswith("*."):
            ident = ident[2:]
        ident = ident.lstrip(".")
    if "://" not in ident:
        ident = "http://" + ident  # give urlsplit a scheme to parse
    return (urlsplit(ident).hostname or "").lower()


def extract_root_domains(scopes: list[dict]) -> list[str]:
    """Return the sorted, unique in-scope hostnames worth feeding to recon.

    Only URL / WILDCARD assets contribute. Non-domain assets (CIDR, mobile
    app IDs, source repos, …) are skipped.
    """
    seen: set[str] = set()
    out: list[str] = []
    for s in scopes:
        if s.get("asset_type") not in DOMAIN_ASSET_TYPES:
            continue
        host = _asset_to_host(s.get("asset_type", ""), s.get("asset_identifier", ""))
        # Sanity: must look like a domain (a dot, no spaces / path separators).
        if host and "." in host and " " not in host and "/" not in host:
            if host not in seen:
                seen.add(host)
                out.append(host)
    return sorted(out)


def roots_for_program(
    username: str, token: str, handle: str, *, timeout: int = 30,
) -> list[str]:
    """Convenience: fetch → filter in-scope → return sorted root domains."""
    raw = get_structured_scopes(username, token, handle, timeout=timeout)
    return extract_root_domains(parse_scopes(raw))
