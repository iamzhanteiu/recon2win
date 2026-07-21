"""Wildcard scope normalisation — "*.rootdomain.com" must lose the "*." before
it ever reaches the recon pipeline, from either the -d flag or HackerOne scope.
"""
from __future__ import annotations

import pytest

from modules.hackerone import _asset_to_host, extract_root_domains
from modules.utils import validate_domain


# ---- choke point: validate_domain (covers -d AND the H1-picked target) ----
@pytest.mark.parametrize("raw,expected", [
    ("*.acme.com", "acme.com"),
    ("*.*.acme.com", "acme.com"),          # nested wildcard
    ("*.ACME.com", "acme.com"),            # lowercased
    ("*.app.acme.com/path", "app.acme.com"),  # path stripped too
    ("https://*.acme.com", "acme.com"),    # scheme + wildcard
    ("acme.com", "acme.com"),              # unchanged
])
def test_validate_domain_strips_wildcard(raw, expected):
    assert validate_domain(raw) == expected


@pytest.mark.parametrize("bad", ["* .acme.com", "*.com", "*."])
def test_validate_domain_rejects_malformed(bad):
    with pytest.raises(ValueError):
        validate_domain(bad)


# ---- H1 layer: WILDCARD asset → bare root ----
@pytest.mark.parametrize("ident,expected", [
    ("*.example.com", "example.com"),
    ("*.*.example.com", "example.com"),
    ("*.sub.example.com", "sub.example.com"),
])
def test_asset_to_host_strips_wildcard(ident, expected):
    assert _asset_to_host("WILDCARD", ident) == expected


def test_extract_root_domains_no_star_leaks():
    scopes = [
        {"asset_type": "WILDCARD", "asset_identifier": "*.acme.io"},
        {"asset_type": "URL", "asset_identifier": "https://api.acme.io"},
    ]
    roots = extract_root_domains(scopes)
    assert roots == ["acme.io", "api.acme.io"]
    assert all("*" not in r for r in roots)
