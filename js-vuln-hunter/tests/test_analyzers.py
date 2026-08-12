"""Analyzer + candidate engine tests against a planted sample."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jsvh import ast_engine as A
from jsvh import candidates as CAND
from jsvh.analyzers import dataflow as A_flow
from jsvh.models import JSAsset

SAMPLE = (Path(__file__).parent / "samples" / "vuln_sample.js").read_text()


def _analyze():
    pm = A.parse(SAMPLE)
    assert pm.ok, pm.error
    asset = JSAsset(asset_id="js_000001", target="t", host="h", url="http://h/a.js")
    flows = A_flow.analyze(asset.asset_id, pm)
    cands, _ = CAND.from_asset(asset, pm, flows)
    # high cap so per-type detection assertions see every candidate; the
    # per-asset cap is exercised separately in test_per_asset_cap.
    return pm, flows, CAND.rank(cands, per_asset_cap=100)


def test_parses():
    assert A.parse(SAMPLE).ok


def test_dom_xss_detected():
    _pm, flows, cands = _analyze()
    xss = [c for c in cands if c.type == "DOM-XSS"]
    assert xss, "expected DOM-XSS candidate"
    # source location.hash -> innerHTML must be attacker-controlled
    assert any(c.attacker_controlled == "yes" for c in xss)


def test_taint_propagation_across_vars():
    _pm, flows, _c = _analyze()
    # location.search -> msg -> outerHTML
    assert any(f.sink == "el.outerHTML" and f.attacker_controlled == "yes" for f in flows), \
        [f.sink for f in flows]


def test_sanitized_flow_suppressed():
    _pm, _f, cands = _analyze()
    # container.innerHTML = DOMPurify.sanitize(...) must not be a candidate
    assert not any(c.sink == "container.innerHTML" for c in cands)


def test_code_injection():
    _pm, _f, cands = _analyze()
    assert any(c.type == "CODE-INJECTION" for c in cands)


def test_prototype_pollution():
    _pm, _f, cands = _analyze()
    pp = [c for c in cands if c.type == "PROTOTYPE-POLLUTION"]
    assert pp and any(c.attacker_controlled == "yes" for c in pp)


def test_postmessage():
    _pm, _f, cands = _analyze()
    assert any(c.type == "POSTMESSAGE-XSS" for c in cands)


def test_client_side_authz():
    _pm, _f, cands = _analyze()
    assert any(c.type == "CLIENT-SIDE-AUTHZ" for c in cands)


def test_bola_object_id_endpoint():
    # /api/admin/users/{userId} carries a client-controlled object id → BOLA,
    # not a plain SENSITIVE-API (the sharper classification, §6).
    _pm, _f, cands = _analyze()
    bola = [c for c in cands if c.type == "BOLA"]
    assert any("/api/admin/users/" in (c.endpoint or "") for c in bola), \
        [(c.type, c.endpoint) for c in cands if c.endpoint]
    assert all(c.method for c in bola)


def test_secret_exposure():
    _pm, _f, cands = _analyze()
    assert any(c.type == "SECRET-EXPOSURE" for c in cands)


def test_ranking_p1_first():
    _pm, _f, cands = _analyze()
    assert cands, "no candidates"
    # highest ranked should be P1
    assert cands[0].priority == "P1"


# --- regression tests for precision fixes ---------------------------------

def _flows(code):
    pm = A.parse(code)
    assert pm.ok, pm.error
    return A_flow.analyze("js_1", pm)


def test_location_hostname_not_a_source():
    # location.hostname / host / origin are the victim's current site, NOT
    # attacker-controlled — must not produce a DOM-XSS flow.
    flows = _flows("el.innerHTML = 'https://' + window.location.hostname + '/x';")
    assert not any(f.attacker_controlled == "yes" for f in flows), \
        [(f.source, f.attacker_controlled) for f in flows]


def test_settimeout_callback_not_code_injection():
    # arrow/function callbacks passed to timers are safe; only string arg0 is
    flows = _flows("setTimeout(() => { go(location.href); }, 100);")
    assert not any("setTimeout" in f.sink for f in flows), [f.sink for f in flows]


def test_settimeout_string_is_code_injection():
    flows = _flows('setTimeout("alert("+location.hash+")", 100);')
    assert any(f.sink == "setTimeout" and f.attacker_controlled == "yes" for f in flows)


def test_third_party_demoted():
    from jsvh.fingerprint import is_third_party
    from jsvh import candidates as C
    pm = A.parse("el.innerHTML = location.hash;")
    asset = JSAsset(asset_id="js_1", target="t", host="cdnjs.cloudflare.com",
                    url="https://cdnjs.cloudflare.com/jquery.min.js", third_party=True)
    cands, _ = C.from_asset(asset, pm, A_flow.analyze("js_1", pm))
    assert cands and all(c.priority == "P3" for c in cands)


def test_per_asset_cap():
    # ranking caps how many candidates one asset contributes to the shortlist
    pm, flows, _ = _analyze()
    from jsvh.models import JSAsset
    asset = JSAsset(asset_id="js_000001", target="t", host="h", url="http://h/a.js")
    cands, _ = CAND.from_asset(asset, pm, flows)
    capped = CAND.rank(cands, per_asset_cap=3)
    assert len([c for c in capped if c.asset_id == "js_000001"]) <= 3


def test_prototype_pollution_bare_set_not_flagged():
    # Map.set / this.set must not be prototype-pollution candidates
    flows = []
    pm = A.parse("myMap.set('k', v); obj.set(a, b);")
    from jsvh.analyzers import prototype_pollution as PP
    assert not PP.analyze(pm)


# --- new detectors (mission §6/§8/§11/§12/§13/§14/§15) ---------------------

SAFE = (Path(__file__).parent / "samples" / "safe_sample.js").read_text()
CHAIN = (Path(__file__).parent / "samples" / "chain_sample.js").read_text()


def _cands(code, host="app.example.com", url=None, third=False):
    pm = A.parse(code)
    assert pm.ok, pm.error
    asset = JSAsset(asset_id="js_x", target="t", host=host,
                    url=url or f"https://{host}/app.js", third_party=third)
    flows = A_flow.analyze("js_x", pm)
    cands, _ = CAND.from_asset(asset, pm, flows, code.encode())
    return CAND.rank(cands, per_asset_cap=100)


def test_class_extension_not_prototype_pollution():
    # Marionette .extend({initialize, render, events}) is inheritance, not a merge
    from jsvh.analyzers import prototype_pollution as PP
    pm = A.parse(SAFE)
    assert not any(f.sink.endswith(".extend") or f.sink == "e.Marionette.ItemView.extend"
                   for f in PP.analyze(pm)), [f.sink for f in PP.analyze(pm)]


def test_strict_origin_postmessage_suppressed():
    # strict `event.origin === "..."` handler must NOT be a candidate
    cands = _cands(SAFE)
    assert not any(c.type == "POSTMESSAGE-XSS" for c in cands)


def test_weak_origin_postmessage_flagged():
    # indexOf-based origin check IS flagged (bypassable, §8)
    from jsvh.analyzers import postmessage as PM
    pm = A.parse(CHAIN)
    findings = PM.analyze(pm)
    recv = [f for f in findings if f.role == "receiver"]
    assert recv and any(f.origin_check == "weak" for f in recv), \
        [(f.role, f.origin_check) for f in findings]


def test_public_identifier_not_secret():
    # OAuth client_id / stripe pk_ are publishable — never P1 secrets (§12)
    cands = _cands(SAFE)
    secrets = [c for c in cands if c.type == "SECRET-EXPOSURE"]
    assert all(c.priority == "P3" or c.severity == "info" for c in secrets), \
        [(c.title, c.priority, c.severity) for c in secrets]


def test_token_storage_detected():
    cands = _cands(CHAIN)
    assert any(c.type == "TOKEN-STORAGE" for c in cands)


def test_bola_and_bfla_from_chain_sample():
    cands = _cands(CHAIN)
    assert any(c.type == "BOLA" for c in cands), [c.type for c in cands]
    assert any(c.type == "BFLA" for c in cands), [c.type for c in cands]


def test_oauth_missing_state_flagged():
    cands = _cands(CHAIN)
    assert any(c.type == "OAUTH-REDIRECT" for c in cands)


def test_exploitability_attached():
    cands = _cands(CHAIN)
    assert cands and all(c.exploitability is not None for c in cands)
    dom = [c for c in cands if c.type in ("BOLA", "BFLA")]
    assert dom and all(c.exploitability.boundary != "unknown" for c in dom)


def test_attack_chain_correlation():
    from jsvh import chains as CHAINS
    cands = _cands(CHAIN)
    ch = CHAINS.correlate(cands)
    assert ch, "expected at least one attack chain"
    names = " ".join(c.name.lower() for c in ch)
    # BOLA/BFLA authorization chain should form (object-id + client authz)
    assert any("authorization" in c.name.lower() for c in ch), [c.name for c in ch]
    # chains link back to candidate ids
    assert all(c.observations for c in ch)


def test_safe_sample_no_p1_dom_xss():
    # the safe corpus must not produce a P1 DOM-XSS (all patterns are safe)
    cands = _cands(SAFE)
    assert not any(c.type == "DOM-XSS" and c.priority == "P1" for c in cands), \
        [(c.title, c.priority) for c in cands if c.type == "DOM-XSS"]


if __name__ == "__main__":
    pm, flows, cands = _analyze()
    print(f"flows={len(flows)} candidates={len(cands)}")
    for c in cands:
        print(f"  {c.rank_score:6.0f}  {c.priority}/{c.severity:8} {c.type:20} "
              f"conf={c.confidence:.2f}  {c.source}->{c.sink}")
