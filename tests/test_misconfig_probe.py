"""Tests for modules/misconfig_probe.py — server/microservice misconfig
probe, deep-tier hosts only.

Same precision principle as apidocs.parse_spec: a 200 alone is never proof
(the SPA-catch-all problem applies here too). Every path family needs a
content-shape validator, not just a status code.
"""
from __future__ import annotations

import json
from pathlib import Path

from modules import layout, misconfig_probe as mp
from modules.utils import create_output_structure, read_lines, write_lines


# ----------------------------------------------------------------------
# classify_hit — precision per service family
# ----------------------------------------------------------------------
def test_classify_hit_rejects_spa_catch_all():
    row = {"url": "https://a.example.com/actuator/env", "status_code": 200,
           "content_type": "text/html", "body": "<html>home page</html>"}
    assert mp.classify_hit(row) is None


def test_classify_hit_accepts_actuator_env():
    row = {"url": "https://a.example.com/actuator/env", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"propertySources": [], "activeProfiles": ["prod"]})}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Spring Boot actuator/env"
    assert hit["confidence"] == "high"


def test_classify_hit_rejects_actuator_env_without_expected_keys():
    row = {"url": "https://a.example.com/actuator/env", "status_code": 200,
           "content_type": "application/json", "body": json.dumps({"ok": True})}
    assert mp.classify_hit(row) is None


def test_classify_hit_accepts_actuator_heapdump_by_content_type_and_size():
    row = {"url": "https://a.example.com/actuator/heapdump", "status_code": 200,
           "content_type": "application/octet-stream", "body": "x" * 2000}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Spring Boot actuator/heapdump"


def test_classify_hit_rejects_heapdump_html_response():
    row = {"url": "https://a.example.com/actuator/heapdump", "status_code": 200,
           "content_type": "text/html", "body": "<html>nope</html>"}
    assert mp.classify_hit(row) is None


def test_classify_hit_accepts_jenkins_whoami():
    row = {"url": "https://ci.example.com/whoAmI/api/json", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"id": "admin", "fullName": "Administrator"})}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Jenkins whoAmI"
    assert hit["tech"] == "jenkins"


def test_classify_hit_accepts_jenkins_script_console_by_marker_text():
    row = {"url": "https://ci.example.com/script", "status_code": 200,
           "content_type": "text/html",
           "body": "<h1>Script Console</h1><p>Groovy script</p>"}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Jenkins script console"


def test_classify_hit_accepts_gitlab_version():
    row = {"url": "https://gl.example.com/api/v4/version", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"version": "16.0.0", "revision": "abcd123"})}
    hit = mp.classify_hit(row)
    assert hit["service"] == "GitLab API version"


def test_classify_hit_rejects_gitlab_version_without_revision():
    row = {"url": "https://gl.example.com/api/v4/version", "status_code": 200,
           "content_type": "application/json", "body": json.dumps({"version": "16.0.0"})}
    assert mp.classify_hit(row) is None


def test_classify_hit_accepts_k8s_namespaces_even_on_403():
    """The apiserver's own 403 Status body still confirms it's reachable —
    the apiserver being locked down is itself the finding."""
    row = {"url": "https://k8s.example.com/api/v1/namespaces", "status_code": 403,
           "content_type": "application/json",
           "body": json.dumps({"kind": "Status", "message": "forbidden"})}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Kubernetes API (namespaces)"


def test_classify_hit_accepts_k8s_version():
    row = {"url": "https://k8s.example.com/version", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"major": "1", "minor": "28"})}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Kubernetes API version"


def test_classify_hit_accepts_docker_catalog():
    row = {"url": "https://reg.example.com/v2/_catalog", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"repositories": ["app/backend", "app/worker"]})}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Docker registry catalog"


def test_classify_hit_accepts_elasticsearch_health():
    row = {"url": "https://es.example.com/_cluster/health", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"cluster_name": "prod", "status": "green"})}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Elasticsearch cluster health"


def test_classify_hit_accepts_phpmyadmin_marker():
    row = {"url": "https://db.example.com/phpmyadmin/", "status_code": 200,
           "content_type": "text/html", "body": "<title>phpMyAdmin</title>"}
    hit = mp.classify_hit(row)
    assert hit["service"] == "phpMyAdmin"


def test_classify_hit_rejects_phpmyadmin_path_without_marker():
    row = {"url": "https://db.example.com/phpmyadmin/", "status_code": 200,
           "content_type": "text/html", "body": "<html>not it</html>"}
    assert mp.classify_hit(row) is None


def test_classify_hit_weak_validator_paths_get_low_confidence():
    row = {"url": "https://c.example.com/v1/agent/self", "status_code": 200,
           "content_type": "application/json", "body": "{}"}
    hit = mp.classify_hit(row)
    assert hit is not None
    assert hit["confidence"] == "low"


def test_classify_hit_unrelated_path_is_none():
    row = {"url": "https://a.example.com/some/random/path", "status_code": 200,
           "body": "{}"}
    assert mp.classify_hit(row) is None


def test_classify_hit_empty_body_is_none():
    row = {"url": "https://a.example.com/actuator/env", "status_code": 200,
           "content_type": "application/json", "body": ""}
    assert mp.classify_hit(row) is None


# ----------------------------------------------------------------------
# classify_hit → tech key — the field misconfig_probe feeds back into
# fuzz_depth.TECH_WORDLIST_MAP / _TECH_HINTS via tech_confirmed.json.
# ----------------------------------------------------------------------
def test_classify_hit_spring_actuator_tags_spring():
    row = {"url": "https://a.example.com/actuator/env", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"propertySources": []})}
    assert mp.classify_hit(row)["tech"] == "spring"


def test_classify_hit_gitlab_tags_gitlab():
    row = {"url": "https://gl.example.com/api/v4/version", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"version": "1", "revision": "a"})}
    assert mp.classify_hit(row)["tech"] == "gitlab"


def test_classify_hit_k8s_tags_kubernetes():
    row = {"url": "https://k8s.example.com/version", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"major": "1", "minor": "28"})}
    assert mp.classify_hit(row)["tech"] == "kubernetes"


def test_classify_hit_docker_catalog_tags_docker():
    row = {"url": "https://r.example.com/v2/_catalog", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"repositories": []})}
    assert mp.classify_hit(row)["tech"] == "docker"


def test_classify_hit_elasticsearch_tags_elastic():
    row = {"url": "https://es.example.com/_cluster/health", "status_code": 200,
           "content_type": "application/json",
           "body": json.dumps({"cluster_name": "x", "status": "green"})}
    assert mp.classify_hit(row)["tech"] == "elastic"


def test_classify_hit_phpmyadmin_tags_phpmyadmin():
    row = {"url": "https://a.example.com/phpmyadmin/", "status_code": 200,
           "content_type": "text/html", "body": "phpMyAdmin login"}
    assert mp.classify_hit(row)["tech"] == "phpmyadmin"


def test_classify_hit_adminer_tags_adminer():
    row = {"url": "https://a.example.com/adminer.php", "status_code": 200,
           "content_type": "text/html", "body": "Adminer 4.8"}
    assert mp.classify_hit(row)["tech"] == "adminer"


def test_classify_hit_prometheus_tags_prometheus():
    row = {"url": "https://a.example.com/metrics", "status_code": 200,
           "content_type": "text/plain", "body": "# HELP up 1\n# TYPE up gauge\n"}
    assert mp.classify_hit(row)["tech"] == "prometheus"


def test_classify_hit_consul_tags_consul():
    row = {"url": "https://c.example.com/v1/agent/self", "status_code": 200,
           "content_type": "application/json", "body": "{}"}
    assert mp.classify_hit(row)["tech"] == "consul"


def test_classify_hit_nexus_and_artifactory_are_distinguished():
    nexus = {"url": "https://n.example.com/service/rest/v1/status",
             "status_code": 200, "content_type": "application/json", "body": "{}"}
    artifactory = {"url": "https://a.example.com/artifactory/api/system/ping",
                   "status_code": 200, "content_type": "text/plain", "body": "OK"}
    assert mp.classify_hit(nexus)["tech"] == "nexus"
    assert mp.classify_hit(artifactory)["tech"] == "artifactory"


def test_classify_hit_eureka_has_no_mapped_tech_key():
    """Still a real finding — just no fuzz_depth._TECH_HINTS key to
    propagate yet, so tech_confirmed.json gets nothing from it."""
    row = {"url": "https://e.example.com/eureka/apps", "status_code": 200,
           "content_type": "application/json", "body": '{"applications": {}}'}
    hit = mp.classify_hit(row)
    assert hit["service"] == "Eureka service registry"
    assert hit["tech"] == ""


# ----------------------------------------------------------------------
# discover() — stage wiring
# ----------------------------------------------------------------------
def _base(tmp_path, hosts=("https://app3.example.com",), tech=None):
    base = create_output_structure("example.com", root=str(tmp_path))
    alive = layout.path(base, "alive.txt")
    write_lines(alive, list(hosts))
    if tech is not None:
        from modules.utils import write_json
        write_json(layout.path(base, "alive_detail.json"),
                   [{"url": h, "tech": tech} for h in hosts])
    return base, alive


def test_discover_skip_flag_writes_empty_outputs(tmp_path):
    base, alive = _base(tmp_path)
    res = mp.discover(alive, base, {}, skip=True)
    assert res["status"] == "skipped"
    assert (base / "findings" / "misconfig_probe.json").exists()
    assert read_lines(layout.path(base, "misconfig_urls.txt")) == []


def test_discover_disabled_in_config(tmp_path):
    base, alive = _base(tmp_path)
    res = mp.discover(alive, base, {"misconfig_probe": {"enabled": False}})
    assert res["status"] == "skipped"
    assert "disabled" in res["error"]


def test_discover_dry_run_makes_no_requests(tmp_path, monkeypatch):
    base, alive = _base(tmp_path)
    called = []
    monkeypatch.setattr(mp.runner, "run", lambda *a, **k: called.append(1))
    res = mp.discover(alive, base, {}, dry_run=True)
    assert res["status"] == "skipped"
    assert called == []


def test_discover_no_deep_tier_hosts_is_skipped_not_failed(tmp_path):
    """A generic hostname with no tech signal never reaches "deep" —
    discover() must treat "nothing to probe" as skipped, not a failure."""
    base, alive = _base(tmp_path, hosts=("https://cdn-assets-3.example.com",))
    res = mp.discover(alive, base, {}, domain="example.com")
    assert res["status"] == "skipped"
    assert "deep-tier" in res["error"]


def test_discover_only_probes_deep_tier_hosts(tmp_path, monkeypatch):
    """Two hosts selected; only the tech-flagged one is deep-tier and only
    it should show up in the httpx candidate list."""
    base, alive = _base(
        tmp_path,
        hosts=("https://app3.example.com", "https://cdn-assets-3.example.com"),
        tech=None,
    )
    # app3 gets Jenkins via alive_detail.json, cdn-assets-3 gets nothing.
    from modules.utils import write_json
    write_json(layout.path(base, "alive_detail.json"), [
        {"url": "https://app3.example.com", "tech": ["Jenkins"]},
        {"url": "https://cdn-assets-3.example.com"},
    ])
    monkeypatch.setattr(mp.runner, "tool_available", lambda b: True)

    captured = {}

    def fake_run(cmd, **kw):
        in_file = Path(cmd[cmd.index("-l") + 1])
        captured["candidates"] = read_lines(in_file)
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w") as fh:
            pass  # no hits needed for this test
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(mp.runner, "run", fake_run)
    res = mp.discover(alive, base, {}, domain="example.com")

    assert res["status"] == "success"
    assert all("app3.example.com" in u for u in captured["candidates"])
    assert not any("cdn-assets-3" in u for u in captured["candidates"])


def test_discover_parses_hits_and_writes_outputs(tmp_path, monkeypatch):
    base, alive = _base(tmp_path, hosts=("https://ci.example.com",))
    from modules.utils import write_json
    write_json(layout.path(base, "alive_detail.json"),
               [{"url": "https://ci.example.com", "tech": ["Jenkins"]}])
    monkeypatch.setattr(mp.runner, "tool_available", lambda b: True)

    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-o") + 1]
        rows = [
            {"url": "https://ci.example.com/whoAmI/api/json", "status_code": 200,
             "content_type": "application/json",
             "body": json.dumps({"id": "admin", "fullName": "Administrator"})},
            # catch-all noise that must NOT be counted
            {"url": "https://ci.example.com/script", "status_code": 200,
             "content_type": "text/html", "body": "<html>home</html>"},
        ]
        with open(out, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(mp.runner, "run", fake_run)
    res = mp.discover(alive, base, {}, domain="example.com")

    assert res["status"] == "success"
    assert res["extra"]["findings"] == 1
    urls = read_lines(layout.path(base, "misconfig_urls.txt"))
    assert urls == ["https://ci.example.com/whoAmI/api/json"]

    import json as _json
    saved = _json.loads((base / "findings" / "misconfig_probe.json").read_text())
    assert saved["findings"][0]["service"] == "Jenkins whoAmI"
    assert saved["findings"][0]["tech"] == "jenkins"


def test_discover_saves_confirmed_tech_for_next_scan(tmp_path, monkeypatch):
    """The feedback-loop point: a real (tech-tagged) hit must persist into
    tech_confirmed.json so fuzz_depth picks it up on this target's next
    scan — see modules/fuzz_depth.py::load_confirmed_tech."""
    from modules import fuzz_depth

    base, alive = _base(tmp_path, hosts=("https://ci.example.com",))
    from modules.utils import write_json
    write_json(layout.path(base, "alive_detail.json"),
               [{"url": "https://ci.example.com", "tech": ["Jenkins"]}])
    monkeypatch.setattr(mp.runner, "tool_available", lambda b: True)

    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-o") + 1]
        rows = [
            {"url": "https://ci.example.com/whoAmI/api/json", "status_code": 200,
             "content_type": "application/json",
             "body": json.dumps({"id": "admin", "fullName": "Administrator"})},
        ]
        with open(out, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(mp.runner, "run", fake_run)
    res = mp.discover(alive, base, {}, domain="example.com")

    assert res["extra"]["confirmed_tech"] == {"ci.example.com": ["jenkins"]}
    assert fuzz_depth.load_confirmed_tech(base) == {"ci.example.com": ["jenkins"]}


def test_discover_no_findings_leaves_confirmed_tech_untouched(tmp_path, monkeypatch):
    base, alive = _base(tmp_path, hosts=("https://ci.example.com",))
    from modules import fuzz_depth
    monkeypatch.setattr(mp.runner, "tool_available", lambda b: True)

    def fake_run(cmd, **kw):
        out = cmd[cmd.index("-o") + 1]
        Path(out).write_text("")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(mp.runner, "run", fake_run)
    mp.discover(alive, base, {}, domain="example.com")
    assert fuzz_depth.load_confirmed_tech(base) == {}


def test_discover_resume_reuses_existing_outputs(tmp_path):
    base, alive = _base(tmp_path)
    findings_dir = base / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "misconfig_probe.json").write_text(
        json.dumps({"findings": [{"url": "x"}], "hosts_probed": 1}))
    write_lines(layout.path(base, "misconfig_urls.txt"), ["https://x/"])
    res = mp.discover(alive, base, {}, resume=True)
    assert res["status"] == "success"
    assert res["count"] == 1
