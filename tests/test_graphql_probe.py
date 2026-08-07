from __future__ import annotations

import json
from pathlib import Path

from modules import graphql_probe, layout
from modules.utils import write_lines


# ----------------------------------------------------------------------
# parse_schema — pure logic, no I/O
# ----------------------------------------------------------------------
def test_parse_schema_extracts_root_fields_and_types():
    body = json.dumps({
        "data": {
            "__schema": {
                "queryType": {"name": "Query", "fields": [
                    {"name": "users"}, {"name": "me"}]},
                "mutationType": {"name": "Mutation", "fields": [
                    {"name": "deleteUser"}]},
                "subscriptionType": None,
                "types": [
                    {"name": "User", "kind": "OBJECT"},
                    {"name": "__Type", "kind": "OBJECT"},
                ],
            }
        }
    })
    schema = graphql_probe.parse_schema(body)
    assert schema is not None
    assert schema["query_fields"] == ["me", "users"]
    assert schema["mutation_fields"] == ["deleteUser"]
    assert schema["subscription_fields"] == []
    # dunder/introspection types are filtered out
    assert "__Type" not in schema["types"]
    assert "User" in schema["types"]


def test_parse_schema_none_when_introspection_disabled():
    assert graphql_probe.parse_schema(
        json.dumps({"errors": [{"message": "introspection disabled"}]})
    ) is None
    assert graphql_probe.parse_schema(
        json.dumps({"data": {"__schema": None}})
    ) is None


def test_parse_schema_none_on_garbage():
    assert graphql_probe.parse_schema("") is None
    assert graphql_probe.parse_schema("<html>404</html>") is None
    assert graphql_probe.parse_schema("not json{") is None


def test_url_looks_like_graphql():
    assert graphql_probe._url_looks_like_graphql("https://x.com/graphql")
    assert graphql_probe._url_looks_like_graphql("https://x.com/api/GraphQL")
    assert graphql_probe._url_looks_like_graphql("https://x.com/graphiql")
    assert not graphql_probe._url_looks_like_graphql("https://x.com/about")


# ----------------------------------------------------------------------
# discover — config gating + end-to-end with a faked runner
# ----------------------------------------------------------------------
def _make_alive(tmp_path: Path, hosts: list[str]) -> Path:
    (tmp_path / "processed").mkdir(parents=True, exist_ok=True)
    (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
    alive = layout.path(tmp_path, "alive.txt")
    write_lines(alive, hosts)
    return alive


def test_discover_disabled_via_config(tmp_path: Path):
    alive = _make_alive(tmp_path, ["https://x.com"])
    cfg = {"graphql_probe": {"enabled": False}}
    res = graphql_probe.discover(alive, tmp_path, cfg=cfg, resume=False, dry_run=False)
    assert res["status"] == "skipped"
    assert "disabled" in res["error"]


def test_discover_skip_flag(tmp_path: Path):
    alive = _make_alive(tmp_path, ["https://x.com"])
    res = graphql_probe.discover(alive, tmp_path, cfg={}, resume=False,
                                 dry_run=False, skip=True)
    assert res["status"] == "skipped"
    assert "skip-graphql-probe" in res["error"]


def test_discover_end_to_end_with_fake_httpx(tmp_path: Path, monkeypatch):
    introspectable_body = json.dumps({
        "data": {"__schema": {
            "queryType": {"name": "Query", "fields": [{"name": "users"}]},
            "mutationType": {"name": "Mutation", "fields": [
                {"name": "deleteUser"}, {"name": "createInvoice"}]},
            "subscriptionType": None,
            "types": [{"name": "User", "kind": "OBJECT"}],
        }}
    })
    rows = [
        {"url": "https://x.com/graphql", "status_code": 200,
         "body": introspectable_body},
        {"url": "https://x.com/altair", "status_code": 404, "body": "<html>404</html>"},
    ]

    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(json.dumps(r) for r in rows))
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 0.1}

    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    alive = _make_alive(tmp_path, ["https://x.com"])
    res = graphql_probe.discover(alive, tmp_path, cfg={}, resume=False, dry_run=False)

    assert res["status"] == "success"
    assert res["count"] == 1
    data = json.loads((tmp_path / "findings" / "graphql_schema.json").read_text())
    assert len(data["targets"]) == 1
    t = data["targets"][0]
    assert t["url"] == "https://x.com/graphql"
    assert "deleteUser" in t["mutation_fields"]


def test_discover_no_candidates_is_clean_success(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    alive = _make_alive(tmp_path, [])
    res = graphql_probe.discover(alive, tmp_path, cfg={}, resume=False, dry_run=False)
    assert res["status"] == "success"
    assert res["count"] == 0
