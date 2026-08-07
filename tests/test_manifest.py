"""Tests for processed/MANIFEST.json — why an artefact is empty.

A 0-line file has two opposite meanings that look identical on disk: "we
looked and the target has none of this" (a result) and "we never looked"
(no data). Reporting the second as the first is how a broken run turns into
a clean bill of health, so these tests pin the distinction.
"""
from __future__ import annotations

from modules import audit, layout
from modules.utils import write_lines


def _result(stage, status, outputs, *, error=None, extra=None):
    return {"stage": stage, "status": status, "error": error,
            "outputs": [str(p) for p in outputs], "extra": extra or {}}


# ----------------------------------------------------------------------
# The four ways a file ends up empty
# ----------------------------------------------------------------------
def test_empty_after_a_successful_stage_is_a_real_result(tmp_path):
    p = layout.path(tmp_path, "apidocs_urls.txt")
    p.write_text("")
    audit.build_manifest(tmp_path, [_result("apidocs", "success", [p])])

    e = audit.load_manifest(tmp_path)["apidocs_urls.txt"]
    assert e["state"] == "ran_empty"
    assert "IS a result" in e["means"]


def test_empty_after_a_skipped_stage_is_not_a_result(tmp_path):
    p = layout.path(tmp_path, "arjun_params.txt")
    p.write_text("")
    audit.build_manifest(
        tmp_path, [_result("arjun", "skipped", [p], error="--skip-arjun")])

    e = audit.load_manifest(tmp_path)["arjun_params.txt"]
    assert e["state"] == "skipped"
    assert e["reason"] == "--skip-arjun"
    assert "says nothing about the target" in e["means"]


def test_empty_after_a_failed_stage_is_not_a_result(tmp_path):
    p = layout.path(tmp_path, "ffuf_urls.txt")
    p.write_text("")
    audit.build_manifest(
        tmp_path, [_result("ffuf", "failed", [p], error="binary crashed")])

    e = audit.load_manifest(tmp_path)["ffuf_urls.txt"]
    assert e["state"] == "failed"
    assert e["reason"] == "binary crashed"


def test_timed_out_stage_is_truncated_even_when_it_reports_success(tmp_path):
    # The archetype this whole file exists for: status "success" while the
    # stage actually ran out of budget. The status lies; extra does not.
    p = layout.path(tmp_path, "dirsearch_urls.txt")
    p.write_text("")
    audit.build_manifest(tmp_path, [_result(
        "dirsearch", "success", [p],
        error="timeout after 6000s", extra={"timed_out": True},
    )])

    e = audit.load_manifest(tmp_path)["dirsearch_urls.txt"]
    assert e["state"] == "truncated"
    assert "NOT a result" in e["means"]


def test_deadline_hit_also_counts_as_truncated(tmp_path):
    p = layout.path(tmp_path, "crawler_urls.txt")
    p.write_text("")
    audit.build_manifest(tmp_path, [_result(
        "content_discovery", "success", [p], extra={"deadline_hit": True},
    )])
    assert audit.load_manifest(tmp_path)["crawler_urls.txt"]["state"] == "truncated"


# ----------------------------------------------------------------------
# Non-empty and never-written
# ----------------------------------------------------------------------
def test_a_file_with_data_is_ok(tmp_path):
    p = layout.path(tmp_path, "all_urls.txt")
    write_lines(p, ["https://x.com/a", "https://x.com/b"])
    audit.build_manifest(tmp_path, [_result("url_merge", "success", [p])])

    e = audit.load_manifest(tmp_path)["all_urls.txt"]
    assert e["state"] == "ok"
    assert e["lines"] == 2


def test_a_file_that_was_never_written_is_absent(tmp_path):
    audit.build_manifest(tmp_path, [])
    e = audit.load_manifest(tmp_path)["forms.json"]
    assert e["state"] == "absent"
    assert e["path"] is None


def test_every_registered_artifact_appears(tmp_path):
    audit.build_manifest(tmp_path, [])
    manifest = audit.load_manifest(tmp_path)
    registered = {n for names in layout.GROUPS.values() for n in names}
    assert set(manifest) == registered


# ----------------------------------------------------------------------
# Attribution comes from the stages themselves
# ----------------------------------------------------------------------
def test_stage_is_attributed_from_its_declared_outputs(tmp_path):
    p = layout.path(tmp_path, "jsluice_urls.txt")
    write_lines(p, ["https://x.com/api"])
    audit.build_manifest(tmp_path, [_result("jsluice", "success", [p])])

    e = audit.load_manifest(tmp_path)["jsluice_urls.txt"]
    assert e["stage"] == "jsluice"
    assert e["group"] == "js"


def test_counts_summarise_the_states(tmp_path):
    ok = layout.path(tmp_path, "all_urls.txt")
    write_lines(ok, ["https://x.com/a"])
    skipped = layout.path(tmp_path, "arjun_params.txt")
    skipped.write_text("")

    r = audit.build_manifest(tmp_path, [
        _result("url_merge", "success", [ok]),
        _result("arjun", "skipped", [skipped], error="--skip-arjun"),
    ])
    states = r["extra"]["states"]
    assert states["ok"] == 1
    assert states["skipped"] == 1


# ----------------------------------------------------------------------
# INDEX.md surfaces the distinction
# ----------------------------------------------------------------------
def test_index_shows_the_reason_next_to_each_empty_file(tmp_path):
    p = layout.path(tmp_path, "arjun_params.txt")
    p.write_text("")
    audit.build_manifest(
        tmp_path, [_result("arjun", "skipped", [p], error="--skip-arjun")])
    audit.build_index(tmp_path, "x.com")

    index = (tmp_path / "INDEX.md").read_text()
    assert "arjun_params.txt" in index
    assert "skipped" in index
    assert "--skip-arjun" in index


def test_index_still_works_without_a_manifest(tmp_path):
    # build_index must not require build_manifest to have run first.
    layout.path(tmp_path, "arjun_params.txt").write_text("")
    audit.build_index(tmp_path, "x.com")
    assert "arjun_params.txt" in (tmp_path / "INDEX.md").read_text()


def test_a_refused_probe_is_blocked_not_a_result(tmp_path):
    # apidocs succeeding while every candidate returned 403 is the case this
    # state exists for: the stage learned nothing, which must not read as
    # "this target publishes no API docs".
    p = layout.path(tmp_path, "apidocs_urls.txt")
    p.write_text("")
    audit.build_manifest(tmp_path, [_result(
        "apidocs", "success", [p],
        error="no specs parsed — all 24 candidate hit(s) returned 401/403",
        extra={"blocked": True},
    )])

    e = audit.load_manifest(tmp_path)["apidocs_urls.txt"]
    assert e["state"] == "blocked"
    assert "NOT a result" in e["means"]


def test_blocked_false_still_reads_as_a_real_result(tmp_path):
    p = layout.path(tmp_path, "apidocs_urls.txt")
    p.write_text("")
    audit.build_manifest(tmp_path, [_result(
        "apidocs", "success", [p], extra={"blocked": False},
    )])
    assert audit.load_manifest(tmp_path)["apidocs_urls.txt"]["state"] == "ran_empty"
