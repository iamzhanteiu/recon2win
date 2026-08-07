from __future__ import annotations

import json
import subprocess
import zlib
from pathlib import Path

import pytest

from modules import gitdump, layout
from modules.utils import write_lines


# ----------------------------------------------------------------------
# looks_like_git_head / sanitize_host — pure logic
# ----------------------------------------------------------------------
def test_looks_like_git_head_ref():
    assert gitdump.looks_like_git_head("ref: refs/heads/main\n")


def test_looks_like_git_head_detached_sha():
    assert gitdump.looks_like_git_head("a" * 40)


def test_looks_like_git_head_rejects_garbage():
    assert not gitdump.looks_like_git_head("<html>404</html>")
    assert not gitdump.looks_like_git_head("")


def test_sanitize_host_is_filesystem_safe():
    assert gitdump.sanitize_host("https://x.example.com") == "x.example.com"
    name = gitdump.sanitize_host("https://x.example.com:8443")
    assert name == "x.example.com_8443"
    assert "/" not in name and ":" not in name


# ----------------------------------------------------------------------
# parse_blob
# ----------------------------------------------------------------------
def test_parse_blob_valid():
    raw = zlib.compress(b"blob 5\x00hello")
    assert gitdump.parse_blob(raw) == b"hello"


def test_parse_blob_rejects_non_zlib():
    assert gitdump.parse_blob(b"not zlib data") is None


def test_parse_blob_rejects_wrong_object_type():
    # a tree/commit object has a different header — must not be mistaken
    # for a blob and written to disk as file content.
    raw = zlib.compress(b"tree 5\x00stuff")
    assert gitdump.parse_blob(raw) is None


# ----------------------------------------------------------------------
# parse_index — round-tripped against a REAL git index, not a hand-built
# one, since the binary layout (padding rule especially) is exactly the
# kind of thing worth verifying against the real tool rather than memory.
# ----------------------------------------------------------------------
@pytest.fixture
def real_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "a@a.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "a"], cwd=repo, check=True)
    (repo / "file1.txt").write_text("hello world\n")
    (repo / "sub").mkdir()
    (repo / "sub" / "config.env").write_text("secret=abc123\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)
    return repo


def _ls_files_sha(repo: Path) -> dict[str, str]:
    out = subprocess.run(["git", "ls-files", "-s"], cwd=repo, check=True,
                         capture_output=True, text=True).stdout
    result = {}
    for line in out.splitlines():
        # "100644 <sha1> 0\t<path>"
        meta, path = line.split("\t", 1)
        sha = meta.split()[1]
        result[path] = sha
    return result


def test_parse_index_matches_git_ls_files(real_git_repo: Path):
    index_bytes = (real_git_repo / ".git" / "index").read_bytes()
    entries = dict(gitdump.parse_index(index_bytes))
    assert entries == _ls_files_sha(real_git_repo)


def test_parse_index_rejects_non_index_data():
    assert gitdump.parse_index(b"not an index file") == []
    assert gitdump.parse_index(b"") == []


def test_parse_blob_matches_real_object(real_git_repo: Path):
    shas = _ls_files_sha(real_git_repo)
    sha = shas["file1.txt"]
    obj_path = real_git_repo / ".git" / "objects" / sha[:2] / sha[2:]
    content = gitdump.parse_blob(obj_path.read_bytes())
    assert content == b"hello world\n"


# ----------------------------------------------------------------------
# dump_host — mocked HTTP, exercising both the happy path and the
# git-gc-packed-objects degradation path.
# ----------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, status_code: int, content: bytes = b"", text: str = ""):
        self.status_code = status_code
        self.content = content
        self.text = text or content.decode("utf-8", errors="ignore")


def test_dump_host_happy_path(real_git_repo: Path, tmp_path: Path, monkeypatch):
    shas = _ls_files_sha(real_git_repo)
    index_bytes = (real_git_repo / ".git" / "index").read_bytes()

    def fake_get(url, timeout=10):
        if url.endswith("/.git/HEAD"):
            return _FakeResponse(200, text="ref: refs/heads/master\n")
        if url.endswith("/.git/index"):
            return _FakeResponse(200, content=index_bytes)
        for path, sha in shas.items():
            if url.endswith(f"/.git/objects/{sha[:2]}/{sha[2:]}"):
                obj = (real_git_repo / ".git" / "objects" / sha[:2] / sha[2:]).read_bytes()
                return _FakeResponse(200, content=obj)
        return _FakeResponse(404)

    monkeypatch.setattr("modules.gitdump.requests.get", fake_get)

    dest = tmp_path / "dump"
    summary = gitdump.dump_host("https://victim.example", dest, max_files=100)

    assert summary["files_in_index"] == 2
    assert summary["files_recovered"] == 2
    assert summary["files_skipped"] == 0
    assert (dest / "file1.txt").read_text() == "hello world\n"
    assert (dest / "sub" / "config.env").read_text() == "secret=abc123\n"


def test_dump_host_degrades_gracefully_when_objects_are_packed(
    real_git_repo: Path, tmp_path: Path, monkeypatch,
):
    """After `git gc`, .git/index still lists every file (survives repack)
    but the loose objects a naive tree-walk needs are gone — this is
    exactly why the index-based approach is used, and it must report a
    partial result rather than crash or silently claim full recovery."""
    index_bytes = (real_git_repo / ".git" / "index").read_bytes()

    def fake_get(url, timeout=10):
        if url.endswith("/.git/HEAD"):
            return _FakeResponse(200, text="ref: refs/heads/master\n")
        if url.endswith("/.git/index"):
            return _FakeResponse(200, content=index_bytes)
        return _FakeResponse(404)          # every object "packed away"

    monkeypatch.setattr("modules.gitdump.requests.get", fake_get)

    dest = tmp_path / "dump"
    summary = gitdump.dump_host("https://victim.example", dest, max_files=100)

    assert summary["files_in_index"] == 2
    assert summary["files_recovered"] == 0
    assert summary["files_skipped"] == 2


def test_dump_host_max_files_cap(real_git_repo: Path, tmp_path: Path, monkeypatch):
    index_bytes = (real_git_repo / ".git" / "index").read_bytes()

    def fake_get(url, timeout=10):
        if url.endswith("/.git/HEAD"):
            return _FakeResponse(200, text="ref: refs/heads/master\n")
        if url.endswith("/.git/index"):
            return _FakeResponse(200, content=index_bytes)
        return _FakeResponse(404)

    monkeypatch.setattr("modules.gitdump.requests.get", fake_get)
    dest = tmp_path / "dump"
    summary = gitdump.dump_host("https://victim.example", dest, max_files=1)
    # files_in_index reports the true total; only 1 is ever attempted.
    assert summary["files_in_index"] == 2


def test_dump_host_no_git_exposure(tmp_path: Path, monkeypatch):
    def fake_get(url, timeout=10):
        return _FakeResponse(404)
    monkeypatch.setattr("modules.gitdump.requests.get", fake_get)
    dest = tmp_path / "dump"
    summary = gitdump.dump_host("https://safe.example", dest, max_files=100)
    assert summary["files_in_index"] == 0
    assert summary["files_recovered"] == 0


# ----------------------------------------------------------------------
# discover — config gating + end-to-end with faked runner + requests
# ----------------------------------------------------------------------
def _make_alive(tmp_path: Path, hosts: list[str]) -> Path:
    (tmp_path / "processed").mkdir(parents=True, exist_ok=True)
    (tmp_path / "raw").mkdir(parents=True, exist_ok=True)
    alive = layout.path(tmp_path, "alive.txt")
    write_lines(alive, hosts)
    return alive


def test_discover_disabled_by_default(tmp_path: Path):
    alive = _make_alive(tmp_path, ["https://x.com"])
    res = gitdump.discover(alive, tmp_path, cfg={}, resume=False, dry_run=False)
    assert res["status"] == "skipped"
    assert "opt-in" in res["error"]


def test_discover_skip_flag(tmp_path: Path):
    alive = _make_alive(tmp_path, ["https://x.com"])
    cfg = {"gitdump": {"enabled": True}}
    res = gitdump.discover(alive, tmp_path, cfg=cfg, resume=False,
                           dry_run=False, skip=True)
    assert res["status"] == "skipped"
    assert "skip-gitdump" in res["error"]


def test_discover_no_confirmed_exposure(tmp_path: Path, monkeypatch):
    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("")   # nothing matched -mc 200
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 0.1}
    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")

    alive = _make_alive(tmp_path, ["https://safe.example"])
    cfg = {"gitdump": {"enabled": True}}
    res = gitdump.discover(alive, tmp_path, cfg=cfg, resume=False, dry_run=False)
    assert res["status"] == "success"
    assert res["count"] == 0
    assert "no confirmed" in res["error"]


def test_discover_end_to_end(real_git_repo: Path, tmp_path: Path, monkeypatch):
    shas = _ls_files_sha(real_git_repo)
    index_bytes = (real_git_repo / ".git" / "index").read_bytes()

    def fake_run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        row = {"url": "https://victim.example/.git/HEAD",
               "body": "ref: refs/heads/master\n"}
        out.write_text(json.dumps(row))
        return {"returncode": 0, "stdout": "", "stderr": "",
                "missing_binary": False, "timed_out": False, "success": True,
                "stdout_path": "", "stderr_path": "", "log_path": "",
                "duration": 0.1}

    def fake_get(url, timeout=10):
        if url.endswith("/.git/HEAD"):
            return _FakeResponse(200, text="ref: refs/heads/master\n")
        if url.endswith("/.git/index"):
            return _FakeResponse(200, content=index_bytes)
        for path, sha in shas.items():
            if url.endswith(f"/.git/objects/{sha[:2]}/{sha[2:]}"):
                obj = (real_git_repo / ".git" / "objects" / sha[:2] / sha[2:]).read_bytes()
                return _FakeResponse(200, content=obj)
        return _FakeResponse(404)

    monkeypatch.setattr("modules.runner.run", fake_run)
    monkeypatch.setattr("modules.runner.tool_available", lambda b: True)
    monkeypatch.setattr("modules.runner.which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr("modules.gitdump.requests.get", fake_get)

    alive = _make_alive(tmp_path, ["https://victim.example"])
    cfg = {"gitdump": {"enabled": True}}
    res = gitdump.discover(alive, tmp_path, cfg=cfg, resume=False, dry_run=False)

    assert res["status"] == "success"
    assert res["count"] == 2
    data = json.loads((tmp_path / "findings" / "git_dump.json").read_text())
    assert data["hosts"][0]["host"] == "https://victim.example"
    assert data["hosts"][0]["files_recovered"] == 2
