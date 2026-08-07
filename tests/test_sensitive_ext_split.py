"""Tách extension thật khỏi tên file (fix cho fallback mode).

Trước đây cả hai nằm chung một list rồi đổ hết vào ``-e``, nên dirsearch đi
thử ``admin..env`` trong khi ``/.env`` — mục tiêu thật — không bao giờ được
chạm tới.
"""
from pathlib import Path

from modules import dirsearch, ffuf, layout
from modules.sensitive_ext import (
    SENSITIVE_EXT,
    to_dirsearch_flag,
    to_wordlist_lines,
)
from modules.waymore import _should_keep


def test_ext_list_contains_only_real_extensions():
    """Mọi entry phải có nghĩa khi nối sau một từ: <từ> + <ext>."""
    for e in SENSITIVE_EXT:
        assert e.startswith("."), f"{e!r} thiếu dấu chấm đầu"
        assert "/" not in e, f"{e!r} là đường dẫn, không phải extension"
        assert "*" not in e, f"{e!r} là glob, không phải extension"


def test_filenames_are_no_longer_in_the_extension_list():
    flag = to_dirsearch_flag(SENSITIVE_EXT)
    for name in ("docker-compose.yml", "package.json", "requirements.txt",
                 "thumbs.db", "_*", "env.local", "web.config"):
        assert name not in flag.split(","), f"{name} vẫn bị coi là extension"


def test_dotfiles_reachable_through_the_wordlist():
    """Nhóm giá trị nhất khi đi săn — phải nằm trong wordlist, không phải -e."""
    lines = to_wordlist_lines()
    for path in (".env", ".git/config", ".git/HEAD", ".DS_Store",
                 "docker-compose.yml", ".aws/credentials"):
        assert path in lines


def test_no_leading_slash_in_wordlist_lines():
    """Cả hai tool tự nối vào base URL — thêm '/' sẽ thành '//path'."""
    assert all(not p.startswith("/") for p in to_wordlist_lines())


def test_wordlist_lines_are_deduped():
    lines = to_wordlist_lines([".env", ".env", "/.env"])
    assert lines == [".env"]


def test_compound_extensions_stay_in_ext_list():
    """``backup.tar.gz`` / ``app.js.map`` là extension hợp lệ, giữ nguyên."""
    for e in (".tar.gz", ".js.map", ".key.pem"):
        assert e in SENSITIVE_EXT


def test_dirsearch_fallback_uses_both_channels(tmp_path: Path, monkeypatch):
    out = tmp_path / "out"
    (layout.path(out, "alive.txt")).write_text("https://a.example.com\n")

    captured: list = []
    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(
        dirsearch.runner, "run",
        lambda cmd, **kw: captured.append(cmd) or {
            "success": True, "stderr": "", "stdout": "", "missing_binary": False},
    )
    dirsearch.scan(layout.path(out, "alive.txt"), out, {"dirsearch": {}})
    cmd = captured[0]
    # -w trỏ vào danh sách file nhạy cảm, -e vẫn có extension
    assert "-w" in cmd and "-e" in cmd
    wl = Path(cmd[cmd.index("-w") + 1])
    assert ".env" in wl.read_text().split()
    assert ".git/config" in wl.read_text().split()
    assert "docker-compose.yml" not in cmd[cmd.index("-e") + 1]


def test_ffuf_fallback_fuzzes_paths_not_extensions(tmp_path: Path, monkeypatch):
    out = tmp_path / "out"
    (layout.path(out, "alive.txt")).write_text("https://a.example.com\n")

    captured: list = []

    def fake_run(cmd, **kw):
        captured.append(cmd)
        Path(cmd[cmd.index("-o") + 1]).write_text('{"results": []}')
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)
    ffuf.scan(layout.path(out, "alive.txt"), out, {"ffuf": {}})
    cmd = captured[0]
    wl = Path(cmd[cmd.index("-w") + 1])
    assert ".env" in wl.read_text().split()


def test_waymore_still_keeps_sensitive_filenames():
    """Tách list không được làm waymore vứt mất URL đáng giữ."""
    for url in ("https://x.com/.env",
                "https://x.com/docker-compose.yml",
                "https://x.com/path/.git/config",
                "https://x.com/backup.sql"):
        assert _should_keep(url), url


def test_waymore_still_drops_noise():
    assert not _should_keep("https://x.com/logo.png")
    assert not _should_keep("https://x.com/about")
