"""Tests cho bước chọn target dùng chung của dirsearch (4.2) + ffuf (4.3).

Trọng tâm: wildcard DNS — N host trả về cùng một response phải co lại còn
một, và việc co đó phải xảy ra TRƯỚC khi cap, nếu không cap sẽ bị các bản
sao chiếm chỗ.
"""
import json
from pathlib import Path

from modules import fuzz_targets
from modules.fuzz_targets import (
    is_waf,
    load_targets,
    response_fingerprint,
    select_targets,
    summary_line,
)


def _row(url, status=200, words=27, lines=1, title="Home",
         webserver="nginx", **extra):
    return {"url": url, "status_code": status, "words": words, "lines": lines,
            "title": title, "webserver": webserver, **extra}


# ----------------------------------------------------------------------
# response_fingerprint
# ----------------------------------------------------------------------
def test_fingerprint_ignores_content_length_jitter():
    """Nonce/timestamp làm lệch byte count nhưng words/lines không đổi."""
    a = _row("https://a.com", content_length=1234)
    b = _row("https://b.com", content_length=1237)
    assert response_fingerprint(a) == response_fingerprint(b)


def test_fingerprint_separates_different_apps():
    a = _row("https://a.com", title="Home", words=27)
    b = _row("https://b.com", title="Admin Login", words=105)
    assert response_fingerprint(a) != response_fingerprint(b)


def test_fingerprint_none_when_signal_missing():
    assert response_fingerprint({"url": "https://a.com"}) is None
    assert response_fingerprint({"status_code": 200}) is None
    assert response_fingerprint("not a dict") is None


def test_fingerprint_status_distinguishes():
    a = _row("https://a.com", status=200)
    b = _row("https://b.com", status=403)
    assert response_fingerprint(a) != response_fingerprint(b)


# ----------------------------------------------------------------------
# select_targets — dedup
# ----------------------------------------------------------------------
def test_wildcard_dns_collapses_to_one_target():
    """200 subdomain cùng một app → fuzz 1, không phải 200."""
    urls = [f"https://h{i}.example.com" for i in range(200)]
    rows = [_row(u) for u in urls]
    targets, stats = select_targets(urls, rows, max_hosts=50)
    assert len(targets) == 1
    assert stats["input"] == 200
    assert stats["deduped"] == 199
    assert stats["largest_group"] == 200


def test_distinct_apps_are_all_kept():
    urls = [f"https://h{i}.example.com" for i in range(5)]
    rows = [_row(u, words=10 * i, title=f"App {i}") for i, u in enumerate(urls)]
    targets, stats = select_targets(urls, rows, max_hosts=50)
    assert len(targets) == 5
    assert stats["deduped"] == 0


def test_dedup_keeps_highest_value_hostname():
    """Trong nhóm giống nhau, giữ host đáng quan tâm nhất chứ không phải cái đầu."""
    urls = ["https://cdn-assets-3.example.com", "https://admin.example.com",
            "https://x9f2.example.com"]
    targets, _ = select_targets(urls, [_row(u) for u in urls], max_hosts=50)
    assert targets == ["https://admin.example.com"]


def test_rows_without_fingerprint_are_never_collapsed():
    """Thiếu dữ liệu → coi là app riêng. Thà fuzz thừa còn hơn bỏ sót."""
    urls = ["https://a.example.com", "https://b.example.com"]
    rows = [{"url": u} for u in urls]          # không có status/words/lines
    targets, stats = select_targets(urls, rows, max_hosts=50)
    assert len(targets) == 2
    assert stats["deduped"] == 0


def test_dedup_can_be_disabled():
    urls = [f"https://h{i}.example.com" for i in range(10)]
    rows = [_row(u) for u in urls]
    targets, _ = select_targets(urls, rows, max_hosts=50, dedup=False)
    assert len(targets) == 10


def test_no_detail_json_still_ranks_and_caps():
    """Không có alive_detail.json thì mất dedup, nhưng cap vẫn chạy."""
    urls = [f"https://h{i}.example.com" for i in range(10)]
    targets, stats = select_targets(urls, [], max_hosts=3)
    assert len(targets) == 3
    assert stats["deduped"] == 0


# ----------------------------------------------------------------------
# select_targets — thứ tự dedup trước, cap sau
# ----------------------------------------------------------------------
def test_dedup_happens_before_cap():
    """Điểm mấu chốt: 60 bản sao + 3 app thật, cap 5.

    Nếu cap trước thì 5 slot bị bản sao chiếm sạch và 3 app thật biến mất.
    """
    dupes = [f"https://dup{i}.example.com" for i in range(60)]
    reals = ["https://api.example.com", "https://admin.example.com",
             "https://staging.example.com"]
    rows = ([_row(u) for u in dupes]
            + [_row(u, words=100 + i, title=f"Real {i}")
               for i, u in enumerate(reals)])
    targets, stats = select_targets(dupes + reals, rows, max_hosts=5)
    # 1 đại diện của nhóm trùng + 3 app thật = 4, vừa trong cap 5
    assert len(targets) == 4
    for r in reals:
        assert r in targets


def test_cap_keeps_highest_ranked():
    urls = ["https://cdn1.example.com", "https://admin.example.com",
            "https://cdn2.example.com"]
    rows = [_row(u, words=i) for i, u in enumerate(urls)]   # không nhóm nào trùng
    targets, stats = select_targets(urls, rows, max_hosts=1)
    assert targets == ["https://admin.example.com"]
    assert stats["capped"] == 2


def test_max_hosts_zero_means_no_cap():
    urls = [f"https://h{i}.example.com" for i in range(30)]
    rows = [_row(u, words=i) for i, u in enumerate(urls)]
    targets, _ = select_targets(urls, rows, max_hosts=0)
    assert len(targets) == 30


# ----------------------------------------------------------------------
# WAF
# ----------------------------------------------------------------------
def test_is_waf_reads_httpx_cdn_type():
    assert is_waf({"cdn_type": "waf"})
    assert is_waf({"cdn_type": "WAF"})
    assert not is_waf({"cdn_type": "cdn"})
    assert not is_waf({})


def test_waf_hosts_kept_by_default_but_counted():
    urls = ["https://a.example.com", "https://b.example.com"]
    rows = [_row("https://a.example.com", cdn_type="waf"),
            _row("https://b.example.com", words=99)]
    targets, stats = select_targets(urls, rows, max_hosts=50)
    assert len(targets) == 2
    assert stats["waf_seen"] == 1
    assert stats["waf_skipped"] == 0


def test_skip_waf_drops_them():
    urls = ["https://a.example.com", "https://b.example.com"]
    rows = [_row("https://a.example.com", cdn_type="waf"),
            _row("https://b.example.com", words=99)]
    targets, stats = select_targets(urls, rows, max_hosts=50, skip_waf=True)
    assert targets == ["https://b.example.com"]
    assert stats["waf_skipped"] == 1


# ----------------------------------------------------------------------
# load_targets / write_target_file / summary_line
# ----------------------------------------------------------------------
def test_load_targets_reads_both_files(tmp_path: Path):
    out = tmp_path / "out"
    proc = out / "processed"
    proc.mkdir(parents=True)
    urls = [f"https://h{i}.example.com" for i in range(4)]
    (proc / "alive.txt").write_text("\n".join(urls) + "\n")
    (proc / "alive_detail.json").write_text(json.dumps([_row(u) for u in urls]))
    targets, stats = load_targets(proc / "alive.txt", out, max_hosts=50)
    assert len(targets) == 1          # cả 4 cùng response
    assert stats["deduped"] == 3


def test_load_targets_without_detail_json(tmp_path: Path):
    out = tmp_path / "out"
    proc = out / "processed"
    proc.mkdir(parents=True)
    (proc / "alive.txt").write_text("https://a.example.com\n")
    targets, stats = load_targets(proc / "alive.txt", out, max_hosts=50)
    assert targets == ["https://a.example.com"]


def test_write_target_file(tmp_path: Path):
    p = fuzz_targets.write_target_file(
        ["https://a.example.com"], tmp_path / "targets.txt")
    assert p.read_text().strip() == "https://a.example.com"


def test_summary_line_mentions_each_reduction():
    line = summary_line({"input": 200, "deduped": 190, "capped": 5,
                         "waf_skipped": 0, "selected": 5})
    assert "200 alive" in line and "190" in line and "5 target" in line


# ----------------------------------------------------------------------
# Tích hợp: hai stage fuzzing đều phải dùng chung bước chọn target
# ----------------------------------------------------------------------
def test_ffuf_uses_deduped_targets(tmp_path: Path, monkeypatch):
    from modules import ffuf
    out = tmp_path / "out"
    proc = out / "processed"
    proc.mkdir(parents=True)
    urls = [f"https://h{i}.example.com" for i in range(20)]
    (proc / "alive.txt").write_text("\n".join(urls) + "\n")
    (proc / "alive_detail.json").write_text(json.dumps([_row(u) for u in urls]))
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")

    calls: list[str] = []

    def fake_run(cmd, **kw):
        calls.append(cmd[cmd.index("-u") + 1])
        Path(cmd[cmd.index("-o") + 1]).write_text('{"results": []}')
        return {"success": True, "stderr": "", "missing_binary": False}

    monkeypatch.setattr(ffuf.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(ffuf.runner, "run", fake_run)
    res = ffuf.scan(proc / "alive.txt", out, {"ffuf": {"wordlists": [str(wl)]}})
    assert len(calls) == 1                      # 20 host → 1 process
    assert res["extra"]["selection"]["deduped"] == 19


def test_dirsearch_writes_deduped_target_file(tmp_path: Path, monkeypatch):
    from modules import dirsearch
    out = tmp_path / "out"
    proc = out / "processed"
    proc.mkdir(parents=True)
    urls = [f"https://h{i}.example.com" for i in range(20)]
    (proc / "alive.txt").write_text("\n".join(urls) + "\n")
    (proc / "alive_detail.json").write_text(json.dumps([_row(u) for u in urls]))
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")

    seen: list[str] = []

    def fake_run(cmd, **kw):
        seen.append(cmd[cmd.index("-l") + 1])
        return {"success": True, "stderr": "", "stdout": "",
                "missing_binary": False}

    monkeypatch.setattr(dirsearch.runner, "tool_available", lambda _b: True)
    monkeypatch.setattr(dirsearch.runner, "run", fake_run)
    res = dirsearch.scan(
        proc / "alive.txt", out, {"dirsearch": {"wordlists": [str(wl)]}})
    # dirsearch nhận -l trỏ vào file target đã lọc, không phải alive.txt
    assert seen[0].endswith("targets.txt")
    assert Path(seen[0]).read_text().strip().count("\n") == 0   # đúng 1 host
    assert res["extra"]["selection"]["deduped"] == 19
