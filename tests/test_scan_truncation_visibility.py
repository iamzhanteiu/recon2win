"""Ba chỗ pipeline cắt cụt kết quả mà không nói ra — nay phải nói ra.

Điểm chung của cả ba: stage vẫn báo ``success`` và output vẫn trông bình
thường, nên cách duy nhất phát hiện là ngồi đối chiếu số trong stages.json.
Ở 157 host thì không cái nào kích hoạt; ở vài nghìn host thì cả ba là mặc
định. Test khoá lại phần *hiện lên*, không khoá giá trị ngưỡng.

  1. dnsx.max_resolved  — cắt danh sách host trước mọi stage sau
  2. katana timeout     — crawl dở dang, output ghi vẫn đủ định dạng
  3. nuclei batch_size  — vượt ngân sách batch ⇒ mọi batch timeout, 0 finding
"""
from __future__ import annotations

from pathlib import Path

from modules import content_discovery as cd_mod, layout
from modules import dnsx as dnsx_mod
from modules import nuclei as nuclei_mod
from modules.utils import create_output_structure, write_lines


# ----------------------------------------------------------------- dnsx

def _dnsx_jsonl(hosts: list[str]) -> str:
    return "\n".join(
        '{"host": "%s", "a": ["1.2.3.4"]}' % h for h in hosts
    ) + "\n"


def _fake_dnsx_run(hosts: list[str]):
    def _run(cmd, **kw):
        out = Path(cmd[cmd.index("-o") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_dnsx_jsonl(hosts))
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}
    return _run


def test_dnsx_truncation_warns_and_records(tmp_path, monkeypatch, capsys):
    out = tmp_path / "example.com"
    create_output_structure(out)
    subs = layout.path(out, "subdomains.txt")
    hosts = [f"h{i}.example.com" for i in range(50)]
    write_lines(subs, hosts)

    monkeypatch.setattr(dnsx_mod.runner, "run", _fake_dnsx_run(hosts))
    monkeypatch.setattr(dnsx_mod.runner, "tool_available", lambda _n: True)

    r = dnsx_mod.resolve(subs, out, {"dnsx": {"max_resolved": 10}})

    assert r["extra"]["truncated"] == 40
    assert r["extra"]["kept_for_downstream"] == 10
    # Con số phải lên console, không chỉ nằm trong stages.json.
    assert "cắt cụt" in capsys.readouterr().out


def test_dnsx_no_truncation_stays_quiet(tmp_path, monkeypatch, capsys):
    out = tmp_path / "example.com"
    create_output_structure(out)
    subs = layout.path(out, "subdomains.txt")
    hosts = [f"h{i}.example.com" for i in range(5)]
    write_lines(subs, hosts)

    monkeypatch.setattr(dnsx_mod.runner, "run", _fake_dnsx_run(hosts))
    monkeypatch.setattr(dnsx_mod.runner, "tool_available", lambda _n: True)

    r = dnsx_mod.resolve(subs, out, {"dnsx": {"max_resolved": 1000}})

    assert "truncated" not in r["extra"]
    assert "cắt cụt" not in capsys.readouterr().out


# --------------------------------------------------------------- katana

def _fake_katana_run(*, timed_out: bool):
    def _run(cmd, **kw):
        out = Path(cmd[cmd.index("-output") + 1])
        out.parent.mkdir(parents=True, exist_ok=True)
        # Katana ghi dần: bị giết giữa chừng vẫn để lại phần đã crawl, và
        # phần đó đúng định dạng — đó là lý do timeout không lộ ra.
        out.write_text('{"timestamp":"t","request":{"endpoint":'
                       '"https://a.example.com/x"}}\n')
        return {"success": not timed_out, "missing_binary": False,
                "timed_out": timed_out, "stdout": "", "stderr": "",
                "returncode": 124 if timed_out else 0}
    return _run


def _cd_cfg() -> dict:
    return {"content_discovery": {
        "katana": {"enabled": True, "timeout": 1800, "form_extraction": True},
        "urlfinder": {"enabled": False},
        "gau": {"enabled": False},
        "dedup_targets": False,
    }}


def test_katana_timeout_is_recorded_as_truncated(tmp_path, monkeypatch, capsys):
    out = tmp_path / "example.com"
    create_output_structure(out)
    alive = layout.path(out, "alive.txt")
    write_lines(alive, [f"https://h{i}.example.com" for i in range(7)])

    monkeypatch.setattr(cd_mod.runner, "run", _fake_katana_run(timed_out=True))
    monkeypatch.setattr(cd_mod.runner, "tool_available", lambda _n: True)

    r = cd_mod.crawl(alive, out, _cd_cfg())

    # Stage vẫn success — phần đã crawl là kết quả thật, không vứt đi.
    assert r["status"] == "success"
    assert r["extra"]["truncated"]["katana"] == {"timeout": 1800, "targets": 7}
    assert "CẮT CỤT" in capsys.readouterr().out


def test_katana_completes_without_truncation_note(tmp_path, monkeypatch, capsys):
    out = tmp_path / "example.com"
    create_output_structure(out)
    alive = layout.path(out, "alive.txt")
    write_lines(alive, ["https://a.example.com"])

    monkeypatch.setattr(cd_mod.runner, "run", _fake_katana_run(timed_out=False))
    monkeypatch.setattr(cd_mod.runner, "tool_available", lambda _n: True)

    r = cd_mod.crawl(alive, out, _cd_cfg())

    assert "truncated" not in r["extra"]
    assert "CẮT CỤT" not in capsys.readouterr().out


# --------------------------------------------------------- nuclei autotune

def test_safe_batch_size_matches_documented_formula():
    # Đúng phép tính ghi trong config.yml cho nuclei_default:
    # 0,7 × 1800s × 400 rps / (3,2 req × 1078 template) = 146
    n_cfg = {"rate_limit": 400, "req_per_template": 3.2}
    assert nuclei_mod._safe_batch_size(1078, n_cfg, 1800) == 146

    # Corpus to gấp 5 ⇒ batch phải nhỏ đi tương ứng.
    assert nuclei_mod._safe_batch_size(5390, n_cfg, 1800) == 29


def test_oversized_batch_is_shrunk_before_scanning(tmp_path, monkeypatch, capsys):
    """batch_size 250 với corpus 1078 template là cấu hình đã từng làm
    6/6 batch chết ở 1800s. Nay nó phải bị chặn trước khi bắn request."""
    out = tmp_path / "example.com"
    create_output_structure(out)
    urls = layout.path(out, "alive.txt")
    write_lines(urls, [f"https://a.example.com/{i}" for i in range(600)])

    monkeypatch.setattr(nuclei_mod, "_template_count", lambda *a, **k: 1078)
    monkeypatch.setattr(nuclei_mod.runner, "tool_available", lambda _n: True)

    sizes: list[int] = []

    def _run(cmd, **kw):
        batch_in = Path(cmd[cmd.index("-l") + 1])
        sizes.append(len(batch_in.read_text().strip().splitlines()))
        Path(cmd[cmd.index("-o") + 1]).write_text("")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(nuclei_mod.runner, "run", _run)

    cfg = {"nuclei": {"rate_limit": 400, "default": {
        "batch_size": 250, "batch_timeout": 1800, "batch_min_size": 25,
        "req_per_template": 3.2, "timeout": 10800,
        "severity": ["critical", "high"], "tags": ["exposure"],
    }}}
    r = nuclei_mod._run(urls, "default", cfg, out,
                        severity=["critical", "high"], tags=["exposure"],
                        timeout=10800)

    b = r["extra"]["batches"]
    assert b["configured_size"] == 250        # cấu hình giữ nguyên trong báo cáo
    assert b["autotune"]["safe_size"] == 146
    assert b["autotune"]["applied_size"] == 146
    assert max(sizes) == 146                  # và thực sự áp vào lệnh chạy
    assert "vượt ngân sách" in capsys.readouterr().out


def test_batch_within_budget_is_left_alone(tmp_path, monkeypatch, capsys):
    out = tmp_path / "example.com"
    create_output_structure(out)
    urls = layout.path(out, "alive.txt")
    write_lines(urls, [f"https://a.example.com/{i}" for i in range(300)])

    monkeypatch.setattr(nuclei_mod, "_template_count", lambda *a, **k: 1078)
    monkeypatch.setattr(nuclei_mod.runner, "tool_available", lambda _n: True)

    sizes: list[int] = []

    def _run(cmd, **kw):
        batch_in = Path(cmd[cmd.index("-l") + 1])
        sizes.append(len(batch_in.read_text().strip().splitlines()))
        Path(cmd[cmd.index("-o") + 1]).write_text("")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(nuclei_mod.runner, "run", _run)

    cfg = {"nuclei": {"rate_limit": 400, "default": {
        "batch_size": 120, "batch_timeout": 1800, "batch_min_size": 25,
        "req_per_template": 3.2, "timeout": 10800,
    }}}
    r = nuclei_mod._run(urls, "default", cfg, out,
                        severity=["critical", "high"], tags=["exposure"],
                        timeout=10800)

    b = r["extra"]["batches"]
    assert "applied_size" not in b["autotune"]   # 120 < 146 → không đụng
    assert max(sizes) == 120
    # KHÔNG tự phóng to 120 → 146: batch to hơn mất đuôi danh sách template.
    assert "vượt ngân sách" not in capsys.readouterr().out


def test_dast_scan_skips_autotune(tmp_path, monkeypatch):
    """``nuclei -tl`` lờ đi ``-dast`` và đếm cả corpus non-fuzzing, nên
    dùng số đó cho một scan bật dast sẽ hạ batch_size xuống sàn vô cớ."""
    out = tmp_path / "example.com"
    create_output_structure(out)
    urls = layout.path(out, "parameterized_urls.txt")
    write_lines(urls, [f"https://a.example.com/?id={i}" for i in range(600)])

    called: list[int] = []
    monkeypatch.setattr(nuclei_mod, "_template_count",
                        lambda *a, **k: called.append(1) or 13000)
    monkeypatch.setattr(nuclei_mod.runner, "tool_available", lambda _n: True)

    sizes: list[int] = []

    def _run(cmd, **kw):
        sizes.append(len(Path(cmd[cmd.index("-l") + 1])
                         .read_text().strip().splitlines()))
        Path(cmd[cmd.index("-o") + 1]).write_text("")
        return {"success": True, "missing_binary": False, "timed_out": False,
                "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(nuclei_mod.runner, "run", _run)

    cfg = {"nuclei": {"rate_limit": 400, "default": {
        "dast": True, "batch_size": 250, "batch_timeout": 1800,
        "batch_min_size": 25, "timeout": 10800,
    }}}
    r = nuclei_mod._run(urls, "default", cfg, out,
                        severity=["critical"], tags=None, timeout=10800)

    assert called == []                       # không hề đo
    assert max(sizes) == 250                  # batch_size giữ nguyên
    assert "autotune" not in r["extra"]["batches"]
