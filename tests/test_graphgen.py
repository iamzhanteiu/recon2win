"""Tests for modules.graphgen — auto-generated output provenance graph."""
from __future__ import annotations

import json
from pathlib import Path


from modules import graphgen


def _seed_outputs(root: Path) -> None:
    """Create a realistic subset of pipeline outputs with known counts."""
    proc = root / "processed"
    proc.mkdir(parents=True, exist_ok=True)
    (proc / "subdomains.txt").write_text("a.x.com\nb.x.com\nc.x.com\n")
    (proc / "resolved.txt").write_text("a.x.com\nb.x.com\n")
    (proc / "alive.txt").write_text("https://a.x.com\n")
    (proc / "crawler_urls.txt").write_text("\n".join(f"https://a.x.com/{i}" for i in range(5)) + "\n")
    (proc / "dirsearch_urls.txt").write_text("https://a.x.com/admin\n")
    (proc / "waymore_urls.txt").write_text("https://a.x.com/old\nhttps://a.x.com/old2\n")
    (proc / "all_urls.txt").write_text("\n".join(f"https://a.x.com/{i}" for i in range(8)) + "\n")
    (proc / "js_urls.txt").write_text("https://a.x.com/app.js\n")
    (proc / "dynamic_urls.txt").write_text("https://a.x.com/s?q=1\nhttps://a.x.com/u?id=2\n")
    (proc / "parameterized_urls.txt").write_text("https://a.x.com/s?q=1\n")
    (proc / "jsluice_params.json").write_text(json.dumps([
        {"url": "https://a.x.com/api", "method": "POST", "queryParams": [], "bodyParams": ["x"]},
    ]))

    find = root / "findings"
    (find / "default").mkdir(parents=True, exist_ok=True)
    (find / "dynamic").mkdir(parents=True, exist_ok=True)
    (find / "default" / "nuclei.json").write_text(json.dumps({
        "findings": [{"info": {"severity": "info"}}],
        "severity_count": {"info": 1},
    }))
    (find / "dynamic" / "nuclei.json").write_text(json.dumps({
        "findings": [{"info": {"severity": "high"}}, {"info": {"severity": "medium"}}],
        "severity_count": {"high": 1, "medium": 1},
    }))
    (find / "jsluice_secrets.json").write_text(json.dumps({
        "findings": [{"k": "v"}], "severity_count": {"high": 1},
    }))


def test_build_model_counts(tmp_path: Path):
    _seed_outputs(tmp_path)
    nodes, edges = graphgen.build_model(tmp_path, "x.com")
    by_id = {n["id"]: n for n in nodes}

    assert by_id["subdomains"]["count"] == 3
    assert by_id["alive"]["count"] == 1
    assert by_id["crawler"]["count"] == 5
    assert by_id["all_urls"]["count"] == 8
    assert by_id["jsluice_params"]["count"] == 1
    assert by_id["domain"]["count"] is None
    # severity carried onto finding nodes
    assert by_id["nuclei_dynamic"]["count"] == 2
    assert by_id["nuclei_dynamic"]["sev"] == "high"
    assert by_id["nuclei_dynamic"]["sub"] == "1H 1M"
    assert by_id["secrets"]["count"] == 1


def test_missing_files_are_zero(tmp_path: Path):
    # No outputs created at all — every count is zero, nothing raises.
    nodes, edges = graphgen.build_model(tmp_path, "x.com")
    counts = [n["count"] for n in nodes if n["count"] is not None]
    assert counts and all(c == 0 for c in counts)


def test_layers_are_a_dag(tmp_path: Path):
    _seed_outputs(tmp_path)
    nodes, edges = graphgen.build_model(tmp_path, "x.com")
    layer = graphgen._layers(nodes, edges)
    # Every SOLID edge must go strictly downward (parent layer < child layer).
    for src, dst, style in edges:
        if style == "solid":
            assert layer[src] < layer[dst], f"{src}->{dst} not downward"
    # Funnel sanity: domain at the top, report at the bottom.
    assert layer["domain"] == 0
    assert layer["report"] == max(layer.values())


def test_waymore_pinned_to_discovery_row(tmp_path: Path):
    _seed_outputs(tmp_path)
    nodes, edges = graphgen.build_model(tmp_path, "x.com")
    layer = graphgen._layers(nodes, edges)
    assert layer["waymore"] == layer["crawler"] == layer["dirsearch"]


def test_render_mermaid_shapes(tmp_path: Path):
    _seed_outputs(tmp_path)
    nodes, edges = graphgen.build_model(tmp_path, "x.com")
    mmd = graphgen.render_mermaid(nodes, edges)
    assert mmd.startswith("flowchart TB")
    assert 'domain(["x.com"]):::src' in mmd
    assert "all_urls" in mmd and "8" in mmd
    assert "-. append .->" in mmd  # loop-back edge present
    assert "classDef finding" in mmd


def test_render_svg_is_wellformed(tmp_path: Path):
    _seed_outputs(tmp_path)
    nodes, edges = graphgen.build_model(tmp_path, "x.com")
    svg = graphgen.render_svg(nodes, edges)
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    assert svg.count("<svg") == 1
    assert "<rect" in svg and "<path" in svg
    # A known count is rendered as label text.
    assert ">8<" in svg or ">8 " in svg or ">8" in svg
    # Severity colour applied to the high-severity finding node.
    assert "#c0392b" in svg


def test_build_output_graph_writes_mmd(tmp_path: Path):
    _seed_outputs(tmp_path)
    res = graphgen.build_output_graph(tmp_path, "x.com")
    assert res["status"] == "success"
    mmd = tmp_path / "report" / "graph.mmd"
    assert mmd.exists()
    assert "flowchart TB" in mmd.read_text()
    assert res["extra"]["injected_html"] is False  # no report html present


def test_injection_into_report_html(tmp_path: Path):
    _seed_outputs(tmp_path)
    report_dir = tmp_path / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "final_report.html").write_text(
        "<!DOCTYPE html>\n<html><head></head><body>\n<div class=\"container\">\n"
        "<h2>12. Appendix</h2>\n</div>\n<script>\n</script>\n</body>\n</html>\n"
    )
    res = graphgen.build_output_graph(tmp_path, "x.com")
    assert res["extra"]["injected_html"] is True
    html = (report_dir / "final_report.html").read_text()
    assert "13. Output Graph" in html
    assert "<svg" in html
    # Section sits inside the container, before the closing div/script.
    assert html.index("13. Output Graph") < html.index("</div>\n<script")


def test_injection_is_idempotent(tmp_path: Path):
    _seed_outputs(tmp_path)
    report_dir = tmp_path / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "final_report.html").write_text(
        "<body>\n<div class=\"container\">\n<h2>12. Appendix</h2>\n"
        "</div>\n<script>\n</script>\n</body>\n"
    )
    graphgen.build_output_graph(tmp_path, "x.com")
    graphgen.build_output_graph(tmp_path, "x.com")
    html = (report_dir / "final_report.html").read_text()
    assert html.count("13. Output Graph") == 1  # not stacked
