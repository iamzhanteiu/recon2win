"""End-to-end pipeline orchestrator.

    recon2win outputs
        → ingest (load/validate/adapt/normalize)
        → acquire JS bodies (from recon2win URLs only)
        → fingerprint
        → AST parse
        → analyzers (source/sink/dataflow/endpoints/…)
        → candidate engine + ranking
        → verification plans
        → artifacts + report

Nothing here performs reconnaissance. Missing upstream data is reported,
never regenerated (mission §17).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import acquire, candidates as CAND, chains as CHAINS, exploitability as EXPLOIT
from . import fingerprint, report, verification
from . import ast_engine as A
from .analyzers import dataflow as A_flow
from .analyzers import regex_scan
from .config import Config, resolve_target_dir
from .ingest import adapter, loader, normalizer, validator
from .models import Candidate, JSAsset


@dataclass
class PipelineResult:
    target: str
    ok: bool
    validation: validator.ValidationReport
    assets: list[JSAsset] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    flows: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    files: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)


def ingest(cfg: Config) -> tuple[loader.ReconData, validator.ValidationReport, list[JSAsset]]:
    base = resolve_target_dir(cfg.outputs_dir, cfg.target)
    if base is None:
        base = cfg.recon_target_dir  # let loader report everything missing
    rd = loader.load(cfg.target, base)
    vr = validator.validate(rd)
    assets = normalizer.normalize(adapter.to_assets(rd))
    if cfg.max_assets:
        assets = assets[: cfg.max_assets]
    return rd, vr, assets


def run(cfg: Config, do_acquire: bool = True) -> PipelineResult:
    cfg.ensure_dirs()
    rd, vr, assets = ingest(cfg)

    if not vr.ok:
        return PipelineResult(cfg.target, ok=False, validation=vr, assets=assets)

    if do_acquire and cfg.acquire:
        # Prefer recon2win's already-downloaded bodies (zero duplication,
        # exact analysed bytes). Only network-fetch what's still missing.
        reused = acquire.from_recon_raw(assets, rd.base_dir, rd.js_detail, cfg)
        if cfg.net and reused < len(assets):
            acquire.acquire_all([a for a in assets if a.analysis_status == "pending"], cfg)

    all_flows: list = []
    all_endpoints: list = []
    all_cands: list[Candidate] = []
    parsed_ok = parse_fail = regex_only = 0

    acquired = [a for a in assets if a.local_path]
    for i, a in enumerate(acquired, 1):
        if cfg.progress_every and i % cfg.progress_every == 0:
            print(f"    ...analyzed {i}/{len(acquired)}", flush=True)
        data = acquire.local_bytes(a, cfg)
        if data is None:
            continue
        fingerprint.fingerprint(a, data)
        text = data.decode("utf-8", "replace")

        # oversized/huge-minified: skip esprima, use bounded regex scan
        if len(data) > cfg.max_parse_bytes:
            regex_only += 1
            a.analysis_status = "regex_scan"
            flows = regex_scan.scan(a.asset_id, text)
            all_flows.extend(f.to_dict() for f in flows)
            all_cands.extend(_regex_candidates(a, flows))
            continue

        try:
            pm = A.parse(text)
        except Exception as e:  # noqa: BLE001
            a.analysis_status = "error"
            a.parse_error = f"parse: {type(e).__name__}"
            continue
        if pm.ok:
            parsed_ok += 1
            a.analysis_status = "analyzed"
            flows = A_flow.analyze(a.asset_id, pm)
            cands, dump = CAND.from_asset(a, pm, flows, data)
            all_flows.extend(dump["flows"])
            all_endpoints.extend(dump["endpoints"])
            all_cands.extend(cands)
        else:
            # esprima 4.0.1 predates optional-chaining / nullish / BigInt, so
            # modern bundles routinely fail to parse. Don't drop them — fall
            # back to the regex scan for flows, and still run the text-based
            # secret patterns via from_asset.
            parse_fail += 1
            a.analysis_status = "parse_error"
            a.parse_error = pm.error
            flows = regex_scan.scan(a.asset_id, text)
            all_flows.extend(f.to_dict() for f in flows)
            all_cands.extend(_regex_candidates(a, flows))
            secret_cands, _ = CAND.from_asset(a, pm, [], data)
            all_cands.extend(secret_cands)

    ranked = CAND.rank(all_cands)
    # correlate ranked candidates into attack chains (§14)
    attack_chains = CHAINS.correlate(ranked)

    meta = {
        "target": cfg.target,
        "generated": report.now_iso(),
        "recon2win_dir": str(rd.base_dir),
        "assets_total": len(assets),
        "assets_acquired": sum(1 for a in assets if a.analysis_status in ("acquired", "analyzed", "parse_error")),
        "assets_parsed": parsed_ok,
        "assets_parse_failed": parse_fail,
        "assets_regex_only": regex_only,
        "candidates_total": len(ranked),
        "p1": sum(1 for c in ranked if c.priority == "P1"),
        "p2": sum(1 for c in ranked if c.priority == "P2"),
        "p3": sum(1 for c in ranked if c.priority == "P3"),
        "attack_chains": len(attack_chains),
    }

    files = report.write_artifacts(cfg.output_dir, assets, ranked, all_flows,
                                   all_endpoints, meta, attack_chains)

    # write verification plans + candidate records into the lifecycle dirs
    _emit_candidate_files(cfg, ranked)

    # top-candidates summary + prioritized verification queue (§17)
    (cfg.output_dir / "TOP_CANDIDATES.txt").write_text(report.top_candidates_text(ranked))
    (cfg.output_dir / "VERIFICATION_QUEUE.txt").write_text(
        report.verification_queue_text(ranked, attack_chains))
    (cfg.output_dir / "validation.md").write_text(vr.render())

    return PipelineResult(
        target=cfg.target, ok=True, validation=vr, assets=assets,
        candidates=ranked, flows=all_flows, endpoints=all_endpoints,
        files=files, stats=meta)


def _regex_candidates(asset: JSAsset, flows: list) -> list[Candidate]:
    """Low-confidence candidates from the regex fallback (oversized files)."""
    # regex fallback runs on the biggest bundles, which are disproportionately
    # vendored libraries — demote those so they never top the shortlist (§18).
    third = asset.third_party
    out: list[Candidate] = []
    for i, f in enumerate(flows, 1):
        ctype = "CODE-INJECTION" if f.sink_kind == "code-injection" else "DOM-XSS"
        out.append(Candidate(
            id=f"{asset.asset_id}-rx{i:03d}", type=ctype,
            priority="P3" if third else "P2",
            severity="info" if third else "medium",
            confidence=0.2 if third else 0.3, asset_id=asset.asset_id,
            url=asset.url, title=f"[regex] {f.source} → {f.sink}",
            source=f.source, sink=f.sink, attacker_controlled="unknown",
            sanitization="unknown", evidence=f.evidence, flow_id=f.flow_id,
            notes=["third-party library asset — demoted (§18)"] if third else []))
    for c in out:
        EXPLOIT.refine(c)
    return out


def _emit_candidate_files(cfg: Config, candidates: list[Candidate]) -> None:
    """Write verification plans for P1/P2 candidates into candidates/new/."""
    new_dir = cfg.workspace / "candidates" / "new" / cfg.target
    new_dir.mkdir(parents=True, exist_ok=True)
    for c in candidates:
        if c.priority in ("P1", "P2"):
            (new_dir / f"{c.id}.md").write_text(verification.plan_for(c))
