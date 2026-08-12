"""Configuration + path resolution.

The workspace is co-located with recon2win, so by default it reads the
sibling ``outputs/`` directory. Nothing here writes into recon2win's tree
— all workspace artifacts land under ``js-vuln-hunter/{targets,output}``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


# js-vuln-hunter/jsvh/config.py -> js-vuln-hunter/
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
# js-vuln-hunter/ -> recon2win/
RECON2WIN_ROOT = WORKSPACE_ROOT.parent
DEFAULT_OUTPUTS = RECON2WIN_ROOT / "outputs"


@dataclass
class Config:
    target: str                                   # domain, e.g. omnicell.com
    outputs_dir: Path = DEFAULT_OUTPUTS           # recon2win outputs/
    project: str | None = None                    # optional -p grouping
    workspace: Path = WORKSPACE_ROOT
    # acquisition
    acquire: bool = True                          # enable acquisition step
    net: bool = False                             # allow network fetch for the
                                                  # long tail not in recon raw
                                                  # (off by default: prefer
                                                  # recon2win's cached bodies)
    max_bytes: int = 6_000_000                    # per JS file cap
    timeout: int = 20
    workers: int = 12
    user_agent: str = "jsvh/0.1 (+recon2win-analysis-layer)"
    # analysis
    max_assets: int = 0                           # 0 = no cap
    max_parse_bytes: int = 150_000                # above this: regex fallback.
                                                  # pure-Python esprima costs
                                                  # ~20s+ on a 500KB minified
                                                  # bundle; hand-written JS
                                                  # (where DOM-XSS lives) is
                                                  # almost always well under
                                                  # this. Raise with --max-parse
                                                  # when you can spend the time.
    progress_every: int = 100                     # print a heartbeat

    @property
    def recon_target_dir(self) -> Path:
        """recon2win output dir for this target (supports -p grouping)."""
        if self.project:
            return self.outputs_dir / self.project / self.target
        return self.outputs_dir / self.target

    @property
    def target_dir(self) -> Path:
        """This workspace's per-target scratch dir."""
        d = self.workspace / "targets" / self.target
        return d

    @property
    def raw_js_dir(self) -> Path:
        return self.target_dir / "raw"

    @property
    def output_dir(self) -> Path:
        d = self.workspace / "output" / self.target
        return d

    def ensure_dirs(self) -> None:
        for d in (self.target_dir, self.raw_js_dir, self.output_dir):
            d.mkdir(parents=True, exist_ok=True)


def resolve_target_dir(outputs_dir: Path, target: str) -> Path | None:
    """Find a recon2win target dir, checking flat and one-level project nesting."""
    flat = outputs_dir / target
    if (flat / "processed").is_dir():
        return flat
    # search one level deep for outputs/<project>/<target>/processed
    if outputs_dir.is_dir():
        for child in outputs_dir.iterdir():
            cand = child / target
            if (cand / "processed").is_dir():
                return cand
    return None
