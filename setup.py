#!/usr/bin/env python3
"""setup.py — environment bootstrap for recon-agent.

This script helps you get a fresh machine ready to run the framework. It:

  1. Verifies which external tools (subfinder, amass, chaos, dnsx, httpx,
     katana, urlfinder, dirsearch, waymore, xnLinkFinder, arjun, nuclei, …)
     are on ``$PATH`` and prints their versions.
  2. Optionally installs missing tools via the platform's package manager
     (``brew`` on macOS, ``apt`` on Linux, ``go install`` for Go tools,
     ``pip3`` for Python tools).
  3. Clones ``danielmiessler/SecLists`` into ``~/wordlists/SecLists`` so
     every ``dirsearch.wordlists`` path in ``config.yml`` resolves out of
     the box.
  4. Creates the ``outputs/`` directory used by every run.
  5. Prints a summary so you can see at a glance what is ready and what is
     missing.

Usage
-----
    python3 setup.py                       # verify only, no installs
    python3 setup.py --wordlists           # clone SecLists
    python3 setup.py --install             # install missing tools
    python3 setup.py --all                 # install + download
    python3 setup.py --all -y              # same, skip confirmation prompts
    python3 setup.py --wordlists-dir PATH  # custom clone target
    python3 setup.py --no-color            # disable ANSI colors

By default nothing is installed or downloaded — the script is read-only.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


# ----------------------------------------------------------------------
# Tool catalogue
# ----------------------------------------------------------------------
# Each entry maps the executable name on $PATH to its install commands
# per platform. ``check`` is used to grab a version string when present.
TOOLS: dict[str, dict] = {
    # Runtime
    "python3": {
        "label": "Python 3.8+",
        "category": "runtime",
        "version_args": [["--version"]],
        "install": {
            "Darwin": ["brew", "install", "python@3.11"],
            "Linux": ["sudo", "apt-get", "install", "-y", "python3", "python3-pip"],
        },
    },
    "pip3": {
        "label": "pip3",
        "category": "runtime",
        "version_args": [["--version"]],
        "install": {
            "Darwin": ["brew", "install", "python@3.11"],
            "Linux": ["sudo", "apt-get", "install", "-y", "python3-pip"],
        },
    },
    "go": {
        "label": "Go (for go install …)",
        "category": "runtime",
        "version_args": [["version"]],
        "install": {
            "Darwin": ["brew", "install", "go"],
            "Linux": ["sudo", "apt-get", "install", "-y", "golang-go"],
        },
    },
    # Go-based recon tools (projectdiscovery + xnl-h4ck3r)
    "subfinder": {
        "label": "subfinder",
        "category": "go",
        "version_args": [["-version"], ["-v"]],
        "install": {
            "Darwin": ["brew", "install", "subfinder"],
            "Linux": ["go", "install", "-v",
                      "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
        },
    },
    "amass": {
        "label": "amass",
        "category": "go",
        "version_args": [["version"], ["-version"]],
        "install": {
            "Darwin": ["brew", "install", "amass"],
            "Linux": ["sudo", "apt-get", "install", "-y", "amass"],
        },
    },
    "chaos": {
        "label": "chaos",
        "category": "go",
        "version_args": [["version"], ["-v"]],
        "install": {
            "Darwin": ["go", "install", "-v",
                      "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"],
            "Linux": ["go", "install", "-v",
                      "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"],
        },
    },
    "dnsx": {
        "label": "dnsx",
        "category": "go",
        "version_args": [["-version"], ["-v"]],
        "install": {
            "Darwin": ["brew", "install", "dnsx"],
            "Linux": ["go", "install", "-v",
                      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
        },
    },
    "httpx": {
        "label": "httpx",
        "category": "go",
        "version_args": [["-version"], ["-v"]],
        "install": {
            "Darwin": ["brew", "install", "httpx"],
            "Linux": ["go", "install", "-v",
                      "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
        },
    },
    "katana": {
        "label": "katana",
        "category": "go",
        "version_args": [["-version"], ["-v"]],
        "install": {
            "Darwin": ["go", "install", "-v",
                      "github.com/projectdiscovery/katana/v2/cmd/katana@latest"],
            "Linux": ["go", "install", "-v",
                      "github.com/projectdiscovery/katana/v2/cmd/katana@latest"],
        },
    },
    "nuclei": {
        "label": "nuclei",
        "category": "go",
        "version_args": [["-version"], ["-v"]],
        "install": {
            "Darwin": ["brew", "install", "nuclei"],
            "Linux": ["go", "install", "-v",
                      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
        },
    },
    "xnlinkfinder": {
        "label": "xnLinkFinder",
        "category": "go",
        "version_args": [["-h"]],
        "install": {
            "Darwin": ["go", "install", "-v",
                      "github.com/xnl-h4ck3r/xnLinkFinder@latest"],
            "Linux": ["go", "install", "-v",
                      "github.com/xnl-h4ck3r/xnLinkFinder@latest"],
        },
    },
    # Python-based recon tools
    "urlfinder": {
        "label": "urlfinder",
        "category": "python",
        "version_args": [["--help"]],
        "install": {
            "Darwin": ["pip3", "install", "urlfinder"],
            "Linux": ["pip3", "install", "urlfinder"],
        },
    },
    "dirsearch": {
        "label": "dirsearch",
        "category": "python",
        "version_args": [["--help"]],
        "install": {
            "Darwin": ["pip3", "install", "dirsearch"],
            "Linux": ["pip3", "install", "dirsearch"],
        },
    },
    "waymore": {
        "label": "waymore",
        "category": "python",
        "version_args": [["-h"]],
        "install": {
            "Darwin": ["pip3", "install", "waymore"],
            "Linux": ["pip3", "install", "waymore"],
        },
    },
    "arjun": {
        "label": "arjun",
        "category": "python",
        "version_args": [["-h"]],
        "install": {
            "Darwin": ["pip3", "install", "arjun"],
            "Linux": ["pip3", "install", "arjun"],
        },
    },
}


# Wordlists the framework expects out of the box.
SECLISTS_PATHS = [
    "Discovery/Web-Content/raft-small-directories.txt",
    "Discovery/Web-Content/uri-from-top-55-most-popular-apps.txt",
    "Discovery/Web-Content/Service-Specific",
]
SECLISTS_REPO = "https://github.com/danielmiessler/SecLists.git"


# ----------------------------------------------------------------------
# ANSI helpers
# ----------------------------------------------------------------------
def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


def _c(code: str, text: str, *, enabled: bool = True) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(t: str, enabled: bool) -> str:  return _c("32", t, enabled=enabled)
def _red(t: str, enabled: bool) -> str:    return _c("31", t, enabled=enabled)
def _yellow(t: str, enabled: bool) -> str: return _c("33", t, enabled=enabled)
def _cyan(t: str, enabled: bool) -> str:   return _c("36", t, enabled=enabled)
def _bold(t: str, enabled: bool) -> str:   return _c("1", t, enabled=enabled)


# ----------------------------------------------------------------------
# Pure helpers — no subprocess, no I/O. Unit-testable.
# ----------------------------------------------------------------------
def is_tool_available(binary: str) -> bool:
    """True iff *binary* is on PATH (delegates to shutil.which)."""
    return shutil.which(binary) is not None


def which(binary: str) -> Optional[str]:
    """Return absolute path to *binary* or None."""
    return shutil.which(binary)


def expected_wordlist_paths() -> list[str]:
    """Paths relative to the SecLists root that the framework uses."""
    return list(SECLISTS_PATHS)


def verify_wordlists(wordlists_dir: Path) -> dict[str, bool]:
    """Return {relpath: present} for every SecLists path the framework uses."""
    wordlists_dir = Path(wordlists_dir).expanduser()
    return {p: (wordlists_dir / p).exists() for p in SECLISTS_PATHS}


def missing_wordlists(wordlists_dir: Path) -> list[str]:
    return [p for p, present in verify_wordlists(wordlists_dir).items()
            if not present]


def select_install_command(binary: str, system: Optional[str] = None) -> Optional[list[str]]:
    """Return the platform-appropriate install command, or None if unknown."""
    system = system or platform.system()
    installs = TOOLS.get(binary, {}).get("install", {}) or {}
    return installs.get(system)


def _run(cmd: list[str], *, timeout: int = 600) -> tuple[int, str, str]:
    """Run a subprocess; return (rc, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as e:
        return 127, "", f"command not found: {e}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def _version_of(binary: str) -> Optional[str]:
    """Try every documented version flag and return the first hit."""
    for args in TOOLS.get(binary, {}).get("version_args", []):
        rc, out, err = _run([binary] + args)
        if rc == 0 and (out or err):
            line = (out or err).strip().splitlines()
            return line[0] if line else None
    return None


def check_tools() -> dict[str, dict]:
    """Return ``{binary: {label, available, version, category}}`` for every tool."""
    out: dict[str, dict] = {}
    for binary, info in TOOLS.items():
        avail = is_tool_available(binary)
        out[binary] = {
            "label": info["label"],
            "category": info.get("category", ""),
            "available": avail,
            "version": _version_of(binary) if avail else None,
            "path": which(binary),
        }
    return out


def category_sort_key(category: str) -> int:
    """Order: runtime, required (go/python), optional."""
    return {"runtime": 0, "go": 1, "python": 2}.get(category, 9)


# ----------------------------------------------------------------------
# I/O actions — install / clone / verify
# ----------------------------------------------------------------------
def install_missing_tools(
    results: dict[str, dict],
    *,
    system: Optional[str] = None,
    skip_confirm: bool = False,
    color: bool = True,
) -> dict[str, dict]:
    """Install every missing tool that has an install command.

    Mutates and returns ``results``. Each install runs separately so a single
    failure does not abort the whole batch.
    """
    system = system or platform.system()
    missing = [(b, info) for b, info in results.items() if not info["available"]]
    if not missing:
        print(_green("[+] All tools already installed.", color))
        return results

    print(_yellow(f"[!] {len(missing)} tool(s) missing on {system}:", color))
    for binary, info in missing:
        print(f"    • {info['label']}")

    for binary, info in missing:
        cmd = select_install_command(binary, system=system)
        if not cmd:
            print(_yellow(f"    ! {info['label']}: no install command for {system} — skip", color))
            continue
        if not skip_confirm:
            try:
                resp = input(_cyan(
                    f"  Run `{' '.join(cmd)}` to install {info['label']}? [y/N] ", color,
                ))
            except EOFError:
                resp = "n"
            if resp.strip().lower() not in ("y", "yes"):
                print(_yellow(f"    ! skipped {info['label']}", color))
                continue
        print(_cyan(f"  > {' '.join(cmd)}", color))
        rc, out, err = _run(cmd)
        if rc == 0:
            # re-check (Go installs land in ~/go/bin which may not be on PATH yet)
            results[binary]["available"] = is_tool_available(binary)
            if results[binary]["available"]:
                results[binary]["path"] = which(binary)
                results[binary]["version"] = _version_of(binary)
                print(_green(f"    ✓ {info['label']} installed", color))
            else:
                print(_yellow(
                    f"    ? {info['label']} command ran but binary still not on PATH "
                    f"(you may need to add ~/go/bin to PATH and re-source your shell)",
                    color,
                ))
        else:
            tail = (err or out).strip().splitlines()[-1] if (err or out) else "(no output)"
            print(_red(f"    ✗ {info['label']} install failed: {tail}", color))
    return results


def seclists_already_present(target: Path) -> bool:
    """SecLists is considered 'present' if its Discovery/ folder exists."""
    target = Path(target).expanduser()
    return (target / "Discovery").exists()


def download_wordlists(
    target_dir: Path,
    *,
    skip_confirm: bool = False,
    color: bool = True,
) -> bool:
    """Clone SecLists into ``target_dir`` (default ``~/wordlists/SecLists``)."""
    target_dir = Path(target_dir).expanduser()

    if seclists_already_present(target_dir):
        print(_green(f"[+] SecLists already present at {target_dir}", color))
        return True

    if target_dir.exists() and any(target_dir.iterdir()) and not skip_confirm:
        try:
            resp = input(_cyan(
                f"[?] {target_dir} exists and is non-empty — clone into it? [y/N] ",
                color,
            ))
        except EOFError:
            resp = "n"
        if resp.strip().lower() not in ("y", "yes"):
            print(_yellow("    ! skipped wordlist download", color))
            return False

    target_dir.parent.mkdir(parents=True, exist_ok=True)
    print(_cyan(f"[+] Cloning SecLists into {target_dir} (this may take a minute)…", color))
    rc, _out, err = _run(["git", "clone", "--depth", "1", SECLISTS_REPO, str(target_dir)])
    if rc == 0:
        print(_green(f"    ✓ SecLists cloned to {target_dir}", color))
        return True
    print(_red(f"    ✗ git clone failed: {err.strip()[:300]}", color))
    return False


def setup_output_dir(base: Path = Path("outputs")) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    return base


# ----------------------------------------------------------------------
# Summary printer — pure given inputs, returns issue count.
# ----------------------------------------------------------------------
def build_summary(
    tool_results: dict[str, dict],
    wl_results: dict[str, bool],
    output_dir: Path,
    wordlists_dir: Path,
) -> dict:
    """Build a structured summary that the caller can print or send."""
    issues = 0
    tools_block = []
    for binary, info in tool_results.items():
        ok = info["available"]
        if not ok:
            issues += 1
        tools_block.append({
            "binary": binary,
            "label": info["label"],
            "category": info["category"],
            "available": ok,
            "version": info.get("version"),
            "path": info.get("path"),
        })
    wl_block = []
    for relpath, present in wl_results.items():
        if not present:
            issues += 1
        wl_block.append({"path": relpath, "present": present})
    return {
        "tools": tools_block,
        "wordlists": wl_block,
        "output_dir": str(output_dir),
        "wordlists_dir": str(wordlists_dir),
        "issues": issues,
    }


def print_summary(summary: dict, *, color: bool = True) -> int:
    print("\n" + "=" * 70)
    print(_bold("RECON-AGENT ENVIRONMENT SUMMARY", color))
    print("=" * 70)

    print("\n[ External tools ]")
    last_cat = None
    for t in summary["tools"]:
        if t["category"] != last_cat:
            last_cat = t["category"]
            print(f"  ── {last_cat} ──")
        if t["available"]:
            ver = t["version"] or "(unknown version)"
            print(f"  {_green('✓', color)} {t['label']:<24} {ver}")
        else:
            print(f"  {_red('✗', color)} {t['label']:<24} MISSING")

    print(f"\n[ Wordlists @ {summary['wordlists_dir']} ]")
    for w in summary["wordlists"]:
        if w["present"]:
            print(f"  {_green('✓', color)} {w['path']}")
        else:
            print(f"  {_red('✗', color)} {w['path']}  (will be skipped at runtime)")

    print(f"\n[ Output directory ]")
    print(f"  {_green('✓', color)} {summary['output_dir']}/")

    print("\n[ Next steps ]")
    print("  1. Edit config.yml (set Telegram bot_token + chat_id if desired)")
    print("  2. python3 main.py -d example.com --dry-run    # preview the workflow")
    print("  3. python3 main.py -d example.com              # run for real")

    print("\n" + "=" * 70)
    if summary["issues"] == 0:
        print(_green("[+] All checks passed — ready to run.", color))
    else:
        print(_yellow(f"[!] {summary['issues']} issue(s) — see ✗ marks above.", color))
    return summary["issues"]


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser(
        prog="setup",
        description="recon-agent environment bootstrap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="By default this script is read-only (verify only). "
               "Use --install to actually install missing tools, "
               "--wordlists to clone SecLists.",
    )
    p.add_argument("--install", action="store_true",
                   help="install missing tools via brew/apt/go/pip")
    p.add_argument("--wordlists", action="store_true",
                   help="clone SecLists into --wordlists-dir")
    p.add_argument("--all", action="store_true",
                   help="equivalent to --install --wordlists")
    p.add_argument("--wordlists-dir", default="~/wordlists",
                   help="where to clone SecLists (default: ~/wordlists)")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI color output")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip confirmation prompts")
    args = p.parse_args()

    if args.all:
        args.install = True
        args.wordlists = True

    color = _supports_color() and not args.no_color
    system = platform.system()

    print(_bold("[*] recon-agent setup", color))
    print(f"[*] platform : {system} {platform.release()}")
    print(f"[*] python   : {sys.version.split()[0]}")
    print(f"[*] wordlists target: {Path(args.wordlists_dir).expanduser()}")

    # 1) verify tools
    print(_bold("\n[1/4] Checking external tools…", color))
    results = check_tools()
    for binary, info in sorted(results.items(),
                                key=lambda kv: category_sort_key(kv[1]["category"])):
        if info["available"]:
            ver = info["version"] or "?"
            print(f"  {_green('✓', color)} {info['label']:<24} {ver}")
        else:
            print(f"  {_red('✗', color)} {info['label']:<24} MISSING")

    # 2) install (optional)
    if args.install:
        print(_bold("\n[2/4] Installing missing tools…", color))
        install_missing_tools(results, system=system,
                             skip_confirm=args.yes, color=color)
    else:
        print(_yellow("\n[2/4] Skipping tool install (use --install to enable).", color))

    # 3) wordlists (optional)
    wordlists_dir = Path(args.wordlists_dir).expanduser()
    if args.wordlists:
        print(_bold(f"\n[3/4] Downloading wordlists to {wordlists_dir}…", color))
        download_wordlists(wordlists_dir, skip_confirm=args.yes, color=color)
    else:
        print(_yellow(
            f"\n[3/4] Skipping wordlist download (use --wordlists to enable). "
            f"Expected at {wordlists_dir}/SecLists", color,
        ))

    # 4) verify wordlists
    print(_bold("\n[4/4] Verifying expected wordlists…", color))
    wl_results = verify_wordlists(wordlists_dir / "SecLists")
    for relpath, present in wl_results.items():
        if present:
            print(f"  {_green('✓', color)} {relpath}")
        else:
            print(f"  {_red('✗', color)} {relpath}")

    # output dir
    out = setup_output_dir()
    print(_green(f"\n[+] Created {out}/", color))

    # summary
    summary = build_summary(results, wl_results, out, wordlists_dir / "SecLists")
    print_summary(summary, color=color)
    return 0 if summary["issues"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
