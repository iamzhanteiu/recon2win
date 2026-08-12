"""Lightweight framework / bundler / source-map fingerprinting.

Runs on raw bytes before AST parsing — cheap signals that (a) help
prioritise (a React SPA is a richer DOM-XSS surface than a static widget)
and (b) drive source-map discovery. Pure heuristics, no network.
"""

from __future__ import annotations

import re

from .models import JSAsset

_FRAMEWORK_SIGNS = [
    ("Next.js", re.compile(rb"__NEXT_DATA__|/_next/|next/dist")),
    ("Nuxt", re.compile(rb"__NUXT__|nuxt\.js|/_nuxt/")),
    ("React", re.compile(rb"React\.createElement|__REACT_DEVTOOLS|react-dom|useState\(")),
    ("Vue", re.compile(rb"__vue__|Vue\.component|createElementVNode|__VUE__")),
    ("Angular", re.compile(rb"@angular|ng-version|\xc9\xb5\xc9\xb5|platformBrowserDynamic")),
    ("Svelte", re.compile(rb"svelte/internal|__svelte")),
    ("jQuery", re.compile(rb"jQuery|\$\.fn\.jquery")),
    ("Ember", re.compile(rb"Ember\.Application|ember-source")),
]

_BUNDLER_SIGNS = [
    ("Webpack", re.compile(rb"webpackJsonp|__webpack_require__|webpackChunk")),
    ("Vite", re.compile(rb"import\.meta\.env|/@vite/|__vite__")),
    ("Rollup", re.compile(rb"ROLLUP_|\.rollup\.")),
    ("Parcel", re.compile(rb"parcelRequire")),
    ("esbuild", re.compile(rb"__esbuild|esbuild")),
]

_SOURCEMAP = re.compile(rb"//[#@]\s*sourceMappingURL=([^\s'\"]+)")

# Third-party libraries / CDNs / trackers. A source→sink flow *inside* these
# is the library's own implementation, not the target app's bug (mission §18
# ranks "generic library findings" P3). Matched on URL.
_THIRD_PARTY_HOSTS = (
    "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "unpkg.com", "code.jquery.com", "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "cdn.bizible.com", "cdn.cookielaw.org",
    "www.googletagmanager.com", "www.google-analytics.com", "connect.facebook.net",
    "static.hotjar.com", "js.hs-scripts.com", "snap.licdn.com", "cdn.segment.com",
    "widget.intercom.io", "browser.sentry-cdn.com", "polyfill.io",
)
_THIRD_PARTY_FILE = re.compile(
    r"(?:^|/)(?:jquery|jquery-\d|jquery\.[\w.]*min|angular|react|react-dom|vue|"
    r"lodash|underscore|moment|bootstrap|popper|d3|three|axios|polyfill|"
    r"modernizr|handlebars|ember|backbone|zepto|gtm|gtag|analytics|hotjar|"
    r"otSDKStub|otBannerSdk|bizible|recaptcha|require|core-js|runtime)"
    r"[\w.\-]*\.js",
    re.I,
)
_THIRD_PARTY_PATH = re.compile(r"/(?:node_modules|bower_components|vendors?|libs?)/", re.I)


def is_third_party(url: str) -> bool:
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.hostname in _THIRD_PARTY_HOSTS:
        return True
    if _THIRD_PARTY_PATH.search(parts.path):
        return True
    return bool(_THIRD_PARTY_FILE.search(parts.path))


def fingerprint(asset: JSAsset, data: bytes) -> None:
    """Mutate *asset* with framework/bundler/sourcemap/minified fields."""
    asset.third_party = is_third_party(asset.url)
    sample = data[:200_000]  # signatures are near the top/bottom; cap work

    for name, rx in _FRAMEWORK_SIGNS:
        if rx.search(sample) or rx.search(data[-50_000:]):
            asset.framework = name
            break
    for name, rx in _BUNDLER_SIGNS:
        if rx.search(sample) or rx.search(data[-50_000:]):
            asset.bundler = name
            break

    m = _SOURCEMAP.search(data[-4000:]) or _SOURCEMAP.search(data)
    if m:
        asset.source_map = True
        asset.source_map_url = m.group(1).decode("ascii", "replace")
    else:
        asset.source_map = False

    # minified heuristic: few newlines relative to size, long lines
    if data:
        nl = data.count(b"\n") or 1
        avg_line = len(data) / nl
        asset.minified = avg_line > 300
