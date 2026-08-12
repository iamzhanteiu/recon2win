# DOM XSS

**Sources** (attacker-influenceable): `location.hash|search|href|pathname`,
`document.URL|documentURI|baseURI|referrer|cookie`, `window.name`,
`history.state`, `URLSearchParams`, `postMessage` event data,
`localStorage/sessionStorage.getItem`.

**Sinks**: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write(ln)`,
`eval`, `Function`, `setTimeout/Interval(string)`, `location`, `window.open`,
`script.src`, jQuery `.html/.append/.before/.after`, `$(...)`.

**Analysis**: build `source → transform → sanitize → sink`. Attacker-control
is `yes` when a source reaches the sink value directly or through a tainted
local. Sanitization is `known-safe` (DOMPurify, textContent, createTextNode),
`weak` (encodeURIComponent for an HTML sink, `replace`, `escape`), or `none`.

**Verify**: drive the source (`#<img src=x onerror=alert(document.domain)>`),
confirm unescaped execution at the sink. Test sanitizer-specific bypasses
before discarding a `weak` case.
