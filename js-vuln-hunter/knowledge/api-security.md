# API Discovery & Security

Extract REST / GraphQL / WebSocket endpoints from JS, resolving dynamically
constructed URLs (`fetch(base + "/users/" + id)` → structured
`{method, url_template, parameters, auth_hint}`). Flag admin/internal/debug/
auth/token/upload paths as interesting.

**Verify**: resolve dynamic segments, probe with the correct method, test
authn/authz (no token, another user's token, IDOR on ids), look for verbose
errors / debug data / missing access control.
