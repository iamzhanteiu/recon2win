# Client-side Authorization

Identifiers: `isAdmin`, `isOwner`, `canEdit/Delete/View`, `hasRole`,
`hasPermission`, `roles`, `permissions`, `featureFlags`, `accessLevel`.

**These are candidates, never confirmed privilege escalation.** A UI gate
enforced only in JS is usually re-enforced server-side (safe). The entire
value is telling that apart from a gate that is the only control.

**Verify**: identify the endpoint the check guards; as a low-priv /
unauthenticated user, replay that request directly (curl/Burp) bypassing the
JS gate. Privileged data/action back = real bypass; 401/403 = cosmetic →
FALSE_POSITIVE.
