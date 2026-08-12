# WebSocket

Flag `new WebSocket(url)` — record endpoint and `wss` vs `ws`. Check whether
`onmessage` data flows into a DOM/eval sink (client trusting server push),
and whether authorization is enforced per-message or only at connect.

**Verify**: connect, learn the message protocol, replay privileged commands
as a low-priv user; test message-level authz.
