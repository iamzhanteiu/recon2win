# postMessage

**Receiver risk**: `addEventListener('message', h)` where `h` uses
`event.data` but never validates `event.origin`, and routes `event.data`
into a DOM/eval/auth sink. Origin check detected structurally (any compare
against `*.origin`).

**Sender risk**: `target.postMessage(data, '*')` — wildcard origin leaks
data to any framing page.

**Verify**: host an attacker page that opens/iframes the target, post a
payload matching the handler's shape, confirm it reaches the sink / that
sensitive data is captured cross-origin.
