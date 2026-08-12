// True-negative corpus: patterns that LOOK dangerous but are safe / correct.
// The engine must NOT emit high-priority candidates for these.

// 1. innerHTML with a constant — no attacker source.
document.getElementById("x").innerHTML = "<b>static</b>";

// 2. DOMPurify (known-safe) before the sink — correct defensive pattern.
container.innerHTML = DOMPurify.sanitize(location.hash);

// 3. setTimeout with a function callback (not a string) — safe.
setTimeout(function () { render(location.href); }, 200);

// 4. Backbone/Marionette class factory .extend({...}) — inheritance, NOT
//    prototype pollution, even though a source appears inside the definition.
var View = e.Marionette.ItemView.extend({
  initialize: function () { this.url = location.href; },
  render: function () { return this; },
  events: { "click": "onClick" },
});

// 5. postMessage receiver WITH a strict origin check — the correct pattern.
window.addEventListener("message", function (event) {
  if (event.origin === "https://trusted.example.com") {
    handle(event.data);
  }
});

// 6. A public/publishable identifier — NOT a secret (§12).
var oauth = { client_id: "123456789012-abcdefghijklmnopqrstuvwx.apps.googleusercontent.com" };
var stripe = "pk_live_51H8xYzAbCdEfGhIjKlMnOpQr";

// 7. location.hostname — the victim's current host, not attacker-controlled.
el.innerHTML = "Host: " + window.location.hostname;
