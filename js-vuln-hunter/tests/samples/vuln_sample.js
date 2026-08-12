// Synthetic sample with known-planted issues for testing jsvh analyzers.

// 1. DOM XSS: location.hash -> innerHTML, no sanitization
var frag = decodeURIComponent(location.hash.substring(1));
document.getElementById("out").innerHTML = frag;

// 2. DOM XSS through a tainted local (taint propagation across vars)
var raw = location.search;
var msg = "Hello " + raw;
el.outerHTML = msg;

// 3. Sanitized (known-safe) -> should NOT be a candidate
var safe = DOMPurify.sanitize(location.hash);
container.innerHTML = safe;

// 4. eval of user input -> code injection
eval(location.hash.slice(1));

// 5. dynamic endpoint resolution + interesting path
fetch(baseURL + "/api/admin/users/" + userId, {
  headers: { Authorization: "Bearer " + token }
}).then(function (r) { return r.json(); });

// 6. prototype pollution via deep merge of parsed URL data
lodash.merge({}, JSON.parse(location.search.substring(1)));

// 7. postMessage receiver, no origin check, data -> innerHTML
window.addEventListener("message", function (event) {
  document.querySelector("#panel").innerHTML = event.data.html;
});

// 8. client-side authorization gate
if (user.isAdmin) {
  fetch("/api/admin/secrets");
}

// 9. secret literal
var cfg = { apiKey: "AKIAIOSFODNN7EXAMPLE1", token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKLmnoPQRstuVWxyz012345" };

// 10. open redirect
window.location.href = new URLSearchParams(location.search).get("next");

// 11. websocket
var ws = new WebSocket("wss://api.example.com/socket");
