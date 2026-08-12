// Corpus for the attack-chain + new-detector tests. Contains observations
// that, correlated, form a BOLA/BFLA authorization chain and a token chain.

// client-side authorization gate (only visible control)
if (user.isAdmin) {
  showAdminPanel();
}

// object-scoped, client-controlled id → BOLA lever
fetch(baseURL + "/api/accounts/" + accountId + "/balance", {
  headers: { Authorization: "Bearer " + token },
});

// privileged, mutating function on a sensitive namespace, no object id → BFLA
axios.post("/api/admin/broadcast", message);

// token written to localStorage (readable by any XSS) → account-compromise leg
localStorage.setItem("access_token", token);

// weak origin validation on a message handler → cross-origin leg
window.addEventListener("message", function (e) {
  if (e.origin.indexOf("example.com") !== -1) {
    document.querySelector("#out").innerHTML = e.data.html;
  }
});

// OAuth flow missing state (CSRF) + implicit token
var authUrl =
  "https://idp.example.com/authorize?response_type=token&client_id=abc&redirect_uri=" +
  redirectUri;
