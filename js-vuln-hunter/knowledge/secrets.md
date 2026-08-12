# Secrets in JS

recon2win/jsluice already extracts secrets (`findings/jsluice_secrets.json`,
ingested, owned upstream). This workspace only adds high-signal literal
patterns (AWS/Google/Slack/GitHub/Stripe keys, JWTs, private keys, firebase
URLs, generic `key/secret/token = "…"`).

**Verify**: recover the full secret (reports redact it), confirm it is live
and scoped to something sensitive with a single benign read, document scope.
Never use beyond proving validity. Generic matches are low-confidence (P3).
