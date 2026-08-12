# Prototype Pollution

**Sinks**: recursive/deep merges — `merge`, `mergeWith`, `defaultsDeep`,
`$.extend(true,…)`, `_.set/setWith`, `Object.assign` on attacker JSON,
`deepmerge`. Also literal computed writes of `__proto__` / `constructor` /
`prototype`.

**Reachability decides everything**: only a candidate when attacker data
(URL param, JSON body, query string) reaches the merge. A merge of two
literals is not a finding.

**Verify**: send `?__proto__[jsvhTest]=polluted` and
`constructor[prototype][jsvhTest]=polluted`; in console check
`({}).jsvhTest === 'polluted'`. Then find a gadget (a property the app reads)
to escalate to XSS / auth bypass and document it.
