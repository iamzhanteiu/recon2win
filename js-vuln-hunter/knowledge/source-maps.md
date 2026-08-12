# Source Maps

`//# sourceMappingURL=…` exposes original source (pre-minification),
sometimes including comments, internal paths, and unshipped code. Detected
during fingerprinting (`source_map`, `source_map_url`).

**Verify**: fetch the `.map`, reconstruct sources, review for secrets,
internal endpoints, and logic not meant to ship. Treat an exposed map of a
private app as P2 sensitive exposure.
