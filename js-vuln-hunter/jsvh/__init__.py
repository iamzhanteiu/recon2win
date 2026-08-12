"""jsvh — JavaScript Vulnerability Hunting workspace on top of recon2win.

This package is the *analysis layer*. It never performs reconnaissance
(no subdomain enumeration, DNS, port scanning, crawling). It consumes the
reconnaissance datasets produced by recon2win under ``outputs/<domain>/``
and turns the discovered JavaScript into ranked, verifiable vulnerability
candidates.

See ``docs/architecture.md`` and ``docs/recon2win-integration.md``.
"""

__version__ = "0.1.0"
