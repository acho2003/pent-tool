# Xalgorix — Deterministic Security Scanner Pipeline

Xalgorix runs Nuclei, OWASP ZAP, OpenVAS/Greenbone, Trivy, and Vuls in a fixed sequence. It streams and preserves native scanner output and produces a downloadable report even when AI is offline.

AI is optional and report-only. It cannot select scanners, construct commands, change scan depth, control execution, or add findings without a scanner source record.

The container includes scanner clients. ZAP and Greenbone are internal authenticated services with persistent feeds and databases. Configure Report AI under Settings → Report AI only if you want enriched explanations; deterministic fallback reports require no model or API key.

Use only on assets you own or are authorized to test.
