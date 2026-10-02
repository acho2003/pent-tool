# Xalgorix — Deterministic Security Scanner Pipeline

Xalgorix runs Nuclei, OWASP ZAP, OpenVAS/Greenbone, Trivy, and Vuls in a fixed sequence. It streams and preserves native scanner output and produces a downloadable report assembled deterministically from that output.

Report assembly is deterministic and driven only by scanner source records. Every finding retains its source scanner and exact source record ID.

The Debian slim container includes integrated scanner clients and runtime dependencies, without the general Kali toolbox or build toolchains. ZAP and Greenbone are internal authenticated services with persistent feeds and databases.

Use only on assets you own or are authorized to test.
