# Testing checklist

- [ ] Scanner applicability produces one of completed, failed, cancelled, not_applicable, or skipped.
- [ ] Execution order is Nuclei, ZAP, OpenVAS, Trivy, Vuls.
- [ ] A scanner subset runs only the selected scanners; the rest are recorded as `skipped` with a reason.
- [ ] A scanner failure does not prevent later attempts.
- [ ] Cancellation stops the active scanner and prevents later attempts.
- [ ] Resume starts at the first incomplete attempt and preserves completed checksums.
- [ ] Commands use argument arrays without shell interpolation.
- [ ] Scope, rate, headers, authentication, timeouts, redaction, and output limits are deterministic.
- [ ] Native parser fixtures cover all five formats, malformed data, empty data, duplicates, and partial files.
- [ ] Raw output is streamed and persisted outside scan.json.
- [ ] No LLM request occurs before all scanner attempts are terminal.
- [ ] Report source IDs and checksums are validated.
- [ ] Provider failure creates a deterministic fallback PDF.
- [ ] Report regeneration reuses immutable artifacts.
- [ ] Legacy records and existing reports remain readable.
- [ ] CLI, schedules, API, UI, race tests, and container health checks pass.
