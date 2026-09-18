# Architecture

Xalgorix uses one deterministic scanner engine from the web server, scheduler, and CLI.

```text
request
  -> scope validation
  -> optional deterministic wildcard discovery
  -> Nuclei
  -> ZAP
  -> OpenVAS/Greenbone
  -> Trivy (when artifact supplied)
  -> Vuls (when SSH alias supplied)
  -> native artifact parsers
  -> Report AI or deterministic fallback
  -> report.json and PDF
```

The scanner package has no dependency on the agent or LLM packages. Commands are executed with argument arrays and cancellation contexts. Scanner failures are terminal records and do not prevent later attempts. Resume reuses terminal records and immutable artifacts.

A request may name a subset of scanners. The pipeline still walks every scanner in the fixed order and writes a terminal record for each one, so the selection changes what is attempted, never the shape of the scan: a deselected scanner is recorded as `skipped`. An empty selection means the whole pipeline, so a saved or scheduled scan is not pinned to today's pipeline membership.

ZAP is accessed through its authenticated internal API. Greenbone is controlled through authenticated GMP. Native installations may point at external services and configurable binaries.

Live scan events contain scanner lifecycle and raw stdout/stderr chunks. Raw data is persisted in append-only files; scan JSON contains metadata only.

Report AI is called only after every scanner attempt is terminal. It receives parsed scanner records, and every returned finding must retain a source scanner and exact source record ID. Invalid or unavailable AI output triggers a deterministic fallback report.

Legacy schema-v1 records and reports remain readable, but new requests use schema version 2.
