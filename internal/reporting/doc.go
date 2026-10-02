// Package reporting owns the branded-PDF generation pipeline used by the
// self-hosted Xalgorix binary. It encapsulates the layout primitives
// (palette, fonts, page chrome), the scan-summary helpers (severity rollups,
// risk scoring, recon extraction), the security-framework mappings
// (CWE / OWASP / PTES), and the methodology phase catalog.
//
// The package is intentionally free of any dependency on the in-process web
// server or its session/storage state. Callers convert their own scan record
// into the package's transport types (Scan, Vuln, Event) and invoke
// Generate. This keeps the package consumable from any execution context —
// the web server at internal/web or future CLI report exporters.
//
// Behavior is byte-identical to the previous in-package implementation in
// internal/web/report.go. This package is a pure structural move; no
// behavioral drift is introduced here.
package reporting
