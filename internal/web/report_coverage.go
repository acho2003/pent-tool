package web

import (
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"
)

// reportScopeLabel is the one-line heading for a scope in the scanner report.
func reportScopeLabel(sc reportScope) string {
	if sc.Kind == "source" {
		return "SOURCE CODE  " + firstNonBlank(sc.Origin, sc.Target, "none provided")
	}
	label := "HOST  " + sc.Target
	if len(sc.Tracks) > 0 {
		label += "  [" + strings.Join(sc.Tracks, ", ") + "]"
	}
	return label
}

// fitPDFText truncates s with "..." so it fits width w (mm) in the pdf's current
// font. Call it after SetFont. Labels are single-line cells, so an over-long
// hostname would otherwise overflow the page.
func fitPDFText(pdf *fpdf.Fpdf, s string, w float64) string {
	if pdf.GetStringWidth(s) <= w {
		return s
	}
	runes := []rune(s)
	for len(runes) > 0 && pdf.GetStringWidth(string(runes)+"...") > w {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "..."
}

// scopeCoverageLines lists what the classifier decided for a host (tracks, open
// ports) and the terminal status each tool recorded on the scope.
func scopeCoverageLines(sc reportScope) []string {
	var lines []string
	if sc.Kind != "source" {
		lines = append(lines, "Tracks: "+strings.Join(sc.Tracks, ", "))
		ports := "none recorded"
		if len(sc.OpenPorts) > 0 {
			ports = strings.Join(sc.OpenPorts, ", ")
		}
		lines = append(lines, "Open ports: "+ports)
	}
	for _, r := range sc.Runs {
		line := fmt.Sprintf("%-10s %s", r.Scanner, r.Status)
		if r.Reason != "" && r.Status != "completed" {
			line += " - " + r.Reason
		}
		lines = append(lines, line)
	}
	return lines
}

func reconSummaryLine(sum reportReconSummary) string {
	services := "none recorded"
	if len(sum.Services) > 0 {
		services = strings.Join(sum.Services, ", ")
	}
	return fmt.Sprintf("Recon discovered %d host(s) with %d open port(s). Detected services: %s.", sum.Hosts, sum.OpenPorts, services)
}

// drawScanCoverage renders the scanner report's "Scan Coverage" section: the
// recon rollup, then one block per scope with its tracks, ports, and every
// tool's terminal status, so the report accounts for every scope x tool.
func drawScanCoverage(pdf *fpdf.Fpdf, pal reportPalette, recon reportReconSummary, scopes []reportScope) {
	fill := func(x, y, w, h float64, c [3]int) {
		pdf.SetFillColor(c[0], c[1], c[2])
		pdf.Rect(x, y, w, h, "F")
	}
	text := func(c [3]int) { pdf.SetTextColor(c[0], c[1], c[2]) }
	newPage := func() {
		pdf.AddPage()
		fill(0, 0, 210, 297, pal.bg)
		fill(0, 0, 210, 1.5, pal.accent)
		pdf.SetY(15)
	}

	newPage()
	pdf.SetFont("Helvetica", "B", 22)
	text(pal.accent)
	pdf.CellFormat(190, 12, "Scan Coverage", "", 1, "L", false, 0, "")
	fill(10, pdf.GetY()+2, 45, 0.8, pal.accent)
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 9)
	text(pal.fg)
	pdf.SetX(10)
	pdf.MultiCell(190, 4.5, reconSummaryLine(recon)+" Every tool records exactly one terminal status per scope; tools that do not apply to a scope are recorded not_applicable or skipped.", "", "L", false)
	pdf.Ln(4)

	for _, sc := range scopes {
		if pdf.GetY() > 240 {
			newPage()
		}
		y := pdf.GetY()
		fill(10, y, 190, 8, pal.card)
		pdf.SetXY(14, y+1)
		pdf.SetFont("Helvetica", "B", 9)
		text(pal.accent)
		pdf.CellFormat(182, 6, fitPDFText(pdf, reportScopeLabel(sc), 182), "", 1, "L", false, 0, "")
		pdf.Ln(1)
		pdf.SetFont("Courier", "", 7)
		for _, line := range scopeCoverageLines(sc) {
			if pdf.GetY() > 270 {
				newPage()
			}
			text(pal.fg)
			pdf.SetX(14)
			pdf.MultiCell(182, 4, line, "", "L", false)
		}
		pdf.Ln(4)
	}
}

// assessmentCoverageLines uses the same recorded coverage snapshot as the API
// and JSON report. A completed scanner job is not evidence that every API
// operation or requested assessment type was tested.
func assessmentCoverageLines(coverage assessmentCoverageResponse) []string {
	lines := []string{
		"Assessment state: " + coverage.State,
		"Mode: " + string(coverage.Mode),
		"Profile: " + coverage.Profile,
		"Plan fingerprint: " + coverage.PlanFingerprint,
		fmt.Sprintf("API operations: discovered %d, eligible %d, attempted %d, completed %d, batch completed %d, failed %d, skipped %d, not attempted %d.", coverage.OperationCounts.Discovered, coverage.OperationCounts.Eligible, coverage.OperationCounts.Attempted, coverage.OperationCounts.Completed, coverage.OperationCounts.BatchCompleted, coverage.OperationCounts.Failed, coverage.OperationCounts.Skipped, coverage.OperationCounts.NotAttempted),
	}
	if proof := coverage.Proof; proof != nil {
		lines = append(lines, fmt.Sprintf("Inventory: %d requests, %d seeds, %d hosts, %d services, %d TLS services, %d forms, %d parameterized requests.", proof.Discovered, proof.Seeds, proof.Hosts, proof.Services, proof.TLS, proof.Forms, proof.Parameterized))
		lines = append(lines, fmt.Sprintf("Requests: observed %d, approved %d, eligible %d.", proof.Observed, proof.Approved, proof.Eligible))
		for _, row := range proof.Scanners {
			templates := "NOT TRACKED"
			if row.EnabledTemplates != nil {
				templates = fmt.Sprint(*row.EnabledTemplates)
			}
			lines = append(lines, fmt.Sprintf("%s enabled templates: %s; executed checks: NOT TRACKED.", row.Scanner, templates))
			completed := "NOT TRACKED"
			if row.Completed != nil {
				completed = fmt.Sprint(*row.Completed)
			}
			lines = append(lines, fmt.Sprintf("%s individually completed requests: %s.", row.Scanner, completed))
			exercised := "NOT TRACKED"
			if row.Exercised != nil {
				exercised = fmt.Sprint(*row.Exercised)
			}
			lines = append(lines, fmt.Sprintf("%s: selected %d, submitted %d, acknowledged %d, observed active requests %s, batch completed %d, failed %d, skipped %d, unknown %d.", row.Scanner, row.Selected, row.Submitted, row.Acknowledged, exercised, row.BatchCompleted, row.Failed, row.Skipped, row.Unknown))
		}
		for _, result := range proof.AuthorizationResults {
			lines = append(lines, fmt.Sprintf("Authorization %s (%s), %s %s: expected %s, observed %s, %s; HTTP %d. %s", result.Identity, result.Role, result.Method, result.URL, result.Expected, result.Observed, result.Status, result.ResponseCode, result.Reason))
			lines = append(lines, fmt.Sprintf("Context: %s; request: %s; operation: %s; resource fixture: %s; evidence: %s", result.AuthContextID, result.EndpointID, result.OperationID, result.FixtureRef, result.EvidenceRef))
		}
		for _, metric := range proof.NotTracked {
			lines = append(lines, metric+": NOT TRACKED")
		}
		for _, gap := range proof.DiscoveryGaps {
			lines = append(lines, "Discovery gap: "+gap)
		}
	}
	for _, typ := range coverage.TypeCoverage {
		lines = append(lines, fmt.Sprintf("Type %s: %s - %s", typ.Type, typ.State, typ.Reason))
	}
	for _, job := range coverage.Jobs {
		line := fmt.Sprintf("Job %s (%s): %s", job.Scanner, job.TargetID, job.Status)
		if job.Reason != "" {
			line += " - " + job.Reason
		}
		lines = append(lines, line)
	}
	for _, operation := range coverage.Operations {
		line := fmt.Sprintf("API %s %s: %s", operation.Method, operation.Path, operation.Status)
		if operation.Reason != "" {
			line += " - " + operation.Reason
		}
		lines = append(lines, line)
	}
	for _, gap := range coverage.Gaps {
		lines = append(lines, fmt.Sprintf("Gap %s: %s - %s", gap.Scanner, gap.State, gap.Reason))
	}
	return lines
}

func drawAssessmentCoverage(pdf *fpdf.Fpdf, pal reportPalette, coverage assessmentCoverageResponse) {
	newPage := func() {
		pdf.AddPage()
		pdf.SetFillColor(pal.bg[0], pal.bg[1], pal.bg[2])
		pdf.Rect(0, 0, 210, 297, "F")
		pdf.SetFillColor(pal.accent[0], pal.accent[1], pal.accent[2])
		pdf.Rect(0, 0, 210, 1.5, "F")
		pdf.SetY(15)
	}
	newPage()
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(pal.accent[0], pal.accent[1], pal.accent[2])
	pdf.CellFormat(190, 12, "Assessment Coverage", "", 1, "L", false, 0, "")
	pdf.Ln(5)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(pal.fg[0], pal.fg[1], pal.fg[2])
	for _, line := range assessmentCoverageLines(coverage) {
		if pdf.GetY() > 265 {
			newPage()
			pdf.SetFont("Helvetica", "", 8)
			pdf.SetTextColor(pal.fg[0], pal.fg[1], pal.fg[2])
		}
		pdf.SetX(10)
		pdf.MultiCell(190, 4.5, line, "", "L", false)
	}
}
