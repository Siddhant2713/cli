package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// The three context banners. These strings are load-bearing and are reproduced
// verbatim from FEATURE-SPEC.md — the whole privacy/honesty story depends on a
// reader seeing, at a glance, whether a finding is backed by a complete record.
const (
	bannerComplete = `✓ COMPLETE CONTEXT
Entire analyzed the complete checkpoint history.`

	bannerPartial = `⚠ PARTIAL CONTEXT
Some checkpoint information was unavailable or redacted.
This finding may be incomplete and should not be treated as authoritative.`

	bannerInsufficient = `⚠ INSUFFICIENT CONTEXT
Entire cannot verify the implementation history required for this finding.
No authoritative risk conclusion was generated.`
)

// Banner returns the banner for a completeness level.
//
// Note that redacted and missing both map to INSUFFICIENT, not PARTIAL: when the
// record backing a finding is gone entirely, saying "this may be incomplete"
// understates the problem.
func Banner(c Completeness) string {
	switch c {
	case CompletenessComplete:
		return bannerComplete
	case CompletenessPartial:
		return bannerPartial
	default:
		return bannerInsufficient
	}
}

// RenderText writes the human-readable audit report.
func RenderText(w io.Writer, r Report) error {
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }

	p("Feature audit — %s\n", r.FeatureID)
	p("Repository %s at commit %s\n", r.RepositoryHash, shortSHA(r.CommitSHA))
	p("Generated %s\n\n", r.GeneratedAt.Format("2006-01-02 15:04:05 MST"))

	p("%s\n\n", Banner(r.Coverage.Completeness))

	p("Requirement coverage: %.1f%%\n", r.Coverage.RawPercent)
	p("Risk-adjusted coverage: %.1f%%\n", r.Coverage.RiskAdjustedPercent)
	p("Risk-adjusted assessment: %s\n", strings.ToUpper(string(r.Coverage.Verdict)))
	if len(r.Coverage.MissingHighImpact) > 0 {
		p("Missing high-impact controls: %s\n", strings.Join(r.Coverage.MissingHighImpact, ", "))
	} else {
		p("Missing high-impact controls: none identified\n")
	}
	p("Authoritative: %t\n", r.Coverage.Authoritative)
	p("\nReasoning: %s\n", wrap(r.Coverage.Reasoning, 92))

	p("\n%s\n", strings.Repeat("─", 92))
	p("Checkpoints analyzed: %d\n", len(r.Checkpoints))
	for _, cp := range r.Checkpoints {
		p("  %s  %-10s  %s\n", shortID(cp.ID), cp.Completeness, cp.Date)
	}

	p("\n%s\nREQUIREMENT STATES\n%s\n", strings.Repeat("─", 92), strings.Repeat("─", 92))
	for _, s := range r.Requirements {
		p("\n[%s] %s\n", strings.ToUpper(string(s.State)), s.Requirement.Summary)
		p("  id=%s  risk=%s  weight=%.1f\n", s.Requirement.ID, s.Requirement.RiskCategory, s.Requirement.RiskWeight)
		p("  Context completeness: %s   Authoritative: %t\n", s.Completeness, s.Authoritative)
		if s.Notes != "" {
			p("  %s\n", wrap(s.Notes, 88))
		}
		if len(s.Evidence) == 0 {
			p("  Evidence: none found\n")
			continue
		}
		p("  Evidence:\n")
		for _, e := range s.Evidence {
			p("    - [%s] %s (%s)\n", e.Kind, e.Citation, e.Completeness)
			p("      %s\n", e.Detail)
			p("      verify: %s\n", e.Command)
		}
	}

	p("\n%s\nFINDINGS (%d)\n%s\n", strings.Repeat("─", 92), len(r.Findings), strings.Repeat("─", 92))
	if len(r.Findings) == 0 {
		p("\nNo pivots, decision contradictions or requirement gaps were detected.\n")
		p("Note: the detectors match narrated decisions in the checkpoint record.\n")
		p("A pivot that was never written down is not visible to them, so this is not\n")
		p("a guarantee that none occurred.\n")
	}
	for _, f := range r.Findings {
		p("\n%s\n", strings.Repeat("·", 92))
		p("%s [%s / %s]\n", f.Summary, f.Kind, strings.ToUpper(string(f.RiskLevel)))
		p("%s\n", Banner(f.Completeness))
		p("\n  Original requirement:    %s\n", orNotEstablished(f.OriginalRequirement))
		p("  Agent decision:          %s\n", wrapIndent(orNotEstablished(f.AgentDecision), 27))
		p("  Failed attempt:          %s\n", wrapIndent(orNotEstablished(f.FailedAttempt), 27))
		p("  Pivot:                   %s\n", wrapIndent(orNotEstablished(f.Pivot), 27))
		p("  Current implementation:  %s\n", wrapIndent(orNotEstablished(f.CurrentImplementation), 27))
		p("  Risk inference:          %s\n", wrapIndent(orNotEstablished(f.RiskInference), 27))
		p("  Risk category:           %s\n", f.RiskCategory)
		p("  Context completeness:    %s\n", f.Completeness)
		p("  Authoritative:           %t\n", f.Authoritative)
		if len(f.Checkpoints) > 0 {
			p("  Checkpoints:             %s\n", strings.Join(shortIDs(f.Checkpoints), ", "))
		}
		if len(f.EvidenceIDs) > 0 {
			p("  Evidence:                %s\n", strings.Join(f.EvidenceIDs, ", "))
		}
		if f.Recommendation != "" {
			p("  Recommendation:          %s\n", wrapIndent(f.Recommendation, 27))
		}
	}

	if len(r.Limitations) > 0 {
		p("\n%s\nLIMITATIONS OF THIS AUDIT\n%s\n", strings.Repeat("─", 92), strings.Repeat("─", 92))
		for _, l := range r.Limitations {
			p("  - %s\n", wrapIndent(l, 4))
		}
	}
	p("\n")
	return nil
}

// RenderJSON writes the machine-readable report.
func RenderJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func shortSHA(s string) string {
	if len(s) > 9 {
		return s[:9]
	}
	if s == "" {
		return "(unknown)"
	}
	return s
}

func shortIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, shortID(id))
	}
	return out
}

// wrap soft-wraps text to width, for terminal readability.
func wrap(s string, width int) string { return wrapWithIndent(s, width, 0) }

// wrapIndent wraps continuation lines to align under a label of the given width.
func wrapIndent(s string, indent int) string { return wrapWithIndent(s, 92-indent, indent) }

func wrapWithIndent(s string, width, indent int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	pad := strings.Repeat(" ", indent)
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if lineLen > 0 && lineLen+1+len(w) > width {
			b.WriteString("\n" + pad)
			lineLen = 0
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}
