package audit

import (
	"fmt"
	"sort"
	"strings"
)

// highImpactWeight is the risk weight at or above which an unmet requirement is
// named individually in the verdict rather than absorbed into a percentage.
const highImpactWeight = 3.5

// ComputeCoverage produces the risk-adjusted verdict.
//
// The central idea, straight from the spec: 8 of 10 requirements met is not
// "80%, minor gap" when the missing two are rate limiting and session
// invalidation. Raw coverage counts requirements; risk-adjusted coverage counts
// risk weight, so a gap in a 5.0-weight security requirement costs five times
// what a 1.0-weight cosmetic one does.
//
// Both numbers are reported. The raw number is the honest headline; the
// risk-adjusted number is the one that should drive a decision, and it always
// arrives with the specific missing items named so the reader can check the
// reasoning rather than trust the score.
func ComputeCoverage(states []RequirementState) Coverage {
	c := Coverage{Total: len(states)}
	if len(states) == 0 {
		c.Verdict = RiskLevelInfo
		c.Completeness = CompletenessUnknown
		c.Authoritative = false
		c.Reasoning = "No requirements were extracted, so no coverage can be computed."
		return c
	}

	var totalWeight, earnedWeight float64
	var missingHigh []string
	worst := CompletenessComplete

	for _, s := range states {
		w := s.Requirement.RiskWeight
		if w <= 0 {
			w = 2.0
		}
		totalWeight += w
		worst = WorstCompleteness(worst, s.Completeness)

		switch s.State {
		case StateCompleted:
			c.Completed++
			// Unverified-but-complete evidence earns full credit; anything less
			// than a complete record earns partial credit, because we are not
			// entitled to full confidence in it.
			if s.Completeness.Authoritative() {
				earnedWeight += w
			} else {
				earnedWeight += w * 0.5
			}
		case StatePartial:
			c.Partial++
			earnedWeight += w * 0.5
		default:
			c.Unverified++
			if w >= highImpactWeight {
				missingHigh = append(missingHigh, s.Requirement.Summary)
			}
		}
	}

	c.RawPercent = round1(float64(c.Completed) / float64(c.Total) * 100)
	if totalWeight > 0 {
		c.RiskAdjustedPercent = round1(earnedWeight / totalWeight * 100)
	}
	sort.Strings(missingHigh)
	c.MissingHighImpact = missingHigh
	c.Completeness = worst
	c.Authoritative = worst.Authoritative()

	c.Verdict = verdictFor(c.RiskAdjustedPercent, len(missingHigh))
	c.Reasoning = coverageReasoning(c, totalWeight, earnedWeight)
	return c
}

func verdictFor(riskAdjusted float64, missingHighCount int) RiskLevel {
	switch {
	case missingHighCount >= 2 || riskAdjusted < 40:
		return RiskLevelCritical
	case missingHighCount == 1 || riskAdjusted < 65:
		return RiskLevelHigh
	case riskAdjusted < 85:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

// coverageReasoning spells out how the verdict was reached. The score is never
// asserted as a bare number — a reader must be able to disagree with it on the
// merits, which requires seeing the arithmetic.
func coverageReasoning(c Coverage, totalWeight, earnedWeight float64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d of %d requirements have confirming evidence (%.1f%% raw). ",
		c.Completed, c.Total, c.RawPercent)
	fmt.Fprintf(&b, "Weighting each requirement by its risk weight gives %.1f of %.1f points (%.1f%% risk-adjusted); ",
		earnedWeight, totalWeight, c.RiskAdjustedPercent)
	b.WriteString("partial evidence earns half credit, and confirmed evidence drawn from an incomplete record also earns half credit rather than full. ")

	switch {
	case len(c.MissingHighImpact) > 0:
		fmt.Fprintf(&b, "The verdict is %s because %d high-impact requirement(s) have no confirming evidence: %s. ",
			strings.ToUpper(string(c.Verdict)), len(c.MissingHighImpact), strings.Join(c.MissingHighImpact, "; "))
	default:
		fmt.Fprintf(&b, "The verdict is %s; no requirement with weight ≥ %.1f is unevidenced. ",
			strings.ToUpper(string(c.Verdict)), highImpactWeight)
	}

	if !c.Authoritative {
		fmt.Fprintf(&b, "This verdict is NOT authoritative: the underlying record was %s, "+
			"so unevidenced requirements may simply be unverifiable rather than unimplemented.", c.Completeness)
	} else {
		b.WriteString("The full checkpoint record was available, so this verdict is authoritative.")
	}
	return b.String()
}

// GapFindings turns unevidenced requirements into first-class findings.
//
// The wording here is the crux of the whole feature. An unevidenced requirement
// produces "could not be verified", never "was not implemented". The first is a
// statement about our search; the second is a claim about the code that we have
// not earned. Emitting the second is exactly the bug
// TestRedactedCheckpointNeverBecomesAuthoritativeClaim guards against.
func GapFindings(states []RequirementState) []Finding {
	var out []Finding
	for _, s := range states {
		if s.State == StateCompleted || s.State == StatePartial {
			continue
		}
		level := RiskLevelMedium
		if s.Requirement.RiskWeight >= highImpactWeight {
			level = RiskLevelHigh
		}
		if s.Requirement.RiskCategory == RiskSecurity && s.Requirement.RiskWeight >= highImpactWeight {
			level = RiskLevelCritical
		}

		summary := fmt.Sprintf("%s could not be verified", s.Requirement.Summary)
		inference := "No structural evidence was found for this requirement. " +
			"This is a gap in verification, not a confirmed absence in the code."
		if s.State == StateUnknown {
			inference = "The evidence search for this requirement could not be completed, " +
				"so nothing at all is known about its state. No risk conclusion was generated."
		}

		out = append(out, Finding{
			ID:                    fmt.Sprintf("gap_%s", s.Requirement.ID),
			Kind:                  FindingRequirementGap,
			Requirement:           s.Requirement.ID,
			OriginalRequirement:   s.Requirement.Summary,
			AgentDecision:         "Not established from the available checkpoint record.",
			FailedAttempt:         "Not established from the available checkpoint record.",
			Pivot:                 "Not established from the available checkpoint record.",
			CurrentImplementation: "Not established — no structural evidence located.",
			RiskInference:         inference,
			RiskCategory:          s.Requirement.RiskCategory,
			RiskLevel:             level,
			Summary:               summary,
			Recommendation: fmt.Sprintf("Manually confirm whether %q is implemented, then re-run with search hints that match the actual symbol names.",
				s.Requirement.Summary),
			Completeness: s.Completeness,
			// A gap is never authoritative: we are reporting what we could not
			// find, and that is not a fact about the codebase.
			Authoritative: false,
		})
	}
	return out
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
