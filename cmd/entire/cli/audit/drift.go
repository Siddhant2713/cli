package audit

import (
	"fmt"
	"regexp"
	"strings"
)

// Pivot and decision-drift detection.
//
// Both detectors are deterministic pattern matchers over checkpoint narrative,
// not LLM judgement calls. That is a deliberate constraint: a model asked "did
// the agent contradict itself?" will confabulate a plausible answer for any
// input, and a confabulated contradiction is worse than no finding at all.
// A regex over the record either matches real text or it does not, and every
// finding it produces quotes the checkpoint it came from.
//
// The cost of that choice is recall: these detectors find stated pivots and
// stated contradictions. A pivot nobody wrote down is invisible to them. The
// report says so rather than implying the history was clean.

var (
	// attemptPatterns mark an approach being tried.
	attemptPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(tried|attempted|first tried|started with|initial approach|planned to use)\b`),
		regexp.MustCompile(`(?i)\bimplemented\s+(?:it\s+)?(?:using|with)\b`),
	}
	// failurePatterns mark that approach not working.
	failurePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(failed|didn't work|did not work|doesn't work|broke|blocked by|unavailable|not available|couldn't|could not|gave up|too slow|timed out|rejected)\b`),
	}
	// pivotPatterns mark the replacement.
	pivotPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(instead|fell back|fallback|switched to|replaced (?:it )?with|pivoted to|ended up using|settled on|opted for|went with)\b`),
	}
	// decisionPatterns mark an explicit commitment that later work can contradict.
	decisionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(must|should always|we will|decided to|requirement is|non-negotiable|always|never)\b`),
	}
)

func matchesAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// firstSentenceMatching returns the sentence containing a pattern hit, so a
// finding can quote the record instead of paraphrasing it into agreement.
func firstSentenceMatching(res []*regexp.Regexp, text string) string {
	for _, sent := range splitSentences(text) {
		if matchesAny(res, sent) {
			return strings.TrimSpace(sent)
		}
	}
	return ""
}

func splitSentences(text string) []string {
	replacer := strings.NewReplacer("\n", " ", "! ", ". ", "? ", ". ")
	flat := replacer.Replace(text)
	raw := strings.Split(flat, ". ")
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// riskyPivotTerms map a pivot's replacement technology onto the guarantee it
// silently changes. This is the canonical case from the spec: swapping Redis for
// an in-memory store is not a neutral refactor, it drops a distributed-system
// property, and nothing in a diff will say so.
var riskyPivotTerms = []struct {
	pattern   *regexp.Regexp
	category  RiskCategory
	level     RiskLevel
	guarantee string
}{
	{regexp.MustCompile(`(?i)\bin-?memory\b`), RiskScalability, RiskLevelHigh,
		"state held in process memory does not survive a restart and is not shared across instances, so any guarantee that depended on it holding cluster-wide no longer holds"},
	{regexp.MustCompile(`(?i)\b(sqlite|local file|json file|flat file)\b`), RiskScalability, RiskLevelMedium,
		"single-writer local storage changes the concurrency and durability profile of the original design"},
	{regexp.MustCompile(`(?i)\b(skip(?:ped)?|disabled?|turned off|bypass(?:ed)?|stub(?:bed)?|mock(?:ed)?|hard-?cod(?:ed|ing))\b`), RiskCorrectness, RiskLevelHigh,
		"a control was disabled or stubbed rather than implemented, so the behaviour it was meant to guarantee is absent"},
	{regexp.MustCompile(`(?i)\b(no (?:auth|validation|encryption)|without (?:auth|validation|encryption)|plain-?text)\b`), RiskSecurity, RiskLevelCritical,
		"a security control named in the original requirement is not present in the implemented path"},
	{regexp.MustCompile(`(?i)\b(synchronous|blocking|sequential)\b`), RiskPerformance, RiskLevelMedium,
		"the implemented path is synchronous where the plan assumed concurrency, changing latency behaviour under load"},
}

// DetectPivots finds planned→attempted→failed→replaced chains across the
// checkpoint sequence and flags the ones that materially change a guarantee.
//
// The chain is matched both within a single checkpoint (an agent that narrates
// its own course correction in one message) and across consecutive checkpoints
// (attempt in one, failure and replacement in a later one).
func DetectPivots(cps []Checkpoint) []Finding {
	var findings []Finding
	for i, cp := range cps {
		if cp.Redacted() {
			// A redacted checkpoint cannot be pattern-matched. Say so as its own
			// finding rather than skipping silently, so the gap is visible.
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("pivot_redacted_%s", shortID(cp.ID)),
				Kind:           FindingPivot,
				Summary:        fmt.Sprintf("Checkpoint %s is redacted; pivot detection could not run against it", shortID(cp.ID)),
				RiskCategory:   RiskFunctional,
				RiskLevel:      RiskLevelInfo,
				Checkpoints:    []string{cp.ID},
				Completeness:   CompletenessRedacted,
				Authoritative:  false,
				RiskInference:  "Not established — the record needed to evaluate this checkpoint was withheld.",
				Recommendation: "Re-run the audit with access to the unredacted checkpoint to evaluate this window.",
			})
			continue
		}

		// Widen the window to the next checkpoint so a chain that spans two
		// checkpoints is still caught.
		window := cp.Narrative()
		windowIDs := []string{cp.ID}
		windowCompleteness := cp.Completeness
		if i+1 < len(cps) && !cps[i+1].Redacted() {
			window += "\n" + cps[i+1].Narrative()
			windowIDs = append(windowIDs, cps[i+1].ID)
			windowCompleteness = WorstCompleteness(windowCompleteness, cps[i+1].Completeness)
		}

		attempt := firstSentenceMatching(attemptPatterns, window)
		failure := firstSentenceMatching(failurePatterns, window)
		pivot := firstSentenceMatching(pivotPatterns, window)
		if pivot == "" || (attempt == "" && failure == "") {
			continue
		}

		category, level, guarantee := RiskFunctional, RiskLevelLow,
			"No guarantee-changing keyword was matched in the replacement; this pivot is recorded for review but not scored as risky."
		for _, t := range riskyPivotTerms {
			if t.pattern.MatchString(pivot) {
				category, level, guarantee = t.category, t.level, t.guarantee
				break
			}
		}

		f := Finding{
			ID:                    fmt.Sprintf("pivot_%s", shortID(cp.ID)),
			Kind:                  FindingPivot,
			AgentDecision:         orNotEstablished(attempt),
			FailedAttempt:         orNotEstablished(failure),
			Pivot:                 pivot,
			CurrentImplementation: "See cited evidence for the requirement this pivot affects.",
			RiskInference:         guarantee,
			RiskCategory:          category,
			RiskLevel:             level,
			Summary: fmt.Sprintf("Pivot recorded in checkpoint %s: an approach was abandoned and replaced, changing a stated guarantee",
				shortID(cp.ID)),
			Recommendation: "Confirm the replacement still satisfies the original requirement, or amend the requirement to match reality.",
			Checkpoints:    windowIDs,
			Completeness:   windowCompleteness,
			Authoritative:  windowCompleteness.Authoritative(),
		}
		findings = append(findings, f)
	}
	return findings
}

// DetectDecisionDrift compares explicit commitments made in earlier checkpoints
// against choices narrated in later ones, and flags contradictions.
//
// Both sides are quoted verbatim from their own checkpoints. Paraphrasing the
// two into a single sentence is how a real contradiction gets smoothed into
// apparent agreement, which is the failure this detector exists to prevent.
func DetectDecisionDrift(cps []Checkpoint) []Finding {
	type decision struct {
		cpID     string
		sentence string
		terms    []string
	}
	var decisions []decision
	var findings []Finding

	for _, cp := range cps {
		if cp.Redacted() {
			continue
		}
		text := cp.Narrative()

		// A later checkpoint contradicts an earlier decision when it names a
		// technology or property the earlier decision ruled out.
		for _, d := range decisions {
			if d.cpID == cp.ID {
				continue
			}
			for _, term := range d.terms {
				contradiction := contradictionFor(term, text)
				if contradiction == "" {
					continue
				}
				comp := WorstCompleteness(cp.Completeness, CompletenessPartial)
				findings = append(findings, Finding{
					ID:                    fmt.Sprintf("drift_%s_%s", shortID(d.cpID), shortID(cp.ID)),
					Kind:                  FindingDecisionDrift,
					AgentDecision:         fmt.Sprintf("Checkpoint %s stated: %q", shortID(d.cpID), d.sentence),
					CurrentImplementation: fmt.Sprintf("Checkpoint %s later stated: %q", shortID(cp.ID), contradiction),
					RiskInference: fmt.Sprintf("The later choice appears to contradict the earlier commitment regarding %q. "+
						"Both sides are quoted from their own checkpoints; this is a flag for human adjudication, not a proven defect.", term),
					RiskCategory:   RiskCorrectness,
					RiskLevel:      RiskLevelMedium,
					Summary:        fmt.Sprintf("Decision drift: %q committed in %s, apparently contradicted in %s", term, shortID(d.cpID), shortID(cp.ID)),
					Recommendation: "Reconcile the two checkpoints: either restore the original constraint or record an explicit, reasoned reversal.",
					Checkpoints:    []string{d.cpID, cp.ID},
					Completeness:   comp,
					// Drift is a textual signal, never authoritative on its own.
					Authoritative: false,
				})
			}
		}

		if sent := firstSentenceMatching(decisionPatterns, text); sent != "" {
			decisions = append(decisions, decision{cpID: cp.ID, sentence: sent, terms: constraintTerms(sent)})
		}
	}
	return findings
}

// constraintTerms extracts the properties an explicit decision commits to.
var constraintVocab = map[string][]*regexp.Regexp{
	"horizontal scaling": {regexp.MustCompile(`(?i)\bin-?memory\b`), regexp.MustCompile(`(?i)\bsingle (?:node|instance|process)\b`)},
	"distributed state":  {regexp.MustCompile(`(?i)\bin-?memory\b`), regexp.MustCompile(`(?i)\blocal (?:map|cache|store)\b`)},
	"persistence":        {regexp.MustCompile(`(?i)\bin-?memory\b`), regexp.MustCompile(`(?i)\bephemeral\b`)},
	"no secrets in repo": {regexp.MustCompile(`(?i)\bhard-?cod(?:ed|ing) (?:the )?(?:key|token|secret|password)\b`)},
	"read-only":          {regexp.MustCompile(`(?i)\b(write|edit|mutat\w+) (?:access|permission)\b`)},
	"no hosted fallback": {regexp.MustCompile(`(?i)\b(hosted|proxy) (?:inference|fallback|endpoint)\b`)},
	"rate limiting":      {regexp.MustCompile(`(?i)\b(disabled?|skipped?|removed) (?:the )?rate limit\w*\b`)},
}

func constraintTerms(sentence string) []string {
	var out []string
	lower := strings.ToLower(sentence)
	for term := range constraintVocab {
		if strings.Contains(lower, term) {
			out = append(out, term)
		}
	}
	// Also treat a named technology in a "must/will" sentence as a commitment.
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(redis|postgres|kafka|s3|dynamodb)\b`),
	} {
		if m := re.FindString(lower); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// contradictionFor returns the sentence in text that contradicts a committed
// term, or "" when there is none.
func contradictionFor(term, text string) string {
	if pats, ok := constraintVocab[term]; ok {
		for _, sent := range splitSentences(text) {
			if matchesAny(pats, sent) {
				return strings.TrimSpace(sent)
			}
		}
		return ""
	}
	// A named technology is contradicted by a sentence that drops it.
	drop := regexp.MustCompile(`(?i)\b(without|instead of|replaced|dropped|removed|no longer using|fell back from)\b[^.]*\b` + regexp.QuoteMeta(term) + `\b`)
	alt := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(term) + `\b[^.]*\b(unavailable|not available|failed|couldn't|could not)\b`)
	for _, sent := range splitSentences(text) {
		if drop.MatchString(sent) || alt.MatchString(sent) {
			return strings.TrimSpace(sent)
		}
	}
	return ""
}

func orNotEstablished(s string) string {
	if strings.TrimSpace(s) == "" {
		return "Not established from the available checkpoint record."
	}
	return s
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
