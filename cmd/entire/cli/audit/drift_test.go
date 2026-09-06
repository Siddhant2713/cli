package audit

import (
	"strings"
	"testing"
)

func cp(id, narrative string) Checkpoint {
	return Checkpoint{ID: id, Message: narrative, Date: "2026-09-06T10:00:00Z", Completeness: CompletenessComplete}
}

// TestDetectPivotsFindsTheRedisToInMemoryCase is the canonical example from
// FEATURE-SPEC.md: an approach fails and is silently replaced by one with weaker
// guarantees. The diff shows a small change; the guarantee change is invisible
// without the checkpoint narrative.
func TestDetectPivotsFindsTheRedisToInMemoryCase(t *testing.T) {
	cps := []Checkpoint{
		cp("01ABCDEF01", "Added rate limiting. Tried Redis for the shared counter but the Redis "+
			"connection failed in CI. Fell back to an in-memory map instead."),
	}
	got := DetectPivots(cps)
	if len(got) != 1 {
		t.Fatalf("expected 1 pivot finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.RiskCategory != RiskScalability {
		t.Errorf("risk category = %q, want scalability: an in-memory swap drops a distributed guarantee", f.RiskCategory)
	}
	if f.RiskLevel != RiskLevelHigh {
		t.Errorf("risk level = %q, want high", f.RiskLevel)
	}
	if !strings.Contains(strings.ToLower(f.FailedAttempt), "failed") {
		t.Errorf("failed attempt not captured, got %q", f.FailedAttempt)
	}
	if !strings.Contains(strings.ToLower(f.Pivot), "in-memory") {
		t.Errorf("pivot not captured, got %q", f.Pivot)
	}
	if !strings.Contains(f.RiskInference, "restart") {
		t.Errorf("risk inference should name the lost guarantee, got %q", f.RiskInference)
	}
}

// TestDetectPivotsAcrossCheckpoints covers a chain that spans two checkpoints,
// which is the common shape: an attempt in one session, the correction in the next.
func TestDetectPivotsAcrossCheckpoints(t *testing.T) {
	cps := []Checkpoint{
		cp("01AAAAAAAA", "Attempted to implement session storage with Postgres."),
		cp("01BBBBBBBB", "The Postgres migration failed to apply. Switched to an in-memory session map instead."),
	}
	if got := DetectPivots(cps); len(got) == 0 {
		t.Fatal("expected a pivot finding spanning two checkpoints, got none")
	}
}

// TestDetectPivotsIgnoresCleanWork guards against the detector inventing findings
// from ordinary progress narration.
func TestDetectPivotsIgnoresCleanWork(t *testing.T) {
	cps := []Checkpoint{
		cp("01CCCCCCCC", "Added the login handler and its tests. All tests pass."),
		cp("01DDDDDDDD", "Documented the login flow in the README."),
	}
	if got := DetectPivots(cps); len(got) != 0 {
		t.Errorf("expected no findings on clean work, got %d: %+v", len(got), got)
	}
}

// TestDetectPivotsSurfacesRedactedGap asserts that a redacted checkpoint produces
// a visible "could not evaluate" finding rather than being silently skipped.
// Silence would read as "we checked and it was fine".
func TestDetectPivotsSurfacesRedactedGap(t *testing.T) {
	cps := []Checkpoint{{ID: "01EEEEEEEE", Message: "[REDACTED]", Prompt: "[REDACTED]", Completeness: CompletenessRedacted}}
	got := DetectPivots(cps)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for the redacted checkpoint, got %d", len(got))
	}
	if got[0].Authoritative {
		t.Error("a finding about a redacted checkpoint must not be authoritative")
	}
	if !strings.Contains(got[0].Summary, "redacted") {
		t.Errorf("summary should name the redaction, got %q", got[0].Summary)
	}
}

// TestDetectDecisionDriftQuotesBothSides is the drift detector's core contract:
// an early commitment and a later contradiction, each quoted from its own
// checkpoint rather than paraphrased into agreement.
func TestDetectDecisionDriftQuotesBothSides(t *testing.T) {
	cps := []Checkpoint{
		cp("01FFFFFFFF", "We decided to build for horizontal scaling from the start. Every component must be stateless."),
		cp("01GGGGGGGG", "Implemented the session store as an in-memory map for now."),
	}
	got := DetectDecisionDrift(cps)
	if len(got) == 0 {
		t.Fatal("expected a decision drift finding, got none")
	}
	f := got[0]
	if !strings.Contains(f.AgentDecision, "horizontal scaling") {
		t.Errorf("earlier decision not quoted, got %q", f.AgentDecision)
	}
	if !strings.Contains(strings.ToLower(f.CurrentImplementation), "in-memory") {
		t.Errorf("later contradiction not quoted, got %q", f.CurrentImplementation)
	}
	if f.Authoritative {
		t.Error("decision drift is a textual signal for human adjudication; it must never be authoritative")
	}
	if len(f.Checkpoints) != 2 {
		t.Errorf("expected both checkpoint IDs cited, got %v", f.Checkpoints)
	}
}

// TestDetectDecisionDriftIgnoresConsistentWork guards against false positives.
func TestDetectDecisionDriftIgnoresConsistentWork(t *testing.T) {
	cps := []Checkpoint{
		cp("01HHHHHHHH", "We decided the store must support horizontal scaling."),
		cp("01IIIIIIII", "Implemented the session store on Redis with a shared connection pool."),
	}
	if got := DetectDecisionDrift(cps); len(got) != 0 {
		t.Errorf("expected no drift on consistent work, got %d: %+v", len(got), got)
	}
}

// TestDetectDecisionDriftSkipsRedacted confirms a redacted checkpoint contributes
// no drift claims — we cannot read it, so we cannot allege a contradiction in it.
func TestDetectDecisionDriftSkipsRedacted(t *testing.T) {
	cps := []Checkpoint{
		cp("01JJJJJJJJ", "The system must support horizontal scaling."),
		{ID: "01KKKKKKKK", Message: "[REDACTED]", Completeness: CompletenessRedacted},
	}
	if got := DetectDecisionDrift(cps); len(got) != 0 {
		t.Errorf("expected no drift claims from a redacted checkpoint, got %+v", got)
	}
}

// TestNarrativeExcludesTheUserPrompt covers a real false positive found while
// running against live checkpoints: the user's instruction said "if Redis turns
// out not to be usable, implement the best alternative instead", and the
// detector matched that as a completed attempt→failure→pivot chain. An
// instruction describing a hypothetical is not a record that it happened.
func TestNarrativeExcludesTheUserPrompt(t *testing.T) {
	c := Checkpoint{
		Message:        "Add a cache",
		Intent:         "Add a cache",
		Prompt:         "Use Redis. If Redis turns out not to be usable, it failed, so use an in-memory map instead.",
		AgentNarrative: "Added the cache.",
	}
	if strings.Contains(c.Narrative(), "in-memory") {
		t.Error("Narrative() included the user prompt; instructions are not evidence of what happened")
	}
	if !strings.Contains(c.Narrative(), "Added the cache") {
		t.Error("Narrative() dropped the agent's own account of its work")
	}
	if got := DetectPivots([]Checkpoint{c}); len(got) != 0 {
		t.Errorf("detected %d pivot(s) from a hypothetical in the user's instruction: %+v", len(got), got)
	}
}

// TestPivotSummaryDoesNotOverclaim: a pivot with no guarantee-changing keyword
// must not be summarised as "changing a stated guarantee". Overclaiming is the
// exact failure mode this feature argues against, so it must not appear in the
// feature's own output.
func TestPivotSummaryDoesNotOverclaim(t *testing.T) {
	neutral := Checkpoint{
		ID:             "01NEUTRAL1",
		AgentNarrative: "Tried the v2 helper API. It failed to compile. Switched to the v1 helper instead.",
		Completeness:   CompletenessComplete,
	}
	got := DetectPivots([]Checkpoint{neutral})
	if len(got) != 1 {
		t.Fatalf("expected 1 pivot finding, got %d", len(got))
	}
	if strings.Contains(got[0].Summary, "changing a stated guarantee") {
		t.Errorf("summary overclaims a guarantee change that the risk analysis did not find: %q", got[0].Summary)
	}
	if got[0].RiskLevel != RiskLevelLow {
		t.Errorf("risk level = %q, want low for a pivot with no guarantee keyword", got[0].RiskLevel)
	}

	risky := Checkpoint{
		ID:             "01RISKY001",
		AgentNarrative: "Tried Redis for the shared counter. The connection failed. Fell back to an in-memory map instead.",
		Completeness:   CompletenessComplete,
	}
	got = DetectPivots([]Checkpoint{risky})
	if len(got) != 1 {
		t.Fatalf("expected 1 pivot finding, got %d", len(got))
	}
	if !strings.Contains(got[0].Summary, "changing a stated guarantee") {
		t.Errorf("a genuine guarantee-changing pivot should say so: %q", got[0].Summary)
	}
}
