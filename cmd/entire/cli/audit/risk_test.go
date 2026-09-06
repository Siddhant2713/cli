package audit

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func state(id string, weight float64, cat RiskCategory, st State, comp Completeness) RequirementState {
	return RequirementState{
		Requirement:   Requirement{ID: id, Summary: id, RiskWeight: weight, RiskCategory: cat},
		State:         st,
		Completeness:  comp,
		Authoritative: comp.Authoritative() && st == StateCompleted,
	}
}

// TestRiskAdjustedCoverageBeatsRawPercentage is the spec's motivating example:
// 8 of 10 requirements met is not "80%, minor gap" when the two missing ones are
// rate limiting and session invalidation.
func TestRiskAdjustedCoverageBeatsRawPercentage(t *testing.T) {
	var states []RequirementState
	for i := 0; i < 8; i++ {
		states = append(states, state(
			"cosmetic_"+string(rune('a'+i)), 1.0, RiskFunctional, StateCompleted, CompletenessComplete))
	}
	states = append(states,
		state("rate_limiting", 4.5, RiskSecurity, StateNotVerified, CompletenessComplete),
		state("session_invalidation", 4.0, RiskSecurity, StateNotVerified, CompletenessComplete),
	)

	c := ComputeCoverage(states)
	if c.RawPercent != 80 {
		t.Errorf("raw percent = %.1f, want 80", c.RawPercent)
	}
	if c.RiskAdjustedPercent >= c.RawPercent {
		t.Errorf("risk-adjusted (%.1f%%) should be well below raw (%.1f%%) when the gaps are the high-weight items",
			c.RiskAdjustedPercent, c.RawPercent)
	}
	if c.Verdict != RiskLevelCritical {
		t.Errorf("verdict = %q, want critical with two high-impact security gaps", c.Verdict)
	}
	if len(c.MissingHighImpact) != 2 {
		t.Errorf("expected both high-impact gaps named, got %v", c.MissingHighImpact)
	}
	// The score must arrive with its reasoning, never as a bare number.
	for _, want := range []string{"rate_limiting", "session_invalidation", "risk-adjusted"} {
		if !strings.Contains(c.Reasoning, want) {
			t.Errorf("reasoning does not mention %q: %s", want, c.Reasoning)
		}
	}
}

// TestCoverageNotAuthoritativeOnIncompleteRecord asserts the verdict is demoted
// whenever the underlying record was incomplete.
func TestCoverageNotAuthoritativeOnIncompleteRecord(t *testing.T) {
	c := ComputeCoverage([]RequirementState{
		state("a", 3.0, RiskSecurity, StateCompleted, CompletenessComplete),
		state("b", 3.0, RiskSecurity, StateNotVerified, CompletenessRedacted),
	})
	if c.Authoritative {
		t.Error("coverage marked authoritative despite a redacted requirement record")
	}
	if !strings.Contains(c.Reasoning, "NOT authoritative") {
		t.Errorf("reasoning must say the verdict is not authoritative, got: %s", c.Reasoning)
	}
}

// TestEmptyCoverageIsNotSuccess: auditing nothing must not read as a clean bill
// of health.
func TestEmptyCoverageIsNotSuccess(t *testing.T) {
	c := ComputeCoverage(nil)
	if c.Authoritative {
		t.Error("empty coverage must not be authoritative")
	}
	if c.RiskAdjustedPercent != 0 {
		t.Errorf("empty coverage percent = %.1f, want 0", c.RiskAdjustedPercent)
	}
}

// TestGapFindingsNeverAssertAbsence locks the wording contract across every
// unevidenced state.
func TestGapFindingsNeverAssertAbsence(t *testing.T) {
	for _, st := range []State{StateNotVerified, StateUnknown, StateFailed, StateAbandoned} {
		fs := GapFindings([]RequirementState{state("rate_limit", 4.5, RiskSecurity, st, CompletenessPartial)})
		if len(fs) != 1 {
			t.Fatalf("state %q: expected 1 gap finding, got %d", st, len(fs))
		}
		f := fs[0]
		if !strings.Contains(f.Summary, "could not be verified") {
			t.Errorf("state %q: summary = %q, want 'could not be verified'", st, f.Summary)
		}
		if f.Authoritative {
			t.Errorf("state %q: gap finding must never be authoritative", st)
		}
		if strings.Contains(f.RiskInference, "was not implemented") {
			t.Errorf("state %q: risk inference asserts absence: %q", st, f.RiskInference)
		}
	}
}

// TestStateFromEvidenceSeparatesSearchQualityFromResult is the distinction the
// whole feature rests on: "we looked and found nothing" and "we could not look"
// are different answers.
func TestStateFromEvidenceSeparatesSearchQualityFromResult(t *testing.T) {
	st, comp, notes := StateFromEvidence(nil, CompletenessComplete)
	if st != StateNotVerified {
		t.Errorf("complete search with no hits: state = %q, want not_verified", st)
	}
	if !comp.Authoritative() {
		t.Errorf("complete search should keep complete completeness, got %q", comp)
	}
	if !strings.Contains(notes, "absence of evidence is not evidence of absence") {
		t.Errorf("notes should state the epistemic limit, got %q", notes)
	}

	st, comp, _ = StateFromEvidence(nil, CompletenessPartial)
	if st != StateUnknown {
		t.Errorf("incomplete search with no hits: state = %q, want unknown", st)
	}
	if comp.Authoritative() {
		t.Errorf("incomplete search must not report complete completeness, got %q", comp)
	}
}

// TestStateFromEvidenceDemotesLexicalOnly: a grep hit is not a structural fact.
func TestStateFromEvidenceDemotesLexicalOnly(t *testing.T) {
	ev := []Evidence{{ID: "ev_1", Kind: EvidenceTextSearch, Completeness: CompletenessPartial}}
	st, comp, notes := StateFromEvidence(ev, CompletenessComplete)
	if st != StatePartial {
		t.Errorf("text-only evidence: state = %q, want partial", st)
	}
	if comp.Authoritative() {
		t.Errorf("text-only evidence must not be complete, got %q", comp)
	}
	if !strings.Contains(notes, "lexical") {
		t.Errorf("notes should flag the evidence as lexical, got %q", notes)
	}
}

// TestSelectExtractorFailsClearlyWithoutBackend is the required failure-path
// test: with no BYOK key, no agent and no requirements file, the command must
// fail with actionable guidance rather than silently producing an empty
// requirement graph — which would render as "nothing was required".
func TestSelectExtractorFailsClearlyWithoutBackend(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	// Empty PATH so no headless agent can be discovered.
	t.Setenv("PATH", t.TempDir())

	_, err := SelectExtractor("")
	if err == nil {
		t.Fatal("expected an error when no inference backend is configured")
	}
	if !errors.Is(err, ErrNoInference) {
		t.Errorf("error should wrap ErrNoInference, got %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"ANTHROPIC_API_KEY", "--requirements", "headless agent", "no hosted inference fallback"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message should mention %q, got: %s", want, msg)
		}
	}
}

// TestSelectExtractorPrefersExplicitRequirements confirms an operator-supplied
// graph wins over inference: it is intent, not a fallback.
func TestSelectExtractorPrefersExplicitRequirements(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	ext, err := SelectExtractor("testdata/requirements_auth.json")
	if err != nil {
		t.Fatalf("select extractor: %v", err)
	}
	if !strings.HasPrefix(ext.Name(), "file:") {
		t.Errorf("extractor = %q, want the file extractor", ext.Name())
	}
	reqs, err := ext.Extract(context.Background(), "")
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(reqs) != 3 {
		t.Errorf("expected 3 requirements from the fixture, got %d", len(reqs))
	}
}

// TestSelectExtractorUsesBYOKKey confirms the BYOK path is chosen when a key is set.
func TestSelectExtractorUsesBYOKKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	ext, err := SelectExtractor("")
	if err != nil {
		t.Fatalf("select extractor: %v", err)
	}
	if !strings.HasPrefix(ext.Name(), "anthropic-byok:") {
		t.Errorf("extractor = %q, want the BYOK extractor", ext.Name())
	}
}

// TestParseRequirementsToleratesFencedJSON covers the common model output shape.
func TestParseRequirementsToleratesFencedJSON(t *testing.T) {
	raw := "Here you go:\n```json\n{\"requirements\":[{\"id\":\"a\",\"summary\":\"A\"}]}\n```\n"
	reqs, err := parseRequirements(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(reqs) != 1 || reqs[0].ID != "a" {
		t.Fatalf("unexpected parse result: %+v", reqs)
	}
	// Defaults must be filled so downstream weighting never divides by zero.
	if reqs[0].RiskWeight == 0 || reqs[0].RiskCategory == "" {
		t.Errorf("defaults not applied: %+v", reqs[0])
	}
}

// TestParseRequirementsRejectsEmpty: zero requirements is an error, never a
// silently clean audit.
func TestParseRequirementsRejectsEmpty(t *testing.T) {
	if _, err := parseRequirements(`{"requirements":[]}`); err == nil {
		t.Error("expected an error for a zero-requirement response")
	}
}

func TestBannersMatchSpecVerbatim(t *testing.T) {
	if !strings.Contains(Banner(CompletenessComplete), "✓ COMPLETE CONTEXT") {
		t.Error("complete banner text drifted from the spec")
	}
	if !strings.Contains(Banner(CompletenessPartial), "should not be treated as authoritative") {
		t.Error("partial banner text drifted from the spec")
	}
	// Redacted and missing are worse than partial and must say so.
	for _, c := range []Completeness{CompletenessRedacted, CompletenessMissing, CompletenessUnknown} {
		if !strings.Contains(Banner(c), "INSUFFICIENT CONTEXT") {
			t.Errorf("completeness %q should map to the insufficient banner", c)
		}
	}
}

func TestWorstCompletenessTakesTheWeakest(t *testing.T) {
	if got := WorstCompleteness(CompletenessComplete, CompletenessRedacted, CompletenessPartial); got != CompletenessRedacted {
		t.Errorf("WorstCompleteness = %q, want redacted", got)
	}
	if got := WorstCompleteness(); got != CompletenessUnknown {
		t.Errorf("WorstCompleteness() with no args = %q, want unknown", got)
	}
}

func TestRepositoryHashIsStableAndNotReversible(t *testing.T) {
	url := "git@github.com:acme/private-repo.git"
	h1, h2 := RepositoryHash(url), RepositoryHash(url)
	if h1 != h2 {
		t.Error("repository hash is not stable across calls")
	}
	if strings.Contains(h1, "acme") || strings.Contains(h1, "private") {
		t.Errorf("hash leaks the source URL: %q", h1)
	}
}

func TestDDLDeclaresContextCompletenessOnBothTables(t *testing.T) {
	ddl := DatabricksConfig{Catalog: "workspace", Schema: "entire_audit"}.DDL()
	if strings.Count(ddl, "context_completeness") != 2 {
		t.Error("context_completeness must be a column on both exported tables — the schema is the privacy evidence")
	}
	for _, want := range []string{"feature_requirements", "risk_findings", "USING DELTA"} {
		if !strings.Contains(ddl, want) {
			t.Errorf("DDL missing %q", want)
		}
	}
}

func TestWriteStaticExportProducesLoadableArtifacts(t *testing.T) {
	dir := t.TempDir()
	bundle := ExportBundle{
		FeatureRequirements: []FeatureRequirementRow{{FeatureID: "f", RequirementID: "r", ContextCompleteness: "partial"}},
		RiskFindings:        []RiskFindingRow{{FindingID: "g", FeatureID: "f", ContextCompleteness: "partial"}},
	}
	written, err := WriteStaticExport(dir, DatabricksConfigFromEnv(), bundle)
	if err != nil {
		t.Fatalf("write export: %v", err)
	}
	if len(written) != 3 {
		t.Fatalf("expected schema.sql + 2 ndjson files, got %v", written)
	}
	for _, p := range written {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if len(b) == 0 {
			t.Errorf("%s is empty", p)
		}
	}
}

// TestCircularEvidenceIsExcluded covers a real false positive found on the first
// end-to-end run: every requirement came back PARTIAL because git grep matched
// the search hints inside the requirements file that defined them. Citing your
// own input as proof the input was implemented is circular, not evidence.
func TestCircularEvidenceIsExcluded(t *testing.T) {
	cases := []struct {
		path, reqFile string
		want          bool
	}{
		{"cmd/entire/cli/audit/testdata/requirements_auth.json", "cmd/entire/cli/audit/testdata/requirements_auth.json", true},
		{"testdata/reqs.json", "", true},
		{"pkg/foo/testdata/golden.json", "", true},
		{"cmd/entire/cli/audit/evidence.go", "reqs.json", false},
		{"internal/auth/ratelimit.go", "", false},
	}
	for _, tc := range cases {
		if got := circularEvidencePath(tc.path, tc.reqFile); got != tc.want {
			t.Errorf("circularEvidencePath(%q, %q) = %v, want %v", tc.path, tc.reqFile, got, tc.want)
		}
	}
}

// TestSemanticSearchAloneCannotConfirmARequirement covers a real false positive
// found by running against a repo that genuinely had no rate limiting.
//
// `graph def RateLimiter` found nothing and `graph impact` returned an empty
// focus, but semantic search matched a nearby Login function and the requirement
// was reported COMPLETED. Text search had correctly reported it unverified — so
// turning the graph ON made the answer strictly worse.
//
// Semantic search is a nearest-neighbour query: it always returns the closest
// code, including when nothing implements the requirement at all. It locates;
// it does not confirm.
func TestSemanticSearchAloneCannotConfirmARequirement(t *testing.T) {
	proximityOnly := []Evidence{
		{ID: "ev_1", Kind: EvidenceGraphSearch, Citation: "auth/login.go:5", Completeness: CompletenessComplete},
		{ID: "ev_2", Kind: EvidenceGraphSearch, Citation: "auth/login.go:2", Completeness: CompletenessComplete},
	}
	st, _, notes := StateFromEvidence(proximityOnly, CompletenessComplete)
	if st == StateCompleted {
		t.Error("semantic-search hits alone confirmed a requirement; proximity is not identity")
	}
	if st != StatePartial {
		t.Errorf("state = %q, want partial", st)
	}
	if !strings.Contains(notes, "no declaration") {
		t.Errorf("notes should explain that no declaration was found, got %q", notes)
	}

	// A declaration-level hit is a different claim and may confirm.
	withDef := append([]Evidence{
		{ID: "ev_0", Kind: EvidenceGraphDef, Citation: "auth/ratelimit.go:12", Completeness: CompletenessComplete},
	}, proximityOnly...)
	if st, _, _ := StateFromEvidence(withDef, CompletenessComplete); st != StateCompleted {
		t.Errorf("declaration-level evidence should confirm, got %q", st)
	}
}
