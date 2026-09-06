package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeReader serves a fixed checkpoint sequence, so the audit can be exercised
// without a live Entire repository.
type fakeReader struct{ cps []Checkpoint }

func (f fakeReader) List(context.Context) ([]Checkpoint, error) { return f.cps, nil }
func (f fakeReader) Explain(_ context.Context, id string) (Checkpoint, error) {
	for _, cp := range f.cps {
		if cp.ID == id {
			return cp, nil
		}
	}
	return Checkpoint{ID: id, Completeness: CompletenessMissing}, nil
}

// blindGraph answers every query as "nothing found", cleanly. It models the case
// the audit must never mishandle: a search that ran fine and found nothing.
type blindGraph struct{}

func (blindGraph) Available(context.Context) bool { return true }
func (blindGraph) Def(context.Context, string) (*GraphDef, error) {
	return &GraphDef{}, nil
}
func (blindGraph) Search(context.Context, string, int) (*GraphSearch, error) {
	return &GraphSearch{}, nil
}
func (blindGraph) Impact(context.Context, string) (*GraphImpact, error) {
	return &GraphImpact{}, nil
}

// redactedFixture is the fixture from FEATURE-SPEC.md: a checkpoint whose prompt
// and transcript were withheld, leaving rate limiting in an unknown state.
func redactedFixture(t *testing.T) []Checkpoint {
	t.Helper()
	raw, err := os.ReadFile("testdata/redacted_checkpoint.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f struct {
		CheckpointID string `json:"checkpoint_id"`
		Prompt       string `json:"prompt"`
		Transcript   string `json:"transcript"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return []Checkpoint{{
		ID:           f.CheckpointID,
		Prompt:       f.Prompt,
		Intent:       f.Transcript,
		Message:      "[REDACTED]",
		Date:         "2026-09-06T10:00:00Z",
		Completeness: CompletenessRedacted,
	}}
}

// TestRedactedCheckpointNeverBecomesAuthoritativeClaim is the required privacy
// test from FEATURE-SPEC.md, and the single most important test in this package.
//
// The bug it exists to catch: a checkpoint is redacted, the audit therefore finds
// no evidence of rate limiting, and it reports "Rate limiting was not
// implemented." That converts missing information into an authoritative negative
// claim about the code — a claim the audit has not earned and cannot support.
//
// The test asserts the correct behaviour ("could not be verified",
// context_completeness partial-or-worse, authoritative false) AND explicitly
// fails on the incorrect one, so the failure mode is caught by name rather than
// only by the absence of the right string.
func TestRedactedCheckpointNeverBecomesAuthoritativeClaim(t *testing.T) {
	rep, err := Run(context.Background(), Options{
		Dir:              t.TempDir(),
		FeatureID:        "auth_001",
		RequirementsFile: "testdata/requirements_auth.json",
		Ask:              "build authentication",
		Reader:           fakeReader{cps: redactedFixture(t)},
		Graph:            blindGraph{},
		Now:              func() time.Time { return time.Unix(0, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("audit run: %v", err)
	}

	var rateLimit *RequirementState
	for i := range rep.Requirements {
		if rep.Requirements[i].Requirement.ID == "rate_limit" {
			rateLimit = &rep.Requirements[i]
		}
	}
	if rateLimit == nil {
		t.Fatal("rate_limit requirement missing from report")
	}

	if rateLimit.State == StateCompleted {
		t.Errorf("rate_limit reported as completed with no evidence; got state %q", rateLimit.State)
	}
	if rateLimit.Authoritative {
		t.Error("rate_limit state marked authoritative despite a redacted checkpoint record")
	}
	if rateLimit.Completeness.Authoritative() {
		t.Errorf("context_completeness = %q; a redacted record must never be complete", rateLimit.Completeness)
	}

	// Find the finding that speaks about rate limiting.
	var finding *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Requirement == "rate_limit" {
			finding = &rep.Findings[i]
		}
	}
	if finding == nil {
		t.Fatal("no finding emitted for the unverifiable rate_limit requirement; " +
			"silence about a requirement we could not check is itself a false signal")
	}

	if !strings.Contains(finding.Summary, "could not be verified") {
		t.Errorf("finding summary = %q; want it to say the requirement could not be verified", finding.Summary)
	}
	if finding.Authoritative {
		t.Error("finding marked authoritative: a gap discovered through missing context is never authoritative")
	}
	if finding.Completeness.Authoritative() {
		t.Errorf("finding context_completeness = %q, want partial or weaker", finding.Completeness)
	}

	// The forbidden claim, in every phrasing the report could produce.
	var buf bytes.Buffer
	if err := RenderText(&buf, rep); err != nil {
		t.Fatalf("render: %v", err)
	}
	rendered := buf.String()
	for _, forbidden := range []string{
		"Rate limiting was not implemented",
		"was not implemented",
		"is not implemented",
		"is missing from the implementation",
	} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("report contains the forbidden authoritative negative claim %q — "+
				"missing information must never be rendered as a fact about the code", forbidden)
		}
	}

	// The reader must be told the context was insufficient.
	if !strings.Contains(rendered, "INSUFFICIENT CONTEXT") && !strings.Contains(rendered, "PARTIAL CONTEXT") {
		t.Error("report never showed a partial/insufficient context banner despite a redacted checkpoint")
	}
}

// TestExportRecordsCarryNoFreeText locks the structural privacy boundary: no
// prompt, transcript or narrative text may appear in the Databricks export, even
// when every in-memory field is full of it.
func TestExportRecordsCarryNoFreeText(t *testing.T) {
	const secretPrompt = "PROMPT_CANARY_do_not_export_this_text"
	const secretNarrative = "TRANSCRIPT_CANARY_agent_said_something_private"

	rep := Report{
		FeatureID:      "auth_001",
		RepositoryHash: RepositoryHash("git@github.com:acme/private.git"),
		CommitSHA:      "abc123",
		GeneratedAt:    time.Unix(0, 0).UTC(),
		Requirements: []RequirementState{{
			Requirement: Requirement{
				ID: "rate_limit", Summary: "Rate limiting", RiskCategory: RiskSecurity, RiskWeight: 4.5,
				SourceCheckpoint: "cp_001",
			},
			State: StateNotVerified,
			Evidence: []Evidence{{
				ID: "ev_001", Kind: EvidenceGraphDef, Citation: "a.go:1",
				Detail:  secretNarrative,
				Command: "entire graph def " + secretPrompt,
			}},
			Completeness: CompletenessPartial,
			Notes:        secretNarrative,
		}},
		Findings: []Finding{{
			ID: "gap_rate_limit", Kind: FindingRequirementGap, Requirement: "rate_limit",
			Summary:               "Rate limiting could not be verified",
			AgentDecision:         secretPrompt,
			FailedAttempt:         secretNarrative,
			Pivot:                 secretNarrative,
			CurrentImplementation: secretPrompt,
			RiskInference:         secretNarrative,
			Checkpoints:           []string{"cp_001"},
			Completeness:          CompletenessPartial,
		}},
	}

	out, err := MarshalExport(BuildExport(rep))
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	for _, canary := range []string{secretPrompt, secretNarrative} {
		if bytes.Contains(out, []byte(canary)) {
			t.Errorf("export contains %q — raw narrative text crossed the privacy boundary", canary)
		}
	}
	// The repository URL must be hashed, never shipped in the clear.
	if bytes.Contains(out, []byte("acme/private")) {
		t.Error("export contains the raw repository URL; it must be hashed")
	}
	// And the approved fields must actually be present, or the boundary is
	// trivially satisfied by exporting nothing useful.
	for _, want := range []string{"rate_limit", "context_completeness", "partial", "auth_001"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("export is missing the approved field/value %q", want)
		}
	}
}

// TestSanitizeSummaryScrubsSecrets covers the defence-in-depth layer behind the
// structural allowlist.
func TestSanitizeSummaryScrubsSecrets(t *testing.T) {
	cases := []struct{ name, in string }{
		{"anthropic key", "uses sk-ant-api03-abcdefghijklmnopqrstuvwxyz for auth"},
		{"github token", "token ghp_abcdefghijklmnopqrstuvwxyz012345"},
		{"aws key", "AKIAIOSFODNN7EXAMPLE is in the config"},
		{"labelled secret", "password = hunter2correcthorse"},
		{"jwt", "bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeSummary(tc.in)
			if !strings.Contains(got, "[REDACTED-SECRET]") {
				t.Errorf("sanitizeSummary(%q) = %q; expected the credential to be scrubbed", tc.in, got)
			}
		})
	}
}

// TestSanitizeSummaryBoundsLength stops a transcript leaking through a field
// that was only ever meant to hold a short summary.
func TestSanitizeSummaryBoundsLength(t *testing.T) {
	long := strings.Repeat("transcript ", 200)
	got := sanitizeSummary(long)
	if len(got) > maxSummaryLen+4 {
		t.Errorf("sanitizeSummary returned %d bytes; want <= %d", len(got), maxSummaryLen+4)
	}
}
