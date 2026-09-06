package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// remoteExtractor stands in for any network-backed extractor and records whether
// it was ever actually invoked. The assertion that matters is not just that the
// audit errors — it is that the prompt never reached the wire.
type remoteExtractor struct{ called *bool }

func (r remoteExtractor) Name() string { return "anthropic-byok:test" }
func (r remoteExtractor) Extract(context.Context, string) ([]Requirement, error) {
	*r.called = true
	return nil, nil
}

// TestPromptEgressBlockedOnRedactedRepo is the Curveball test: a repository whose
// checkpoints are redacted must not have its prompt text sent to an external
// inference service, and the block must happen BEFORE the call is made.
func TestPromptEgressBlockedOnRedactedRepo(t *testing.T) {
	called := false
	ext := remoteExtractor{called: &called}
	redacted := []Checkpoint{{ID: "cp_001", Prompt: "[REDACTED]", Completeness: CompletenessRedacted}}

	err := AuthorizeExtraction(ext, redacted, EgressPolicy{})
	if err == nil {
		t.Fatal("extraction was authorized against a redacted checkpoint record")
	}
	if !errors.Is(err, ErrPromptEgressBlocked) {
		t.Errorf("error should wrap ErrPromptEgressBlocked, got %v", err)
	}
	if called {
		t.Error("the extractor was invoked; prompt text must never reach the wire when blocked")
	}
	// The error has to tell the operator how to proceed, or they will just
	// disable the guard.
	for _, want := range []string{"--requirements", "--allow-prompt-egress", "sensitive"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message should mention %q, got: %s", want, err.Error())
		}
	}
}

// TestPromptEgressAllowedWithExplicitOptIn: the guard is a default, not a wall.
func TestPromptEgressAllowedWithExplicitOptIn(t *testing.T) {
	called := false
	redacted := []Checkpoint{{ID: "cp_001", Prompt: "[REDACTED]", Completeness: CompletenessRedacted}}
	if err := AuthorizeExtraction(remoteExtractor{called: &called}, redacted,
		EgressPolicy{AllowPromptEgress: true}); err != nil {
		t.Errorf("explicit opt-in should permit extraction, got %v", err)
	}
}

// TestLocalExtractionAlwaysAllowed: a file-supplied requirement graph sends
// nothing anywhere, so the guard must not block it — otherwise the documented
// remedy for a sensitive repo would itself be blocked.
func TestLocalExtractionAlwaysAllowed(t *testing.T) {
	redacted := []Checkpoint{{ID: "cp_001", Prompt: "[REDACTED]", Completeness: CompletenessRedacted}}
	if err := AuthorizeExtraction(FileExtractor{Path: "testdata/requirements_auth.json"},
		redacted, EgressPolicy{Sensitive: true}); err != nil {
		t.Errorf("local file extraction must never be blocked, got %v", err)
	}
}

// TestSensitiveFlagBlocksEvenCleanHistory: --sensitive is an operator override
// that does not depend on detecting redaction.
func TestSensitiveFlagBlocksEvenCleanHistory(t *testing.T) {
	called := false
	clean := []Checkpoint{{ID: "cp_001", Prompt: "build auth", Completeness: CompletenessComplete}}
	if err := AuthorizeExtraction(remoteExtractor{called: &called}, clean,
		EgressPolicy{Sensitive: true}); err == nil {
		t.Error("--sensitive must block remote extraction regardless of the record")
	}
	if called {
		t.Error("extractor invoked despite --sensitive")
	}
}

// TestUnknownExtractorFailsClosed: an extractor added later that the guard does
// not recognise must be treated as remote. Forgetting to update the allowlist
// must not silently open an egress path.
func TestUnknownExtractorFailsClosed(t *testing.T) {
	if !extractorSendsPromptOffMachine(remoteExtractor{called: new(bool)}) {
		t.Error("unrecognised extractor treated as local; the guard must fail closed")
	}
}

// TestSensitiveRepoStillProducesAUsefulAudit is the Curveball's second
// requirement: useful output must survive redaction. With a locally supplied
// requirement graph the full pipeline still runs on a fully redacted history.
func TestSensitiveRepoStillProducesAUsefulAudit(t *testing.T) {
	rep, err := Run(context.Background(), Options{
		Dir:              t.TempDir(),
		FeatureID:        "sensitive_repo",
		RequirementsFile: "testdata/requirements_auth.json",
		Ask:              "build authentication",
		Reader:           fakeReader{cps: []Checkpoint{{ID: "cp_001", Prompt: "[REDACTED]", Message: "[REDACTED]", Completeness: CompletenessRedacted}}},
		Graph:            blindGraph{},
		Egress:           EgressPolicy{Sensitive: true},
		Now:              func() time.Time { return time.Unix(0, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("audit must still run on a sensitive repo: %v", err)
	}
	if len(rep.Requirements) == 0 {
		t.Fatal("no requirements audited; the sensitive path produced no useful output")
	}
	if rep.Coverage.Authoritative {
		t.Error("a fully redacted history must not yield an authoritative verdict")
	}
	for _, rs := range rep.Requirements {
		if rs.Authoritative {
			t.Errorf("requirement %s marked authoritative on a redacted record", rs.Requirement.ID)
		}
	}
}
