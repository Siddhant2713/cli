// Package audit implements `entire audit`: Feature Audit & Decision Drift.
//
// The command reads a feature's checkpoint history, decomposes the original ask
// into a requirement graph, searches for structural evidence that each
// requirement was actually implemented, detects pivots and decision drift
// across the checkpoint sequence, and reports risk-adjusted coverage.
//
// The organising discipline of this package is that unknown is not completed,
// and unknown is equally not "not implemented". Every state and every finding
// carries a [Completeness] describing how much of the record backed it, and no
// finding is presented as authoritative unless the evidence behind it was
// actually complete. See privacy.go for the boundary that keeps raw prompts and
// transcripts from ever leaving the machine.
package audit

import "time"

// Completeness records how much of the underlying history was actually
// available when a conclusion was reached. It gates whether a finding may be
// presented as authoritative.
type Completeness string

const (
	// CompletenessComplete means the full checkpoint record backing this
	// conclusion was read successfully.
	CompletenessComplete Completeness = "complete"
	// CompletenessPartial means some of the record was reachable and some was
	// not — a redacted field, an unreachable remote, a partial graph parse.
	CompletenessPartial Completeness = "partial"
	// CompletenessRedacted means the record exists but its content was
	// deliberately withheld by redaction.
	CompletenessRedacted Completeness = "redacted"
	// CompletenessMissing means the record that should back this conclusion
	// could not be found at all.
	CompletenessMissing Completeness = "missing"
	// CompletenessUnknown is the zero value: we never established how complete
	// the record was. It is treated as strictly as missing.
	CompletenessUnknown Completeness = "unknown"
)

// Authoritative reports whether a conclusion drawn from a record of this
// completeness may be stated as fact. Only a complete record qualifies.
//
// This is the single gate the whole privacy/honesty discipline hangs from:
// TestRedactedCheckpointNeverBecomesAuthoritativeClaim asserts that a partial
// record can never produce an authoritative negative claim.
func (c Completeness) Authoritative() bool { return c == CompletenessComplete }

// Rank orders completeness from best to worst so that merging several evidence
// sources can take the worst of them.
func (c Completeness) Rank() int {
	switch c {
	case CompletenessComplete:
		return 0
	case CompletenessPartial:
		return 1
	case CompletenessRedacted:
		return 2
	case CompletenessMissing:
		return 3
	default:
		return 4
	}
}

// WorstCompleteness returns the least complete of the given values, which is
// the only safe way to combine evidence: a conclusion is exactly as trustworthy
// as its weakest input. With no inputs it returns [CompletenessUnknown].
func WorstCompleteness(vals ...Completeness) Completeness {
	worst := CompletenessUnknown
	if len(vals) == 0 {
		return worst
	}
	worst = vals[0]
	for _, v := range vals[1:] {
		if v.Rank() > worst.Rank() {
			worst = v
		}
	}
	return worst
}

// State is a requirement's verified implementation state.
type State string

const (
	// StateCompleted means structural evidence shows the requirement is implemented.
	StateCompleted State = "completed"
	// StatePartial means some but not all of the requirement is evidenced.
	StatePartial State = "partial"
	// StateFailed means the checkpoint history shows an attempt that failed.
	StateFailed State = "failed"
	// StateAbandoned means the history shows the requirement was dropped after being planned.
	StateAbandoned State = "abandoned"
	// StateNotVerified means we searched and found no evidence either way. This
	// is NOT a claim that the requirement is missing.
	StateNotVerified State = "not_verified"
	// StateUnknown means we could not even complete the search. Strictly weaker
	// than not_verified.
	StateUnknown State = "unknown"
)

// RiskCategory classifies what kind of harm an unmet requirement causes. It
// drives risk weighting, so that "80% complete" is not reported as fine when the
// missing 20% is authentication.
type RiskCategory string

const (
	RiskSecurity      RiskCategory = "security"
	RiskDataIntegrity RiskCategory = "data_integrity"
	RiskAvailability  RiskCategory = "availability"
	RiskScalability   RiskCategory = "scalability"
	RiskCorrectness   RiskCategory = "correctness"
	RiskPerformance   RiskCategory = "performance"
	RiskObservability RiskCategory = "observability"
	RiskFunctional    RiskCategory = "functional"
)

// RiskLevel is the severity assigned to a finding.
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "critical"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelLow      RiskLevel = "low"
	RiskLevelInfo     RiskLevel = "info"
)

// Requirement is one atomic node of the requirement graph extracted from the
// original ask.
type Requirement struct {
	ID           string       `json:"id"`
	Summary      string       `json:"summary"`
	Parent       string       `json:"parent,omitempty"`
	RiskCategory RiskCategory `json:"risk_category"`
	// RiskWeight scales this requirement's contribution to risk-adjusted
	// coverage. Higher means a gap here matters more.
	RiskWeight float64 `json:"risk_weight"`
	// SearchHints are symbol names or plain-language phrases the evidence stage
	// feeds to the graph. Extracted alongside the requirement so the graph query
	// does not need a second LLM call.
	SearchHints []string `json:"search_hints,omitempty"`
	// SourceCheckpoint is the checkpoint whose prompt this requirement came from.
	SourceCheckpoint string `json:"source_checkpoint,omitempty"`
}

// EvidenceKind names how a piece of evidence was obtained, so a reader can tell
// a structural graph fact from a text match.
type EvidenceKind string

const (
	EvidenceGraphDef       EvidenceKind = "graph_def"
	EvidenceGraphSearch    EvidenceKind = "graph_search"
	EvidenceGraphImpact    EvidenceKind = "graph_impact"
	EvidenceGraphNeighbors EvidenceKind = "graph_neighbors"
	EvidenceGraphCommit    EvidenceKind = "graph_commit"
	EvidenceCheckpoint     EvidenceKind = "checkpoint"
	EvidenceTextSearch     EvidenceKind = "text_search"
)

// Evidence is one citation supporting a requirement's state. Every field here
// is something a human can independently re-run or open — that is the point.
// An LLM assertion is never evidence.
type Evidence struct {
	ID   string       `json:"id"`
	Kind EvidenceKind `json:"kind"`
	// Command is the literal command a reader can re-run to reproduce this.
	Command string `json:"command"`
	// Citation is a file:line, a symbol, a graph relation or a checkpoint ID.
	Citation string `json:"citation"`
	// Detail is a short human-readable note about what was found.
	Detail       string       `json:"detail"`
	Completeness Completeness `json:"context_completeness"`
}

// RequirementState is the audited outcome for one requirement.
type RequirementState struct {
	Requirement  Requirement  `json:"requirement"`
	State        State        `json:"status"`
	Evidence     []Evidence   `json:"evidence"`
	Completeness Completeness `json:"context_completeness"`
	// Authoritative is false whenever the record behind this state was not
	// complete. A false value means the state is a report of what we could see,
	// not a claim about the code.
	Authoritative bool `json:"authoritative"`
	// Notes explains, in the report, why the state is what it is.
	Notes string `json:"notes,omitempty"`
}

// FindingKind distinguishes the two detector outputs plus plain requirement gaps.
type FindingKind string

const (
	// FindingPivot is a planned→attempted→failed→replaced-with chain.
	FindingPivot FindingKind = "pivot"
	// FindingDecisionDrift is a later choice contradicting an earlier stated decision.
	FindingDecisionDrift FindingKind = "decision_drift"
	// FindingRequirementGap is a requirement with no evidence of implementation.
	FindingRequirementGap FindingKind = "requirement_gap"
)

// Finding is one reportable observation. The field set deliberately mirrors the
// report format in FEATURE-SPEC.md: every field is printed even when empty, with
// an explicit "not established" rather than being silently dropped.
type Finding struct {
	ID          string      `json:"finding_id"`
	Kind        FindingKind `json:"kind"`
	Requirement string      `json:"requirement_id,omitempty"`
	// OriginalRequirement, AgentDecision, FailedAttempt, Pivot,
	// CurrentImplementation and RiskInference are the spec's per-finding fields.
	OriginalRequirement   string `json:"original_requirement,omitempty"`
	AgentDecision         string `json:"agent_decision,omitempty"`
	FailedAttempt         string `json:"failed_attempt,omitempty"`
	Pivot                 string `json:"pivot,omitempty"`
	CurrentImplementation string `json:"current_implementation,omitempty"`
	RiskInference         string `json:"risk_inference,omitempty"`

	RiskCategory   RiskCategory `json:"risk_category"`
	RiskLevel      RiskLevel    `json:"risk_level"`
	Summary        string       `json:"finding_summary"`
	Recommendation string       `json:"recommendation,omitempty"`
	EvidenceIDs    []string     `json:"evidence_ids"`
	Checkpoints    []string     `json:"checkpoint_ids"`
	Completeness   Completeness `json:"context_completeness"`
	Authoritative  bool         `json:"authoritative"`
}

// Coverage is the risk-adjusted verdict.
type Coverage struct {
	Total      int     `json:"total_requirements"`
	Completed  int     `json:"completed"`
	Partial    int     `json:"partial"`
	Unverified int     `json:"unverified"`
	RawPercent float64 `json:"raw_percent"`
	// RiskAdjustedPercent weights each requirement by RiskWeight, so missing a
	// high-risk requirement costs more than missing a cosmetic one.
	RiskAdjustedPercent float64   `json:"risk_adjusted_percent"`
	Verdict             RiskLevel `json:"risk_adjusted_verdict"`
	// MissingHighImpact names the specific high-weight requirements that are not
	// evidenced. The verdict is never a bare number; this is the reasoning.
	MissingHighImpact []string     `json:"missing_high_impact"`
	Reasoning         string       `json:"reasoning"`
	Completeness      Completeness `json:"context_completeness"`
	Authoritative     bool         `json:"authoritative"`
}

// Report is the whole audit result.
type Report struct {
	FeatureID      string             `json:"feature_id"`
	RepositoryHash string             `json:"repository_hash"`
	CommitSHA      string             `json:"commit_sha"`
	GeneratedAt    time.Time          `json:"generated_at"`
	Checkpoints    []CheckpointRef    `json:"checkpoints"`
	Requirements   []RequirementState `json:"requirements"`
	Findings       []Finding          `json:"findings"`
	Coverage       Coverage           `json:"coverage"`
	// Limitations records, in the output itself, everything the audit could not
	// establish. An empty audit with an honest limitations list is a valid result.
	Limitations []string `json:"limitations,omitempty"`
}

// CheckpointRef is the non-sensitive identity of a checkpoint that took part in
// the audit. Note there is no prompt or transcript field here by construction.
type CheckpointRef struct {
	ID           string       `json:"id"`
	Date         string       `json:"date"`
	SessionID    string       `json:"session_id,omitempty"`
	Completeness Completeness `json:"context_completeness"`
}
