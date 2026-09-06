package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// The privacy boundary.
//
// Raw prompts, raw transcripts, raw tool arguments and unredacted checkpoint
// payloads never leave this machine. That is enforced structurally: the export
// types below are separate structs with a closed set of fields, built by
// explicit field-by-field construction from the in-memory model. There is no
// path by which adding a field to [Checkpoint] or [Finding] can cause that field
// to be exported, because nothing here marshals those types.
//
// This is deliberately not implemented as a redaction pass over the full record.
// A redactor is a denylist — it fails open the moment someone adds a field it
// does not know about. Field-by-field construction is an allowlist: it fails
// closed. TestExportRecordsCarryNoFreeText locks that property in.

// FeatureRequirementRow is the privacy-approved export shape for the
// `feature_requirements` table. Every field is either an identifier, an
// enumerated value, a number, or a summary the operator's own extractor wrote.
type FeatureRequirementRow struct {
	FeatureID           string  `json:"feature_id"`
	RequirementID       string  `json:"requirement_id"`
	RepositoryHash      string  `json:"repository_hash"`
	CheckpointID        string  `json:"checkpoint_id"`
	RequirementSummary  string  `json:"requirement_summary"`
	Status              string  `json:"status"`
	RiskCategory        string  `json:"risk_category"`
	RiskWeight          float64 `json:"risk_weight"`
	ContextCompleteness string  `json:"context_completeness"`
	Authoritative       bool    `json:"authoritative"`
	EvidenceCount       int     `json:"evidence_count"`
	CreatedAt           string  `json:"created_at"`
}

// RiskFindingRow is the privacy-approved export shape for the `risk_findings`
// table.
type RiskFindingRow struct {
	FindingID           string `json:"finding_id"`
	FeatureID           string `json:"feature_id"`
	CheckpointID        string `json:"checkpoint_id"`
	Kind                string `json:"kind"`
	RiskCategory        string `json:"risk_category"`
	RiskLevel           string `json:"risk_level"`
	FindingSummary      string `json:"finding_summary"`
	EvidenceIDs         string `json:"evidence_ids"`
	Recommendation      string `json:"recommendation"`
	ContextCompleteness string `json:"context_completeness"`
	Authoritative       bool   `json:"authoritative"`
	CreatedAt           string `json:"created_at"`
}

// ExportBundle is everything that may cross the boundary into Databricks.
type ExportBundle struct {
	FeatureRequirements []FeatureRequirementRow `json:"feature_requirements"`
	RiskFindings        []RiskFindingRow        `json:"risk_findings"`
}

// maxSummaryLen bounds any operator-authored summary that crosses the boundary.
// Summaries are short by construction; a long one means something upstream put
// transcript text where a summary belongs, and truncating it bounds the blast
// radius of that bug.
const maxSummaryLen = 300

// secretPatterns match credential shapes that must never be exported even
// inside an otherwise-approved summary field. This is defence in depth behind
// the structural allowlist, not the primary control.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)sk-[a-z0-9_\-]{16,}`),
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)\b(api[_-]?key|secret|password|token|bearer)\b\s*[:=]\s*\S+`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`),
}

// sanitizeSummary bounds and scrubs a single summary field.
func sanitizeSummary(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED-SECRET]")
	}
	if len(s) > maxSummaryLen {
		s = s[:maxSummaryLen] + "…"
	}
	return s
}

// RepositoryHash derives a stable, non-reversible repository identifier. The
// remote URL itself can name a private org or a customer, so the raw value never
// crosses the boundary — but a hash still lets rows from the same repo be joined.
func RepositoryHash(remoteURL string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(remoteURL)))
	return hex.EncodeToString(sum[:])[:16]
}

// BuildExport converts a [Report] into the only shape allowed to leave the
// machine. Note what is not read: Checkpoint.Prompt, Checkpoint.Intent,
// Checkpoint.Message, Evidence.Detail, and every per-finding narrative field
// (AgentDecision, FailedAttempt, Pivot, CurrentImplementation, RiskInference).
// Those stay local. Only the operator-facing Summary and Recommendation cross,
// and only after sanitizeSummary.
func BuildExport(r Report) ExportBundle {
	created := r.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z")
	b := ExportBundle{}

	for _, rs := range r.Requirements {
		cpID := rs.Requirement.SourceCheckpoint
		b.FeatureRequirements = append(b.FeatureRequirements, FeatureRequirementRow{
			FeatureID:           r.FeatureID,
			RequirementID:       rs.Requirement.ID,
			RepositoryHash:      r.RepositoryHash,
			CheckpointID:        cpID,
			RequirementSummary:  sanitizeSummary(rs.Requirement.Summary),
			Status:              string(rs.State),
			RiskCategory:        string(rs.Requirement.RiskCategory),
			RiskWeight:          rs.Requirement.RiskWeight,
			ContextCompleteness: string(rs.Completeness),
			Authoritative:       rs.Authoritative,
			EvidenceCount:       len(rs.Evidence),
			CreatedAt:           created,
		})
	}

	for _, f := range r.Findings {
		cpID := ""
		if len(f.Checkpoints) > 0 {
			cpID = f.Checkpoints[0]
		}
		b.RiskFindings = append(b.RiskFindings, RiskFindingRow{
			FindingID:           f.ID,
			FeatureID:           r.FeatureID,
			CheckpointID:        cpID,
			Kind:                string(f.Kind),
			RiskCategory:        string(f.RiskCategory),
			RiskLevel:           string(f.RiskLevel),
			FindingSummary:      sanitizeSummary(f.Summary),
			EvidenceIDs:         strings.Join(f.EvidenceIDs, ","),
			Recommendation:      sanitizeSummary(f.Recommendation),
			ContextCompleteness: string(f.Completeness),
			Authoritative:       f.Authoritative,
			CreatedAt:           created,
		})
	}
	return b
}

// MarshalExport renders the bundle for shipping.
func MarshalExport(b ExportBundle) ([]byte, error) {
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal export: %w", err)
	}
	return out, nil
}
