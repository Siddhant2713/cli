package audit

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Options configures one audit run.
type Options struct {
	// Dir is the repository root to audit.
	Dir string
	// FeatureID labels this audit's rows. Empty derives one from the branch.
	FeatureID string
	// RequirementsFile supplies a pre-extracted requirement graph instead of
	// calling inference.
	RequirementsFile string
	// Ask overrides the original feature request text. Empty means: use the
	// earliest checkpoint's prompt, which is what the spec calls for.
	Ask string
	// Reader and Graph are injectable so tests can run without a live repo.
	Reader CheckpointReader
	Graph  GraphClient
	// Egress controls whether prompt text may be sent to an external inference
	// service. Default-deny on repositories whose checkpoints are redacted.
	Egress EgressPolicy
	// SkipGraph forces the text-search evidence path, for comparison runs and
	// for environments without the plugin.
	SkipGraph bool
	// Now is injectable to keep golden output stable in tests.
	Now func() time.Time
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Run executes the full audit pipeline: read checkpoints, extract requirements,
// search for evidence, detect pivots and drift, and score risk-adjusted coverage.
//
// The pipeline degrades rather than aborts. Every stage that cannot complete
// appends to Report.Limitations and weakens the affected completeness value, so
// a partial audit is still a usable — and honestly labelled — result.
func Run(ctx context.Context, opts Options) (Report, error) {
	rep := Report{
		GeneratedAt: opts.now(),
		FeatureID:   opts.FeatureID,
	}

	reader := opts.Reader
	if reader == nil {
		reader = CLICheckpointReader{Dir: opts.Dir}
	}

	rep.RepositoryHash = RepositoryHash(gitRemote(ctx, opts.Dir))
	rep.CommitSHA = gitHead(ctx, opts.Dir)
	if rep.FeatureID == "" {
		rep.FeatureID = deriveFeatureID(ctx, opts.Dir)
	}

	// Stage 1+2 — checkpoint sequence.
	cps, cpLimits, err := LoadCheckpoints(ctx, reader)
	if err != nil {
		return rep, fmt.Errorf("read checkpoints: %w", err)
	}
	rep.Limitations = append(rep.Limitations, cpLimits...)
	sort.SliceStable(cps, func(i, j int) bool { return cps[i].Date < cps[j].Date })

	for _, cp := range cps {
		rep.Checkpoints = append(rep.Checkpoints, CheckpointRef{
			ID: cp.ID, Date: cp.Date, SessionID: cp.SessionID, Completeness: cp.Completeness,
		})
	}

	// The original ask: earliest checkpoint's prompt, per the spec.
	ask := opts.Ask
	askCheckpoint := ""
	if ask == "" {
		for _, cp := range cps {
			if p := strings.TrimSpace(cp.Prompt); p != "" && !isRedacted(p) {
				ask, askCheckpoint = p, cp.ID
				break
			}
		}
	}
	if ask == "" && opts.RequirementsFile == "" {
		rep.Limitations = append(rep.Limitations,
			"No usable original prompt was found in the checkpoint history (none present, or all redacted). "+
				"Supply --ask or --requirements to audit against a known requirement set.")
		return rep, fmt.Errorf("no original feature request found in checkpoints: "+
			"pass --ask \"<the original request>\" or --requirements <file.json> (%d checkpoint(s) read)", len(cps))
	}

	// Stage 1 — requirement extraction.
	ext, err := SelectExtractor(opts.RequirementsFile)
	if err != nil {
		return rep, err
	}
	// Privacy boundary: refuse to ship checkpoint prompt text off the machine
	// from a sensitive repository. Checked BEFORE the call, not after.
	if err := AuthorizeExtraction(ext, cps, opts.Egress); err != nil {
		rep.Limitations = append(rep.Limitations,
			"Requirement extraction was blocked by the prompt-egress guard; no prompt text was transmitted.")
		return rep, err
	}
	reqs, err := ext.Extract(ctx, ask)
	if err != nil {
		return rep, fmt.Errorf("extract requirements via %s: %w", ext.Name(), err)
	}
	for i := range reqs {
		if reqs[i].SourceCheckpoint == "" {
			reqs[i].SourceCheckpoint = askCheckpoint
		}
	}

	// Stage 3 — evidence.
	collector := &EvidenceCollector{Dir: opts.Dir, RequirementsFile: opts.RequirementsFile}
	if !opts.SkipGraph {
		if opts.Graph != nil {
			collector.Graph = opts.Graph
		} else {
			collector.Graph = &CLIGraphClient{Dir: opts.Dir}
		}
	} else {
		rep.Limitations = append(rep.Limitations,
			"--no-graph was set: all evidence is lexical text search, which cannot establish structural facts.")
	}

	for _, req := range reqs {
		ev, quality, lims := collector.Collect(ctx, req)
		rep.Limitations = append(rep.Limitations, lims...)
		state, comp, notes := StateFromEvidence(ev, quality)

		// A conclusion can never be more complete than the checkpoint record it
		// was reasoned over.
		comp = WorstCompleteness(comp, overallCheckpointCompleteness(cps))

		ids := make([]string, 0, len(ev))
		for _, e := range ev {
			ids = append(ids, e.ID)
		}
		_ = ids

		rep.Requirements = append(rep.Requirements, RequirementState{
			Requirement:   req,
			State:         state,
			Evidence:      ev,
			Completeness:  comp,
			Authoritative: comp.Authoritative() && state == StateCompleted,
			Notes:         notes,
		})
	}

	// Stage 4 — pivots and decision drift.
	rep.Findings = append(rep.Findings, DetectPivots(cps)...)
	rep.Findings = append(rep.Findings, DetectDecisionDrift(cps)...)
	rep.Findings = append(rep.Findings, GapFindings(rep.Requirements)...)

	// Wire evidence IDs onto gap findings so a reader can follow the citation.
	byReq := map[string][]string{}
	for _, rs := range rep.Requirements {
		for _, e := range rs.Evidence {
			byReq[rs.Requirement.ID] = append(byReq[rs.Requirement.ID], e.ID)
		}
	}
	for i := range rep.Findings {
		if ids, ok := byReq[rep.Findings[i].Requirement]; ok {
			rep.Findings[i].EvidenceIDs = ids
		}
	}

	// Stage 5 — risk-adjusted coverage.
	rep.Coverage = ComputeCoverage(rep.Requirements)
	rep.Limitations = append(rep.Limitations,
		fmt.Sprintf("Requirement extraction backend: %s. The requirement graph is a model's or an operator's "+
			"reading of the original ask, not a specification — review it before acting on the coverage number.", ext.Name()))

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		return riskRank(rep.Findings[i].RiskLevel) < riskRank(rep.Findings[j].RiskLevel)
	})
	return rep, nil
}

// overallCheckpointCompleteness is the weakest completeness across the record.
// With no checkpoints at all it is unknown, not complete: an audit that read
// nothing has not verified anything.
func overallCheckpointCompleteness(cps []Checkpoint) Completeness {
	if len(cps) == 0 {
		return CompletenessUnknown
	}
	vals := make([]Completeness, 0, len(cps))
	for _, cp := range cps {
		vals = append(vals, cp.Completeness)
	}
	return WorstCompleteness(vals...)
}

func riskRank(l RiskLevel) int {
	switch l {
	case RiskLevelCritical:
		return 0
	case RiskLevelHigh:
		return 1
	case RiskLevelMedium:
		return 2
	case RiskLevelLow:
		return 3
	default:
		return 4
	}
}

func gitOutput(ctx context.Context, dir string, args ...string) string {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitRemote(ctx context.Context, dir string) string {
	return gitOutput(ctx, dir, "remote", "get-url", "origin")
}

func gitHead(ctx context.Context, dir string) string {
	return gitOutput(ctx, dir, "rev-parse", "HEAD")
}

func deriveFeatureID(ctx context.Context, dir string) string {
	branch := gitOutput(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD")
	if branch == "" {
		return "unknown_feature"
	}
	r := strings.NewReplacer("/", "_", "-", "_", " ", "_")
	return r.Replace(branch)
}
