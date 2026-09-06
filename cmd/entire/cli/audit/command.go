package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// NewCommand builds `entire audit`.
//
// Registered as experimental in root.go: the requirement graph depends on a
// model's reading of the original ask, so the coverage number is a review aid,
// not a gate. Shipping it as stable would invite exactly the over-trust the
// feature is designed to argue against.
func NewCommand() *cobra.Command {
	var (
		jsonOut          bool
		requirementsFile string
		ask              string
		featureID        string
		noGraph          bool
		allowEgress      bool
		sensitive        bool
		exportDir        string
		pushDatabricks   bool
		repoDir          string
		failOn           string
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit a feature's checkpoint history for requirement gaps, pivots and decision drift",
		Long: `Audit reads the checkpoint history of the current branch, decomposes the original
request into a requirement graph, searches the Entire Graph for structural evidence that each
requirement was implemented, detects pivots and decision contradictions across checkpoints, and
reports risk-adjusted coverage.

Every finding carries a context_completeness value and an authoritative flag. A requirement with
no evidence is reported as "could not be verified" — never as "was not implemented". Those are
different claims, and only the first one is earned by an absence of evidence.

Inference backend, in order of preference:
  1. --requirements <file.json>   an operator-supplied requirement graph (no inference at all)
  2. ANTHROPIC_API_KEY            bring your own key
  3. a headless 'claude' CLI      run read-only, with no tool access
There is no hosted fallback: audit never sends your prompts to an Entire-operated model.

Raw prompts and transcripts never leave the machine. The Databricks export is built by
field-by-field construction from an allowlist of derived fields; see privacy.go.`,
		Example: `  entire audit
  entire audit --json
  entire audit --requirements reqs.json --no-graph
  entire audit --ask "build user authentication with rate limiting"
  entire audit --export ./audit-export --databricks`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir := repoDir
			if dir == "" {
				wd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("determine working directory: %w", err)
				}
				dir = wd
			}
			return run(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), runConfig{
				Options: Options{
					Dir:              dir,
					FeatureID:        featureID,
					RequirementsFile: requirementsFile,
					Ask:              ask,
					SkipGraph:        noGraph,
					Egress:           EgressPolicy{AllowPromptEgress: allowEgress, Sensitive: sensitive},
				},
				JSON:           jsonOut,
				ExportDir:      exportDir,
				PushDatabricks: pushDatabricks,
				FailOn:         failOn,
			})
		},
	}

	f := cmd.Flags()
	f.BoolVar(&jsonOut, "json", false, "Output the full report as JSON instead of the human view")
	f.StringVar(&requirementsFile, "requirements", "", "Path to a pre-extracted requirement graph (skips inference)")
	f.StringVar(&ask, "ask", "", "The original feature request (default: the earliest checkpoint's prompt)")
	f.StringVar(&featureID, "feature-id", "", "Label for this audit's exported rows (default: derived from the branch)")
	f.BoolVar(&noGraph, "no-graph", false, "Skip Entire Graph queries and use text search only")
	f.StringVar(&exportDir, "export", "", "Write the privacy-safe Databricks export (NDJSON + DDL) to this directory")
	f.BoolVar(&pushDatabricks, "databricks", false, "Also push the export to Databricks (needs DATABRICKS_HOST/TOKEN/WAREHOUSE_ID)")
	f.BoolVar(&allowEgress, "allow-prompt-egress", false,
		"Explicitly permit sending checkpoint prompt text to an external inference service on a sensitive repository")
	f.BoolVar(&sensitive, "sensitive", false,
		"Treat this repository as sensitive: never send prompt text off the machine (implies --requirements)")
	f.StringVar(&repoDir, "repo", "", "Repository to audit (default: current directory)")
	f.StringVar(&failOn, "fail-on", "", "Exit non-zero when the risk verdict is at or above this level: low|medium|high|critical")
	return cmd
}

type runConfig struct {
	Options
	JSON           bool
	ExportDir      string
	PushDatabricks bool
	FailOn         string
}

// ErrRiskThreshold is returned when --fail-on is met, so CI can gate on it.
var ErrRiskThreshold = errors.New("risk verdict at or above --fail-on threshold")

func run(ctx context.Context, out, errOut io.Writer, cfg runConfig) error {
	rep, err := Run(ctx, cfg.Options)
	if err != nil {
		// The no-inference error is a configuration problem with a known fix,
		// so it is surfaced as guidance rather than a stack-shaped failure.
		if errors.Is(err, ErrNoInference) {
			return err
		}
		return err
	}

	if cfg.JSON {
		if err := RenderJSON(out, rep); err != nil {
			return err
		}
	} else if err := RenderText(out, rep); err != nil {
		return err
	}

	// The export is built from the report through the privacy allowlist. It is
	// written before any network call so the artifact exists even if the push
	// fails.
	if cfg.ExportDir != "" || cfg.PushDatabricks {
		bundle := BuildExport(rep)
		dir := cfg.ExportDir
		if dir == "" {
			dir = "./entire-audit-export"
		}
		dcfg := DatabricksConfigFromEnv()
		written, err := WriteStaticExport(dir, dcfg, bundle)
		if err != nil {
			return fmt.Errorf("write export: %w", err)
		}
		fmt.Fprintf(errOut, "\nPrivacy-safe export written (%d requirement rows, %d finding rows):\n",
			len(bundle.FeatureRequirements), len(bundle.RiskFindings))
		for _, p := range written {
			fmt.Fprintf(errOut, "  %s\n", p)
		}

		if cfg.PushDatabricks {
			if !dcfg.Configured() {
				fmt.Fprintf(errOut, "\nDatabricks push skipped: set DATABRICKS_HOST, DATABRICKS_TOKEN and "+
					"DATABRICKS_WAREHOUSE_ID. The static export above is the reproducible artifact and is complete.\n")
			} else {
				pctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
				defer cancel()
				if err := PushToDatabricks(pctx, dcfg, bundle); err != nil {
					// A failed push must not fail the audit: the report and the
					// static export are the deliverable, Databricks is delivery.
					fmt.Fprintf(errOut, "\nDatabricks push failed: %v\n"+
						"The static export above is unaffected and can be loaded with schema.sql.\n", err)
				} else {
					fmt.Fprintf(errOut, "\nPushed to %s.%s.{feature_requirements,risk_findings} on %s\n",
						dcfg.Catalog, dcfg.Schema, dcfg.Host)
				}
			}
		}
	}

	if cfg.FailOn != "" {
		threshold := RiskLevel(cfg.FailOn)
		if riskRank(rep.Coverage.Verdict) <= riskRank(threshold) {
			return fmt.Errorf("%w: verdict %s (threshold %s)", ErrRiskThreshold, rep.Coverage.Verdict, threshold)
		}
	}
	return nil
}
