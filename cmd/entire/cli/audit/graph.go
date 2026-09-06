package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// GraphClient runs Entire Graph queries. Behind an interface so the audit can be
// tested without a graph plugin installed, and so a missing plugin degrades the
// run to text evidence instead of failing it.
type GraphClient interface {
	// Def looks up what a name IS: declaration, file, line.
	Def(ctx context.Context, symbol string) (*GraphDef, error)
	// Search finds code for a plain-language task description.
	Search(ctx context.Context, query string, topK int) (*GraphSearch, error)
	// Impact reports the blast radius of a symbol — who calls it, what it calls.
	Impact(ctx context.Context, symbol string) (*GraphImpact, error)
	// Available reports whether graph queries can run at all.
	Available(ctx context.Context) bool
}

// GraphDef is the subset of `entire graph def --format json` the audit uses.
type GraphDef struct {
	Query        string            `json:"query"`
	Commit       string            `json:"commit"`
	Declarations []GraphDecl       `json:"declarations"`
	Warnings     []GraphDiagnostic `json:"warnings"`
	PartialFails []GraphDiagnostic `json:"partial_failures"`
}

// GraphDecl is one declaration returned by a def lookup.
type GraphDecl struct {
	Name          string `json:"name"`
	QualifiedName string `json:"qualified_name"`
	Kind          string `json:"kind"`
	Language      string `json:"language"`
	Signature     string `json:"signature"`
	FilePath      string `json:"file_path"`
	StartLine     int    `json:"start_line"`
	EndLine       int    `json:"end_line"`
}

// Citation renders a re-checkable file:line reference.
func (d GraphDecl) Citation() string { return fmt.Sprintf("%s:%d", d.FilePath, d.StartLine) }

// GraphDiagnostic is a warning or partial failure reported by the graph. These
// are the machine-readable basis for downgrading context completeness — the
// graph tells us when its own view was incomplete, so we never have to guess.
type GraphDiagnostic struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	FilePath string `json:"file_path,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Effect   string `json:"effect_on_semantic_completeness,omitempty"`
}

// GraphSearch is the subset of `entire graph search --format json` used here.
type GraphSearch struct {
	Query   string              `json:"query"`
	Commit  string              `json:"commit"`
	Results []GraphSearchResult `json:"results"`
}

// GraphSearchResult is one ranked hit.
type GraphSearchResult struct {
	Rank       int      `json:"rank"`
	Score      float64  `json:"score"`
	FilePath   string   `json:"file_path"`
	StartLine  int      `json:"start_line"`
	SymbolName string   `json:"symbol_name"`
	Kind       string   `json:"kind"`
	Signature  string   `json:"signature"`
	Signals    []string `json:"signals"`
}

// Citation renders a re-checkable file:line reference.
func (r GraphSearchResult) Citation() string { return fmt.Sprintf("%s:%d", r.FilePath, r.StartLine) }

// GraphImpact is the subset of `entire graph impact --format json` used here.
type GraphImpact struct {
	Query    string            `json:"query"`
	Commit   string            `json:"commit"`
	Focus    GraphDecl         `json:"focus"`
	Callers  GraphEdges        `json:"callers"`
	Callees  GraphEdges        `json:"callees"`
	Warnings []GraphDiagnostic `json:"warnings"`
}

// GraphEdges is a relation bucket with its totals.
type GraphEdges struct {
	Total   int              `json:"total"`
	Direct  int              `json:"direct"`
	Entries []GraphEdgeEntry `json:"entries"`
}

// GraphEdgeEntry is one endpoint of a relation.
type GraphEdgeEntry struct {
	Endpoint struct {
		Name      string `json:"name"`
		FilePath  string `json:"file_path"`
		StartLine int    `json:"start_line"`
	} `json:"endpoint"`
	Relation string `json:"relation"`
}

// CLIGraphClient runs the real `entire graph` plugin.
type CLIGraphClient struct {
	// Bin is the entire binary to invoke; empty means this running executable.
	Bin string
	// Dir is the repository to query.
	Dir string
	// Timeout bounds a single query. A cold graph index build on this repo takes
	// ~48s, so the default must be generous, but an audit must never hang.
	Timeout time.Duration
	// LastCommand records the most recent command line, so the report can cite
	// exactly what a reader should re-run.
	LastCommand string
}

func (g *CLIGraphClient) timeout() time.Duration {
	if g.Timeout > 0 {
		return g.Timeout
	}
	return 90 * time.Second
}

func (g *CLIGraphClient) run(ctx context.Context, args ...string) ([]byte, string, error) {
	bin := g.Bin
	if bin == "" {
		var err error
		if bin, err = os.Executable(); err != nil {
			return nil, "", fmt.Errorf("locate entire binary: %w", err)
		}
	}
	line := "entire " + strings.Join(args, " ")
	g.LastCommand = line

	ctx, cancel := context.WithTimeout(ctx, g.timeout())
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = g.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := bytes.TrimSpace(stdout.Bytes())
	if err != nil {
		return nil, line, fmt.Errorf("%s: %w: %s", line, err, strings.TrimSpace(stderr.String()))
	}
	// Without the graph plugin installed, `entire graph ...` prints the root
	// help text and exits 0. Detect that rather than reporting an empty result,
	// which would look like "the symbol does not exist" — exactly the kind of
	// false negative this whole feature exists to prevent.
	if len(out) == 0 || out[0] != '{' {
		return nil, line, fmt.Errorf("%s: graph plugin not available (no JSON returned); run `entire plugin install graph`", line)
	}
	return out, line, nil
}

// Available implements [GraphClient].
func (g *CLIGraphClient) Available(ctx context.Context) bool {
	bin := g.Bin
	if bin == "" {
		var err error
		if bin, err = os.Executable(); err != nil {
			return false
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "graph", "version")
	cmd.Dir = g.Dir
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	// `graph version` prints a bare version like "v0.4.0" when installed, and the
	// root help listing when not.
	return strings.HasPrefix(strings.TrimSpace(string(out)), "v")
}

// Def implements [GraphClient].
func (g *CLIGraphClient) Def(ctx context.Context, symbol string) (*GraphDef, error) {
	out, line, err := g.run(ctx, "graph", "def", symbol, "--repo", ".", "--format", "json")
	if err != nil {
		return nil, err
	}
	var d GraphDef
	if err := json.Unmarshal(out, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", line, err)
	}
	return &d, nil
}

// Search implements [GraphClient].
func (g *CLIGraphClient) Search(ctx context.Context, query string, topK int) (*GraphSearch, error) {
	if topK <= 0 {
		topK = 5
	}
	out, line, err := g.run(ctx, "graph", "search", "--repo", ".", "--query", query,
		"--top-k", fmt.Sprint(topK), "--format", "json")
	if err != nil {
		return nil, err
	}
	var s GraphSearch
	if err := json.Unmarshal(out, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", line, err)
	}
	return &s, nil
}

// Impact implements [GraphClient].
func (g *CLIGraphClient) Impact(ctx context.Context, symbol string) (*GraphImpact, error) {
	out, line, err := g.run(ctx, "graph", "impact", "--repo", ".", "--symbol", symbol, "--format", "json")
	if err != nil {
		return nil, err
	}
	var i GraphImpact
	if err := json.Unmarshal(out, &i); err != nil {
		return nil, fmt.Errorf("parse %s: %w", line, err)
	}
	return &i, nil
}

// completenessFromDiagnostics maps the graph's own warnings onto the audit's
// completeness scale. A partial parse failure means the graph did not see the
// whole tree, so any absence it reports is not authoritative.
func completenessFromDiagnostics(warnings, partials []GraphDiagnostic) Completeness {
	for _, p := range partials {
		if p.Severity == "error" {
			return CompletenessPartial
		}
	}
	if len(partials) > 0 {
		return CompletenessPartial
	}
	for _, w := range warnings {
		// A worktree snapshot is a complete read of the tree we were asked about.
		if w.Code == "W_WORKTREE_SNAPSHOT" {
			continue
		}
		if w.Severity == "error" || w.Severity == "warning" {
			return CompletenessPartial
		}
	}
	return CompletenessComplete
}
