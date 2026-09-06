package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Checkpoint is the audit-side view of one checkpoint. It intentionally holds
// the narrative text needed for pivot and drift detection — this struct never
// crosses the privacy boundary; see privacy.go.
type Checkpoint struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	Date      string `json:"date"`
	SessionID string `json:"session_id"`
	// Prompt is the scoped prompt attributed to this checkpoint. May be empty or
	// literally "[REDACTED]" — both are handled, neither is treated as absence
	// of the underlying work.
	Prompt string `json:"prompt"`
	// Intent is the checkpoint's own summary of what it did.
	Intent string `json:"intent"`
	// Files changed in this checkpoint's commit.
	Files []string `json:"files"`
	// Commit is the commit SHA carrying this checkpoint's Entire-Checkpoint trailer.
	Commit string `json:"commit"`
	// Completeness is derived from what the reader actually got back, not asserted.
	Completeness Completeness `json:"context_completeness"`
}

// Redacted reports whether this checkpoint's narrative content was withheld.
func (c Checkpoint) Redacted() bool {
	return isRedacted(c.Prompt) || isRedacted(c.Intent) || isRedacted(c.Message)
}

func isRedacted(s string) bool {
	t := strings.TrimSpace(strings.ToUpper(s))
	return t == "[REDACTED]" || t == "<REDACTED>" || t == "REDACTED"
}

// Narrative returns the text available for pivot/drift pattern matching, with
// redacted fields dropped rather than matched as literal text.
func (c Checkpoint) Narrative() string {
	var parts []string
	for _, s := range []string{c.Message, c.Intent, c.Prompt} {
		if s != "" && !isRedacted(s) {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n")
}

// CheckpointReader supplies the checkpoint sequence to audit. The interface
// exists so tests can inject a redacted/missing fixture without a live repo —
// that fixture is the mandatory privacy test.
type CheckpointReader interface {
	// List returns checkpoints on the current branch, oldest first.
	List(ctx context.Context) ([]Checkpoint, error)
	// Explain enriches one checkpoint with its narrative detail.
	Explain(ctx context.Context, id string) (Checkpoint, error)
}

// CLICheckpointReader reads checkpoints by shelling out to this same binary's
// `entire checkpoint` subcommands.
//
// Subprocess rather than importing cmd/entire/cli/checkpoint directly: that
// package's readers require a threaded git store and repo context, and its
// on-disk layout is internal and changes freely, whereas `--json` output is the
// documented contract. See .agent-log/decisions.md.
type CLICheckpointReader struct {
	// Bin is the entire binary to invoke. Empty means this running executable.
	Bin string
	// Dir is the repository to run in.
	Dir string
}

func (r CLICheckpointReader) bin() (string, error) {
	if r.Bin != "" {
		return r.Bin, nil
	}
	return os.Executable()
}

// run executes an entire subcommand and returns only stdout. stderr is
// discarded from the parse deliberately: `checkpoint list` prints
// "could not reach checkpoint remote" to stderr while still writing valid JSON
// to stdout, and merging the two corrupts the parse.
func (r CLICheckpointReader) run(ctx context.Context, args ...string) ([]byte, error) {
	bin, err := r.bin()
	if err != nil {
		return nil, fmt.Errorf("locate entire binary: %w", err)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = r.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("entire %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

type listItem struct {
	ID            string `json:"id"`
	Message       string `json:"message"`
	Date          string `json:"date"`
	SessionID     string `json:"session_id"`
	SessionPrompt string `json:"session_prompt"`
	Commit        string `json:"commit"`
	CommitSHA     string `json:"commit_sha"`
}

// List implements [CheckpointReader].
func (r CLICheckpointReader) List(ctx context.Context) ([]Checkpoint, error) {
	out, err := r.run(ctx, "checkpoint", "list", "--json", "--no-pager")
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(out)
	// An unrecognised flag makes the CLI print its root help and exit cleanly,
	// which would otherwise be silently read as "no checkpoints". Fail loudly.
	if len(trimmed) == 0 || (trimmed[0] != '[' && trimmed[0] != '{') {
		return nil, fmt.Errorf("checkpoint list did not return JSON (got %.60q) — is this an Entire-enabled repo?", trimmed)
	}
	var items []listItem
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, fmt.Errorf("parse checkpoint list: %w", err)
	}
	cps := make([]Checkpoint, 0, len(items))
	for _, it := range items {
		sha := it.Commit
		if sha == "" {
			sha = it.CommitSHA
		}
		cps = append(cps, Checkpoint{
			ID:        it.ID,
			Message:   it.Message,
			Date:      it.Date,
			SessionID: it.SessionID,
			Prompt:    it.SessionPrompt,
			Commit:    sha,
			// The list view carries identity and message but not the full
			// narrative, so it is partial until Explain fills it in.
			Completeness: CompletenessPartial,
		})
	}
	return cps, nil
}

// Explain implements [CheckpointReader]. It reads the human view rather than
// asking for regeneration: `--generate` shells out to an LLM CLI and costs real
// time, and an audit should read the record that exists, not create new record.
func (r CLICheckpointReader) Explain(ctx context.Context, id string) (Checkpoint, error) {
	out, err := r.run(ctx, "checkpoint", "explain", id, "--no-pager")
	if err != nil {
		return Checkpoint{ID: id, Completeness: CompletenessMissing}, err
	}
	cp := parseExplainText(id, string(out))
	return cp, nil
}

// parseExplainText pulls the fields the audit needs out of `checkpoint explain`'s
// human output. It is deliberately forgiving: a field it cannot find stays empty
// and downgrades completeness, rather than being guessed at.
func parseExplainText(id, text string) Checkpoint {
	cp := Checkpoint{ID: id}
	var promptLines []string
	inPrompts := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Intent:"):
			cp.Intent = strings.TrimSpace(strings.TrimPrefix(line, "Intent:"))
			inPrompts = false
		case strings.HasPrefix(line, "Session:"):
			cp.SessionID = strings.Fields(strings.TrimPrefix(line, "Session:"))[0]
			inPrompts = false
		case strings.HasPrefix(line, "Commit:"):
			f := strings.Fields(strings.TrimPrefix(line, "Commit:"))
			if len(f) > 0 {
				cp.Commit = f[0]
			}
			inPrompts = false
		case strings.HasPrefix(line, "Files"):
			inPrompts = false
		case strings.HasPrefix(line, "Prompts") || strings.HasPrefix(line, "Prompt:"):
			inPrompts = true
		case inPrompts && line != "":
			promptLines = append(promptLines, line)
		}
	}
	cp.Prompt = strings.Join(promptLines, "\n")

	switch {
	case cp.Redacted():
		cp.Completeness = CompletenessRedacted
	case cp.Intent == "" && cp.Prompt == "":
		cp.Completeness = CompletenessMissing
	case cp.Intent == "" || cp.Prompt == "":
		cp.Completeness = CompletenessPartial
	default:
		cp.Completeness = CompletenessComplete
	}
	return cp
}

// LoadCheckpoints reads the sequence and enriches each entry, tolerating
// per-checkpoint failures: one unreadable checkpoint degrades that checkpoint to
// missing and the overall audit to partial, it does not abort the run.
func LoadCheckpoints(ctx context.Context, r CheckpointReader) ([]Checkpoint, []string, error) {
	list, err := r.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	var limitations []string
	out := make([]Checkpoint, 0, len(list))
	for _, cp := range list {
		full, err := r.Explain(ctx, cp.ID)
		if err != nil {
			cp.Completeness = CompletenessMissing
			limitations = append(limitations, fmt.Sprintf("checkpoint %s could not be explained: %v", cp.ID, err))
			out = append(out, cp)
			continue
		}
		merged := cp
		if full.Intent != "" {
			merged.Intent = full.Intent
		}
		if full.Prompt != "" {
			merged.Prompt = full.Prompt
		}
		if full.Commit != "" {
			merged.Commit = full.Commit
		}
		if full.SessionID != "" {
			merged.SessionID = full.SessionID
		}
		merged.Completeness = full.Completeness
		if merged.Redacted() {
			merged.Completeness = CompletenessRedacted
			limitations = append(limitations, fmt.Sprintf("checkpoint %s is redacted; findings depending on it are not authoritative", cp.ID))
		}
		out = append(out, merged)
	}
	return out, limitations, nil
}
