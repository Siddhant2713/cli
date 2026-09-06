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
	// AgentNarrative is what the AGENT said it did, separated from what the user
	// asked for. The distinction is load-bearing for pivot detection: a prompt
	// saying "if Redis does not work, use something else" is an instruction, not
	// a record that a pivot happened. Matching it produces a confident finding
	// about an event that never occurred.
	AgentNarrative string `json:"agent_narrative"`
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
// Narrative returns the text pivot and drift detection run over.
//
// It deliberately excludes the user's prompt. What the user asked for is not
// evidence of what happened — an instruction like "if Redis does not work, use
// something else" would otherwise be matched as a completed attempt→failure→
// pivot chain, producing a confident finding about an event that never occurred.
// Only the agent's own account of its work, plus the commit message and intent,
// count as a record of what was done.
func (c Checkpoint) Narrative() string {
	var parts []string
	for _, s := range []string{c.Message, c.Intent, c.AgentNarrative} {
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

// listItem covers BOTH shapes `entire checkpoint list` emits, which do not use
// the same key names: the condensed view keys the identifier as
// "checkpoint_id", while --pending keys it as "id" and puts the real checkpoint
// ID in "condensation_id" when the entry is logs-only. Decoding only one of
// them yields entries with a blank ID that then fail to explain — silently
// turning a readable history into "missing", which is exactly the false signal
// this feature exists to prevent. Observed live; see .agent-log/learnings.md.
type listItem struct {
	ID             string `json:"id"`
	CheckpointID   string `json:"checkpoint_id"`
	CondensationID string `json:"condensation_id"`
	Message        string `json:"message"`
	Date           string `json:"date"`
	SessionID      string `json:"session_id"`
	SessionPrompt  string `json:"session_prompt"`
	Commit         string `json:"commit"`
	CommitSHA      string `json:"commit_sha"`
}

// List implements [CheckpointReader].
//
// It reads the condensed view and the pending (live shadow-branch) view and
// unions them. Neither is a superset of the other: condensation runs
// asynchronously, so recent work appears only in --pending, while older
// logs-only resume points also appear only there. Reading one view alone would
// silently drop real history and can report "no checkpoints" on a branch that
// has been worked on all morning — making the audit vacuously clean, which is
// the exact false signal this feature exists to prevent.
func (r CLICheckpointReader) List(ctx context.Context) ([]Checkpoint, error) {
	condensed, err := r.list(ctx, false)
	if err != nil {
		return nil, err
	}
	// Union rather than either/or. The two views overlap but neither is a
	// superset: condensation runs asynchronously, so recent work appears only in
	// --pending, while older logs-only resume points appear only there too.
	// Taking just one view silently drops real history from the audit.
	pending, perr := r.list(ctx, true)
	if perr != nil {
		return condensed, nil
	}
	for i := range pending {
		// Pending entries carry less metadata than condensed ones, so a
		// conclusion drawn from them starts one notch below complete.
		pending[i].Completeness = WorstCompleteness(pending[i].Completeness, CompletenessPartial)
	}

	seen := map[string]bool{}
	out := make([]Checkpoint, 0, len(condensed)+len(pending))
	for _, cp := range append(condensed, pending...) {
		key := cp.ID
		if key == "" {
			key = cp.Commit
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, cp)
	}
	return out, nil
}

func (r CLICheckpointReader) list(ctx context.Context, pending bool) ([]Checkpoint, error) {
	args := []string{"checkpoint", "list", "--json", "--no-pager"}
	if pending {
		args = append(args, "--pending")
	}
	out, err := r.run(ctx, args...)
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
		// Resolve the identifier across both list shapes. In the pending view
		// "id" is the commit SHA and the real checkpoint ID lives in
		// condensation_id; in the condensed view it is "checkpoint_id".
		// `checkpoint explain` resolves either form, but the report should cite
		// the checkpoint ID a reader can look up.
		id := it.CheckpointID
		if id == "" {
			id = it.ID
		}
		if it.CondensationID != "" {
			if sha == "" {
				sha = it.ID
			}
			id = it.CondensationID
		}
		cps = append(cps, Checkpoint{
			ID:        id,
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
// human output.
//
// The real format, verified against the running CLI, is a header block of
// "  key  value" lines followed by "## Intent", "## Summary", "## Files" and a
// "── Transcript" section. This parser is deliberately forgiving: a field it
// cannot find stays empty and downgrades completeness, rather than being guessed
// at. A wrong guess here becomes a false claim three stages downstream.
func parseExplainText(id, text string) Checkpoint {
	cp := Checkpoint{ID: id}

	var intent, transcript, agent []string
	section := ""
	speaker := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)

		// Section headers.
		switch {
		case strings.HasPrefix(line, "## Intent"):
			section = "intent"
			continue
		case strings.HasPrefix(line, "## Summary"):
			section = "summary"
			continue
		case strings.HasPrefix(line, "## Files"):
			section = "files"
			continue
		case strings.Contains(line, "Transcript"):
			section = "transcript"
			continue
		case strings.HasPrefix(line, "## "):
			section = ""
			continue
		}

		// Header block: "session  <id>", "commits  <sha>".
		if fields := strings.Fields(line); len(fields) >= 2 && section == "" {
			switch fields[0] {
			case "session":
				cp.SessionID = fields[1]
				continue
			case "commits":
				if fields[1] != "(none" {
					cp.Commit = fields[1]
				}
				continue
			case "created":
				if cp.Date == "" {
					cp.Date = strings.Join(fields[1:], " ")
				}
				continue
			}
		}

		if line == "" || strings.HasPrefix(line, "─") || strings.HasPrefix(line, "●") {
			continue
		}

		switch section {
		case "intent":
			intent = append(intent, line)
		case "files":
			cp.Files = append(cp.Files, strings.Trim(line, "-` "))
		case "transcript":
			// The transcript is speaker-tagged: "[User] ...", "[Assistant] ...",
			// "[Tool] ...". Track who is speaking so the agent's account of its
			// own work stays separable from the instruction it was given.
			switch {
			case strings.HasPrefix(line, "[User]"):
				speaker = "user"
				line = strings.TrimSpace(strings.TrimPrefix(line, "[User]"))
			case strings.HasPrefix(line, "[Assistant]"):
				speaker = "assistant"
				line = strings.TrimSpace(strings.TrimPrefix(line, "[Assistant]"))
			case strings.HasPrefix(line, "[Tool]"):
				speaker = "tool"
				line = strings.TrimSpace(strings.TrimPrefix(line, "[Tool]"))
			}
			if line == "" {
				continue
			}
			transcript = append(transcript, line)
			if speaker == "assistant" {
				agent = append(agent, line)
			}
		}
	}

	cp.Intent = strings.Join(intent, " ")
	// The transcript is the richest narrative source for pivot and drift
	// detection. It stays in memory and never crosses the privacy boundary —
	// see privacy.go, where the export types have no field that could hold it.
	cp.Prompt = strings.Join(transcript, "\n")
	cp.AgentNarrative = strings.Join(agent, "\n")

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
		if full.AgentNarrative != "" {
			merged.AgentNarrative = full.AgentNarrative
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
