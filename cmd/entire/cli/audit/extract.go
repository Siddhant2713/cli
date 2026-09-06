package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ErrNoInference is returned when neither BYOK nor a headless agent is
// configured. There is deliberately no hosted or proxy fallback: the audit
// either uses inference the operator controls, or it fails loudly and tells them
// how to fix it. A silent degradation here would produce an empty requirement
// graph, which reads as "nothing was required" — a false authoritative claim.
var ErrNoInference = errors.New("no inference backend configured")

// Extractor turns the original ask into a requirement graph.
type Extractor interface {
	Extract(ctx context.Context, ask string) ([]Requirement, error)
	// Name identifies the backend in the report, so a reader knows what produced
	// the requirement list.
	Name() string
}

const extractSystemPrompt = `You decompose a software feature request into atomic, independently verifiable requirements.

Rules:
- Each requirement is ONE testable capability. Never bundle two capabilities into one node.
- Include requirements that are implied by professional practice for the stated feature even
  if not spelled out (e.g. a login feature implies password hashing and session invalidation).
- risk_category is one of: security, data_integrity, availability, scalability, correctness,
  performance, observability, functional.
- risk_weight is 1.0-5.0. Security and data_integrity gaps that expose users are 4.0-5.0.
  Cosmetic or convenience items are 1.0-2.0.
- search_hints are 2-4 concrete identifier names or short phrases that would appear in code
  implementing this requirement. These are fed to a code-graph search verbatim.

Return ONLY a JSON object of the form:
{"requirements":[{"id":"snake_case_id","summary":"...","risk_category":"...","risk_weight":3.0,"search_hints":["..."]}]}
No prose, no markdown fences.`

type extractEnvelope struct {
	Requirements []Requirement `json:"requirements"`
}

// parseRequirements pulls the requirement array out of a model response,
// tolerating markdown fences and leading prose that models sometimes add.
func parseRequirements(raw string) ([]Requirement, error) {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "```"); i >= 0 {
		s = s[i+3:]
		s = strings.TrimPrefix(s, "json")
		if j := strings.Index(s, "```"); j >= 0 {
			s = s[:j]
		}
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON object in model response (got %.120q)", raw)
	}
	var env extractEnvelope
	if err := json.Unmarshal([]byte(s[start:end+1]), &env); err != nil {
		return nil, fmt.Errorf("parse requirement JSON: %w", err)
	}
	if len(env.Requirements) == 0 {
		return nil, errors.New("model returned zero requirements")
	}
	for i := range env.Requirements {
		if env.Requirements[i].RiskWeight <= 0 {
			env.Requirements[i].RiskWeight = 2.0
		}
		if env.Requirements[i].RiskCategory == "" {
			env.Requirements[i].RiskCategory = RiskFunctional
		}
	}
	return env.Requirements, nil
}

// AnthropicExtractor calls the Anthropic Messages API with a bring-your-own key.
//
// Written against net/http rather than pulling in an SDK: adding a module
// dependency requires passing this repo's license allowlist check, which is not
// a deadline-day activity. See .agent-log/decisions.md.
type AnthropicExtractor struct {
	APIKey string
	Model  string
	HTTP   *http.Client
	// BaseURL is overridable for tests. Empty means the real API.
	BaseURL string
}

// Name implements [Extractor].
func (a AnthropicExtractor) Name() string { return "anthropic-byok:" + a.model() }

func (a AnthropicExtractor) model() string {
	if a.Model != "" {
		return a.Model
	}
	return "claude-opus-5"
}

func (a AnthropicExtractor) baseURL() string {
	if a.BaseURL != "" {
		return a.BaseURL
	}
	return "https://api.anthropic.com"
}

// Extract implements [Extractor].
func (a AnthropicExtractor) Extract(ctx context.Context, ask string) ([]Requirement, error) {
	body, err := json.Marshal(map[string]any{
		"model":      a.model(),
		"max_tokens": 4096,
		"system":     extractSystemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": "Feature request to decompose:\n\n" + ask},
		},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL()+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", a.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := a.HTTP
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode anthropic response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := "unknown error"
		if parsed.Error != nil {
			msg = parsed.Error.Message
		}
		return nil, fmt.Errorf("anthropic API returned %d: %s", resp.StatusCode, msg)
	}
	var sb strings.Builder
	for _, c := range parsed.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	return parseRequirements(sb.String())
}

// HeadlessAgentExtractor runs a locally installed coding agent in one-shot mode.
//
// Tool access is restricted to nothing at all: this call must reason over the
// text it is handed, never read or edit the repository. That is enforced with
// the agent's own flags rather than by asking the model to behave.
type HeadlessAgentExtractor struct {
	// Bin is the agent CLI, e.g. "claude".
	Bin string
}

// Name implements [Extractor].
func (h HeadlessAgentExtractor) Name() string { return "headless-agent:" + h.Bin }

// Extract implements [Extractor].
func (h HeadlessAgentExtractor) Extract(ctx context.Context, ask string) ([]Requirement, error) {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, h.Bin,
		"-p", extractSystemPrompt+"\n\nFeature request to decompose:\n\n"+ask,
		// Read-only by construction: no tools are permitted at all.
		"--allowedTools", "",
		"--permission-mode", "plan",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("headless agent %s: %w: %s", h.Bin, err, strings.TrimSpace(stderr.String()))
	}
	return parseRequirements(stdout.String())
}

// FileExtractor loads a pre-extracted requirement graph from disk.
//
// This exists so the pipeline is demonstrable and testable without spending a
// live inference call, and so a reviewer can audit against a requirement list
// they wrote by hand. It is a legitimate input, not a stub: the file is real
// input data, and the report records that extraction was operator-supplied
// rather than model-generated.
type FileExtractor struct{ Path string }

// Name implements [Extractor].
func (f FileExtractor) Name() string { return "file:" + f.Path }

// Extract implements [Extractor].
func (f FileExtractor) Extract(_ context.Context, _ string) ([]Requirement, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read requirements file: %w", err)
	}
	return parseRequirements(string(b))
}

// SelectExtractor picks an inference backend in the documented order of
// preference and returns a precise, actionable error when none is available.
//
// requirementsFile wins when set because an explicitly supplied requirement
// graph is operator intent, not a fallback.
func SelectExtractor(requirementsFile string) (Extractor, error) {
	if requirementsFile != "" {
		return FileExtractor{Path: requirementsFile}, nil
	}
	if key := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); key != "" {
		return AnthropicExtractor{APIKey: key, Model: os.Getenv("ENTIRE_AUDIT_MODEL")}, nil
	}
	if bin, err := exec.LookPath("claude"); err == nil {
		return HeadlessAgentExtractor{Bin: bin}, nil
	}
	return nil, fmt.Errorf("%w: `entire audit` needs one of\n"+
		"  - a headless agent on PATH (install the `claude` CLI), or\n"+
		"  - ANTHROPIC_API_KEY exported in your environment (bring your own key), or\n"+
		"  - --requirements <file.json> with a pre-extracted requirement graph.\n"+
		"There is no hosted inference fallback: `entire audit` never sends your prompts to an Entire-operated model",
		ErrNoInference)
}
