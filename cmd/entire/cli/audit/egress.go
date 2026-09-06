package audit

import (
	"errors"
	"fmt"
	"strings"
)

// Prompt egress guard.
//
// There are exactly two paths out of this package to an external service:
//
//	databricks.go  — receives only ExportBundle rows, which are built by
//	                 field-by-field allowlist in privacy.go. Structurally safe.
//	extract.go     — sends the original ask to an inference API. The ask is
//	                 CHECKPOINT PROMPT TEXT, so this path can carry raw prompt
//	                 content off the machine.
//
// The second path was identified by running
// `entire graph neighbors --symbol <sink> --relation CALLS --direction in` over
// every egress sink in the package. The Databricks boundary had been designed in
// from the start; this one had not, because "we send the prompt to an LLM" is
// the feature working as intended right up until the repository is sensitive.
//
// The guard below closes it. In a sensitive repository the audit still runs —
// it just requires the requirement graph to be supplied locally rather than
// derived by shipping the prompt to a third party.

// ErrPromptEgressBlocked is returned when the audit would have to send prompt
// text to an external inference service in a context where that is not allowed.
var ErrPromptEgressBlocked = errors.New("prompt egress blocked")

// EgressPolicy decides whether prompt text may leave the machine.
type EgressPolicy struct {
	// AllowPromptEgress is the operator's explicit opt-in. It must be set
	// deliberately; the default is deny whenever the repository looks sensitive.
	AllowPromptEgress bool
	// Sensitive forces deny regardless of what the checkpoint record looks like.
	Sensitive bool
}

// checkpointsLookSensitive reports whether the checkpoint record itself signals
// that this repository is handled under redaction.
//
// The signal is deliberately conservative: if ANY checkpoint in the range is
// redacted, the repository is treated as sensitive. A repo that redacts some of
// its history is a repo whose operators have already said the content is not for
// general distribution, and inferring "the un-redacted ones must be fine" is
// exactly the assumption a privacy boundary must not make.
func checkpointsLookSensitive(cps []Checkpoint) bool {
	for _, cp := range cps {
		if cp.Redacted() || cp.Completeness == CompletenessRedacted {
			return true
		}
	}
	return false
}

// AuthorizeExtraction decides whether the given extractor may run against the
// given checkpoint record, and returns a precise error when it may not.
//
// Local extractors are always allowed: FileExtractor reads a requirement graph
// off disk and sends nothing anywhere. Only network-backed extraction is gated.
func AuthorizeExtraction(ext Extractor, cps []Checkpoint, pol EgressPolicy) error {
	if ext == nil || !extractorSendsPromptOffMachine(ext) {
		return nil
	}
	sensitive := pol.Sensitive || checkpointsLookSensitive(cps)
	if !sensitive || pol.AllowPromptEgress {
		return nil
	}
	return fmt.Errorf("%w: this repository's checkpoint history contains redacted entries, so it is "+
		"treated as sensitive, and requirement extraction via %s would send checkpoint prompt text to an "+
		"external service.\n\n"+
		"The audit still runs on sensitive repositories — supply the requirement graph locally instead:\n"+
		"  entire audit --requirements <file.json>\n\n"+
		"If sending prompt text off this machine is genuinely acceptable here, opt in explicitly:\n"+
		"  entire audit --allow-prompt-egress",
		ErrPromptEgressBlocked, ext.Name())
}

// extractorSendsPromptOffMachine reports whether an extractor transmits the ask
// to a third party.
//
// Matching on Name() rather than a type switch keeps this honest by default: an
// extractor added later that this function does not recognise is treated as
// remote (fail closed), so forgetting to update this list cannot silently open
// a new egress path.
func extractorSendsPromptOffMachine(ext Extractor) bool {
	name := ext.Name()
	switch {
	case strings.HasPrefix(name, "file:"):
		return false
	case strings.HasPrefix(name, "headless-agent:"):
		// A local agent binary still reaches a model over the network, and we
		// cannot see its configuration from here. Treat it as remote.
		return true
	default:
		return true
	}
}
