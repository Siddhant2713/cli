package audit

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// minSearchScore is the graph search score below which a hit is treated as
// coincidental lexical overlap rather than evidence. Tuned against real
// `entire graph search` output on this repository, where a genuine symbol match
// scores in the 40s and an unrelated file scores in the low single digits.
const minSearchScore = 8.0

// EvidenceCollector gathers structural evidence for each requirement.
//
// Order matters and is deliberate: a definition lookup is the strongest and
// cheapest signal, semantic search is next, and plain text search is a last
// resort recorded as such. The point of the ordering is that the report can say
// which tier of evidence a conclusion rests on, instead of flattening a grep hit
// and a call-graph edge into the same claim.
type EvidenceCollector struct {
	Graph GraphClient
	// Dir is the repository root, used for the text-search fallback.
	Dir string
	// RequirementsFile, when the requirement graph came from a file, is excluded
	// from text evidence: it is where the search hints were defined, so a match
	// in it proves nothing.
	RequirementsFile string
	// graphOK caches whether the graph plugin answered at all.
	graphOK    bool
	graphKnown bool
	// counter names evidence IDs uniquely within one report.
	counter int
}

func (c *EvidenceCollector) nextID(prefix string) string {
	c.counter++
	return fmt.Sprintf("%s_%03d", prefix, c.counter)
}

// GraphAvailable reports (and caches) whether graph queries can run.
func (c *EvidenceCollector) GraphAvailable(ctx context.Context) bool {
	if !c.graphKnown {
		c.graphOK = c.Graph != nil && c.Graph.Available(ctx)
		c.graphKnown = true
	}
	return c.graphOK
}

// Collect runs the evidence ladder for one requirement and returns every
// citation found plus the completeness of the search itself.
//
// The returned completeness describes how well we could look, not what we found.
// Those are different things, and conflating them is precisely the bug that
// turns "we could not check" into "it is not there".
func (c *EvidenceCollector) Collect(ctx context.Context, req Requirement) ([]Evidence, Completeness, []string) {
	var (
		found       []Evidence
		limitations []string
		// searchQuality tracks whether the search itself was fully performed.
		searchQuality = CompletenessComplete
	)

	if !c.GraphAvailable(ctx) {
		// Only report a *plugin* problem when a graph was actually wanted.
		// With --no-graph the caller already recorded the reason, and repeating
		// "plugin unavailable" per requirement would misattribute a deliberate
		// choice to a broken environment.
		if c.Graph != nil {
			limitations = append(limitations,
				"Entire Graph plugin unavailable; evidence for all requirements fell back to text search")
		}
		searchQuality = CompletenessPartial
		found = append(found, c.textSearch(ctx, req)...)
		return found, searchQuality, limitations
	}

	// Tier 1 — definition lookup on each identifier-shaped hint.
	for _, hint := range req.SearchHints {
		if !looksLikeIdentifier(hint) {
			continue
		}
		def, err := c.Graph.Def(ctx, hint)
		if err != nil {
			limitations = append(limitations, fmt.Sprintf("graph def %q failed: %v", hint, err))
			searchQuality = WorstCompleteness(searchQuality, CompletenessPartial)
			continue
		}
		dc := completenessFromDiagnostics(def.Warnings, def.PartialFails)
		searchQuality = WorstCompleteness(searchQuality, dc)
		for _, d := range def.Declarations {
			found = append(found, Evidence{
				ID:           c.nextID("ev"),
				Kind:         EvidenceGraphDef,
				Command:      fmt.Sprintf("entire graph def %s --repo . --format json", hint),
				Citation:     d.Citation(),
				Detail:       fmt.Sprintf("%s %s — %s", d.Kind, d.Name, d.Signature),
				Completeness: dc,
			})
		}
	}

	// Tier 2 — semantic search over the requirement's own wording.
	query := req.Summary
	if len(req.SearchHints) > 0 {
		query = req.Summary + " (" + strings.Join(req.SearchHints, ", ") + ")"
	}
	res, err := c.Graph.Search(ctx, query, 5)
	if err != nil {
		limitations = append(limitations, fmt.Sprintf("graph search for %q failed: %v", req.ID, err))
		searchQuality = WorstCompleteness(searchQuality, CompletenessPartial)
	} else {
		for _, hit := range res.Results {
			if hit.Score < minSearchScore {
				continue
			}
			found = append(found, Evidence{
				ID:       c.nextID("ev"),
				Kind:     EvidenceGraphSearch,
				Command:  fmt.Sprintf("entire graph search --repo . --query %q --format json", query),
				Citation: hit.Citation(),
				Detail: fmt.Sprintf("rank %d score %.1f — %s %s [%s]",
					hit.Rank, hit.Score, hit.Kind, hit.SymbolName, strings.Join(hit.Signals, ",")),
				Completeness: CompletenessComplete,
			})
		}
	}

	// Tier 3 — reachability. A definition existing is not the same as it being
	// wired up, and that distinction is the whole point of the canonical
	// "does the lockout path actually reach the rate limiter" question.
	if len(found) > 0 {
		if sym := firstIdentifier(req.SearchHints); sym != "" {
			imp, err := c.Graph.Impact(ctx, sym)
			if err != nil {
				limitations = append(limitations, fmt.Sprintf("graph impact %q failed: %v", sym, err))
			} else {
				found = append(found, Evidence{
					ID:       c.nextID("ev"),
					Kind:     EvidenceGraphImpact,
					Command:  fmt.Sprintf("entire graph impact --repo . --symbol %s --format json", sym),
					Citation: imp.Focus.Citation(),
					Detail: fmt.Sprintf("%d callers (%d direct), %d callees — reachability of %s",
						imp.Callers.Total, imp.Callers.Direct, imp.Callees.Total, sym),
					Completeness: completenessFromDiagnostics(imp.Warnings, nil),
				})
			}
		}
	}

	if len(found) == 0 {
		found = append(found, c.textSearch(ctx, req)...)
	}
	return found, searchQuality, limitations
}

// circularEvidencePaths are excluded from text search because a hit in them is
// not evidence of anything.
//
// The requirements file literally contains the search hints — it is where they
// were defined — so grepping for a hint and finding it there is circular: the
// audit would cite its own input as proof that the input was implemented. This
// was a real false positive observed on the first end-to-end run, where every
// requirement came back PARTIAL on the strength of matching its own definition.
func circularEvidencePath(path, requirementsFile string) bool {
	if requirementsFile != "" && strings.HasSuffix(requirementsFile, path) {
		return true
	}
	return strings.Contains(path, "/testdata/") || strings.HasPrefix(path, "testdata/")
}

// textSearch is the last-resort fallback, recorded with its own evidence kind so
// nobody mistakes a lexical hit for a structural fact.
func (c *EvidenceCollector) textSearch(ctx context.Context, req Requirement) []Evidence {
	var out []Evidence
	for _, hint := range req.SearchHints {
		hint = strings.TrimSpace(hint)
		if hint == "" {
			continue
		}
		cmd := exec.CommandContext(ctx, "git", "grep", "-n", "-I", "--fixed-strings", hint)
		cmd.Dir = c.Dir
		res, err := cmd.Output()
		if err != nil {
			// git grep exits 1 on no match; that is a real answer, not an error.
			continue
		}
		var lines []string
		for _, l := range strings.Split(strings.TrimSpace(string(res)), "\n") {
			if l == "" {
				continue
			}
			path := l
			if i := strings.Index(l, ":"); i > 0 {
				path = l[:i]
			}
			if circularEvidencePath(path, c.RequirementsFile) {
				continue
			}
			lines = append(lines, l)
		}
		if len(lines) == 0 {
			continue
		}
		citation := lines[0]
		if i := strings.Index(citation, ":"); i > 0 {
			if j := strings.Index(citation[i+1:], ":"); j > 0 {
				citation = citation[:i+1+j]
			}
		}
		out = append(out, Evidence{
			ID:       c.nextID("ev"),
			Kind:     EvidenceTextSearch,
			Command:  fmt.Sprintf("git grep -n -I --fixed-strings %q", hint),
			Citation: citation,
			Detail:   fmt.Sprintf("%d textual match(es) for %q — lexical only, not a structural guarantee", len(lines), hint),
			// Text search cannot establish semantic completeness.
			Completeness: CompletenessPartial,
		})
	}
	return out
}

// looksLikeIdentifier reports whether a hint is shaped like a code symbol worth
// sending to a definition lookup, as opposed to a prose phrase.
func looksLikeIdentifier(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t") {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r == '.' || r == ':' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func firstIdentifier(hints []string) string {
	for _, h := range hints {
		if looksLikeIdentifier(h) {
			return h
		}
	}
	return ""
}

// StateFromEvidence decides a requirement's state from what was found and how
// well we were able to look.
//
// The two arguments are kept separate on purpose. searchQuality is the
// completeness of the *search*; it can only ever weaken a conclusion. Finding
// nothing after a complete search is `not_verified` — still not a claim that the
// code is absent, because a requirement can be satisfied by code our hints never
// named. Finding nothing after an incomplete search is `unknown`.
func StateFromEvidence(ev []Evidence, searchQuality Completeness) (State, Completeness, string) {
	if len(ev) == 0 {
		if searchQuality.Authoritative() {
			return StateNotVerified, CompletenessComplete,
				"No structural evidence found for this requirement. The search itself completed, " +
					"but absence of evidence is not evidence of absence — this is not a claim that the requirement is unimplemented."
		}
		return StateUnknown, searchQuality,
			"The evidence search could not be completed, so no conclusion is available for this requirement."
	}

	var structural, lexical int
	worst := CompletenessComplete
	for _, e := range ev {
		worst = WorstCompleteness(worst, e.Completeness)
		switch e.Kind {
		case EvidenceTextSearch:
			lexical++
		default:
			structural++
		}
	}
	combined := WorstCompleteness(worst, searchQuality)

	switch {
	case structural == 0:
		return StatePartial, WorstCompleteness(combined, CompletenessPartial),
			"Only lexical (text-search) evidence was found. The named identifiers appear in the tree, " +
				"but no structural relationship was verified."
	case combined.Authoritative():
		return StateCompleted, combined,
			fmt.Sprintf("%d structural citations from the code graph support this requirement.", structural)
	default:
		return StatePartial, combined,
			fmt.Sprintf("%d structural citations found, but the graph reported an incomplete view, "+
				"so this is reported as partial rather than confirmed.", structural)
	}
}
