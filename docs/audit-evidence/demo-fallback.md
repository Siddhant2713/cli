# Demo fallback capture — `entire audit`

Recorded 2026-09-06 14:38 IST at commit `595efdfdf0bcccf46e440c39af5db0ce0f64b1f5`.
Use this if live infrastructure is unavailable during judging.

## 1. Critical path — audit this feature against its own requirement graph
```
$ entire audit --requirements cmd/entire/cli/audit/example/feature-audit-requirements.json --no-graph
Feature audit — main
Repository 1b3bcf4033c8166d at commit 595efdfdf
Generated 2026-09-06 14:38:35 IST

⚠ PARTIAL CONTEXT
Some checkpoint information was unavailable or redacted.
This finding may be incomplete and should not be treated as authoritative.

Requirement coverage: 0.0%
Risk-adjusted coverage: 50.0%
Risk-adjusted assessment: HIGH
Missing high-impact controls: none identified
Authoritative: false

Reasoning: 0 of 12 requirements have confirming evidence (0.0% raw). Weighting each requirement by its
risk weight gives 23.0 of 46.0 points (50.0% risk-adjusted); partial evidence earns half
credit, and confirmed evidence drawn from an incomplete record also earns half credit rather
than full. The verdict is HIGH; no requirement with weight ≥ 3.5 is unevidenced. This
verdict is NOT authoritative: the underlying record was partial, so unevidenced requirements
may simply be unverifiable rather than unimplemented.

────────────────────────────────────────────────────────────────────────────────────────────
Checkpoints analyzed: 2
  01M1TQZA  complete    2026-09-06T12:24:56+05:30
  01M1TTR3  complete    2026-09-06T13:13:25+05:30

────────────────────────────────────────────────────────────────────────────────────────────
REQUIREMENT STATES
────────────────────────────────────────────────────────────────────────────────────────────

[PARTIAL] Decompose the original ask into an atomic requirement graph
  id=requirement_extraction  risk=functional  weight=3.0
  Context completeness: partial   Authoritative: false
  Only lexical (text-search) evidence was found. The named identifiers appear in the tree,
but no structural relationship was verified.
  Evidence:
    - [text_search] BUILDATHON.md:293 (partial)
      13 textual match(es) for "SelectExtractor" — lexical only, not a structural guarantee
      verify: git grep -n -I --fixed-strings "SelectExtractor"
    - [text_search] cmd/entire/cli/audit/extract.go:52 (partial)
      7 textual match(es) for "parseRequirements" — lexical only, not a structural guarantee
      verify: git grep -n -I --fixed-strings "parseRequirements"

[PARTIAL] Read the branch's checkpoint sequence with per-checkpoint completeness
  id=checkpoint_sequence_read  risk=correctness  weight=3.0
  Context completeness: partial   Authoritative: false
```

## 2. Curveball — prompt-egress guard blocks a sensitive repo
```
$ ANTHROPIC_API_KEY=sk-ant-... entire audit --sensitive --no-graph
prompt egress blocked: this repository's checkpoint history contains redacted entries, so it is treated as sensitive, and requirement extraction via anthropic-byok:claude-opus-5 would send checkpoint prompt text to an external service.

The audit still runs on sensitive repositories — supply the requirement graph locally instead:
  entire audit --requirements <file.json>

If sending prompt text off this machine is genuinely acceptable here, opt in explicitly:
  entire audit --allow-prompt-egress
```

## 3. Tests — critical + Curveball behaviour
```
$ go test ./cmd/entire/cli/audit/ -run "Egress|Redacted|Export|Semantic" -v
--- PASS: TestDetectPivotsSurfacesRedactedGap (0.00s)
--- PASS: TestDetectDecisionDriftSkipsRedacted (0.00s)
--- PASS: TestPromptEgressBlockedOnRedactedRepo (0.00s)
--- PASS: TestPromptEgressAllowedWithExplicitOptIn (0.00s)
--- PASS: TestRedactedCheckpointNeverBecomesAuthoritativeClaim (0.01s)
--- PASS: TestExportRecordsCarryNoFreeText (0.00s)
--- PASS: TestWriteStaticExportProducesLoadableArtifacts (0.00s)
--- PASS: TestSemanticSearchAloneCannotConfirmARequirement (0.00s)
PASS
ok  	github.com/entireio/cli/cmd/entire/cli/audit	0.015s
```
