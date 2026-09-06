# Feature Audit & Decision Drift — `entire audit`

Bengaluru Tech Week Buildathon 2026 · Track 1 · built on a fork of `github.com/entireio/cli`

---

## One-sentence summary

`entire audit` reads a feature's checkpoint history, decomposes the original request into a
requirement graph, searches the Entire Graph for structural evidence that each requirement was
actually implemented, detects pivots and decision contradictions across checkpoints, and reports
risk-adjusted coverage — honestly labelling what it could not verify instead of guessing.

## Problem, intended user, and why it matters

**The user:** an engineer or reviewer who has to sign off on a feature an AI agent built across
many sessions.

**The problem:** a diff tells you what changed. It does not tell you what was *supposed* to
happen. When an agent is told "add rate limiting", tries Redis, hits a wall, and quietly falls
back to an in-memory map, the diff looks small and clean. What the diff cannot show you is that a
distributed-system guarantee just disappeared. The intent, the failed attempt, and the
substitution live in the session narrative — which nobody reads, because it is thousands of lines
long and scattered across sessions.

Entire Checkpoints already capture that narrative. Nothing yet *audits* it. That gap is the
product.

**Why it matters now:** as more code is agent-written, review shifts from "is this code correct?"
to "is this code the thing we asked for?" Those are different questions, and only the second one
needs the history.

## Selected Entire track and why Entire is essential

Track 1. This feature cannot exist without Entire. It depends on two capabilities that are
Entire's alone:

1. **Checkpoints** preserve prompts, intent, and per-session narrative alongside commits. Pivot
   and decision-drift detection are reads over that record. Git history alone does not contain it.
2. **Entire Graph** answers structural questions — does this symbol exist, who calls it, what
   does this commit actually change — deterministically and with no network egress. That is what
   makes a finding *evidence* rather than a model's opinion.

## Architecture and main workflow

Five stages, in `cmd/entire/cli/audit/`:

| Stage | Input | Output | Implementation |
|---|---|---|---|
| 1. Requirement extraction | the original ask | atomic requirement graph | `extract.go` — forced-JSON, one call |
| 2. Checkpoint read | branch checkpoint range | checkpoint sequence + completeness | `checkpoints.go` |
| 3. Evidence search | each requirement | structural citations | `evidence.go` + `graph.go` |
| 4. Pivot & drift detection | checkpoint sequence | flagged findings | `drift.go` |
| 5. Risk-adjusted report | all states + findings | cited CLI report + export | `risk.go`, `report.go`, `privacy.go`, `databricks.go` |

Registered in `cmd/entire/cli/root.go` via `experimental.Register(cmd, audit.NewCommand())`,
the same way `review` and `investigate` are.

### The central discipline: unknown is not completed — and it is not "not implemented" either

This is the design constraint everything else follows from. `StateFromEvidence` in `evidence.go`
keeps two things apart that are easy to conflate:

- **how well we were able to look** (search quality), and
- **what we found** (the result).

A *complete* search that finds nothing yields `not_verified`, with the report stating in words
that absence of evidence is not evidence of absence. An *incomplete* search that finds nothing
yields `unknown`. Neither ever renders as "was not implemented" — that is a claim about the code
which an absence of evidence does not earn.

Every requirement state, every finding, and the overall verdict carry a `context_completeness`
value and an `authoritative` boolean. Only a `complete` record can produce an authoritative claim.

### Evidence ladder

Evidence is gathered in descending order of strength, and the report always says which tier a
conclusion rests on:

1. `entire graph def <symbol>` — does the code exist, with the right shape?
2. `entire graph search --query "<requirement>"` — semantic location.
3. `entire graph impact --symbol <symbol>` — is it actually *reachable*? A definition existing is
   not the same as it being wired up. This is what answers "does the lockout path really reach the
   rate limiter?"
4. `git grep` — lexical fallback only, recorded under its own evidence kind and never promoted to
   a structural fact.

Every piece of evidence carries the literal command that produced it, so a reader can re-run it.

## Entire Graph findings and verification

Commands run live during the build, all independently reproducible:

```bash
# Definition lookup — used as evidence, and to verify the extension point before writing code
entire graph def NewRootCmd --repo . --format json

# Semantic search
entire graph search --repo . --query "checkpoint list json output" --format json

# Impact analysis — run BEFORE modifying root.go, to check the blast radius of the change
entire graph impact --repo . --symbol NewRootCmd --format json

# Final semantic diff of the submitted implementation
entire graph commit HEAD
```

The `graph impact` on `NewRootCmd` reported **125 callers (101 direct)** before the registration
change, which is what justified making the edit a single additive `experimental.Register` line
rather than restructuring the command table.

The graph's own `completeness`, `warnings`, and `partial_failures` blocks are consumed directly by
`completenessFromDiagnostics` in `graph.go`. When the graph reports an incomplete parse, the audit
downgrades its own conclusions — the provenance is machine-read, not asserted.

## Privacy boundary and required test — what never left the local environment

**Hard constraint:** raw prompts, transcripts, tool arguments, and unredacted checkpoint payloads
never leave the machine.

This is enforced **structurally, not by redaction.** `BuildExport` in `privacy.go` constructs two
export row types field by field from a closed allowlist. Nothing marshals the in-memory `Report`.

The alternative — marshal everything and strip sensitive keys — was rejected deliberately: a
redactor is a *denylist*, and it fails **open** the day someone adds a field it does not know
about. The field that leaks is precisely the new one nobody thought about. Field-by-field
construction fails **closed**: a new field on `Checkpoint` or `Finding` cannot reach the export
unless a human writes an export line for it.

`sanitizeSummary` is defence in depth behind that boundary — it scrubs credential shapes
(API keys, GitHub tokens, AWS keys, JWTs, labelled secrets) and bounds field length, so a bug
upstream that puts transcript text in a summary field has a bounded blast radius.

### The required test

`TestRedactedCheckpointNeverBecomesAuthoritativeClaim` (`privacy_test.go`) uses the redacted
checkpoint fixture from the spec and asserts the system reports *"Rate limiting … could not be
verified"* with `context_completeness: partial` and `authoritative: false` — and explicitly fails
if it instead emits an authoritative negative claim like *"Rate limiting was not implemented."*

**It was mutation-verified, not merely observed passing.** Injecting the exact bug the spec names
— changing `GapFindings` to emit `"%s was not implemented"` with `Authoritative: true` — makes the
test fail on all three assertions (summary wording, authoritative flag, forbidden rendered
string). Reverting makes it pass. A test that has never been seen to fail proves nothing.

`TestExportRecordsCarryNoFreeText` plants canary strings in every narrative field of a report and
asserts none of them reach the exported JSON, and that the repository URL is hashed rather than
shipped in the clear.

## Databricks use, data sources, and limitations

**Capability used:** Delta tables in the Free Edition SQL warehouse, written through the SQL
Statement Execution API (`/api/2.0/sql/statements`).

**Why it is essential:** an audit that only ever prints to a terminal cannot be tracked over time.
The two tables turn per-run output into a queryable record of how requirement coverage and risk
findings move across commits and features — which is the actual product question ("is this getting
better or worse?"), not something a CLI report can answer.

**Schema** (`schema.sql`, generated by `DatabricksConfig.DDL()`):

- **`feature_requirements`** — `feature_id, requirement_id, repository_hash, checkpoint_id,
  requirement_summary, status, risk_category, risk_weight, context_completeness, authoritative,
  evidence_count, created_at`
- **`risk_findings`** — `finding_id, feature_id, checkpoint_id, kind, risk_category, risk_level,
  finding_summary, evidence_ids, recommendation, context_completeness, authoritative, created_at`

**`context_completeness` and `authoritative` are columns on both tables.** The schema *is* the
privacy and provenance evidence — a consumer of these tables cannot accidentally treat an
unverifiable row as a confirmed one, because the row itself says so. `repository_hash` is a
SHA-256 prefix, never the URL, so rows join across runs without naming a private repo.

**Data provenance:** every row derives from a real checkpoint read via `entire checkpoint
list/explain` and real graph queries. Nothing is synthesised. `evidence_count` ties a row back to
citations held locally in the full JSON report.

**Reproduction:**

```bash
export DATABRICKS_HOST=https://<workspace>.cloud.databricks.com
export DATABRICKS_TOKEN=<token>
export DATABRICKS_WAREHOUSE_ID=<warehouse-id>
entire audit --requirements <reqs.json> --export ./audit-export --databricks
```

**Verified live.** The tables were created and populated against a real Databricks Free Edition
workspace, and the rows were read back to confirm — not merely a successful exit code:

- **Workspace:** `https://dbc-42a681b0-04dc.cloud.databricks.com`
- **SQL warehouse:** `Serverless Starter Warehouse` (`95075e699388f0ff`)
- **Tables:** `workspace.entire_audit.feature_requirements` (12 rows),
  `workspace.entire_audit.risk_findings` (0 rows — see below)

```sql
SELECT requirement_id, status, risk_category, risk_weight, context_completeness, authoritative
FROM workspace.entire_audit.feature_requirements ORDER BY risk_weight DESC;
```

Every row on that run came back `context_completeness = partial`, `authoritative = false`. That is
the correct result, not a bug: the run used `--no-graph`, so all evidence was lexical, and lexical
evidence cannot establish a structural fact. **A judge should be able to see that the tool declines
to mark its own requirements "confirmed" when it only has grep hits to go on.** That is the entire
argument of the feature, visible in the data rather than asserted in prose.

`risk_findings` is legitimately empty on this corpus — no pivot or drift was detected in the two
available checkpoints. An empty findings table is an honest result; fabricating a finding to fill
it would be the exact failure this tool is built to detect.

**Privacy boundary verified against the live table**, not only in unit tests. Querying
`SELECT *` and scanning for text that exists locally in the checkpoint record — the prompts
("Add a result cache…", "edit somehting…"), the transcript speaker tags (`[User]`, `[Assistant]`),
the technology named in the pivot ("Redis"), and the repo owner's name — returns **none of them**.
`repository_hash` is `1b3bcf4033c8166d`, a SHA-256 prefix; the workspace never receives the
repository URL.

**Reproduce the verification:**

```bash
curl -s -X POST -H "Authorization: Bearer $DATABRICKS_TOKEN" -H "Content-Type: application/json" \
  "$DATABRICKS_HOST/api/2.0/sql/statements" \
  -d '{"statement":"SELECT * FROM workspace.entire_audit.feature_requirements",
       "warehouse_id":"'"$DATABRICKS_WAREHOUSE_ID"'","wait_timeout":"50s"}'
```

**Remaining limitation:** the static NDJSON + DDL export is written on *every* run, before any
network call, and is the reproducible artifact. A failed push logs a warning and does not fail the
audit — the report is the deliverable, Databricks is delivery.

## Known limitations and next steps

Stated plainly, because the whole feature is an argument for honest labelling:

- **Requirement extraction is a model's reading of the ask, not a specification.** Coverage is a
  review aid, not a gate. This is why the command ships behind `experimental.Register`.
- **Pivot and drift detection are deterministic pattern matchers, so they find *stated* pivots.**
  A pivot nobody wrote down is invisible to them. Handing the sequence to an LLM was rejected:
  a model returns a plausible contradiction for *any* input, and a confabulated contradiction is
  worse than no finding — it poisons exactly the trust this feature is selling. The report says
  this in its own output rather than implying the history was clean.
- **Drift detection's constraint vocabulary is a fixed list.** It catches the shapes it knows and
  will miss novel phrasings.
- **Graph-backed evidence does not yet complete for a full requirement set on a repo this size.**
  Each requirement issues several `entire graph` subprocess calls, and on this ~1,250-Go-file
  repository the index does not stay warm across them, so a 12-requirement audit does not finish
  in a usable time. **Individual graph queries work and are shown in
  `docs/audit-evidence/graph-evidence.md`** (def, impact, and the final semantic diff, all
  reproducible); what is not yet proven is the whole requirement set running through them in one
  pass. `--no-graph` completes in under a second and is the path demonstrated end to end.
  `cache.go` (a filesystem-backed graph result cache, keyed on HEAD plus a worktree-status digest)
  exists to close this gap but is **not yet wired into `CLIGraphClient`** — that is the single
  highest-value next commit, and it is honest to say it is unfinished rather than to imply the
  graph path is production-ready.
- **Condensed checkpoints may lag.** The reader falls back to the pending view and records that as
  a completeness downgrade, rather than reporting a vacuous "no checkpoints found".

**Next steps** (Phase 2-4 from the source feature spec, deliberately out of scope today):

- **Phase 2 — Entire Guard:** move from post-session audit to real-time interception, flagging a
  guarantee-changing pivot *while* the agent makes it.
- **Phase 3 — Historical Why:** connect `entire why <file>:<line>` output into the requirement and
  decision graph, so a line of code resolves to the requirement it serves.
- **Phase 4 — Databricks AI Search, MLflow evaluation, Unity Catalog governance:** evaluate
  detector precision/recall against a labelled corpus of real pivots, and govern the audit tables.

## Setup, run, and test instructions

```bash
# Prerequisites: Go 1.26.x, mise
mise trust && mise install && go mod download
mise run build

# Entire + graph plugin
entire enable -y --agent claude-code
entire plugin install graph        # required — graph is NOT bundled with the CLI

# Run the audit
entire audit                                              # infers requirements from checkpoint 1
entire audit --requirements cmd/entire/cli/audit/example/feature-audit-requirements.json
entire audit --no-graph                                   # fast lexical pass, no graph queries
entire audit --json                                       # machine-readable full report
entire audit --export ./audit-export                      # privacy-safe NDJSON + DDL
entire audit --fail-on high                               # non-zero exit for CI gating

# Tests — including the mandatory privacy test
go test ./cmd/entire/cli/audit/ -v
```

**Inference backends**, in order of preference — `--requirements <file>` (no inference at all),
`ANTHROPIC_API_KEY` (BYOK), or a headless `claude` CLI run with no tool access. With none
configured the command **fails with actionable guidance** rather than returning an empty
requirement graph, which would render as "nothing was required" — a false authoritative claim of
exactly the kind this feature exists to prevent. That failure path is covered by
`TestSelectExtractorFailsClearlyWithoutBackend`.

There is no hosted or proxy inference fallback. `entire audit` never sends prompts to an
Entire-operated model.
