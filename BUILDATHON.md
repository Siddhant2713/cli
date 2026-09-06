# `entire audit` — Feature Audit & Decision Drift

**Bengaluru Tech Week Buildathon 2026 · Track 1 · Databricks track opted in**

| | |
|---|---|
| **Fork** | `https://github.com/Siddhant2713/cli` |
| **Final commit** | `465f11db5c4a7330795f8f0710854f89b30fe64e` (branch `main`) |
| **Entire mirror** | `entire://aws-ap-south-1.entire.io/gh/siddhant2713/cli` |
| **Databricks workspace** | `https://dbc-42a681b0-04dc.cloud.databricks.com` |
| **Delta tables** | `workspace.entire_audit.feature_requirements`, `workspace.entire_audit.risk_findings` |
| **Tests** | 37 passing (`go test ./cmd/entire/cli/audit/`) |
| **Checkpoints** | 4, covering all four required milestones |

---

## One sentence

`entire audit` reads a feature's checkpoint history, decomposes the original request into a
requirement graph, uses Entire Graph to find structural evidence that each requirement was
actually implemented, detects pivots and decision contradictions, and reports risk-adjusted
coverage — **honestly labelling what it could not verify instead of guessing.**

## The problem

A diff shows that code changed. It does not show what was *supposed* to happen.

Tell an agent "add rate limiting". It tries Redis, hits a wall, and quietly falls back to an
in-memory map. The diff looks small and clean. What the diff cannot show you is that a
distributed-system guarantee just disappeared — the limiter no longer holds across instances and
does not survive a restart. The intent, the failed attempt, and the substitution live in the
session narrative, which nobody reads because it is thousands of lines scattered across sessions.

Entire Checkpoints already preserve that narrative. Nothing yet **audits** it. That gap is the product.

As more code is agent-written, review shifts from *"is this code correct?"* to *"is this code the
thing we asked for?"* Only the second question needs the history.

## Why Entire is essential

This feature cannot exist without Entire. It depends on two capabilities that are Entire's alone:

1. **Checkpoints** preserve prompts, intent and per-session narrative alongside commits. Pivot and
   decision-drift detection are reads over that record. Git history does not contain it.
2. **Entire Graph** answers structural questions deterministically, with no network egress — does
   this symbol exist, who calls it, what did this commit change. That is what makes a finding
   *evidence* rather than a model's opinion.

---

## The strongest evidence this works: it caught four real bugs in itself

Every one was found by pointing the tool at real data, and every one is the same failure the tool
exists to detect — **claiming more than the evidence supports.** Each is a commit with the
reasoning in its message.

| # | Bug | Commit |
|---|---|---|
| 1 | **Turning Graph ON made the answer worse.** In a repo with no rate limiting, `graph def RateLimiter` correctly found nothing — but fuzzy semantic search matched a nearby `Login` function and the requirement was reported **COMPLETED**. `--no-graph` had it right. | `1fbe30f8a` |
| 2 | **The user's prompt was read as the agent's decision.** A prompt saying *"if Redis turns out not to be usable, implement the best alternative"* was matched as a completed attempt→failure→pivot chain. A hypothetical in an instruction is not a record that it happened. | `86d2603e6` |
| 3 | **Circular evidence.** `git grep` matched search hints inside the requirements file *that defined them* — citing its own input as proof the input was implemented. | `86d2603e6` |
| 4 | **A prompt-egress leak, found by the Curveball's Graph requirement.** See below. | `d4c232f54` |

Bug 1 is the one worth dwelling on. A tool whose entire pitch is *"we do not claim more than the
evidence supports"* was reporting a **missing security control as implemented** — and the
better-instrumented code path was the one that got it wrong. It was caught only by running against
a repository where the right answer was known in advance.

**The fix**: evidence is now graded into three tiers, and only the top one can confirm.

- **Definitional** (`graph def`, `graph impact` with a resolved focus) — *"does a thing with this
  name exist?"* An identity claim. **Can confirm.**
- **Proximity** (`graph search`) — *"what is the nearest code to this description?"* A
  nearest-neighbour query that **always returns something**, including when nothing implements the
  requirement. It locates; it does not confirm. **Caps at partial.**
- **Lexical** (`git grep`) — weakest, recorded under its own evidence kind.

---

## The central discipline: unknown is not completed — and it is not "not implemented" either

This is the constraint everything else follows from. `StateFromEvidence` keeps apart two things
that are easy to conflate:

- **how well we were able to look** (search quality), and
- **what we found** (the result).

A *complete* search that finds nothing yields `not_verified`, and the report says in words that
absence of evidence is not evidence of absence. An *incomplete* search that finds nothing yields
`unknown`. **Neither ever renders as "was not implemented"** — that is a claim about the code which
an absence of evidence does not earn.

Every requirement state, every finding and the overall verdict carry a `context_completeness` value
and an `authoritative` boolean. `Completeness.Authoritative()` is the single gate, and only a
`complete` record passes it.

**Risk-adjusted coverage.** Eight of ten requirements met is not "80%, minor gap" when the missing
two are rate limiting and session invalidation. Coverage is weighted by risk, both numbers are
reported, and **the verdict always arrives with its arithmetic shown** so a reader can disagree on
the merits rather than trust a score.

---

## Noon Curveball — privacy boundary

Six of the seven requirements were already satisfied by the original design; the privacy boundary
was built in from the first commit because it is cheap to design in and expensive to retrofit.

**The requirement that earned its keep was #6: "use Entire Graph to identify every code path
affected by this privacy boundary."** It found a real leak.

The privacy question is reverse-reachability — *what are the egress sinks, and what reaches them* —
which is exactly `graph neighbors --direction in`:

```bash
entire graph neighbors --repo . --symbol BuildExport --relation CALLS --direction in --profile full --format json
# FOCUS: BuildExport  cmd/entire/cli/audit/privacy.go:110
#   <-   run          cmd/entire/cli/audit/command.go
```

**Exactly two paths leave the machine:**

| Sink | Reached from | Carries | Status |
|---|---|---|---|
| `execStatement` → Databricks | `run` → `BuildExport` → `PushToDatabricks` | `ExportBundle` rows only | Safe by construction |
| `AnthropicExtractor.Extract` → Anthropic | `Run` (audit.go) | **raw checkpoint prompt** | **Was unguarded** |

The second path was invisible until the reachability question was asked, because **sending the
prompt to a model is the feature working exactly as designed** — right up until the repository is
sensitive. The Databricks boundary had been designed in and reasoned about repeatedly; no scrutiny
of the export types would have surfaced this, because the leak is not in the export path at all.

**Closed in `egress.go`** — default-deny whenever any checkpoint in range is redacted:

```bash
entire audit --requirements <file.json>   # sensitive-safe: sends nothing anywhere
entire audit --sensitive                  # force-deny regardless of history
entire audit --allow-prompt-egress        # explicit operator opt-in
```

Three deliberate choices: the redaction signal is **conservative** (one redacted checkpoint marks
the whole repo sensitive — inferring "the un-redacted ones must be fine" is exactly the assumption a
privacy boundary must not make); `extractorSendsPromptOffMachine` **fails closed** so an
unrecognised future extractor is treated as remote; and the check runs **before** the extractor is
invoked, with the test asserting it was *never called* rather than merely that an error came back.

### All seven Curveball requirements

| # | Requirement | Where |
|---|---|---|
| 1 | No raw prompts/transcripts to a new external service | Allowlist in `privacy.go`; egress guard in `egress.go`; verified against live rows |
| 2 | Useful output when fields are redacted | `TestSensitiveRepoStillProducesAUsefulAudit` — full pipeline on a wholly redacted history |
| 3 | Existing local functionality unchanged | 37 tests green; `--requirements` / `--no-graph` untouched |
| 4 | Interface distinguishes complete vs incomplete | Three context banners + `context_completeness` and `authoritative` on every state, finding and row |
| 5 | A test using redacted/missing Checkpoint data | `TestRedactedCheckpointNeverBecomesAuthoritativeClaim` (mutation-verified) + 4 egress tests |
| 6 | Graph identifies affected paths | `docs/audit-evidence/curveball-privacy-paths.md` |
| 7 | Never present incomplete context as authoritative | `Completeness.Authoritative()` — the single gate |

---

## Privacy boundary — enforced structurally, not by redaction

`BuildExport` constructs the two export row types **field by field from a closed allowlist**.
Nothing marshals the in-memory `Report`.

Marshalling everything and stripping sensitive keys was rejected deliberately: **a redactor is a
denylist, and it fails open** the day someone adds a field it does not know about — and the field
that leaks is precisely the new one nobody considered. Field-by-field construction **fails closed**:
a new field on `Checkpoint` or `Finding` cannot reach the export unless a human writes an export
line for it.

**The required test was mutation-verified, not merely observed passing.** Injecting the exact bug
the spec names — `GapFindings` emitting `"%s was not implemented"` with `Authoritative: true` —
makes the test fail on all three assertions (summary wording, authoritative flag, forbidden
rendered string); reverting makes it pass. *A test that has never been seen to fail proves nothing.*

---

## Databricks — verified live, and the schema is the evidence

Delta tables in the Free Edition SQL warehouse, written via the SQL Statement Execution API.

- **Workspace** `https://dbc-42a681b0-04dc.cloud.databricks.com`
- **Warehouse** Serverless Starter Warehouse (`95075e699388f0ff`)
- **`feature_requirements`** — 12 rows · **`risk_findings`** — 0 rows

**Why it is essential:** an audit that only prints to a terminal cannot be tracked over time. These
tables turn per-run output into a queryable record of how coverage and risk move across commits —
the actual product question ("is this getting better or worse?"), which a CLI report cannot answer.

**`context_completeness` and `authoritative` are columns on both tables.** The schema *is* the
provenance evidence: a consumer cannot mistake an unverifiable row for a confirmed one, because the
row says so. `repository_hash` is a SHA-256 prefix (`1b3bcf4033c8166d`) — never the URL.

**Privacy verified against the live table, not only in tests.** Querying `SELECT *` and scanning for
text known to exist locally — the prompts, `[User]`/`[Assistant]` speaker tags, "Redis", the repo
owner's name — returns **none of it**.

**Two results that look like failures and are not.** Every row reads `context_completeness=partial,
authoritative=false`: that run used `--no-graph`, so all evidence was lexical, and lexical evidence
cannot establish a structural fact. **The tool declining to mark its own requirements confirmed on
the strength of grep hits is the argument of the feature, visible in data rather than asserted in
prose.** And `risk_findings` is empty because no pivot exists in the available checkpoints —
fabricating a row to make the table look alive would be exactly the failure this tool detects.

---

## Architecture

Five stages in `cmd/entire/cli/audit/`, registered in `root.go` via
`experimental.Register(cmd, audit.NewCommand())` — the same shape as `review` and `investigate`.

| Stage | Output | File |
|---|---|---|
| 1. Requirement extraction | atomic requirement graph | `extract.go` |
| 2. Checkpoint read | sequence + per-checkpoint completeness | `checkpoints.go` |
| 3. Evidence search | structural citations | `evidence.go`, `graph.go` |
| 4. Pivot & drift detection | flagged findings | `drift.go` |
| 5. Risk-adjusted report | cited report + export | `risk.go`, `report.go`, `privacy.go`, `databricks.go` |
| — | privacy egress guard | `egress.go` |

**Pivot and drift detection are deterministic pattern matchers, not LLM calls.** Asking a model
"did the agent contradict itself?" was rejected: a model returns a plausible contradiction for *any*
input, and a confabulated contradiction is worse than no finding — it poisons the trust the feature
is selling. Regex over narrative either matches real text or it does not, and every finding quotes
the checkpoint it came from. **Known cost: recall.** A pivot nobody wrote down is invisible, and the
report says so rather than implying the history was clean.

**Checkpoint access is by subprocess**, not by importing `cmd/entire/cli/checkpoint` directly: that
package's readers need a threaded git store and its on-disk layout is internal, whereas `--json` is
the documented contract. Both the reader and the graph client sit behind interfaces — which is also
what makes the privacy fixture test possible without a live repo.

---

## Entire Graph evidence — all reproducible

```bash
entire graph def NewRootCmd --repo . --format json                     # definition lookup
entire graph search --repo . --query "checkpoint list json output"     # semantic search
entire graph impact --repo . --symbol NewRootCmd --format json         # impact BEFORE editing root.go
entire graph commit HEAD                                               # final semantic diff
entire graph neighbors --repo . --symbol BuildExport --relation CALLS --direction in --profile full
```

The `impact` run on `NewRootCmd` reported **125 callers (101 direct)** *before* the registration
change — which is what justified making the edit a single additive `experimental.Register` line
rather than restructuring the command table.

Full captures: `docs/audit-evidence/graph-evidence.md`, `docs/audit-evidence/curveball-privacy-paths.md`.

---

## Checkpoints — the four milestones

| Milestone | Commit |
|---|---|
| 1. Initial understanding and intended architecture | `476802db5` |
| 2. Last stable state before the Curveball | `1fbe30f8a` |
| 3. Response to the Curveball | `d4c232f54` |
| 4. Final implementation and verification | `465f11db5` |

Four checkpoints exist on the branch (`entire checkpoint list`). Each milestone's decisions,
rejected options, failures and open risks are written out in
`docs/audit-evidence/MILESTONES.md` and in the commit messages themselves — a fresh session can
reconstruct intent and state from those alone.

---

## Setup, run and test

```bash
mise trust && mise install && go mod download && mise run build
entire enable -y --agent claude-code
entire plugin install graph          # required — graph is NOT bundled with the CLI

entire audit --requirements cmd/entire/cli/audit/example/feature-audit-requirements.json --no-graph
entire audit --json
entire audit --sensitive             # privacy-boundary mode
entire audit --export ./out          # privacy-safe NDJSON + Delta DDL
entire audit --fail-on high          # CI gate

go test ./cmd/entire/cli/audit/ -v   # 37 tests
```

**Inference backends**, in order: `--requirements <file>` (no inference at all), `ANTHROPIC_API_KEY`
(BYOK), or a headless `claude` CLI with no tool access. With none configured the command **fails
with actionable guidance** rather than returning an empty requirement graph — which would render as
"nothing was required", a false authoritative claim of exactly the kind this feature prevents.
Covered by `TestSelectExtractorFailsClearlyWithoutBackend`. **There is no hosted fallback.**

---

## Known limitations — stated plainly

The whole feature is an argument for honest labelling, so:

- **Graph evidence does not scale to this repository.** It completes in **0.49s on a normal repo**,
  but a 12-requirement audit of the ~1,250-file CLI repo does not finish in usable time — each
  requirement issues several `graph` subprocesses and the index does not stay warm. `cache.go` (a
  filesystem-backed result cache) is written but **not yet wired into `CLIGraphClient`**. That is
  the single highest-value next commit. `--no-graph` completes in ~1.4s and is the demonstrated path.
- **Pivot detection has never fired on a live pivot.** It is proven against constructed narratives
  in `drift_test.go`. The real Redis→filesystem pivot generated during the build lives in the
  agent's final summary message, which the checkpoint-scope transcript truncates.
- **Graph reverse-reachability was inconsistent under a time bound** — the same query returned a
  caller at `--profile full` and an empty array at the default profile. The Curveball analysis
  therefore pairs the graph pass with an exhaustive `grep` of every outbound HTTP call.
  **Grep, not the graph, is what makes the "exactly two egress paths" claim provable.**
- **Requirement extraction is a model's reading of the ask, not a specification.** Coverage is a
  review aid, not a gate — which is why the command ships behind `experimental.Register`.
- **Drift detection's constraint vocabulary is a fixed list**; it catches the shapes it knows.

## Next steps

- **Phase 2 — Entire Guard:** move from post-session audit to real-time interception, flagging a
  guarantee-changing pivot *while* the agent makes it.
- **Phase 3 — Historical Why:** connect `entire why <file>:<line>` into the requirement and decision
  graph, so a line of code resolves to the requirement it serves.
- **Phase 4 — Databricks AI Search, MLflow, Unity Catalog:** evaluate detector precision and recall
  against a labelled corpus of real pivots, and govern the audit tables.
