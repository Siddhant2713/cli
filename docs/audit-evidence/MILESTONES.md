# `entire audit` — Buildathon Milestones

Four milestones, each anchored to a real commit. Everything below is taken from
the commit messages and the code as it stands; where a claim is weaker than it
sounds, it says so.

| # | Milestone | Commit | Time |
| --- | --- | --- | --- |
| 1 | Initial understanding and intended architecture | `476802db5` | 13:02 |
| 2 | Last stable state before the Noon Curveball | `1fbe30f8a` | 14:09 |
| 3 | Response to the Curveball (privacy boundary) | `d4c232f54` | 14:18 |
| 4 | Final implementation and verification | `595efdfdf` | 14:29 |

---

## Milestone 1 — Initial understanding and intended architecture

**Commit `476802db5` — "Add `entire audit`: feature audit & decision drift"**
19 files, 3,468 insertions: a new `cmd/entire/cli/audit` package plus two lines
in `root.go` registering the command through `experimental.Register`, the same
shape `review` and `investigate` use.

### The problem, as understood at the start

A diff shows that code changed. It does not show that an agent tried Redis for
rate limiting, failed, and silently fell back to an in-memory map — dropping a
distributed-system guarantee the original requirement depended on. That
information exists only in the checkpoint narrative. This command reads it.

### The 5-stage pipeline (`audit.go`, `Run`)

1. **Requirement extraction** — decompose the original ask (the earliest
   checkpoint's prompt) into a requirement graph.
2. **Checkpoint sequence** — `LoadCheckpoints` reads the branch's history.
   Stages 1 and 2 are interleaved in the code, because the ask is *sourced from*
   the checkpoint sequence: the loader runs first (`audit.go:67`) and extraction
   follows at `audit.go:100`.
3. **Evidence** — per requirement, collect structural evidence via the Entire
   Graph, falling back to lexical text search.
4. **Pivots and decision drift** — `DetectPivots`, `DetectDecisionDrift`,
   `GapFindings` over the checkpoint narratives.
5. **Risk-adjusted coverage** — `ComputeCoverage` over the requirement states.

### Decisions made

- **Checkpoint access by subprocess, not package import.** The `--json` output
  of `entire checkpoint list` / `explain` is the documented contract. Both the
  checkpoint reader and the graph client sit behind interfaces, which is what
  makes the privacy fixture test possible without a live repo.
- **Privacy boundary by allowlist construction.** `BuildExport` builds the two
  export row types field by field from separate structs. Raw prompts,
  transcripts, tool arguments and unredacted payloads have no path to the export
  because the export types have no field to hold them.
- **Pivot/drift detection as deterministic pattern matchers.** Regex over
  narrative either matches real text or it does not, and every finding quotes
  the checkpoint it came from.
- **No hosted inference fallback.** Backends in order: `--requirements` file,
  `ANTHROPIC_API_KEY` (BYOK), headless `claude` CLI with no tool access. With
  none configured the command fails with actionable guidance.
- **The central discipline.** "Unknown" is not "completed", and equally is not
  "not implemented". `StateFromEvidence` keeps *how well we were able to look*
  separate from *what we found*. A complete search finding nothing yields
  `not_verified`; an incomplete search finding nothing yields `unknown`. Neither
  ever renders as "was not implemented".

### Rejected, and why

- **Importing `cmd/entire/cli/checkpoint` directly** — its readers need a
  threaded git store and repo context, and its on-disk layout is internal and
  changes freely. Cost of the subprocess is one spawn per call, irrelevant at
  this scale.
- **Marshalling the in-memory `Report` and stripping sensitive keys** — a
  redactor is a denylist, and it fails OPEN the day someone adds a field it does
  not know about. The field that leaks is precisely the new one nobody
  considered. Field-by-field construction fails CLOSED.
- **Asking a model "did the agent contradict itself?"** — a model returns a
  plausible contradiction for any input, and a confabulated contradiction is
  worse than no finding: it poisons the trust the feature is selling. Known cost
  is **recall** — a pivot nobody wrote down is invisible to these detectors, and
  the report says so in its own output.
- **Returning an empty requirement graph when no backend is configured** — an
  empty graph renders as "nothing was required", a false authoritative claim of
  exactly the kind this feature exists to prevent.

### What failed

Nothing had been run against real data yet. That is the honest characterisation
of this milestone: the design was sound and the tests passed, but every bug
found later was found by pointing the tool at live checkpoints rather than
fixtures. `TestRedactedCheckpointNeverBecomesAuthoritativeClaim` was
mutation-verified rather than merely observed passing — injecting the spec's
exact bug (emit `"%s was not implemented"` with `Authoritative: true`) makes it
fail on all three assertions, and reverting makes it pass. A test that has never
been seen to fail proves nothing.

### Open risks recorded at the time

- The requirement graph is a model's reading of the original ask, not a
  specification. Coverage is a review aid, not a gate — which is why the command
  is experimental.
- Drift detection's constraint vocabulary is a fixed list; it will miss novel
  phrasings.
- Graph evidence depends on the graph plugin being installed.
- **Databricks delivery not yet exercised against a live workspace.** (Closed at
  `692022cee`.)

---

## Milestone 2 — Last stable state before the Noon Curveball

**Commit `1fbe30f8a` — "audit: semantic search alone must never confirm a
requirement"**

Two commits preceded it in the same run and belong to the same arc:
`86d2603e6` fixed three false-signal bugs found against real checkpoints, and
`c64461cbc` captured reproducible graph evidence while retracting an
over-generous claim about the graph path.

### What failed — a false positive of the exact kind the feature exists to catch

Run against a throwaway repo that genuinely had **no rate limiting**, the audit
reported rate limiting as **COMPLETED**.

`entire graph def RateLimiter` returned zero declarations and `entire graph
impact --symbol RateLimiter` returned an empty focus — both correctly saying the
symbol does not exist. But `entire graph search` matched the nearby `Login`
function, and those proximity hits were counted as "structural evidence" with
the same weight as a declaration, promoting the requirement to completed.

The damning detail: **the text-search path had this right.** Running with
`--no-graph` correctly reported rate limiting as unverified and named it as a
missing high-impact control. Turning the graph ON made the answer strictly
worse. A feature whose entire pitch is "we do not claim more than the evidence
supports" was claiming a security control existed when it did not.

### What was decided — three evidence tiers, not two

- **DEFINITIONAL** — `graph def`, and `graph impact` with a resolved focus.
  Answers "does a thing with this name exist?" An identity claim.
- **PROXIMITY** — `graph search`. Answers "what is the nearest code to this
  description?" A ranked nearest-neighbour query that **always** returns
  something, including when nothing implements the requirement at all. It
  locates; it does not confirm.
- **LEXICAL** — `git grep`. Unchanged.

Only definitional evidence can promote a requirement to completed. Proximity
evidence caps it at `partial`. Separately: an impact result whose focus does not
resolve is no longer recorded as evidence at all — it means the symbol is
absent, so filing it as evidence *for* the requirement inverted its meaning.

Verified by `TestSemanticSearchAloneCannotConfirmARequirement`. Re-running the
trial repo reports `rate_limit` PARTIAL while the two requirements that really
are implemented (`HashPassword`, `InvalidateSession`, both with `graph def`
hits) stay COMPLETED.

### What was rejected

Diagnosing the graph path as merely slow. `c64461cbc` had said graph-backed
evidence "does not complete for a full requirement set on a repo this size" —
true, but an incomplete diagnosis that this commit corrected: on a small repo
the graph path completes in **0.49s**. It is a scaling problem specific to the
1,250-file CLI repo, *and* the code path had a correctness bug, which is worse,
and which only showed up because it was finally run somewhere the right answer
was known in advance.

### Open risks carried into the Curveball

- **Graph evidence does not scale to this repository.** Individual graph queries
  work and are reproducible (`graph-evidence.md`); the full 12-requirement set
  running through them in one pass is **not proven**. Each requirement issues
  several `entire graph` subprocess calls and the index does not stay warm
  across them. `--no-graph` completes in under a second and is the path
  demonstrated end to end.
- **`cache.go` exists to close that gap but is NOT wired into
  `CLIGraphClient`.** Still true as of the final commit — `graph.go` contains no
  reference to the cache.
- **Pivot detection has never fired on a live pivot.** With the user's prompt
  correctly excluded from the narrative (`86d2603e6`), the two-checkpoint corpus
  yields zero pivot findings: the agent's narrated course-correction lives in
  its final summary message, which the checkpoint-scope transcript truncates.
  Detection is proven against constructed narratives in `drift_test.go` only.

---

## Milestone 3 — Response to the Curveball (privacy boundary)

**Commit `d4c232f54` — "Curveball: close the prompt-egress path the Graph
analysis exposed"**

Curveball requirement 6 — "use Entire Graph to identify every code path affected
by this privacy boundary" — is what produced this commit. Running

```
entire graph neighbors --repo . --symbol <sink> --relation CALLS --direction in
```

over every egress sink in the audit package found **exactly two** paths out to
an external service.

### What the graph found

- **`databricks.go` / `execStatement` ← `PushToDatabricks` ← `run`** — receives
  only `ExportBundle` rows, built by the field-by-field allowlist in
  `privacy.go`. Structurally incapable of carrying prompt text. **GUARDED**, and
  already verified against a live workspace.
- **`extract.go` / `AnthropicExtractor.Extract` ← `Run`** — sends `ask` to
  `api.anthropic.com`. `ask` is **checkpoint prompt text**, taken from the
  earliest checkpoint. **UNGUARDED.**

The second path is the real gap, and it was invisible until the graph analysis:
sending the prompt to a model is the feature working exactly as designed — right
up until the repository is sensitive. The Databricks boundary had been designed
in from the first commit; this one had not, and no amount of reasoning about the
export types would have surfaced it, because the leak is not in the export path
at all.

### What was decided — `egress.go`, default-deny

Default-deny prompt egress on any repository whose checkpoint history contains
redacted entries. The audit still runs on sensitive repositories; it just
requires the requirement graph to be supplied locally:

```
entire audit --requirements <file.json>   # works, sends nothing anywhere
entire audit --sensitive                  # force-deny regardless of history
entire audit --allow-prompt-egress        # explicit operator opt-in
```

Three deliberate choices:

- **The redaction signal is conservative.** If ANY checkpoint in range is
  redacted, the whole repository is sensitive. Operators who redact part of
  their history have already said the content is not for general distribution;
  inferring "the un-redacted ones must be fine" is precisely the assumption a
  privacy boundary must not make.
- **`extractorSendsPromptOffMachine` fails CLOSED.** An extractor added later
  that it does not recognise is treated as remote, so forgetting to update the
  list cannot silently open a new egress path. Locked by
  `TestUnknownExtractorFailsClosed`.
- **The headless local agent is also treated as remote.** The binary is local
  but it still reaches a model over the network, and its config is not visible
  from here.

The block happens **before** the extractor is invoked (`audit.go:107`, ahead of
`ext.Extract` at line 112), and the test asserts the extractor was never called
rather than only that an error came back. An error returned after the request is
on the wire would be worthless.

### What was rejected

Guarding after the call, and trusting an allowlist of known-remote extractors.
Both were rejected for the same reason: they fail open.

### What failed

The design review at milestone 1 did not find this path. The privacy thinking
was entirely concentrated on the *export* boundary, which was correct and
verified, while the extraction boundary — an outbound HTTP call in the same
package — went unexamined for the whole build. Being one of two egress sinks and
still missed is the honest summary.

### Open risks

The sensitivity signal is *redaction presence*, a proxy. A repository with
sensitive prompts and no redacted checkpoints reads as non-sensitive and prompt
egress proceeds. `--sensitive` exists for that case, but it requires the
operator to know.

---

## Milestone 4 — Final implementation and verification

**Commit `595efdfdf` — "docs: complete the Curveball privacy-path analysis,
including where Graph fell short"**, resting on `692022cee` for the live
Databricks verification.

### State at submission

- **37 tests** in `cmd/entire/cli/audit` (counted as `Test*` functions across
  the package's `_test.go` files).
- **Databricks verified live**, not merely implemented. Two Delta tables created
  and populated against a real Free Edition workspace
  (`dbc-42a681b0-04dc.cloud.databricks.com`, Serverless Starter Warehouse):
  `workspace.entire_audit.feature_requirements` 12 rows,
  `workspace.entire_audit.risk_findings` 0 rows. The rows were **read back** —
  an exit code is not evidence.
- **The privacy boundary checked against real rows.** `SELECT *` was queried and
  the returned rows scanned for text that demonstrably exists in the local
  checkpoint record: the prompts ("Add a result cache…", "edit somehting…"), the
  transcript speaker tags `[User]` and `[Assistant]`, the technology named in
  the pivot ("Redis"), and the repo owner's name. None are present.
  `repository_hash` is a SHA-256 prefix; the workspace never receives the
  repository URL. This is the claim the whole design rests on, so it was proven
  against real data rather than against a fixture we control.
- No credentials committed. The token lives in `~/.databricks-audit.env`, mode
  600, outside the repository. The static export (`schema.sql` + both NDJSON
  files) is committed so the tables can be rebuilt without workspace access.

### Two results that look like failures and are not

- **Every requirement row came back `context_completeness=partial`,
  `authoritative=false`.** The run used `--no-graph`, so all evidence was
  lexical, and lexical evidence cannot establish a structural fact. The tool
  declining to mark its OWN requirements confirmed on the strength of grep hits
  is the argument of the feature, made visible in the data instead of asserted
  in prose.
- **`risk_findings` is empty** (`risk_findings.ndjson` is 0 bytes). No pivot or
  drift exists in the two available checkpoints. Fabricating a row to make the
  table look alive would be exactly the failure this tool detects.

### What failed — where Graph fell short

Two things recorded in the final commit that are not flattering:

1. **Graph reverse-reachability was UNRELIABLE on this repo under a time
   bound.** The same query returned `run` as a caller at `--profile full` and an
   empty `incoming` array at the default profile; several re-runs did not finish
   inside the deadline. The graph pass is therefore reported alongside an
   exhaustive grep of every `http.NewRequest` / `client.Do` in the package, as a
   completeness check. A graph answer that cannot be reliably re-run is not a
   sound basis for a security claim, and presenting it as one would be the same
   overclaiming this feature exists to detect.
2. **The evidence file polluted its own analysis.** Once an earlier draft
   existed, `graph neighbors --symbol BuildExport` began matching *that markdown
   file* alongside the Go function, because the graph indexes prose and the file
   names the symbols it documents. Worth knowing before trusting a symbol query
   in a repo that documents its own symbols.

Both passes agree: exactly two egress paths exist, one was already guarded, one
was not and now is. The conclusion is sound; the honest part is that **grep, not
the graph, is what makes it provably complete.**

### Open risks at submission

- **Graph evidence does not scale to this repository.** Individual queries are
  reproducible; the full requirement set in one pass is not proven. `--no-graph`
  is the path demonstrated end to end, and it is what the live Databricks run
  used — which is also why every exported row is non-authoritative.
- **`cache.go` is still not wired into `CLIGraphClient`.** `graph.go` contains
  no reference to it. This remains the highest-value next commit, and it is what
  stands between the graph path and being demonstrable at repo scale.
- **Pivot detection has never fired on a live pivot.** It is proven against
  constructed narratives in `drift_test.go` and against the Redis→in-memory case
  as a fixture, but the live corpus produces zero findings because the agent's
  narrated course-correction lives in a final summary message the
  checkpoint-scope transcript truncates. The empty `risk_findings` table is the
  visible consequence.
- **Sensitivity is inferred from redaction presence**, a proxy that can read a
  genuinely sensitive repository as clean.
- **Requirement graphs are a model's reading of the ask, not a specification.**
  Coverage is a review aid, not a gate. The command stays `experimental` for
  this reason.
- **Drift detection's constraint vocabulary is a fixed list** and will miss
  phrasings outside it. Recall is the acknowledged cost of choosing
  deterministic matchers over an LLM judge.
