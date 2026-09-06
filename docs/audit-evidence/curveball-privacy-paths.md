# Curveball response — identifying every code path affected by the privacy boundary

Curveball requirement 6: *"Use Entire Graph to identify every code path affected by this privacy
boundary."* This file records what was run, what it found, and — honestly — where the graph could
not carry the whole load on a repository this size.

Analysis commit: `1fbe30f8ae7112148c1ee355cd999b72ed573d46`

---

## Method

The privacy boundary is about one thing: **can prompt or transcript text reach an external
service?** So the question to answer is not "what touches privacy code" but "what are the egress
sinks, and what reaches them". That is a reverse-reachability question, which is exactly what
`graph neighbors --direction in` answers.

Two passes were used, and both are reported because they did not agree in cost:

1. **Graph reverse-reachability** on each candidate sink.
2. **Exhaustive source enumeration** of every outbound HTTP call in the package, as a completeness
   check on pass 1 — because a graph answer you cannot fully re-run is not a basis for a security
   claim.

---

## Pass 1 — Graph reverse-reachability

```
$ entire graph neighbors --repo . --symbol BuildExport --relation CALLS --direction in \
    --profile full --format json
```

Result (abridged from the JSON):

```
FOCUS:  BuildExport            cmd/entire/cli/audit/privacy.go:110
  <-    run                    cmd/entire/cli/audit/command.go
```

```
$ entire graph neighbors --repo . --symbol execStatement --relation CALLS --direction in \
    --profile full --format json
```

```
FOCUS:  execStatement          cmd/entire/cli/audit/databricks.go:200
```

This established the Databricks chain: `run` → `BuildExport` → (rows) → `PushToDatabricks` →
`execStatement` → network. `BuildExport` is the only constructor of the row types, so everything
reaching the Databricks sink has passed the allowlist in `privacy.go`.

### Two honest caveats on the graph pass

- **Reliability on this repo.** Repeated `neighbors` runs on the ~1,250-file CLI repository were
  inconsistent under a 60s bound: the same query that returned `run` as a caller at `--profile full`
  returned an empty `incoming` array at the default profile. The results above are from runs that
  completed; several later re-runs did not finish inside the deadline. This is the same scaling
  limit recorded in BUILDATHON.md, and it is the reason pass 2 exists.
- **The evidence file polluted its own analysis.** Once an earlier draft of this document existed,
  `graph neighbors --symbol BuildExport` began matching **this Markdown file** alongside the Go
  function, because the graph indexes prose and this file names the symbols. Worth knowing before
  trusting a symbol query in a repo that documents its own symbols.

---

## Pass 2 — Exhaustive egress enumeration (the completeness check)

```
$ grep -n "http.NewRequest\|client.Do\|http.Post\|http.Get" cmd/entire/cli/audit/*.go
cmd/entire/cli/audit/extract.go:129     http.NewRequestWithContext(... a.baseURL()+"/v1/messages" ...)
cmd/entire/cli/audit/extract.go:141     client.Do(req)
cmd/entire/cli/audit/databricks.go:210  http.NewRequestWithContext(... cfg.Host+"/api/2.0/sql/statements" ...)
cmd/entire/cli/audit/databricks.go:219  client.Do(req)
```

**Exactly two paths leave the machine.**

| # | Sink | Reached from | Carries | Status |
|---|---|---|---|---|
| 1 | `execStatement` → Databricks SQL API | `run` → `BuildExport` → `PushToDatabricks` | `ExportBundle` rows only | **Guarded by construction** |
| 2 | `AnthropicExtractor.Extract` → Anthropic Messages API | `Run` (audit.go) | **`ask` — raw checkpoint prompt text** | **Was unguarded** |

### Path 1 — safe by construction

`BuildExport` (`privacy.go:110`) is the only constructor of `FeatureRequirementRow` and
`RiskFindingRow`. It builds them field by field from a closed allowlist; nothing marshals the
in-memory `Report`. There is no field on either row type capable of holding a prompt or a
transcript, so this path cannot leak one regardless of what upstream code does.

Verified against the live workspace, not only in tests: querying `SELECT *` on both tables and
scanning for text known to exist locally — the prompts, `[User]`/`[Assistant]` speaker tags,
"Redis", the repo owner's name — returns none of it.

### Path 2 — the gap this analysis found

`Run` passes `ask` to the extractor. `ask` is the earliest checkpoint's prompt. On a sensitive
repository that is exactly the content the Curveball prohibits sending to an external service.

This was invisible until the reachability question was asked, because **sending the prompt to a
model is the feature working as designed** — right up until the repository is sensitive. The
Databricks boundary had been designed in from the first commit and reasoned about repeatedly; no
amount of scrutiny of the export types would have surfaced this one, because the leak is not in
the export path at all.

**Closed in `egress.go`** (`AuthorizeExtraction`), default-deny whenever any checkpoint in range is
redacted:

```bash
entire audit --requirements <file.json>   # sensitive-safe: sends nothing anywhere
entire audit --sensitive                  # force-deny regardless of history
entire audit --allow-prompt-egress        # explicit operator opt-in
```

The check runs **before** the extractor is invoked, and
`TestPromptEgressBlockedOnRedactedRepo` asserts the extractor was never called — not merely that
an error came back. An error raised after the request is already on the wire would be worthless.

`extractorSendsPromptOffMachine` **fails closed**: an extractor added later that it does not
recognise is treated as remote, so forgetting to update it cannot silently open a new path.
Locked by `TestUnknownExtractorFailsClosed`.

---

## Reproduce

```bash
entire plugin install graph
entire graph neighbors --repo . --symbol BuildExport   --relation CALLS --direction in --profile full --format json
entire graph neighbors --repo . --symbol execStatement --relation CALLS --direction in --profile full --format json
grep -n "http.NewRequest\|client.Do" cmd/entire/cli/audit/*.go
go test ./cmd/entire/cli/audit/ -run 'Egress|Redacted|Export' -v
```
