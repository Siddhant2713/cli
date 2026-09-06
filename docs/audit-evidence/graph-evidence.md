# Graph evidence for `entire audit` (Buildathon submission)

Generated 2026-09-06 13:13 IST. Every command below is reproducible.

## 1. Definition lookup (`entire graph def`)

```
$ entire graph def NewRootCmd --repo . --format json
{
  "declarations": [
    {
      "name": "NewRootCmd",
      "qualified_name": "NewRootCmd",
      "kind": "function",
      "language": "Go",
      "signature": "func NewRootCmd() *cobra.Command",
      "file_path": "cmd/entire/cli/root.go",
      "start_line": 83,
      "end_line": 238,
      "fields_total": 0,
      "methods_total": 0,
      "nested_types_total": 0,
      "implementors_total": 0
    }
  ],
  "commit": "86d2603e6d0b2aab2ad8e2ab9f2c3a7161d917d2"
}
```

## 2. Impact analysis, run BEFORE editing root.go (`entire graph impact`)

```
$ entire graph impact --repo . --symbol NewRootCmd --format json
{
  "focus": {
    "id": "local/cli:Go:cmd/entire/cli/root.go:function:NewRootCmd",
    "name": "NewRootCmd",
    "qualified_name": "NewRootCmd",
    "kind": "function",
    "file_path": "cmd/entire/cli/root.go",
    "start_line": 83,
    "end_line": 238,
    "language": "Go"
  },
  "callers_total": 125,
  "callers_direct": 101,
  "callees_total": 60
}
```

This is what justified making the registration a single additive `experimental.Register`
line rather than restructuring the command table.

## 3. Final semantic diff of the submitted implementation (`entire graph commit`)

```
$ entire graph commit HEAD
Semantic changes 476802db5b998edd362471ca6791eddc180375ad..HEAD

BUILDATHON.md (Markdown)
  + section Feature-Audit-Decision-Drift-entire-audit added
  + section One-sentence-summary added
  + section Problem-intended-user-and-why-it-matters added
  + section Selected-Entire-track-and-why-Entire-is-essential added
  + section Architecture-and-main-workflow added
  + section The-central-discipline:-unknown-is-not-completed-and-it-is-not-not-implemented-either added
  + section Evidence-ladder added
  + section Entire-Graph-findings-and-verification added
  + code_fence code_fence_1_bash added
  + section Definition-lookup-used-as-evidence-and-to-verify-the-extension-point-before-writing-code added
  + section Semantic-search added
  + section Impact-analysis-run-BEFORE-modifying-root.go-to-check-the-blast-radius-of-the-change added
  + section Final-semantic-diff-of-the-submitted-implementation added
  + code_fence code_fence_2_text added
  + section Privacy-boundary-and-required-test-what-never-left-the-local-environment added
  + section The-required-test added
  + section Databricks-use-data-sources-and-limitations added
  + code_fence code_fence_3_bash added
  + code_fence code_fence_4_text added
  + section Known-limitations-and-next-steps added
  + section Setup-run-and-test-instructions added
  + code_fence code_fence_5_bash added
  + section Prerequisites:-Go-1.26.x-mise added
  + section Entire-graph-plugin added
  + section Run-the-audit added
  + section Tests-including-the-mandatory-privacy-test added
  + code_fence code_fence_6_text added

cmd/entire/cli/audit/audit.go (Go)
  ~ function Run body changed (1176 dependents)

cmd/entire/cli/audit/cache.go (Go)
  + type graphCacheEntry added
  + field graphCacheEntry.Schema added
  + field graphCacheEntry.Method added
  + field graphCacheEntry.Key added
  + field graphCacheEntry.Command added
  + field graphCacheEntry.StoredAt added
  + field graphCacheEntry.Payload added
  + field graphCacheEntry.Available added
  + type GraphCacheStats added
  + field GraphCacheStats.Hits added
  + field GraphCacheStats.Misses added
  + field GraphCacheStats.Writes added
  + field GraphCacheStats.Errors added
  + field GraphCacheStats.Disabled added
  + type CachedGraphClient added
  + field CachedGraphClient.inner added
  + field CachedGraphClient.dir added
  + field CachedGraphClient.ttl added
  + field CachedGraphClient.fingerprintOnce added
  + field CachedGraphClient.fingerprint added
  + field CachedGraphClient.repoScope added
  + field CachedGraphClient.mu added
  + field CachedGraphClient.stats added
  + function NewCachedGraphClient added
  + method CachedGraphClient.Stats added
  + method CachedGraphClient.record added
  + method CachedGraphClient.Available added
  + method CachedGraphClient.Def added
  + method CachedGraphClient.Search added
  + method CachedGraphClient.Impact added
  + function cachedQuery added
  + method CachedGraphClient.noteCommand added
  + method CachedGraphClient.currentCommand added
  + method CachedGraphClient.key added
  + method CachedGraphClient.resolveFingerprint added
  + method CachedGraphClient.disable added
  + method CachedGraphClient.git added
  + method CachedGraphClient.entryPath added
  + method CachedGraphClient.load added
  + method CachedGraphClient.store added
  + method CachedGraphClient.prune added
  + function shouldPruneGraphCache added

cmd/entire/cli/audit/checkpoints.go (Go)
  ~ type Checkpoint signature changed (431 dependents)
  + field Checkpoint.AgentNarrative added
  ~ method Checkpoint.Narrative body changed (5 dependents)
  ~ type listItem signature changed (2 dependents)
  + field listItem.CheckpointID added
  + field listItem.CondensationID added
  ~ method CLICheckpointReader.List body changed (142 dependents)
  + method CLICheckpointReader.list added
  ~ function parseExplainText body changed (1 dependent)
  ~ function LoadCheckpoints body changed (1 dependent)

cmd/entire/cli/audit/drift.go (Go)
  ~ function DetectPivots body changed (7 dependents)

cmd/entire/cli/audit/drift_test.go (Go)
  + function TestNarrativeExcludesTheUserPrompt added
  + function TestPivotSummaryDoesNotOverclaim added

cmd/entire/cli/audit/evidence.go (Go)
  ~ type EvidenceCollector signature changed (5 dependents)
  + field EvidenceCollector.RequirementsFile added
  ~ method EvidenceCollector.Collect body changed (20 dependents)
  + function circularEvidencePath added
  ~ method EvidenceCollector.textSearch body changed (1 dependent)

cmd/entire/cli/audit/example/feature-audit-requirements.json (JSON)
  + section _comment added
  + section requirements added
  + section id added
  + section summary added
  + section risk_category added
  + section risk_weight added
  + section search_hints added

cmd/entire/cli/audit/risk_test.go (Go)
  + function TestCircularEvidenceIsExcluded added

```
