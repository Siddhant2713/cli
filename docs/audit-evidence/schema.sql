CREATE SCHEMA IF NOT EXISTS workspace.entire_audit;

CREATE TABLE IF NOT EXISTS workspace.entire_audit.feature_requirements (
  feature_id            STRING,
  requirement_id        STRING,
  repository_hash       STRING,
  checkpoint_id         STRING,
  requirement_summary   STRING,
  status                STRING,
  risk_category         STRING,
  risk_weight           DOUBLE,
  context_completeness  STRING,
  authoritative         BOOLEAN,
  evidence_count        INT,
  created_at            STRING
) USING DELTA;

CREATE TABLE IF NOT EXISTS workspace.entire_audit.risk_findings (
  finding_id            STRING,
  feature_id            STRING,
  checkpoint_id         STRING,
  kind                  STRING,
  risk_category         STRING,
  risk_level            STRING,
  finding_summary       STRING,
  evidence_ids          STRING,
  recommendation        STRING,
  context_completeness  STRING,
  authoritative         BOOLEAN,
  created_at            STRING
) USING DELTA;
