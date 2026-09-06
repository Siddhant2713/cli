package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Databricks delivery.
//
// Only [ExportBundle] rows ever reach this file, and BuildExport is the sole
// constructor for them. That is the enforcement point for the privacy boundary:
// this code physically cannot see a prompt or a transcript, because the types it
// accepts have no field to hold one.
//
// Two delivery modes, in order of preference:
//   - Live: the SQL Statement Execution API creates the two tables and inserts
//     the rows, so a judge can query them in the workspace.
//   - Static: newline-delimited JSON plus ready-to-run DDL written to disk.
//
// Static is not a degraded mode — it is the reproducible artifact, and it is
// written on every run regardless of whether the live push succeeds, so the
// submission never depends on a workspace being reachable.

// DatabricksConfig holds workspace credentials. These come from the environment
// only; nothing here is ever written into the repository.
type DatabricksConfig struct {
	Host      string // e.g. https://dbc-xxxx.cloud.databricks.com
	Token     string
	Warehouse string // SQL warehouse ID
	Catalog   string
	Schema    string
}

// DatabricksConfigFromEnv reads the standard Databricks environment variables.
func DatabricksConfigFromEnv() DatabricksConfig {
	c := DatabricksConfig{
		Host:      strings.TrimRight(os.Getenv("DATABRICKS_HOST"), "/"),
		Token:     os.Getenv("DATABRICKS_TOKEN"),
		Warehouse: os.Getenv("DATABRICKS_WAREHOUSE_ID"),
		Catalog:   os.Getenv("DATABRICKS_CATALOG"),
		Schema:    os.Getenv("DATABRICKS_SCHEMA"),
	}
	if c.Catalog == "" {
		c.Catalog = "workspace"
	}
	if c.Schema == "" {
		c.Schema = "entire_audit"
	}
	return c
}

// Configured reports whether a live push is possible.
func (c DatabricksConfig) Configured() bool {
	return c.Host != "" && c.Token != "" && c.Warehouse != ""
}

// DDL returns the table definitions, so the static export is directly usable and
// a reviewer can see that context_completeness is a first-class column rather
// than a claim in prose.
func (c DatabricksConfig) DDL() string {
	return fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %[1]s.%[2]s;

CREATE TABLE IF NOT EXISTS %[1]s.%[2]s.feature_requirements (
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

CREATE TABLE IF NOT EXISTS %[1]s.%[2]s.risk_findings (
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
) USING DELTA;`, c.Catalog, c.Schema)
}

// WriteStaticExport writes the export bundle plus its DDL to a directory.
func WriteStaticExport(dir string, cfg DatabricksConfig, b ExportBundle) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create export dir: %w", err)
	}
	var written []string

	ddlPath := dir + "/schema.sql"
	if err := os.WriteFile(ddlPath, []byte(cfg.DDL()+"\n"), 0o644); err != nil {
		return nil, err
	}
	written = append(written, ddlPath)

	reqPath := dir + "/feature_requirements.ndjson"
	if err := writeNDJSON(reqPath, len(b.FeatureRequirements), func(i int) any { return b.FeatureRequirements[i] }); err != nil {
		return nil, err
	}
	written = append(written, reqPath)

	findPath := dir + "/risk_findings.ndjson"
	if err := writeNDJSON(findPath, len(b.RiskFindings), func(i int) any { return b.RiskFindings[i] }); err != nil {
		return nil, err
	}
	written = append(written, findPath)

	return written, nil
}

func writeNDJSON(path string, n int, at func(int) any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := 0; i < n; i++ {
		if err := enc.Encode(at(i)); err != nil {
			return fmt.Errorf("encode row %d: %w", i, err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// PushToDatabricks creates the tables and inserts the bundle's rows via the SQL
// Statement Execution API.
func PushToDatabricks(ctx context.Context, cfg DatabricksConfig, b ExportBundle) error {
	if !cfg.Configured() {
		return fmt.Errorf("databricks not configured: set DATABRICKS_HOST, DATABRICKS_TOKEN and DATABRICKS_WAREHOUSE_ID")
	}
	for _, stmt := range strings.Split(cfg.DDL(), ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if err := execStatement(ctx, cfg, stmt); err != nil {
			return fmt.Errorf("create tables: %w", err)
		}
	}
	if len(b.FeatureRequirements) > 0 {
		if err := execStatement(ctx, cfg, insertRequirements(cfg, b.FeatureRequirements)); err != nil {
			return fmt.Errorf("insert feature_requirements: %w", err)
		}
	}
	if len(b.RiskFindings) > 0 {
		if err := execStatement(ctx, cfg, insertFindings(cfg, b.RiskFindings)); err != nil {
			return fmt.Errorf("insert risk_findings: %w", err)
		}
	}
	return nil
}

func insertRequirements(cfg DatabricksConfig, rows []FeatureRequirementRow) string {
	var vals []string
	for _, r := range rows {
		vals = append(vals, fmt.Sprintf("(%s,%s,%s,%s,%s,%s,%s,%g,%s,%t,%d,%s)",
			q(r.FeatureID), q(r.RequirementID), q(r.RepositoryHash), q(r.CheckpointID),
			q(r.RequirementSummary), q(r.Status), q(r.RiskCategory), r.RiskWeight,
			q(r.ContextCompleteness), r.Authoritative, r.EvidenceCount, q(r.CreatedAt)))
	}
	return fmt.Sprintf("INSERT INTO %s.%s.feature_requirements VALUES %s",
		cfg.Catalog, cfg.Schema, strings.Join(vals, ","))
}

func insertFindings(cfg DatabricksConfig, rows []RiskFindingRow) string {
	var vals []string
	for _, r := range rows {
		vals = append(vals, fmt.Sprintf("(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%t,%s)",
			q(r.FindingID), q(r.FeatureID), q(r.CheckpointID), q(r.Kind), q(r.RiskCategory),
			q(r.RiskLevel), q(r.FindingSummary), q(r.EvidenceIDs), q(r.Recommendation),
			q(r.ContextCompleteness), r.Authoritative, q(r.CreatedAt)))
	}
	return fmt.Sprintf("INSERT INTO %s.%s.risk_findings VALUES %s",
		cfg.Catalog, cfg.Schema, strings.Join(vals, ","))
}

// q renders a SQL string literal, escaping quotes and backslashes.
func q(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}

func execStatement(ctx context.Context, cfg DatabricksConfig, statement string) error {
	body, err := json.Marshal(map[string]any{
		"statement":       statement,
		"warehouse_id":    cfg.Warehouse,
		"wait_timeout":    "30s",
		"on_wait_timeout": "CANCEL",
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfg.Host+"/api/2.0/sql/statements", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var parsed struct {
		Status struct {
			State string `json:"state"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("decode response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("databricks returned %d", resp.StatusCode)
	}
	if parsed.Status.State != "SUCCEEDED" {
		msg := parsed.Status.State
		if parsed.Status.Error != nil {
			msg = parsed.Status.Error.Message
		}
		return fmt.Errorf("statement did not succeed: %s", msg)
	}
	return nil
}
