/*
# KAVACH Core Schema - Evidence-Driven Cyber Reasoning Platform

## Overview
This migration creates the core data model for KAVACH, a defensive cybersecurity
research prototype. It stores investigations, findings, evidence, patches, verification
runs, security memory records, and audit events.

## Tables Created
1. `kavach_projects` - Source code projects (demo or uploaded)
2. `kavach_investigations` - Security investigation sessions
3. `kavach_findings` - Vulnerability findings from security tools
4. `kavach_evidence` - Fused evidence from multiple sources
5. `kavach_patches` - Patch candidates with evaluation metrics
6. `kavach_verifications` - Verification run results
7. `kavach_security_memory` - Verified fix records (immune memory)
8. `kavach_audit_events` - Audit log of all agent actions
9. `kavach_agent_actions` - Guardian-tracked agent actions
10. `kavach_twin_snapshots` - Digital twin snapshots over time

## Security
- All tables use RLS enabled.
- Single-tenant prototype: policies allow anon+authenticated CRUD (no sign-in required).
- No API keys or secrets are stored in any table.
*/

-- 1. Projects
CREATE TABLE IF NOT EXISTS kavach_projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text,
  source text NOT NULL DEFAULT 'demo',
  demo_project_id text,
  files jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_projects ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_projects" ON kavach_projects;
CREATE POLICY "anon_select_projects" ON kavach_projects FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_projects" ON kavach_projects;
CREATE POLICY "anon_insert_projects" ON kavach_projects FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_projects" ON kavach_projects;
CREATE POLICY "anon_update_projects" ON kavach_projects FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_projects" ON kavach_projects;
CREATE POLICY "anon_delete_projects" ON kavach_projects FOR DELETE TO anon, authenticated USING (true);

-- 2. Investigations
CREATE TABLE IF NOT EXISTS kavach_investigations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid REFERENCES kavach_projects(id) ON DELETE CASCADE,
  project_name text NOT NULL,
  vulnerability_class text NOT NULL,
  status text NOT NULL DEFAULT 'IDLE',
  steps jsonb NOT NULL DEFAULT '[]',
  current_step text,
  findings jsonb NOT NULL DEFAULT '[]',
  evidence jsonb NOT NULL DEFAULT '[]',
  experiments jsonb NOT NULL DEFAULT '[]',
  hypotheses jsonb NOT NULL DEFAULT '[]',
  attack_path jsonb,
  patches jsonb NOT NULL DEFAULT '[]',
  verification_run jsonb,
  security_memory jsonb,
  started_at timestamptz DEFAULT now(),
  completed_at timestamptz
);
ALTER TABLE kavach_investigations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_investigations" ON kavach_investigations;
CREATE POLICY "anon_select_investigations" ON kavach_investigations FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_investigations" ON kavach_investigations;
CREATE POLICY "anon_insert_investigations" ON kavach_investigations FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_investigations" ON kavach_investigations;
CREATE POLICY "anon_update_investigations" ON kavach_investigations FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_investigations" ON kavach_investigations;
CREATE POLICY "anon_delete_investigations" ON kavach_investigations FOR DELETE TO anon, authenticated USING (true);

-- 3. Findings
CREATE TABLE IF NOT EXISTS kavach_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id uuid REFERENCES kavach_investigations(id) ON DELETE CASCADE,
  vulnerability_class text NOT NULL,
  severity text NOT NULL,
  file text NOT NULL,
  line integer NOT NULL,
  col integer,
  evidence text NOT NULL,
  confidence double precision NOT NULL,
  tool text NOT NULL,
  authenticity text NOT NULL,
  description text NOT NULL,
  code_snippet text,
  cwe text,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_findings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_findings" ON kavach_findings;
CREATE POLICY "anon_select_findings" ON kavach_findings FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_findings" ON kavach_findings;
CREATE POLICY "anon_insert_findings" ON kavach_findings FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_findings" ON kavach_findings;
CREATE POLICY "anon_update_findings" ON kavach_findings FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_findings" ON kavach_findings;
CREATE POLICY "anon_delete_findings" ON kavach_findings FOR DELETE TO anon, authenticated USING (true);

-- 4. Evidence (fused)
CREATE TABLE IF NOT EXISTS kavach_evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id uuid REFERENCES kavach_investigations(id) ON DELETE CASCADE,
  finding_id text NOT NULL,
  sources jsonb NOT NULL DEFAULT '[]',
  fused_score double precision NOT NULL,
  fused_confidence double precision NOT NULL,
  contradictions jsonb NOT NULL DEFAULT '[]',
  missing_evidence jsonb NOT NULL DEFAULT '[]',
  recommendation text NOT NULL,
  status text NOT NULL,
  reasoning text NOT NULL,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_evidence ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_evidence" ON kavach_evidence;
CREATE POLICY "anon_select_evidence" ON kavach_evidence FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_evidence" ON kavach_evidence;
CREATE POLICY "anon_insert_evidence" ON kavach_evidence FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_evidence" ON kavach_evidence;
CREATE POLICY "anon_update_evidence" ON kavach_evidence FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_evidence" ON kavach_evidence;
CREATE POLICY "anon_delete_evidence" ON kavach_evidence FOR DELETE TO anon, authenticated USING (true);

-- 5. Patches
CREATE TABLE IF NOT EXISTS kavach_patches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id uuid REFERENCES kavach_investigations(id) ON DELETE CASCADE,
  label text NOT NULL,
  strategy text NOT NULL,
  description text NOT NULL,
  original_code text NOT NULL,
  patched_code text NOT NULL,
  diff text NOT NULL,
  security_score double precision NOT NULL,
  regression_risk double precision NOT NULL,
  code_complexity double precision NOT NULL,
  performance_impact double precision NOT NULL,
  lines_changed integer NOT NULL,
  affected_components jsonb NOT NULL DEFAULT '[]',
  dependencies_added jsonb NOT NULL DEFAULT '[]',
  risk_level text NOT NULL,
  authenticity text NOT NULL,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_patches ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_patches" ON kavach_patches;
CREATE POLICY "anon_select_patches" ON kavach_patches FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_patches" ON kavach_patches;
CREATE POLICY "anon_insert_patches" ON kavach_patches FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_patches" ON kavach_patches;
CREATE POLICY "anon_update_patches" ON kavach_patches FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_patches" ON kavach_patches;
CREATE POLICY "anon_delete_patches" ON kavach_patches FOR DELETE TO anon, authenticated USING (true);

-- 6. Verifications
CREATE TABLE IF NOT EXISTS kavach_verifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id uuid REFERENCES kavach_investigations(id) ON DELETE CASCADE,
  finding_id text NOT NULL,
  patch_id text NOT NULL,
  original_attack_blocked boolean NOT NULL,
  mutation_tests jsonb NOT NULL DEFAULT '[]',
  mutation_pass_rate double precision NOT NULL,
  regression_tests jsonb NOT NULL DEFAULT '[]',
  regression_pass_rate double precision NOT NULL,
  functional_tests jsonb NOT NULL DEFAULT '[]',
  functional_pass_rate double precision NOT NULL,
  new_findings integer NOT NULL DEFAULT 0,
  status text NOT NULL,
  report text NOT NULL,
  authenticity text NOT NULL,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_verifications ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_verifications" ON kavach_verifications;
CREATE POLICY "anon_select_verifications" ON kavach_verifications FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_verifications" ON kavach_verifications;
CREATE POLICY "anon_insert_verifications" ON kavach_verifications FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_verifications" ON kavach_verifications;
CREATE POLICY "anon_update_verifications" ON kavach_verifications FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_verifications" ON kavach_verifications;
CREATE POLICY "anon_delete_verifications" ON kavach_verifications FOR DELETE TO anon, authenticated USING (true);

-- 7. Security Memory (Immune Memory)
CREATE TABLE IF NOT EXISTS kavach_security_memory (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kavach_id text NOT NULL,
  investigation_id uuid REFERENCES kavach_investigations(id) ON DELETE CASCADE,
  vulnerability_class text NOT NULL,
  status text NOT NULL DEFAULT 'VERIFIED',
  original_evidence text NOT NULL,
  attack_pattern text NOT NULL,
  patch_applied text NOT NULL,
  verification_result text NOT NULL,
  regression_test text NOT NULL,
  project_version text NOT NULL,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_security_memory ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_memory" ON kavach_security_memory;
CREATE POLICY "anon_select_memory" ON kavach_security_memory FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_memory" ON kavach_security_memory;
CREATE POLICY "anon_insert_memory" ON kavach_security_memory FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_update_memory" ON kavach_security_memory;
CREATE POLICY "anon_update_memory" ON kavach_security_memory FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_memory" ON kavach_security_memory;
CREATE POLICY "anon_delete_memory" ON kavach_security_memory FOR DELETE TO anon, authenticated USING (true);

-- 8. Audit Events
CREATE TABLE IF NOT EXISTS kavach_audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event text NOT NULL,
  category text NOT NULL,
  detail text NOT NULL,
  severity text NOT NULL DEFAULT 'INFO',
  source text NOT NULL DEFAULT 'system',
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_audit_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_audit" ON kavach_audit_events;
CREATE POLICY "anon_select_audit" ON kavach_audit_events FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_audit" ON kavach_audit_events;
CREATE POLICY "anon_insert_audit" ON kavach_audit_events FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_audit" ON kavach_audit_events;
CREATE POLICY "anon_delete_audit" ON kavach_audit_events FOR DELETE TO anon, authenticated USING (true);

-- 9. Agent Actions (Guardian)
CREATE TABLE IF NOT EXISTS kavach_agent_actions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent text NOT NULL,
  tool text NOT NULL,
  action text NOT NULL,
  target text NOT NULL,
  action_class text NOT NULL,
  status text NOT NULL,
  result text NOT NULL,
  sandboxed boolean NOT NULL DEFAULT true,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_agent_actions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_actions" ON kavach_agent_actions;
CREATE POLICY "anon_select_actions" ON kavach_agent_actions FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_actions" ON kavach_agent_actions;
CREATE POLICY "anon_insert_actions" ON kavach_agent_actions FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_actions" ON kavach_agent_actions;
CREATE POLICY "anon_delete_actions" ON kavach_agent_actions FOR DELETE TO anon, authenticated USING (true);

-- 10. Twin Snapshots
CREATE TABLE IF NOT EXISTS kavach_twin_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id uuid REFERENCES kavach_investigations(id) ON DELETE CASCADE,
  label text NOT NULL,
  description text NOT NULL,
  state text NOT NULL,
  nodes jsonb NOT NULL DEFAULT '[]',
  edges jsonb NOT NULL DEFAULT '[]',
  attack_path_active boolean NOT NULL DEFAULT false,
  patch_applied text,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE kavach_twin_snapshots ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "anon_select_twin" ON kavach_twin_snapshots;
CREATE POLICY "anon_select_twin" ON kavach_twin_snapshots FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS "anon_insert_twin" ON kavach_twin_snapshots;
CREATE POLICY "anon_insert_twin" ON kavach_twin_snapshots FOR INSERT TO anon, authenticated WITH CHECK (true);
DROP POLICY IF EXISTS "anon_delete_twin" ON kavach_twin_snapshots;
CREATE POLICY "anon_delete_twin" ON kavach_twin_snapshots FOR DELETE TO anon, authenticated USING (true);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_investigations_project ON kavach_investigations(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_investigation ON kavach_findings(investigation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON kavach_evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_patches_investigation ON kavach_patches(investigation_id);
CREATE INDEX IF NOT EXISTS idx_verifications_investigation ON kavach_verifications(investigation_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON kavach_audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_actions_created ON kavach_agent_actions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memory_created ON kavach_security_memory(created_at DESC);
