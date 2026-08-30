-- Real Assessments table for ABHEDYA KAVACH
-- Stores user-initiated real security assessments with their full results

CREATE TABLE IF NOT EXISTS kavach_real_assessments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_name text NOT NULL,
  target_type text NOT NULL DEFAULT 'SOURCE_CODE',
  language text NOT NULL DEFAULT 'Python',
  source_hash text NOT NULL,
  source_filename text,
  source_line_count integer,
  status text NOT NULL DEFAULT 'QUEUED',
  stages jsonb NOT NULL DEFAULT '[]',
  findings jsonb NOT NULL DEFAULT '[]',
  evidence jsonb,
  attack_path jsonb,
  patches jsonb NOT NULL DEFAULT '[]',
  verification jsonb,
  reasoning jsonb,
  audit_trail jsonb NOT NULL DEFAULT '[]',
  error text,
  created_at timestamptz DEFAULT now(),
  completed_at timestamptz
);

ALTER TABLE kavach_real_assessments ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_assessments" ON kavach_real_assessments;
CREATE POLICY "anon_select_assessments" ON kavach_real_assessments
  FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_assessments" ON kavach_real_assessments;
CREATE POLICY "anon_insert_assessments" ON kavach_real_assessments
  FOR INSERT TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_assessments" ON kavach_real_assessments;
CREATE POLICY "anon_update_assessments" ON kavach_real_assessments
  FOR UPDATE TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_assessments" ON kavach_real_assessments;
CREATE POLICY "anon_delete_assessments" ON kavach_real_assessments
  FOR DELETE TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_assessments_created ON kavach_real_assessments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_status ON kavach_real_assessments(status);
