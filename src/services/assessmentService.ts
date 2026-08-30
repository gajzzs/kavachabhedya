import { supabase } from '@/lib/supabase';

export interface AssessmentRecord {
  id?: string;
  project_name: string;
  target_type: string;
  language: string;
  source_hash: string;
  source_filename: string | null;
  source_line_count: number | null;
  status: string;
  stages: unknown[];
  findings: unknown[];
  evidence: unknown | null;
  attack_path: unknown | null;
  patches: unknown[];
  verification: unknown | null;
  reasoning: unknown | null;
  audit_trail: unknown[];
  error: string | null;
  completed_at?: string | null;
}

export async function createAssessment(record: Omit<AssessmentRecord, 'id'>): Promise<string | null> {
  const { data, error } = await supabase
    .from('kavach_real_assessments')
    .insert(record)
    .select('id')
    .single();
  if (error) {
    console.error('Failed to create assessment:', error.message);
    return null;
  }
  return data?.id ?? null;
}

export async function updateAssessment(id: string, updates: Partial<AssessmentRecord>): Promise<boolean> {
  const { error } = await supabase
    .from('kavach_real_assessments')
    .update(updates)
    .eq('id', id);
  if (error) {
    console.error('Failed to update assessment:', error.message);
    return false;
  }
  return true;
}

export async function listAssessments(): Promise<AssessmentRecord[]> {
  const { data, error } = await supabase
    .from('kavach_real_assessments')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) {
    console.error('Failed to list assessments:', error.message);
    return [];
  }
  return (data ?? []) as AssessmentRecord[];
}
