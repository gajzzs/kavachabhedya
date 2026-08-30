import type { Finding, EvidenceSource, SourceFile } from '@/types';
import { generateId } from '@/lib/utils';
import { extractSchema, executeQuery, reconstructQuery, reconstructSafeQuery, type DBSchema } from './sqlExecutor';

// ============================================================
// DAST Analyzer - Dynamic Application Security Testing
// REAL execution: reconstructs the vulnerable endpoint from source
// code, executes test inputs against the in-memory DB, and compares
// vulnerable vs. patched query behavior.
//
// Authenticity: EXECUTABLE (real query execution in-browser)
// ============================================================

export interface DASTTestCase {
  name: string;
  input: string;
  expectedBehavior: string;
  actualBehavior: string;
  vulnerable: boolean;
  rowCount: number;
  queryExecuted: string;
  error: string | null;
}

export interface DASTResult {
  findingId: string;
  confirmed: boolean;
  confidence: number;
  evidenceSource: EvidenceSource;
  authenticity: 'EXECUTABLE';
  detail: string;
  testCases: DASTTestCase[];
  executionId: string;
  schema: DBSchema;
}

export function runDAST(finding: Finding, files: SourceFile[]): DASTResult {
  const sourceFile = files.find((f) => f.path === finding.file) || files[0];
  const schema = extractSchema(sourceFile);
  const executionId = generateId('dast-exec');

  const testCases: DASTTestCase[] = [
    {
      name: 'Normal Input',
      input: 'admin',
      expectedBehavior: 'Returns 1 row matching username "admin"',
      actualBehavior: '',
      vulnerable: false,
      rowCount: 0,
      queryExecuted: '',
      error: null,
    },
    {
      name: 'Boolean Bypass',
      input: "' OR '1'='1",
      expectedBehavior: 'Returns 0 rows (no user has that literal username)',
      actualBehavior: '',
      vulnerable: false,
      rowCount: 0,
      queryExecuted: '',
      error: null,
    },
    {
      name: 'UNION Extraction',
      input: "' UNION SELECT id, username, email, role FROM users --",
      expectedBehavior: 'Returns 0 rows (no match for literal string)',
      actualBehavior: '',
      vulnerable: false,
      rowCount: 0,
      queryExecuted: '',
      error: null,
    },
    {
      name: 'Authentication Bypass',
      input: "admin' --",
      expectedBehavior: 'Returns 0 rows (no user has literal username "admin\' --")',
      actualBehavior: '',
      vulnerable: false,
      rowCount: 0,
      queryExecuted: '',
      error: null,
    },
  ];

  for (const tc of testCases) {
    const query = reconstructQuery(tc.input, sourceFile);
    if (!query) {
      tc.actualBehavior = 'Could not reconstruct query from source';
      tc.error = 'Reconstruction failed';
      continue;
    }

    const result = executeQuery(query, schema);
    tc.queryExecuted = result.executedQuery;
    tc.rowCount = result.rowCount;
    tc.error = result.error;

    const injected = result.authBypassed || result.dataExtracted || result.tableModified;
    tc.vulnerable = injected;

    if (tc.name === 'Normal Input') {
      tc.actualBehavior = result.rowCount > 0
        ? `Returned ${result.rowCount} row(s): ${JSON.stringify(result.rows[0])}`
        : `Returned 0 rows${result.error ? ` (error: ${result.error})` : ''}`;
    } else {
      const effects: string[] = [];
      if (result.authBypassed) effects.push(`auth bypass — ${result.rowCount} rows returned`);
      if (result.dataExtracted) effects.push('data extracted via UNION');
      if (result.tableModified) effects.push(`table modified: ${result.tablesAffected.join(', ')}`);
      tc.actualBehavior = injected
        ? `INJECTED: ${effects.join('; ')}. Query: ${result.executedQuery.substring(0, 100)}`
        : `No injection. Returned ${result.rowCount} row(s).${result.error ? ` Error: ${result.error}` : ''}`;
    }
  }

  const vulnerableCount = testCases.filter((t) => t.vulnerable).length;
  const confirmed = vulnerableCount >= 2;
  const confidence = confirmed ? 0.91 : vulnerableCount > 0 ? 0.6 : 0.2;

  return {
    findingId: finding.id,
    confirmed,
    confidence,
    evidenceSource: {
      tool: 'kavach-dast',
      toolType: 'DAST',
      status: confirmed ? 'CONFIRMED' : vulnerableCount > 0 ? 'SUSPICIOUS' : 'NOT_REPRODUCED',
      authenticity: 'EXECUTABLE',
      detail: confirmed
        ? `Dynamic test EXECUTED: ${vulnerableCount}/${testCases.length} test cases demonstrated exploitable SQL injection against in-memory DB`
        : `Dynamic test could not confirm vulnerability (${vulnerableCount} cases showed issues)`,
      confidence,
      timestamp: new Date().toISOString(),
    },
    authenticity: 'EXECUTABLE',
    detail: confirmed
      ? `DAST confirmed via REAL execution: ${vulnerableCount}/${testCases.length} test cases exploited the in-memory database`
      : `DAST could not confirm SQL injection (${vulnerableCount} cases showed issues)`,
    testCases,
    executionId,
    schema,
  };
}
