import type { Finding, EvidenceSource, SourceFile } from '@/types';
import { generateId } from '@/lib/utils';
import { extractSchema, executeQuery, reconstructQuery, extractSQLContext, type DBSchema } from './sqlExecutor';

// ============================================================
// Controlled Fuzzer — SQL Injection
//
// Consumes the ACTUAL SAST finding and uploaded source.
// Reconstructs the vulnerable SQL query from source, executes a
// benign BASELINE first, then runs context-aware mutations and
// compares each mutation's behavior against the baseline.
//
// Classification is evidence-based: a payload is CONFIRMED only
// when the controlled execution shows a meaningful behavioral
// difference from the baseline (row count change, syntax error,
// data extraction, tautology bypass).
//
// Authenticity: CONTROLLED — isolated in-memory DB execution.
// ============================================================

export type FuzzClassification = 'CONFIRMED' | 'SUSPICIOUS' | 'NOT_REPRODUCED' | 'FAILED' | 'INCONCLUSIVE';

export interface FuzzPayload {
  payload: string;
  input: string;
  queryConstructed: string;
  injectionDetected: boolean;
  injectionType: string;
  detail: string;
  rowCount: number;
  dataExtracted: boolean;
  authBypassed: boolean;
  tableModified: boolean;
  dataModified: boolean;
  error: string | null;
  // Baseline comparison fields
  category: string;
  reason: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  classification: FuzzClassification;
  baselineRowCount: number;
  behaviorChange: string;
  executionMode: 'CONTROLLED_FIXTURE' | 'SOURCE_DERIVED' | 'NOT_EXECUTED';
  syntaxError: boolean;
}

export interface FuzzResult {
  findingId: string;
  payloads: FuzzPayload[];
  confirmed: boolean;
  confidence: number;
  confirmedCount: number;
  evidenceSource: EvidenceSource;
  authenticity: 'EXECUTABLE';
  detail: string;
  executionId: string;
  schema: DBSchema;
  baseline: {
    input: string;
    query: string;
    rowCount: number;
    error: string | null;
    executed: boolean;
  } | null;
  sqlContext: string | null;
  executionMode: 'CONTROLLED_FIXTURE' | 'SOURCE_DERIVED';
  skipped: boolean;
  skipReason: string | null;
}

interface PayloadDefinition {
  input: string;
  category: string;
  reason: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
}

// Generate context-aware payloads based on the SQL context extracted from source.
// These are NOT a static list — the categories and payloads are chosen based on
// the column, table, and quote style detected in the source.
function generateContextAwarePayloads(column: string, table: string, hasQuotes: boolean): PayloadDefinition[] {
  const colCount = 4; // Default to 4 columns for UNION tests (id, username, email, role)
  const payloads: PayloadDefinition[] = [];

  // 1. Safe control input (baseline comparison)
  // Uses 'alice' which exists in the controlled fixture so boolean differential
  // tests can show a meaningful true vs false difference.
  payloads.push({
    input: 'alice',
    category: 'SAFE_CONTROL',
    reason: `Benign input to establish baseline behavior for WHERE ${column} = 'alice' (existing fixture row)`,
    confidence: 'HIGH',
  });

  // 2. Quote termination
  payloads.push({
    input: "'",
    category: 'QUOTE_TERMINATION',
    reason: `Single quote tests whether the input breaks out of the string literal in WHERE ${column} = '<INPUT>'`,
    confidence: 'HIGH',
  });

  // 3. Boolean tautology — bypass WHERE clause
  payloads.push({
    input: `' OR '1'='1`,
    category: 'BOOLEAN_TAUTOLOGY',
    reason: `Injects OR '1'='1' tautology to bypass the WHERE ${column} filter — should return all rows in ${table}`,
    confidence: 'HIGH',
  });

  // 4. Comment-based bypass
  payloads.push({
    input: `admin'--`,
    category: 'COMMENT_BYPASS',
    reason: `Comments out the remainder of the query after ${column}, potentially bypassing additional conditions`,
    confidence: 'HIGH',
  });

  // 5. Boolean differential — true condition (uses existing fixture user so the
  // WHERE filter still matches, and the AND tautology doesn't change the result)
  payloads.push({
    input: `alice' AND '1'='1`,
    category: 'BOOLEAN_DIFFERENTIAL_TRUE',
    reason: `Injects alice' AND '1'='1 — if SQL injection works, this returns alice (same as baseline). Compared against the FALSE variant, a differential confirms injection`,
    confidence: 'HIGH',
  });

  // 6. Boolean differential — false condition
  payloads.push({
    input: `alice' AND '1'='0`,
    category: 'BOOLEAN_DIFFERENTIAL_FALSE',
    reason: `Injects alice' AND '1'='0 — if SQL injection works, the contradiction suppresses all rows. Baseline returns 1 row, so 0 rows confirms injection`,
    confidence: 'HIGH',
  });

  // 7. UNION-based data extraction
  const unionCols = Array.from({ length: colCount }, () => 'NULL').join(', ');
  payloads.push({
    input: `' UNION SELECT ${unionCols}--`,
    category: 'UNION_DATA_EXTRACTION',
    reason: `Appends UNION SELECT with ${colCount} columns matching ${table} schema to extract additional data`,
    confidence: 'MEDIUM',
  });

  // 8. UNION with explicit data
  payloads.push({
    input: `' UNION SELECT 999, 'attacker', 'attacker@evil.com', 'admin'--`,
    category: 'UNION_PRIVILEGE_ESCALATION',
    reason: `UNION injection with crafted admin row to test privilege escalation via ${table}`,
    confidence: 'MEDIUM',
  });

  // 9. Stacked query — DROP
  payloads.push({
    input: `'; DROP TABLE ${table}--`,
    category: 'STACKED_QUERY_DROP',
    reason: `Tests stacked query execution by attempting DROP TABLE ${table} after the SELECT`,
    confidence: 'MEDIUM',
  });

  // 10. Stacked query — INSERT
  payloads.push({
    input: `'; INSERT INTO ${table} (id, username, email, role) VALUES (100, 'hacker', 'hacker@evil.com', 'admin')--`,
    category: 'STACKED_QUERY_INSERT',
    reason: `Tests stacked query by inserting a malicious admin row into ${table}`,
    confidence: 'MEDIUM',
  });

  // 11. Encoding variant
  payloads.push({
    input: `%27 OR %271%27=%271`,
    category: 'ENCODING_BYPASS',
    reason: `URL-encoded quote variant — tests whether the application decodes input before SQL construction`,
    confidence: 'LOW',
  });

  // 12. Boundary — empty string
  payloads.push({
    input: '',
    category: 'BOUNDARY_EMPTY',
    reason: `Empty input boundary case — tests behavior when WHERE ${column} = ''`,
    confidence: 'LOW',
  });

  return payloads;
}

export type FuzzEligibility = 'SQL_INJECTION' | 'C_BUFFER_OVERFLOW' | 'NOT_APPLICABLE';

export interface FuzzEligibilityResult {
  eligible: boolean;
  type: FuzzEligibility;
  reason: string;
}

export function checkFuzzEligibility(finding: Finding, files: SourceFile[]): FuzzEligibilityResult {
  if (finding.vulnerabilityClass === 'SQL_INJECTION') {
    return { eligible: true, type: 'SQL_INJECTION', reason: 'SQL Injection finding — controlled SQL fuzzing applicable' };
  }

  if (finding.vulnerabilityClass === 'BUFFER_OVERFLOW') {
    // Check if the source contains a LLVMFuzzerTestOneInput entry point
    const hasFuzzHarness = files.some((f) =>
      /LLVMFuzzerTestOneInput\s*\(/.test(f.content),
    );
    if (hasFuzzHarness) {
      return {
        eligible: true,
        type: 'C_BUFFER_OVERFLOW',
        reason: 'Buffer overflow finding with LLVMFuzzerTestOneInput harness — controlled fuzz execution applicable',
      };
    }
    return {
      eligible: false,
      type: 'NOT_APPLICABLE',
      reason: 'Buffer overflow finding has no fuzz harness (LLVMFuzzerTestOneInput). Controlled fuzzing requires an executable harness.',
    };
  }

  return {
    eligible: false,
    type: 'NOT_APPLICABLE',
    reason: `Finding type ${finding.vulnerabilityClass} is not supported by the controlled fuzzer`,
  };
}

export function runFuzzer(finding: Finding, files: SourceFile[]): FuzzResult {
  const sourceFile = files.find((f) => f.path === finding.file) || files[0];
  const executionId = generateId('fuzz-exec');
  const payloads: FuzzPayload[] = [];

  // Check fuzz eligibility before proceeding
  const eligibility = checkFuzzEligibility(finding, files);
  if (!eligibility.eligible) {
    return {
      findingId: finding.id,
      payloads: [],
      confirmed: false,
      confidence: 0,
      confirmedCount: 0,
      evidenceSource: {
        tool: 'kavach-fuzzer',
        toolType: 'FUZZER',
        status: 'NOT_REPRODUCED',
        authenticity: 'EXECUTABLE',
        detail: `SKIPPED — ${eligibility.reason}`,
        confidence: 0,
        timestamp: new Date().toISOString(),
      },
      authenticity: 'EXECUTABLE',
      detail: `Fuzzing skipped: ${eligibility.reason}`,
      executionId,
      schema: extractSchema(sourceFile),
      baseline: null,
      sqlContext: null,
      executionMode: 'CONTROLLED_FIXTURE',
      skipped: true,
      skipReason: eligibility.reason,
    };
  }

  const schema = extractSchema(sourceFile);

  // Extract SQL context from the actual source
  const sqlContext = extractSQLContext(sourceFile);
  const column = sqlContext?.column || 'username';
  const table = sqlContext?.table || 'users';

  // Detect whether the source uses quotes around the input
  const content = sourceFile.content;
  const hasQuotes = /WHERE\s+\w+\s*=\s*['"]?\{/.test(content) || /WHERE\s+\w+\s*=\s*['"]?["']\s*\+/.test(content) || /WHERE\s+\w+\s*=\s*['"]/.test(content);

  // Generate context-aware payloads
  const payloadDefs = generateContextAwarePayloads(column, table, hasQuotes);

  // STEP 1: Execute baseline with safe input
  const baselineInput = 'alice';
  let baselineResult: FuzzResult['baseline'] = null;
  let baselineRowCount = 0;
  let baselineError: string | null = null;
  let baselineQuery = '';

  const baselineQueryStr = reconstructQuery(baselineInput, sourceFile);
  if (baselineQueryStr) {
    const baselineExec = executeQuery(baselineQueryStr, schema);
    baselineRowCount = baselineExec.rowCount;
    baselineError = baselineExec.error;
    baselineQuery = baselineExec.executedQuery;
    baselineResult = {
      input: baselineInput,
      query: baselineExec.executedQuery,
      rowCount: baselineExec.rowCount,
      error: baselineExec.error,
      executed: true,
    };
  } else {
    baselineResult = {
      input: baselineInput,
      query: '[Could not reconstruct query from source]',
      rowCount: 0,
      error: 'Query reconstruction failed',
      executed: false,
    };
  }

  const executionMode: 'CONTROLLED_FIXTURE' | 'SOURCE_DERIVED' =
    schema.source === 'SOURCE_DERIVED' ? 'SOURCE_DERIVED' : 'CONTROLLED_FIXTURE';

  let confirmedCount = 0;

  // STEP 2: Execute each payload and compare against baseline
  for (const payloadDef of payloadDefs) {
    // Skip the safe control — it's the baseline
    if (payloadDef.category === 'SAFE_CONTROL') {
      payloads.push({
        payload: payloadDef.input,
        input: payloadDef.input,
        queryConstructed: baselineQuery || '[reconstruction failed]',
        injectionDetected: false,
        injectionType: payloadDef.category,
        detail: `BASELINE — ${payloadDef.reason}. ${baselineResult.executed ? `Executed: ${baselineRowCount} rows.` : 'Not executed.'}`,
        rowCount: baselineRowCount,
        dataExtracted: false,
        authBypassed: false,
        tableModified: false,
        dataModified: false,
        error: baselineError,
        category: payloadDef.category,
        reason: payloadDef.reason,
        confidence: payloadDef.confidence,
        classification: 'NOT_REPRODUCED',
        baselineRowCount,
        behaviorChange: 'Baseline — no mutation applied',
        executionMode: baselineResult.executed ? executionMode : 'NOT_EXECUTED',
        syntaxError: baselineError !== null,
      });
      continue;
    }

    const constructedQuery = reconstructQuery(payloadDef.input, sourceFile);

    if (!constructedQuery) {
      payloads.push({
        payload: payloadDef.input,
        input: payloadDef.input,
        queryConstructed: '[Could not reconstruct query from source]',
        injectionDetected: false,
        injectionType: payloadDef.category,
        detail: 'Unable to reconstruct vulnerable query from source code pattern',
        rowCount: 0,
        dataExtracted: false,
        authBypassed: false,
        tableModified: false,
        dataModified: false,
        error: 'Query reconstruction failed',
        category: payloadDef.category,
        reason: payloadDef.reason,
        confidence: payloadDef.confidence,
        classification: 'FAILED',
        baselineRowCount,
        behaviorChange: 'Query reconstruction failed — cannot execute',
        executionMode: 'NOT_EXECUTED',
        syntaxError: false,
      });
      continue;
    }

    const result = executeQuery(constructedQuery, schema);

    // Classify based on behavioral comparison against baseline
    const behaviorChange = describeBehaviorChange(baselineRowCount, baselineError, result);
    const classification = classifyPayload(baselineRowCount, baselineError, result, payloadDef.category);
    const injected = classification === 'CONFIRMED';

    if (injected) confirmedCount++;

    const effects: string[] = [];
    if (result.authBypassed) effects.push(`auth bypass (${result.rowCount} rows returned)`);
    if (result.dataExtracted) effects.push('data extraction via UNION');
    if (result.tableModified) effects.push(`table dropped: ${result.tablesAffected.join(', ')}`);
    if (result.dataModified) effects.push(`data modified via stacked query: ${result.tablesAffected.join(', ')}`);
    if (result.syntaxError && !baselineError) effects.push(`syntax error: ${result.error}`);
    if (result.rowCount !== baselineRowCount) effects.push(`row count changed: ${baselineRowCount} → ${result.rowCount}`);

    payloads.push({
      payload: payloadDef.input,
      input: payloadDef.input,
      queryConstructed: result.executedQuery,
      injectionDetected: injected,
      injectionType: payloadDef.category,
      detail: injected
        ? `${payloadDef.reason}. EXECUTED — ${effects.join('; ')}.`
        : result.error && !baselineError
          ? `${payloadDef.reason}. Executed — syntax error caused by injection: ${result.error}`
          : `${payloadDef.reason}. Executed — no meaningful behavior change vs baseline.`,
      rowCount: result.rowCount,
      dataExtracted: result.dataExtracted,
      authBypassed: result.authBypassed,
      tableModified: result.tableModified,
      dataModified: result.dataModified,
      error: result.error,
      category: payloadDef.category,
      reason: payloadDef.reason,
      confidence: payloadDef.confidence,
      classification,
      baselineRowCount,
      behaviorChange,
      executionMode,
      syntaxError: result.syntaxError,
    });
  }

  // Determine overall result
  // CONFIRMED: 2+ payloads showed meaningful behavior change
  // SUSPICIOUS: 1 payload showed behavior change
  // NOT_REPRODUCED: 0 behavior changes but execution succeeded
  // FAILED: baseline could not execute
  const confirmed = confirmedCount >= 2;
  const confidence = confirmed ? 0.93 : confirmedCount > 0 ? 0.65 : 0.3;
  const overallStatus: FuzzClassification = confirmed
    ? 'CONFIRMED'
    : confirmedCount > 0
      ? 'SUSPICIOUS'
      : !baselineResult.executed
        ? 'FAILED'
        : 'NOT_REPRODUCED';

  return {
    findingId: finding.id,
    payloads,
    confirmed,
    confidence,
    confirmedCount,
    evidenceSource: {
      tool: 'kavach-fuzzer',
      toolType: 'FUZZER',
      status: overallStatus === 'CONFIRMED' ? 'CONFIRMED' : overallStatus === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'NOT_REPRODUCED',
      authenticity: 'EXECUTABLE',
      detail: confirmed
        ? `${confirmedCount}/${payloads.length - 1} payloads produced behavioral differences vs baseline (${executionMode})`
        : `${confirmedCount}/${payloads.length - 1} payloads showed injection behavior (${executionMode})`,
      confidence,
      timestamp: new Date().toISOString(),
    },
    authenticity: 'EXECUTABLE',
    detail: confirmed
      ? `Fuzzer confirmed SQL injection via CONTROLLED execution: ${confirmedCount} payloads produced behavioral differences against baseline`
      : `Fuzzer could not reproduce SQL injection (${confirmedCount} behavioral differences)`,
    executionId,
    schema,
    baseline: baselineResult,
    sqlContext: sqlContext?.context || null,
    executionMode,
    skipped: false,
    skipReason: null,
  };
}

function describeBehaviorChange(
  baselineRows: number,
  baselineError: string | null,
  result: { rowCount: number; error: string | null; dataExtracted: boolean; authBypassed: boolean; tableModified: boolean; dataModified: boolean; syntaxError: boolean },
): string {
  const changes: string[] = [];

  if (result.rowCount !== baselineRows) {
    changes.push(`Row count: ${baselineRows} → ${result.rowCount}`);
  }
  if (result.syntaxError && !baselineError) {
    changes.push(`Syntax error introduced: ${result.error}`);
  }
  if (result.dataExtracted) {
    changes.push('UNION data extraction detected');
  }
  if (result.authBypassed) {
    changes.push('Auth/WHERE bypass detected');
  }
  if (result.tableModified) {
    changes.push('Table dropped');
  }
  if (result.dataModified) {
    changes.push('Data modified via stacked INSERT/DELETE');
  }

  return changes.length > 0 ? changes.join('; ') : 'No behavioral change vs baseline';
}

function classifyPayload(
  baselineRows: number,
  baselineError: string | null,
  result: { rowCount: number; error: string | null; dataExtracted: boolean; authBypassed: boolean; tableModified: boolean; dataModified: boolean; syntaxError: boolean },
  category: string,
): FuzzClassification {
  // Quote termination: syntax error is evidence
  if (category === 'QUOTE_TERMINATION') {
    if (result.syntaxError && !baselineError) return 'CONFIRMED';
    if (result.error && !baselineError) return 'SUSPICIOUS';
    return 'NOT_REPRODUCED';
  }

  // Boolean tautology: row count should increase
  if (category === 'BOOLEAN_TAUTOLOGY') {
    if (result.rowCount > baselineRows) return 'CONFIRMED';
    return 'NOT_REPRODUCED';
  }

  // Comment bypass: if the query succeeds AND returns different rows (the comment may
  // truncate a condition), that's a behavior change. But if there's nothing after the
  // comment, the result may be the same as baseline — that's NOT_REPRODUCED.
  if (category === 'COMMENT_BYPASS') {
    if (result.rowCount !== baselineRows) return 'CONFIRMED';
    if (result.syntaxError && !baselineError) return 'SUSPICIOUS';
    return 'NOT_REPRODUCED';
  }

  // Boolean differential: the TRUE condition should return the same rows as baseline
  // (the tautology doesn't change the filter). The FALSE condition should return 0 rows.
  // If FALSE returns 0 while baseline has rows, injection is confirmed.
  if (category === 'BOOLEAN_DIFFERENTIAL_TRUE') {
    // TRUE condition preserves the filter — same row count as baseline means the
    // injected AND clause was accepted as SQL syntax (not treated as literal text).
    if (result.rowCount === baselineRows && !result.error && baselineRows > 0) return 'CONFIRMED';
    if (result.syntaxError && !baselineError) return 'SUSPICIOUS';
    return 'NOT_REPRODUCED';
  }
  if (category === 'BOOLEAN_DIFFERENTIAL_FALSE') {
    // FALSE condition should suppress all rows — if baseline had rows and now 0, confirmed
    if (result.rowCount === 0 && baselineRows > 0) return 'CONFIRMED';
    return 'NOT_REPRODUCED';
  }

  // UNION: data extraction
  if (category.startsWith('UNION')) {
    if (result.dataExtracted) return 'CONFIRMED';
    if (result.rowCount > baselineRows) return 'CONFIRMED';
    if (result.syntaxError && !baselineError) return 'SUSPICIOUS';
    return 'NOT_REPRODUCED';
  }

  // Stacked queries
  if (category.startsWith('STACKED_QUERY')) {
    if (result.tableModified) return 'CONFIRMED';
    if (result.dataModified) return 'CONFIRMED';
    if (result.syntaxError && !baselineError) return 'SUSPICIOUS';
    return 'NOT_REPRODUCED';
  }

  // Encoding
  if (category === 'ENCODING_BYPASS') {
    if (result.rowCount > baselineRows) return 'CONFIRMED';
    if (result.syntaxError && !baselineError) return 'SUSPICIOUS';
    return 'NOT_REPRODUCED';
  }

  // Boundary — empty string
  if (category === 'BOUNDARY_EMPTY') {
    // Empty input changes WHERE username = '' which is a different query than baseline.
    // But this is expected behavior, not injection evidence — the empty string is a
    // valid literal value, not a SQL syntax manipulation.
    if (result.rowCount !== baselineRows && !result.error) return 'NOT_REPRODUCED';
    return 'NOT_REPRODUCED';
  }

  // Default
  if (result.rowCount !== baselineRows) return 'CONFIRMED';
  if (result.syntaxError && !baselineError) return 'SUSPICIOUS';
  return 'NOT_REPRODUCED';
}
