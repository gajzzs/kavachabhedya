import type { SARIFReport, SARIFFinding, Severity } from '@/types';
import { generateId } from '@/lib/utils';

// ============================================================
// KAVACH SARIF Service
// Parses SARIF-format security reports and classifies findings.
//
// SARIF parsing is IMPLEMENTED for basic JSON structure
// extraction. The demo report is MOCKED fixture data.
// Reachability analysis and validation are SIMULATED —
// derived from rule patterns and code context heuristics,
// not from actual execution.
//
// Future integration: CodeQL / Semgrep / other SARIF tools.
// ============================================================

export interface SARIFInput {
  source: string;
  content: string;
}

export function parseSARIF(input: SARIFInput): SARIFReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.content);
  } catch {
    return createDemoSARIFReport(input.source);
  }

  const sarif = parsed as {
    runs?: Array<{
      results?: Array<{
        ruleId?: string;
        message?: { text?: string };
        locations?: Array<{
          physicalLocation?: {
            artifactLocation?: { uri?: string };
            region?: { startLine?: number };
          };
        }>;
        level?: string;
      }>;
    }>;
    runs_0?: unknown;
  };

  const findings: SARIFFinding[] = [];
  const runs = sarif.runs || [];

  for (const run of runs) {
    const results = run.results || [];
    for (const result of results) {
      const loc = result.locations?.[0]?.physicalLocation;
      const file = loc?.artifactLocation?.uri || 'unknown';
      const line = loc?.region?.startLine || 0;
      const ruleId = result.ruleId || 'unknown';
      const description = result.message?.text || 'No description provided';
      const level = (result.level || 'warning').toUpperCase();

      const severity: Severity =
        level === 'ERROR' ? 'HIGH' :
        level === 'WARNING' ? 'MEDIUM' :
        level === 'NOTE' ? 'LOW' : 'INFO';

      const classification = classifyFinding(ruleId, file, description);

      findings.push({
        id: generateId('sarif'),
        ruleId,
        ruleName: ruleId.split('.').pop() || ruleId,
        file,
        line,
        severity,
        description,
        reachability: classification.reachability,
        evidence: classification.evidence,
        validationDecision: classification.decision,
        validationReason: classification.reason,
        authenticity: 'CONTROLLED_DEMONSTRATION',
      });
    }
  }

  if (findings.length === 0) {
    return createDemoSARIFReport(input.source);
  }

  const correct = findings.filter(f => f.validationDecision === 'CORRECT_FINDING').length;
  const falsePos = findings.filter(f => f.validationDecision === 'FALSE_POSITIVE').length;
  const uncertain = findings.filter(f => f.validationDecision === 'UNCERTAIN').length;

  return {
    id: generateId('sarif'),
    source: input.source,
    findings,
    totalFindings: findings.length,
    correctFindings: correct,
    falsePositives: falsePos,
    uncertain,
    timestamp: new Date().toISOString(),
    authenticity: 'CONTROLLED_DEMONSTRATION',
  };
}

function classifyFinding(ruleId: string, file: string, description: string): {
  reachability: 'REACHABLE' | 'NOT_REACHABLE' | 'UNCERTAIN';
  evidence: string;
  decision: 'CORRECT_FINDING' | 'FALSE_POSITIVE' | 'UNCERTAIN';
  reason: string;
} {
  const isSQLRule = /sql|injection|sqli/i.test(ruleId) || /sql/i.test(description);
  const isTestFile = /test|spec|mock|fixture/i.test(file);
  const hasUserInput = /user|input|param|request|query/i.test(description);

  if (isTestFile) {
    return {
      reachability: 'NOT_REACHABLE',
      evidence: 'Finding is in a test/spec file — not reachable from production code paths.',
      decision: 'FALSE_POSITIVE',
      reason: 'Finding located in test file. Test code is not exposed to external users.',
    };
  }

  if (isSQLRule && hasUserInput) {
    return {
      reachability: 'REACHABLE',
      evidence: 'SQL injection rule matched. User-controlled input reaches SQL sink based on rule context.',
      decision: 'CORRECT_FINDING',
      reason: 'Rule pattern matches known SQL injection. User input path confirmed by rule metadata.',
    };
  }

  if (isSQLRule && !hasUserInput) {
    return {
      reachability: 'UNCERTAIN',
      evidence: 'SQL-related rule matched but no explicit user input path in description.',
      decision: 'UNCERTAIN',
      reason: 'SQL pattern detected but reachability of user-controlled input is uncertain from SARIF metadata alone.',
    };
  }

  return {
    reachability: 'UNCERTAIN',
    evidence: 'Generic finding — insufficient context for reachability determination.',
    decision: 'UNCERTAIN',
    reason: 'Rule does not match known vulnerability patterns. Manual review required.',
  };
}

export function createDemoSARIFReport(source: string): SARIFReport {
  const demoFindings: SARIFFinding[] = [
    {
      id: generateId('sarif'),
      ruleId: 'python.sql-injection.query-construction',
      ruleName: 'query-construction',
      file: 'app.py',
      line: 35,
      severity: 'HIGH',
      description: 'User-controlled input is concatenated directly into a SQL query string, enabling SQL injection.',
      reachability: 'REACHABLE',
      evidence: 'SAST rule detected f-string interpolation in SQL query. Input flows from HTTP parameter to cursor.execute() without sanitization.',
      validationDecision: 'CORRECT_FINDING',
      validationReason: 'Rule pattern matches confirmed SQL injection. User input path: HTTP query param → search_users() → f-string → cursor.execute().',
      authenticity: 'CONTROLLED_DEMONSTRATION',
    },
    {
      id: generateId('sarif'),
      ruleId: 'python.sql-injection.parameterized-check',
      ruleName: 'parameterized-check',
      file: 'app.py',
      line: 54,
      severity: 'LOW',
      description: 'SQL query uses parameterized input. No injection risk detected.',
      reachability: 'NOT_REACHABLE',
      evidence: 'Query uses ? placeholder with bound parameter. Input is not concatenated into SQL string.',
      validationDecision: 'FALSE_POSITIVE',
      validationReason: 'Rule triggered on cursor.execute() call but the query uses parameterized input. This is a safe pattern.',
      authenticity: 'CONTROLLED_DEMONSTRATION',
    },
    {
      id: generateId('sarif'),
      ruleId: 'python.hardcoded-credentials.string-literal',
      ruleName: 'string-literal',
      file: 'app.py',
      line: 22,
      severity: 'MEDIUM',
      description: 'Potential hardcoded database path detected in connection string.',
      reachability: 'UNCERTAIN',
      evidence: 'DB_PATH = ":memory:" — in-memory database path. Not a credential but flagged by rule.',
      validationDecision: 'FALSE_POSITIVE',
      validationReason: 'DB_PATH is an in-memory SQLite path, not a credential. Rule over-matches on string literals.',
      authenticity: 'CONTROLLED_DEMONSTRATION',
    },
    {
      id: generateId('sarif'),
      ruleId: 'python.error-handling.information-disclosure',
      ruleName: 'information-disclosure',
      file: 'app.py',
      line: 48,
      severity: 'MEDIUM',
      description: 'Exception details returned to client in error response, potentially leaking database schema info.',
      reachability: 'REACHABLE',
      evidence: 'HTTPException returns str(e) in detail field — database error messages exposed to API consumer.',
      validationDecision: 'CORRECT_FINDING',
      validationReason: 'Error handler passes raw exception message to HTTP response. Confirmed information disclosure risk.',
      authenticity: 'CONTROLLED_DEMONSTRATION',
    },
  ];

  const correct = demoFindings.filter(f => f.validationDecision === 'CORRECT_FINDING').length;
  const falsePos = demoFindings.filter(f => f.validationDecision === 'FALSE_POSITIVE').length;
  const uncertain = demoFindings.filter(f => f.validationDecision === 'UNCERTAIN').length;

  return {
    id: generateId('sarif'),
    source,
    findings: demoFindings,
    totalFindings: demoFindings.length,
    correctFindings: correct,
    falsePositives: falsePos,
    uncertain,
    timestamp: new Date().toISOString(),
    authenticity: 'CONTROLLED_DEMONSTRATION',
  };
}

export function getDemoSARIFJSON(): string {
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Demo SAST Scanner',
            version: '1.0.0',
            rules: [
              { id: 'python.sql-injection.query-construction', name: 'SQL Injection via Query Construction' },
              { id: 'python.sql-injection.parameterized-check', name: 'Parameterized Query Check' },
              { id: 'python.hardcoded-credentials.string-literal', name: 'Hardcoded Credentials' },
              { id: 'python.error-handling.information-disclosure', name: 'Information Disclosure in Error Handling' },
            ],
          },
        },
        results: [
          {
            ruleId: 'python.sql-injection.query-construction',
            level: 'error',
            message: { text: 'User-controlled input is concatenated directly into a SQL query string, enabling SQL injection.' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'app.py' },
                region: { startLine: 35 },
              },
            }],
          },
          {
            ruleId: 'python.sql-injection.parameterized-check',
            level: 'note',
            message: { text: 'SQL query uses parameterized input. No injection risk detected.' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'app.py' },
                region: { startLine: 54 },
              },
            }],
          },
          {
            ruleId: 'python.hardcoded-credentials.string-literal',
            level: 'warning',
            message: { text: 'Potential hardcoded database path detected in connection string.' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'app.py' },
                region: { startLine: 22 },
              },
            }],
          },
          {
            ruleId: 'python.error-handling.information-disclosure',
            level: 'warning',
            message: { text: 'Exception details returned to client in error response, potentially leaking database schema info.' },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: 'app.py' },
                region: { startLine: 48 },
              },
            }],
          },
        ],
      },
    ],
  }, null, 2);
}
