import type { Finding, SourceFile } from '@/types';
import { runSAST } from './security-tools/sastAnalyzer';
import { runFuzzer } from './security-tools/fuzzer';
import { generateId } from '@/lib/utils';

export type BenchmarkExpected = 'VULNERABLE' | 'SAFE';

export interface BenchmarkCase {
  id: string;
  name: string;
  category: string;
  expected: BenchmarkExpected;
  source: SourceFile;
  rationale: string;
}

export interface BenchmarkCaseResult {
  id: string;
  name: string;
  category: string;
  expected: BenchmarkExpected;
  observed: BenchmarkExpected | 'INCONCLUSIVE';
  correct: boolean;
  findings: number;
  findingClasses: string[];
  notes: string;
}

export interface BenchmarkReport {
  id: string;
  startedAt: string;
  finishedAt: string;
  total: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  inconclusive: number;
  precision: number;
  recall: number;
  f1: number;
  results: BenchmarkCaseResult[];
}

function file(id: string, name: string, content: string): SourceFile {
  return { id, filename: name, path: name, language: 'python', content, lineCount: content.split('\n').length };
}

function buildCases(): BenchmarkCase[] {
  const vulnerable = (name: string, category: string, content: string, rationale: string): BenchmarkCase => ({
    id: generateId('bench'), name, category, expected: 'VULNERABLE', source: file(generateId('src'), `${name}.py`, content), rationale,
  });
  const safe = (name: string, category: string, content: string, rationale: string): BenchmarkCase => ({
    id: generateId('bench'), name, category, expected: 'SAFE', source: file(generateId('src'), `${name}.py`, content), rationale,
  });

  return [
    vulnerable('direct-sqli', 'Direct source-to-sink', `from flask import request\nimport sqlite3\n\ndef search():\n    username = request.args.get('username')\n    query = "SELECT * FROM users WHERE username = '" + username + "'"\n    return db.execute(query)`, 'Baseline direct concatenation.'),
    vulnerable('alias-sqli', 'Alias propagation', `from flask import request\n\ndef search():\n    username = request.args.get('username')\n    a = username\n    b = a\n    query = "SELECT * FROM users WHERE username = '" + b + "'"\n    return db.execute(query)`, 'Tests multi-hop alias propagation.'),
    vulnerable('function-argument-sqli', 'Function propagation', `from flask import request\n\ndef build_query(value):\n    query = "SELECT * FROM users WHERE username = '" + value + "'"\n    return query\n\ndef search():\n    username = request.args.get('username')\n    query = build_query(username)\n    return db.execute(query)`, 'Tests taint flowing through a function argument into a returned query.'),
    vulnerable('format-sqli', 'String formatting', `from flask import request\n\ndef search():\n    username = request.args.get('username')\n    query = "SELECT * FROM users WHERE username = '{}'".format(username)\n    return db.execute(query)`, 'Tests format-based construction.'),
    vulnerable('percent-sqli', 'Percent formatting', `from flask import request\n\ndef search():\n    username = request.args.get('username')\n    query = "SELECT * FROM users WHERE username = '%s'" % username\n    return db.execute(query)`, 'Tests percent-format construction.'),
    safe('parameterized', 'Parameterized query', `from flask import request\n\ndef search():\n    username = request.args.get('username')\n    query = "SELECT * FROM users WHERE username = ?"\n    return db.execute(query, (username,))`, 'Secure parameterized baseline.'),
    safe('escaped-alias', 'Safe alias chain', `from flask import request\n\ndef search():\n    username = request.args.get('username')\n    a = username\n    b = a\n    query = "SELECT * FROM users WHERE username = ?"\n    return db.execute(query, (b,))`, 'Ensures aliasing does not create a false positive when the sink is parameterized.'),
    safe('constant-query', 'Constant SQL', `def health():\n    query = "SELECT id, username FROM users"\n    return db.execute(query)`, 'No external input reaches the SQL.'),
    vulnerable('nested-expression-sqli', 'Nested expression', `from flask import request\n\ndef search():\n    username = request.args.get('username')\n    query = "SELECT * FROM users WHERE username = '" + str(username.strip()) + "'"\n    return db.execute(query)`, 'Tests taint through a nested transformation expression.'),
    safe('safe-formatting', 'Non-SQL formatting', `from flask import request\n\ndef log():\n    username = request.args.get('username')\n    message = "hello {}".format(username)\n    return message`, 'Formatting user input outside SQL should not trigger SQLi.'),
  ];
}

function observe(findings: Finding[]): BenchmarkExpected | 'INCONCLUSIVE' {
  if (findings.some((f) => f.vulnerabilityClass === 'SQL_INJECTION' && (f.status === 'CONFIRMED' || f.status === 'POTENTIAL'))) return 'VULNERABLE';
  return 'SAFE';
}

export function runAdversarialBenchmark(): BenchmarkReport {
  const started = new Date();
  const cases = buildCases();
  const results: BenchmarkCaseResult[] = [];

  for (const test of cases) {
    const sast = runSAST([test.source]);
    let observed = observe(sast.findings);
    let notes = `${sast.findings.length} finding(s) from deterministic SAST.`;

    // A fuzz pass is only attempted for a detected SQLi finding. This adds an
    // independent execution signal without allowing the fuzzer to create a
    // finding on its own.
    const sqlFinding = sast.findings.find((f) => f.vulnerabilityClass === 'SQL_INJECTION');
    if (sqlFinding) {
      const fuzz = runFuzzer(sqlFinding, [test.source]);
      notes += ` Fuzzer: ${fuzz.confirmedCount} confirmed mutation(s).`;
      if (fuzz.skipped) notes += ` Fuzzer skipped: ${fuzz.skipReason}.`;
    }

    const correct = observed === test.expected;
    results.push({
      id: test.id,
      name: test.name,
      category: test.category,
      expected: test.expected,
      observed,
      correct,
      findings: sast.findings.length,
      findingClasses: sast.findings.map((f) => f.vulnerabilityClass),
      notes: `${test.rationale} ${notes}`,
    });
  }

  const tp = results.filter((r) => r.expected === 'VULNERABLE' && r.observed === 'VULNERABLE').length;
  const fp = results.filter((r) => r.expected === 'SAFE' && r.observed === 'VULNERABLE').length;
  const tn = results.filter((r) => r.expected === 'SAFE' && r.observed === 'SAFE').length;
  const fn = results.filter((r) => r.expected === 'VULNERABLE' && r.observed === 'SAFE').length;
  const inconclusive = results.filter((r) => r.observed === 'INCONCLUSIVE').length;
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    id: generateId('benchmark-run'),
    startedAt: started.toISOString(),
    finishedAt: new Date().toISOString(),
    total: results.length,
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    inconclusive,
    precision,
    recall,
    f1,
    results,
  };
}
