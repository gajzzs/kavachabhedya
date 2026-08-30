// Regression test suite for Abhedya Kavach security pipeline
// Tests A-I covering C/C++ buffer overflow, SQL injection, mode isolation,
// and end-to-end pipeline data flow.
//
// Run with: npx tsx test-regression.ts

import { runSAST } from './src/services/security-tools/sastAnalyzer';
import { runFuzzer } from './src/services/security-tools/fuzzer';
import { fuseEvidence } from './src/services/evidenceFusion';
import { buildAttackPath } from './src/services/attackPathBuilder';
import type { SourceFile, Finding } from './src/types';

// ============================================================
// Test helpers
// ============================================================

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`  PASS: ${message}`);
    passed++;
  } else {
    console.log(`  FAIL: ${message}`);
    failed++;
  }
}

function section(name: string) {
  console.log(`\n=== ${name} ===`);
}

// ============================================================
// Test source files
// ============================================================

const vulnCpp: SourceFile = {
  id: 'test-cpp-1',
  filename: 'vuln.c',
  path: 'vuln.c',
  language: 'c',
  lineCount: 6,
  content: `uint8_t len = data[0];
char buf[16];

if (size >= 1 + len) {
    memcpy(buf, data + 1, len);
}
`,
};

const safeCpp: SourceFile = {
  id: 'test-cpp-2',
  filename: 'safe.c',
  path: 'safe.c',
  language: 'c',
  lineCount: 6,
  content: `uint8_t len = data[0];
char buf[16];

if (len < sizeof(buf)) {
    memcpy(buf, data + 1, len);
}
`,
};

const constLenCpp: SourceFile = {
  id: 'test-cpp-3',
  filename: 'const_len.c',
  path: 'const_len.c',
  language: 'c',
  lineCount: 3,
  content: `char buf[16];
memcpy(buf, source, 8);
`,
};

const vulnFlask: SourceFile = {
  id: 'test-py-1',
  filename: 'app.py',
  path: 'app.py',
  language: 'python',
  lineCount: 10,
  content: `import sqlite3
from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect('test.db')
cursor = conn.cursor()

@app.route('/users')
def search_users():
    username = request.args.get("username")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
`,
};

const secureFlask: SourceFile = {
  id: 'test-py-2',
  filename: 'secure_app.py',
  path: 'secure_app.py',
  language: 'python',
  lineCount: 10,
  content: `import sqlite3
from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect('test.db')
cursor = conn.cursor()

@app.route('/users')
def search_users():
    username = request.args.get("username")
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()
`,
};

// ============================================================
// TEST A: Vulnerable C++ buffer overflow → DETECTED
// ============================================================

section('TEST A: Vulnerable C++ buffer overflow → DETECTED');
{
  const result = runSAST([vulnCpp]);
  console.log(`  SAST findings: ${result.findings.length}`);

  assert(result.findings.length > 0, 'Vulnerable C++ should produce at least 1 finding');

  const bofFinding = result.findings.find(f => f.vulnerabilityClass === 'BUFFER_OVERFLOW');
  assert(!!bofFinding, 'Should detect BUFFER_OVERFLOW class');
  assert(bofFinding?.cwe === 'CWE-121', `CWE should be CWE-121, got ${bofFinding?.cwe}`);
  assert(bofFinding?.severity === 'HIGH' || bofFinding?.severity === 'CRITICAL',
    `Severity should be HIGH or CRITICAL, got ${bofFinding?.severity}`);
  assert(bofFinding?.sink === 'memcpy', `Sink should be memcpy, got ${bofFinding?.sink}`);
  assert(bofFinding?.destination === 'buf', `Destination should be buf, got ${bofFinding?.destination}`);
  assert(bofFinding?.destinationCapacity === 16,
    `Destination capacity should be 16, got ${bofFinding?.destinationCapacity}`);
}

// ============================================================
// TEST B: Safe bounded C++ memcpy → NO CWE-121
// ============================================================

section('TEST B: Safe bounded C++ memcpy → NO CWE-121');
{
  const result = runSAST([safeCpp]);
  console.log(`  SAST findings: ${result.findings.length}`);

  const bofFinding = result.findings.find(f => f.vulnerabilityClass === 'BUFFER_OVERFLOW');
  assert(!bofFinding, 'Safe bounded memcpy should NOT produce BUFFER_OVERFLOW finding');

  // If any finding exists, it should not be CWE-121
  const cwe121 = result.findings.find(f => f.cwe === 'CWE-121');
  assert(!cwe121, 'Safe bounded memcpy should NOT produce CWE-121');
}

// ============================================================
// TEST C: Constant length memcpy within bounds → NO overflow
// ============================================================

section('TEST C: Constant length memcpy (8 into 16) → NO overflow');
{
  const result = runSAST([constLenCpp]);
  console.log(`  SAST findings: ${result.findings.length}`);

  const bofFinding = result.findings.find(f => f.vulnerabilityClass === 'BUFFER_OVERFLOW');
  assert(!bofFinding, 'memcpy(buf, source, 8) into 16-byte buffer should NOT produce overflow');
}

// ============================================================
// TEST D: Vulnerable Flask SQL injection → DETECTED
// ============================================================

section('TEST D: Vulnerable Flask SQL injection → DETECTED');
{
  const result = runSAST([vulnFlask]);
  console.log(`  SAST findings: ${result.findings.length}`);

  const sqliFinding = result.findings.find(f => f.vulnerabilityClass === 'SQL_INJECTION');
  assert(!!sqliFinding, 'Vulnerable Flask should detect SQL_INJECTION');
  assert(sqliFinding?.cwe === 'CWE-89', `CWE should be CWE-89, got ${sqliFinding?.cwe}`);
}

// ============================================================
// TEST E: Secure Flask parameterized query → no SQL injection
// ============================================================

section('TEST E: Secure Flask parameterized query → no SQL injection');
{
  const result = runSAST([secureFlask]);
  console.log(`  SAST findings: ${result.findings.length}`);

  const sqliFinding = result.findings.find(f => f.vulnerabilityClass === 'SQL_INJECTION');
  assert(!sqliFinding, 'Parameterized query should NOT produce SQL_INJECTION finding');
}

// ============================================================
// TEST F: Buffer overflow finding → fuzzing skipped (no harness)
// ============================================================

section('TEST F: Buffer overflow finding → fuzzing eligibility check');
{
  const sastResult = runSAST([vulnCpp]);
  const bofFinding = sastResult.findings.find(f => f.vulnerabilityClass === 'BUFFER_OVERFLOW');
  assert(!!bofFinding, 'Precondition: buffer overflow finding exists');

  const fuzzResult = runFuzzer(bofFinding!, [vulnCpp]);
  console.log(`  Fuzz skipped: ${fuzzResult.skipped}`);
  console.log(`  Skip reason: ${fuzzResult.skipReason}`);

  assert(fuzzResult.skipped === true, 'Fuzzer should skip C/C++ finding without LLVMFuzzerTestOneInput harness');
  assert(!!fuzzResult.skipReason, 'Skip reason should be provided');
}

// ============================================================
// TEST G: Buffer overflow finding → attack path built
// ============================================================

section('TEST G: Buffer overflow finding → attack path built');
{
  const sastResult = runSAST([vulnCpp]);
  const bofFinding = sastResult.findings.find(f => f.vulnerabilityClass === 'BUFFER_OVERFLOW');
  assert(!!bofFinding, 'Precondition: buffer overflow finding exists');

  const attackPath = buildAttackPath(bofFinding!, vulnCpp);
  console.log(`  Attack path entry: ${attackPath.entryPoint}`);
  console.log(`  Attack path impact: ${attackPath.impact}`);
  console.log(`  Nodes: ${attackPath.nodes.length}`);

  assert(attackPath.nodes.length > 0, 'Attack path should have nodes');
  assert(attackPath.entryPoint.length > 0, 'Attack path should have entry point');
  assert(attackPath.impact.length > 0, 'Attack path should have impact description');

  const hasMemcpyNode = attackPath.nodes.some(n => n.label.toLowerCase().includes('memcpy') || n.detail?.toLowerCase().includes('memcpy'));
  assert(hasMemcpyNode, 'Attack path should reference memcpy sink');
}

// ============================================================
// TEST H: Buffer overflow finding → evidence fusion
// ============================================================

section('TEST H: Buffer overflow finding → evidence fusion');
{
  const sastResult = runSAST([vulnCpp]);
  const bofFinding = sastResult.findings.find(f => f.vulnerabilityClass === 'BUFFER_OVERFLOW');
  assert(!!bofFinding, 'Precondition: buffer overflow finding exists');

  const fusionResult = fuseEvidence({ finding: bofFinding!, sources: sastResult.evidenceSources });
  const evidence = fusionResult.evidence;

  console.log(`  Evidence fused score: ${evidence.fusedScore}`);
  console.log(`  Evidence sources: ${evidence.sources.length}`);

  assert(evidence.sources.length > 0, 'Evidence should have at least 1 source');
  assert(evidence.fusedScore > 0, 'Fused score should be > 0 for a real finding');

  const hasSastSource = evidence.sources.some(s => s.toolType === 'SAST');
  assert(hasSastSource, 'Evidence should include SAST source');
}

// ============================================================
// TEST I: SQL injection finding → fuzzing executes
// ============================================================

section('TEST I: SQL injection finding → fuzzing executes');
{
  const sastResult = runSAST([vulnFlask]);
  const sqliFinding = sastResult.findings.find(f => f.vulnerabilityClass === 'SQL_INJECTION');
  assert(!!sqliFinding, 'Precondition: SQL injection finding exists');

  const fuzzResult = runFuzzer(sqliFinding!, [vulnFlask]);
  console.log(`  Fuzz skipped: ${fuzzResult.skipped}`);
  console.log(`  Payloads: ${fuzzResult.payloads.length}`);
  console.log(`  Confirmed: ${fuzzResult.confirmed}`);

  assert(fuzzResult.skipped === false, 'SQL injection should NOT be skipped by fuzzer');
  assert(fuzzResult.payloads.length > 0, 'Fuzzer should generate payloads');
}

// ============================================================
// TEST J: Zero findings → downstream stages should handle gracefully
// ============================================================

section('TEST J: Zero findings (secure code) → no findings array');
{
  const result = runSAST([secureFlask, safeCpp]);
  console.log(`  Total findings: ${result.findings.length}`);

  assert(result.findings.length === 0, 'Secure sources should produce 0 findings');
}

// ============================================================
// Summary
// ============================================================

console.log(`\n=== RESULTS ===`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(failed === 0 ? '\nALL TESTS PASSED' : `\n${failed} TEST(S) FAILED`);
process.exit(failed === 0 ? 0 : 1);
