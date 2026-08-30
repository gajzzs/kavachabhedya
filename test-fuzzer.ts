import { runFuzzer } from './src/services/security-tools/fuzzer';
import { runSAST } from './src/services/security-tools/sastAnalyzer';
import type { SourceFile } from './src/types';

// TEST A: Vulnerable concatenation source
const vulnerableSource: SourceFile = {
  id: 'test-1',
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

// TEST C: Secure parameterized source
const secureSource: SourceFile = {
  id: 'test-2',
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

console.log('=== TEST A: Vulnerable Source ===');
const vulnSast = runSAST([vulnerableSource]);
console.log('SAST findings:', vulnSast.findings.length);
for (const f of vulnSast.findings) {
  console.log('  -', f.vulnerabilityClass, 'at', f.file + ':' + f.line, 'confidence:', f.confidence, 'status:', f.status);
}

if (vulnSast.findings.length > 0) {
  const fuzzResult = runFuzzer(vulnSast.findings[0], [vulnerableSource]);
  console.log('\nFuzzer results:');
  console.log('  Payloads:', fuzzResult.payloads.length);
  console.log('  Confirmed count:', fuzzResult.confirmedCount);
  console.log('  Overall confirmed:', fuzzResult.confirmed);
  console.log('  Execution mode:', fuzzResult.executionMode);
  console.log('  SQL context:', fuzzResult.sqlContext);
  console.log('  Baseline:', fuzzResult.baseline);
  console.log('\n  Per-payload:');
  for (const p of fuzzResult.payloads) {
    console.log(`    [${p.classification}] ${p.category}: input="${p.input}" | baseline=${p.baselineRowCount}rows mutation=${p.rowCount}rows | ${p.behaviorChange}`);
  }
}

console.log('\n=== TEST C: Secure Source ===');
const secureSast = runSAST([secureSource]);
console.log('SAST findings:', secureSast.findings.length);
console.log('Fuzzing should be SKIPPED (no SQL injection finding)');
if (secureSast.findings.length === 0) {
  console.log('  PASS — no findings, fuzzing correctly skipped');
} else {
  console.log('  FAIL — secure source produced findings:');
  for (const f of secureSast.findings) {
    console.log('    -', f.vulnerabilityClass, 'at', f.file + ':' + f.line);
  }
}
