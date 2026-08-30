import type { LLMConfig, LLMReasoningResult, Finding, Evidence, PatchCandidate, SourceFile, ObservedEvidence } from '@/types';
import { generateId } from '@/lib/utils';

// ============================================================
// LLM Provider Abstraction
// Provider-agnostic interface for AI reasoning.
// Supports: demo (deterministic), openai, anthropic, custom
// API keys are read from environment variables, never hardcoded.
// ============================================================

export interface LLMProviderInterface {
  analyzeEvidence(findings: Finding[], evidence: Evidence[]): Promise<LLMReasoningResult>;
  explainRootCause(finding: Finding, evidence: Evidence): Promise<string>;
  generatePatchCandidates(finding: Finding, files: SourceFile[]): Promise<Partial<PatchCandidate>[]>;
  generateVerificationPlan(finding: Finding, patch: PatchCandidate): Promise<string[]>;
  prioritizeInvestigation(findings: Finding[], evidence: Evidence[]): Promise<string>;
  getConfig(): LLMConfig;
}

// Detect LLM configuration from environment
export function detectLLMConfig(): LLMConfig {
  // In browser context, we can only check VITE_ prefixed env vars
  // Server-side keys (LLM_API_KEY) are NOT exposed to the frontend
  const provider = (import.meta.env.VITE_LLM_PROVIDER as string) || 'demo';
  const model = (import.meta.env.VITE_LLM_MODEL as string) || undefined;
  const apiKeyConfigured = Boolean(import.meta.env.VITE_LLM_API_KEY);

  return {
    provider: provider as LLMConfig['provider'],
    model,
    apiKeyConfigured,
  };
}

// ============================================================
// Demo Reasoner - Deterministic (no LLM required)
// This is NOT an LLM. It uses rule-based reasoning over evidence.
// It is clearly labeled as "DEMO REASONER" in the UI.
// ============================================================

export class DemoReasoner implements LLMProviderInterface {
  getConfig(): LLMConfig {
    return {
      provider: 'demo',
      apiKeyConfigured: false,
    };
  }

  async analyzeEvidence(findings: Finding[], evidence: Evidence[]): Promise<LLMReasoningResult> {
    const finding = findings[0];
    const ev = evidence[0];

    if (!finding) {
      return {
        vulnerabilitySuspected: 'UNKNOWN',
        supportingEvidence: [],
        contradictoryEvidence: [],
        rootCause: 'No findings to analyze.',
        attackPath: 'No attack path available.',
        potentialImpact: 'Unknown.',
        confidence: 0,
        confidenceReason: 'No findings provided for analysis.',
        nextInvestigation: 'Run security tools to generate findings.',
        remediationStrategies: [],
        verificationPlan: [],
        insufficientEvidence: true,
        authenticity: 'CONTROLLED_DEMONSTRATION',
        observedEvidence: [],
        aiAnalysis: 'No findings to analyze.',
        recommendation: 'Run security tools first.',
        verificationNote: 'Verification status is determined by deterministic tests, not by AI analysis.',
      };
    }

    const confirmedSources = ev?.sources.filter((s) => s.status === 'CONFIRMED') || [];
    const suspiciousSources = ev?.sources.filter((s) => s.status === 'SUSPICIOUS') || [];
    const notReproducedSources = ev?.sources.filter((s) => s.status === 'NOT_REPRODUCED') || [];

    const supportingEvidence = confirmedSources.map(
      (s) => `${s.toolType} (${s.tool}): ${s.detail}`
    );

    const contradictoryEvidence = [
      ...notReproducedSources.map((s) => `${s.toolType} could not reproduce: ${s.detail}`),
      ...ev?.contradictions.map((c) => c) || [],
    ];

    const insufficientEvidence = confirmedSources.length < 2;

    let rootCause = '';
    let attackPath = '';
    let potentialImpact = '';
    let remediationStrategies: string[] = [];
    let verificationPlan: string[] = [];

    if (finding.vulnerabilityClass === 'SQL_INJECTION') {
      rootCause = `User-controlled input (${finding.evidence}) is directly concatenated into a SQL query string at ${finding.file}:${finding.line}, bypassing parameterized query protections.`;
      attackPath = `HTTP request parameter → endpoint handler → string concatenation → SQL query execution → database access`;
      potentialImpact = `Authentication bypass, data exfiltration, privilege escalation, potential data destruction via stacked queries.`;
      remediationStrategies = [
        'Replace string concatenation with parameterized queries using placeholders (?)',
        'Add input validation/sanitization layer in addition to parameterized queries',
        'Use an ORM or query builder that enforces parameterized queries by default',
      ];
      verificationPlan = [
        'Re-run SAST to confirm no string concatenation patterns remain',
        'Re-run fuzzer with all SQL injection payloads against patched code',
        'Run mutation tests with variant injection payloads',
        'Verify functional tests pass (legitimate queries still work)',
        'Check for new findings introduced by the patch',
      ];
    } else if (finding.vulnerabilityClass === 'BUFFER_OVERFLOW') {
      rootCause = `Untrusted length value (${finding.source || 'untrusted input'}) is used as the copy length in ${finding.sink || 'memcpy'} at ${finding.file}:${finding.line} without verifying it does not exceed the destination buffer capacity. The condition before the copy only checks source size, not destination capacity.`;
      attackPath = `untrusted input → length variable → ${finding.sink || 'memcpy'} → fixed-size stack buffer → memory corruption`;
      potentialImpact = `Stack buffer overflow, memory corruption, potential arbitrary code execution (CWE-121).`;
      remediationStrategies = [
        'Add a bounds check: verify len <= sizeof(buf) before the copy operation',
        'Use a safe alternative with built-in bounds checking (e.g. snprintf, strncpy with correct length)',
        'Reject input if the length exceeds the destination buffer capacity',
      ];
      verificationPlan = [
        'Re-run SAST to confirm the buffer overflow pattern is eliminated',
        'Verify the bounds check constrains len <= sizeof(buf)',
        'Run regression tests with valid inputs within bounds',
        'Run mutation tests with oversized length values',
        'Check for new findings introduced by the patch',
      ];
    } else if (finding.vulnerabilityClass === 'COMMAND_INJECTION') {
      rootCause = `User-controlled input is passed to OS command execution function at ${finding.file}:${finding.line}.`;
      attackPath = `HTTP request parameter → command execution → OS process`;
      potentialImpact = `Arbitrary command execution, system compromise.`;
      remediationStrategies = [
        'Use subprocess with argument list (no shell=True)',
        'Add strict input validation with allowlist',
        'Avoid shell=True entirely',
      ];
      verificationPlan = [
        'Re-run SAST to confirm no unsafe command patterns',
        'Run fuzzer with command injection payloads',
        'Verify functional tests pass',
      ];
    } else {
      rootCause = `Vulnerability detected at ${finding.file}:${finding.line}.`;
      attackPath = `Input → vulnerable function → impact`;
      potentialImpact = `Varies by vulnerability class.`;
      remediationStrategies = ['Apply appropriate remediation pattern for this vulnerability class.'];
      verificationPlan = ['Re-run security tools', 'Run functional tests'];
    }

    const confidence = ev?.fusedConfidence || finding.confidence;
    const confidenceReason = ev
      ? `${confirmedSources.length} independent source(s) confirmed, ${suspiciousSources.length} suspicious, fused score: ${ev.fusedScore}%. ${ev.reasoning}`
      : `Single source confidence: ${(finding.confidence * 100).toFixed(0)}%`;

    const nextInvestigation = insufficientEvidence
      ? 'Insufficient evidence for confident determination. Run additional security tools (fuzzer, DAST) to corroborate SAST findings.'
      : 'Evidence is sufficient. Proceed to patch generation and sandbox verification.';

    // Build evidence contract: OBSERVED facts vs AI ANALYSIS vs RECOMMENDATION
    const observedEvidence: ObservedEvidence[] = [
      { source: 'SAST (kavach-sast)', detail: `${finding.vulnerabilityClass} detected at ${finding.file}:${finding.line} — ${finding.description}`, timestamp: ev?.timestamp || new Date().toISOString() },
      ...confirmedSources.map((s) => ({ source: `${s.toolType} (${s.tool})`, detail: s.detail, timestamp: s.timestamp })),
    ];

    const aiAnalysis = `Root cause: ${rootCause}. Attack path: ${attackPath}. Potential impact: ${potentialImpact}. This is AI interpretation of the observed evidence — the evidence itself has priority over this analysis.`;
    const recommendation = `Remediation: ${remediationStrategies[0] || 'Apply appropriate fix.'}. ${nextInvestigation}`;
    const verificationNote = 'Verification status is determined by deterministic tests (SAST re-scan, attack re-test, mutation tests, regression, functional). The AI cannot override these results.';

    return {
      vulnerabilitySuspected: finding.vulnerabilityClass,
      supportingEvidence,
      contradictoryEvidence,
      rootCause,
      attackPath,
      potentialImpact,
      confidence,
      confidenceReason,
      nextInvestigation,
      remediationStrategies,
      verificationPlan,
      insufficientEvidence,
      authenticity: 'CONTROLLED_DEMONSTRATION',
      observedEvidence,
      aiAnalysis,
      recommendation,
      verificationNote,
    };
  }

  async explainRootCause(finding: Finding, evidence: Evidence): Promise<string> {
    const result = await this.analyzeEvidence([finding], [evidence]);
    return result.rootCause;
  }

  async generatePatchCandidates(finding: Finding, files: SourceFile[]): Promise<Partial<PatchCandidate>[]> {
    const file = files.find((f) => f.path === finding.file) || files[0];
    const content = file.content;

    if (finding.vulnerabilityClass === 'SQL_INJECTION') {
      return generateSQLiPatches(content, finding);
    }
    if (finding.vulnerabilityClass === 'BUFFER_OVERFLOW') {
      return generateBufferOverflowPatches(content, finding);
    }
    return [];
  }

  async generateVerificationPlan(finding: Finding, _patch: PatchCandidate): Promise<string[]> {
    if (finding.vulnerabilityClass === 'SQL_INJECTION') {
      return [
        'Re-run SAST analyzer on patched code',
        'Re-run fuzzer with all SQL injection payloads',
        'Run 5 mutation tests with variant payloads',
        'Run regression tests (12 tests)',
        'Run functional tests (8 tests)',
        'Check for new security findings',
        'Compare before/after security posture',
      ];
    }
    if (finding.vulnerabilityClass === 'BUFFER_OVERFLOW') {
      return [
        'Re-run SAST analyzer on patched code — confirm no buffer overflow patterns',
        'Verify bounds check constrains length <= sizeof(destination)',
        'Run regression tests with valid inputs within bounds',
        'Run mutation tests with oversized length values',
        'Check for new security findings introduced by the patch',
      ];
    }
    return ['Re-run security tools', 'Run functional tests'];
  }

  async prioritizeInvestigation(findings: Finding[], evidence: Evidence[]): Promise<string> {
    const confirmed = evidence[0]?.sources.filter((s) => s.status === 'CONFIRMED').length || 0;
    if (confirmed < 2) {
      return 'Run controlled fuzzing to corroborate SAST findings with runtime evidence.';
    }
    return 'Sufficient evidence available. Proceed to patch generation and verification.';
  }
}

// ============================================================
// SQL Injection Patch Generation
// Generates 2-3 candidate patches with different strategies.
// ============================================================

function generateSQLiPatches(content: string, finding: Finding): Partial<PatchCandidate>[] {
  const patches: Partial<PatchCandidate>[] = [];
  const lines = content.split('\n');
  const vulnerableLineIdx = finding.line - 1;
  const vulnerableLine = lines[vulnerableLineIdx] || '';

  // Detect which pattern type we're dealing with
  const isFString = /f["']SELECT.*?\{.*?\}.*?["']/i.test(vulnerableLine);
  const isConcat = /["']SELECT.*?["']\s*\+\s*\w+/i.test(vulnerableLine) || /\+\s*["']\s*(?:WHERE|AND|OR|VALUES|SET)\s/i.test(vulnerableLine);
  const isFormat = /["']SELECT.*?\{.*?\}.*?["']\.format\s*\(/i.test(vulnerableLine) || /\.format\s*\(\s*.*?SELECT/i.test(vulnerableLine);
  const isPercent = /["']SELECT.*?%[sdr].*?["']\s*%/i.test(vulnerableLine);
  const isExecDyn = /\.execute\s*\(\s*(query|sql|stmt|q)\s*\)/i.test(vulnerableLine);
  const isExecFstr = /\.execute\s*\(\s*f["']/i.test(vulnerableLine);

  // Extract SQL components from the vulnerable line (or nearby lines for multi-line)
  const sqlContext = vulnerableLine + '\n' + lines.slice(vulnerableLineIdx + 1, vulnerableLineIdx + 5).join('\n');
  const paramName = vulnerableLine.match(/\{(\w+)\}/)?.[1]
    || vulnerableLine.match(/\+\s*(\w+)/)?.[1]
    || vulnerableLine.match(/\.format\s*\(\s*(\w+)/)?.[1]
    || vulnerableLine.match(/%\s*(\w+)/)?.[1]
    || vulnerableLine.match(/\.execute\s*\(\s*f["'].*?\{(\w+)\}/)?.[1]
    || 'user_input';
  const tableName = sqlContext.match(/FROM\s+(\w+)/i)?.[1] || 'users';
  const columns = sqlContext.match(/SELECT\s+(.*?)\s+FROM/i)?.[1] || 'id, username, email, role';
  const whereCol = sqlContext.match(/WHERE\s+(\w+)\s*=/i)?.[1] || 'username';

  // Helper: find and update the execute call
  function updateExecuteCall(lineArr: string[], startIdx: number, paramName: string): void {
    for (let i = startIdx; i < Math.min(startIdx + 15, lineArr.length); i++) {
      if (/\.execute\s*\(\s*(query|sql|stmt|q)?\s*\)/.test(lineArr[i]) || /\.execute\s*\(\s*f["']/.test(lineArr[i])) {
        lineArr[i] = lineArr[i].replace(/\.execute\s*\(\s*(?:query|sql|stmt|q)?\s*\)/i, `.execute(query, (${paramName},))`);
        lineArr[i] = lineArr[i].replace(/\.execute\s*\(\s*f["'].*?["']\s*\)/i, `.execute(query, (${paramName},))`);
        break;
      }
    }
  }

  // --- Patch A: Parameterized Query ---
  const patchALines = [...lines];
  if (isFString || isExecFstr) {
    patchALines[vulnerableLineIdx] = `    query = "SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = ?"`;
    updateExecuteCall(patchALines, vulnerableLineIdx + 1, paramName);
  } else if (isConcat) {
    patchALines[vulnerableLineIdx] = `    query = "SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = ?"`;
    updateExecuteCall(patchALines, vulnerableLineIdx + 1, paramName);
  } else if (isFormat) {
    patchALines[vulnerableLineIdx] = `    query = "SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = ?"`;
    updateExecuteCall(patchALines, vulnerableLineIdx + 1, paramName);
  } else if (isPercent) {
    patchALines[vulnerableLineIdx] = `    query = "SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = ?"`;
    updateExecuteCall(patchALines, vulnerableLineIdx + 1, paramName);
  } else if (isExecDyn) {
    // The query variable is built elsewhere; find the construction line
    for (let i = Math.max(0, vulnerableLineIdx - 10); i < vulnerableLineIdx; i++) {
      if (/f["']SELECT/i.test(patchALines[i]) || /["']SELECT.*?\+/i.test(patchALines[i]) || /\.format\s*\(/i.test(patchALines[i]) || /%[sdr].*?%/i.test(patchALines[i])) {
        patchALines[i] = `    query = "SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = ?"`;
        break;
      }
    }
    updateExecuteCall(patchALines, vulnerableLineIdx, paramName);
  }

  const patchedA = patchALines.join('\n');
  const diffA = generateDiff(lines, patchALines);

  patches.push({
    id: generateId('patch'),
    label: 'Patch A',
    strategy: 'Parameterized Query',
    description: 'Replace dynamic SQL construction with a parameterized query using a placeholder (?). User input is passed as a parameter, not concatenated into the SQL string.',
    originalCode: content,
    patchedCode: patchedA,
    diff: diffA,
    securityScore: 0.95,
    regressionRisk: 0.15,
    codeComplexity: 0.20,
    performanceImpact: 0.05,
    linesChanged: 2,
    affectedComponents: ['search endpoint'],
    dependenciesAdded: [],
    riskLevel: 'LOW',
    authenticity: 'CONTROLLED_DEMONSTRATION',
  });

  // --- Patch B: Input Validation + Parameterized Query ---
  const patchBLines = [...lines];
  if (isFString || isExecFstr || isConcat || isFormat || isPercent) {
    patchBLines[vulnerableLineIdx] = `    # Input validation: reject potentially malicious input`;
    patchBLines.splice(vulnerableLineIdx + 1, 0, `    if not ${paramName} or len(${paramName}) > 100 or any(c in ${paramName} for c in ["'", '"', ';', '--', '#']):`);
    patchBLines.splice(vulnerableLineIdx + 2, 0, `        raise HTTPException(status_code=400, detail="Invalid input format")`);
    patchBLines.splice(vulnerableLineIdx + 3, 0, `    query = "SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = ?"`);
    updateExecuteCall(patchBLines, vulnerableLineIdx + 4, paramName);
  } else if (isExecDyn) {
    for (let i = Math.max(0, vulnerableLineIdx - 10); i < vulnerableLineIdx; i++) {
      if (/f["']SELECT/i.test(patchBLines[i]) || /["']SELECT.*?\+/i.test(patchBLines[i]) || /\.format\s*\(/i.test(patchBLines[i]) || /%[sdr].*?%/i.test(patchBLines[i])) {
        patchBLines.splice(i, 1, `    # Input validation: reject potentially malicious input`);
        patchBLines.splice(i + 1, 0, `    if not ${paramName} or len(${paramName}) > 100 or any(c in ${paramName} for c in ["'", '"', ';', '--', '#']):`);
        patchBLines.splice(i + 2, 0, `        raise HTTPException(status_code=400, detail="Invalid input format")`);
        patchBLines.splice(i + 3, 0, `    query = "SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = ?"`);
        break;
      }
    }
    updateExecuteCall(patchBLines, vulnerableLineIdx + 3, paramName);
  }

  const patchedB = patchBLines.join('\n');
  const diffB = generateDiff(lines, patchBLines);

  patches.push({
    id: generateId('patch'),
    label: 'Patch B',
    strategy: 'Input Validation + Parameterized Query',
    description: 'Adds input validation to reject suspicious characters and enforces length limits, combined with parameterized queries. Defense in depth approach.',
    originalCode: content,
    patchedCode: patchedB,
    diff: diffB,
    securityScore: 0.98,
    regressionRisk: 0.25,
    codeComplexity: 0.40,
    performanceImpact: 0.08,
    linesChanged: 5,
    affectedComponents: ['search endpoint', 'input validation layer'],
    dependenciesAdded: [],
    riskLevel: 'LOW',
    authenticity: 'CONTROLLED_DEMONSTRATION',
  });

  // --- Patch C: Query Builder Abstraction ---
  const patchCLines = [...lines];
  if (isFString || isExecFstr || isConcat || isFormat || isPercent) {
    patchCLines[vulnerableLineIdx] = `    # Use query builder pattern for safe SQL construction`;
    patchCLines.splice(vulnerableLineIdx + 1, 0, `    from sqlalchemy import text`);
    patchCLines.splice(vulnerableLineIdx + 2, 0, `    stmt = text("SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = :name")`);
    patchCLines.splice(vulnerableLineIdx + 3, 0, `    result = _cursor.execute(stmt, {"name": ${paramName}})`);
    // Remove old execute call
    for (let i = vulnerableLineIdx + 4; i < Math.min(vulnerableLineIdx + 15, patchCLines.length); i++) {
      if (/\.execute\s*\(\s*(query|sql|stmt|q)?\s*\)/.test(patchCLines[i]) || /\.execute\s*\(\s*f["']/.test(patchCLines[i])) {
        patchCLines.splice(i, 1);
        break;
      }
    }
  } else if (isExecDyn) {
    for (let i = Math.max(0, vulnerableLineIdx - 10); i < vulnerableLineIdx; i++) {
      if (/f["']SELECT/i.test(patchCLines[i]) || /["']SELECT.*?\+/i.test(patchCLines[i]) || /\.format\s*\(/i.test(patchCLines[i]) || /%[sdr].*?%/i.test(patchCLines[i])) {
        patchCLines.splice(i, 1, `    # Use query builder pattern for safe SQL construction`);
        patchCLines.splice(i + 1, 0, `    from sqlalchemy import text`);
        patchCLines.splice(i + 2, 0, `    stmt = text("SELECT ${columns} FROM ${tableName} WHERE ${whereCol} = :name")`);
        patchCLines.splice(i + 3, 0, `    result = _cursor.execute(stmt, {"name": ${paramName}})`);
        break;
      }
    }
    // Remove old execute
    for (let i = vulnerableLineIdx; i < Math.min(vulnerableLineIdx + 10, patchCLines.length); i++) {
      if (/\.execute\s*\(\s*(query|sql|stmt|q)?\s*\)/.test(patchCLines[i])) {
        patchCLines.splice(i, 1);
        break;
      }
    }
  }

  const patchedC = patchCLines.join('\n');
  const diffC = generateDiff(lines, patchCLines);

  patches.push({
    id: generateId('patch'),
    label: 'Patch C',
    strategy: 'Query Builder Abstraction',
    description: 'Introduces a query builder abstraction (SQLAlchemy text() with named parameters) that enforces parameterized queries by design. Adds a dependency but provides a stronger architectural fix.',
    originalCode: content,
    patchedCode: patchedC,
    diff: diffC,
    securityScore: 0.97,
    regressionRisk: 0.35,
    codeComplexity: 0.55,
    performanceImpact: 0.10,
    linesChanged: 4,
    affectedComponents: ['search endpoint', 'database access layer'],
    dependenciesAdded: ['sqlalchemy'],
    riskLevel: 'MEDIUM',
    authenticity: 'CONTROLLED_DEMONSTRATION',
  });

  return patches;
}

// ============================================================
// Buffer Overflow Patch Generation
// Generates candidate patches that add bounds checks before
// dangerous copy operations (memcpy/memmove/strcpy/sprintf).
// ============================================================

function generateBufferOverflowPatches(content: string, finding: Finding): Partial<PatchCandidate>[] {
  const patches: Partial<PatchCandidate>[] = [];
  const lines = content.split('\n');
  const vulnLineIdx = finding.line - 1;
  const vulnLine = lines[vulnLineIdx] || '';

  // Extract the buffer name and length variable from the vulnerable line
  // e.g. memcpy(buf, data + 1, len) → buf="buf", lenVar="len"
  const copyMatch = vulnLine.match(/\b(?:memcpy|memmove|strcpy|sprintf|strncpy|snprintf)\s*\(\s*(\w+)\s*,.*?,\s*(\w+)\s*\)/);
  const bufName = copyMatch?.[1] || 'buf';
  const lenVar = copyMatch?.[2] || 'len';

  // --- Patch A: Add bounds check before copy ---
  const patchALines = [...lines];
  const indent = vulnLine.match(/^\s*/)?.[0] || '    ';
  patchALines.splice(vulnLineIdx, 0,
    `${indent}if (${lenVar} > sizeof(${bufName})) {`,
    `${indent}    return -1;`,
    `${indent}}`,
  );
  const patchedA = patchALines.join('\n');
  patches.push({
    id: generateId('patch'),
    label: 'Patch A',
    strategy: 'Bounds Check Before Copy',
    description: `Adds an explicit bounds check: if ${lenVar} exceeds sizeof(${bufName}), the function returns early instead of proceeding with the copy. This prevents the stack buffer overflow.`,
    originalCode: content,
    patchedCode: patchedA,
    diff: generateDiff(lines, patchALines),
    securityScore: 0.95,
    regressionRisk: 0.10,
    codeComplexity: 0.15,
    performanceImpact: 0.02,
    linesChanged: 3,
    affectedComponents: [`${finding.file}:${finding.line}`],
    dependenciesAdded: [],
    riskLevel: 'LOW',
    authenticity: 'CONTROLLED_DEMONSTRATION',
  });

  // --- Patch B: Clamp length to buffer capacity ---
  const patchBLines = [...lines];
  patchBLines.splice(vulnLineIdx, 0,
    `${indent}if (${lenVar} > sizeof(${bufName})) {`,
    `${indent}    ${lenVar} = sizeof(${bufName});`,
    `${indent}}`,
  );
  const patchedB = patchBLines.join('\n');
  patches.push({
    id: generateId('patch'),
    label: 'Patch B',
    strategy: 'Clamp Length to Buffer Capacity',
    description: `Clamps ${lenVar} to sizeof(${bufName}) if it exceeds the buffer capacity. The copy proceeds but never writes beyond the destination bounds. Useful when returning an error is not acceptable.`,
    originalCode: content,
    patchedCode: patchedB,
    diff: generateDiff(lines, patchBLines),
    securityScore: 0.92,
    regressionRisk: 0.15,
    codeComplexity: 0.15,
    performanceImpact: 0.02,
    linesChanged: 3,
    affectedComponents: [`${finding.file}:${finding.line}`],
    dependenciesAdded: [],
    riskLevel: 'LOW',
    authenticity: 'CONTROLLED_DEMONSTRATION',
  });

  // --- Patch C: Replace memcpy with safe alternative (memcpy_s / snprintf) ---
  const patchCLines = [...lines];
  const safeLine = vulnLine.replace(
    /\bmemcpy\s*\(/,
    '/* bounded copy */ if (sizeof(' + bufName + ') < ' + lenVar + ') ' + lenVar + ' = sizeof(' + bufName + ');\n' + indent + 'memcpy(',
  );
  patchCLines[vulnLineIdx] = safeLine;
  const patchedC = patchCLines.join('\n');
  patches.push({
    id: generateId('patch'),
    label: 'Patch C',
    strategy: 'Inline Bounds Check + Safe Copy',
    description: `Inlines a bounds check immediately before the ${finding.sink || 'memcpy'} call, clamping the length to sizeof(${bufName}). Minimal structural change to the function.`,
    originalCode: content,
    patchedCode: patchedC,
    diff: generateDiff(lines, patchCLines),
    securityScore: 0.93,
    regressionRisk: 0.12,
    codeComplexity: 0.20,
    performanceImpact: 0.02,
    linesChanged: 1,
    affectedComponents: [`${finding.file}:${finding.line}`],
    dependenciesAdded: [],
    riskLevel: 'LOW',
    authenticity: 'CONTROLLED_DEMONSTRATION',
  });

  return patches;
}

function generateDiff(original: string[], patched: string[]): string {
  const maxLen = Math.max(original.length, patched.length);
  const diff: string[] = [];

  for (let i = 0; i < maxLen; i++) {
    const origLine = original[i] || '';
    const patchLine = patched[i] || '';

    if (origLine === patchLine) {
      continue; // No change
    }

    if (origLine && !patchLine) {
      diff.push(`- ${i + 1}: ${origLine}`);
    } else if (!origLine && patchLine) {
      diff.push(`+ ${i + 1}: ${patchLine}`);
    } else {
      diff.push(`- ${i + 1}: ${origLine}`);
      diff.push(`+ ${i + 1}: ${patchLine}`);
    }
  }

  return diff.join('\n');
}

// ============================================================
// Provider Factory
// ============================================================

export function createLLMProvider(): LLMProviderInterface {
  const config = detectLLMConfig();

  switch (config.provider) {
    case 'openai':
    case 'anthropic':
    case 'custom':
      // In a real implementation, these would connect to the respective API
      // via an edge function proxy. For this prototype, we fall back to demo
      // reasoner if the edge function is not configured.
      if (config.apiKeyConfigured) {
        // Would return OpenAI/Anthropic provider here
        // For now, fall back to demo with a note
        return new DemoReasoner();
      }
      return new DemoReasoner();
    default:
      return new DemoReasoner();
  }
}
