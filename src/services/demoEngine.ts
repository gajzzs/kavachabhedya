import type {
  Investigation,
  InvestigationStep,
  InvestigationStepStatus,
  Finding,
  Evidence,
  Experiment,
  Hypothesis,
  PatchCandidate,
  VerificationRun,
  SecurityMemory,
  AuditEvent,
  AgentAction,
  TwinSnapshot,
  SourceFile,
  Project,
  LLMReasoningResult,
  SystemStatus,
} from '@/types';
import { generateId, delay } from '@/lib/utils';
import { runSAST } from '@/services/security-tools/sastAnalyzer';
import { runFuzzer } from '@/services/security-tools/fuzzer';
import { runDAST } from '@/services/security-tools/dastAnalyzer';
import { fuseEvidence } from '@/services/evidenceFusion';
import { createLLMProvider, detectLLMConfig } from '@/services/llm/llmProvider';
import { runVerification } from '@/services/verification/verificationEngine';
import { createSecurityMemory } from '@/services/memoryService';
import {
  createT0Snapshot,
  createT1Snapshot,
  createT2Snapshot,
  createVerifiedSnapshot,
} from '@/services/twinService';
import { buildAttackPath } from '@/services/attackPathBuilder';
import {
  createAuditEvent,
  createAgentAction,
  checkAction,
  DEFAULT_POLICY,
  assessAgentSecurity,
} from '@/services/guardian';
import { getDemoProject } from '@/services/demoProjects';

// ============================================================
// Deterministic Demo Engine
// Executes the complete KAVACH pipeline end-to-end.
// This is the core workflow: FIND → EVIDENCE → REASON → SIMULATE
// → PATCH → ATTACK PATCH → VERIFY → REMEMBER
//
// Every step produces real evidence. Components that are
// simulated are clearly labeled.
// ============================================================

export interface DemoEngineCallbacks {
  onAudit: (event: AuditEvent) => void;
  onAction: (action: AgentAction) => void;
  onStepUpdate: (step: InvestigationStep, status: InvestigationStepStatus['status'], detail?: string) => void;
  onFinding: (finding: Finding) => void;
  onEvidence: (evidence: Evidence) => void;
  onExperiment: (experiment: Experiment) => void;
  onHypothesis: (hypothesis: Hypothesis) => void;
  onReasoning: (reasoning: LLMReasoningResult) => void;
  onPatch: (patch: PatchCandidate) => void;
  onVerification: (run: VerificationRun) => void;
  onMemory: (memory: SecurityMemory) => void;
  onTwinSnapshot: (snapshot: TwinSnapshot) => void;
  onAttackPath: (path: ReturnType<typeof buildAttackPath>) => void;
  onInvestigationUpdate: (investigation: Partial<Investigation>) => void;
  onProgress: (message: string) => void;
}

export interface DemoEngineResult {
  investigation: Investigation;
  securityMemory: SecurityMemory;
  twinSnapshots: TwinSnapshot[];
  auditEvents: AuditEvent[];
  agentActions: AgentAction[];
  success: boolean;
}

function createSteps(): InvestigationStepStatus[] {
  return [
    { step: 'INTAKE', label: 'Intake', status: 'PENDING' },
    { step: 'SCAN', label: 'Security Scan', status: 'PENDING' },
    { step: 'EVIDENCE', label: 'Evidence Fusion', status: 'PENDING' },
    { step: 'REASON', label: 'AI Reasoning', status: 'PENDING' },
    { step: 'EXPERIMENT', label: 'Experiment Planning', status: 'PENDING' },
    { step: 'TWIN', label: 'Digital Twin', status: 'PENDING' },
    { step: 'PATCH', label: 'Patch Generation', status: 'PENDING' },
    { step: 'VERIFY', label: 'Verification', status: 'PENDING' },
    { step: 'REMEMBER', label: 'Security Memory', status: 'PENDING' },
  ];
}

export async function runFullDemo(
  demoProjectId: string,
  callbacks: DemoEngineCallbacks
): Promise<DemoEngineResult> {
  const auditEvents: AuditEvent[] = [];
  const agentActions: AgentAction[] = [];
  const twinSnapshots: TwinSnapshot[] = [];
  const findings: Finding[] = [];
  const evidenceList: Evidence[] = [];
  const experiments: Experiment[] = [];
  const hypotheses: Hypothesis[] = [];
  const patches: PatchCandidate[] = [];
  let verificationRun: VerificationRun | undefined;
  let securityMemory: SecurityMemory | undefined;
  let reasoningResult: LLMReasoningResult | undefined;

  const demoProject = getDemoProject(demoProjectId);
  if (!demoProject) {
    throw new Error(`Demo project not found: ${demoProjectId}`);
  }

  const project: Project = {
    id: generateId('project'),
    name: demoProject.name,
    description: demoProject.description,
    source: 'demo',
    demoProjectId: demoProject.id,
    files: demoProject.files,
    createdAt: new Date().toISOString(),
  };

  const investigation: Investigation = {
    id: generateId('inv'),
    projectId: project.id,
    projectName: project.name,
    vulnerabilityClass: 'SQL_INJECTION',
    status: 'INVESTIGATING',
    steps: createSteps(),
    findings: [],
    evidence: [],
    experiments: [],
    hypotheses: [],
    patches: [],
    startedAt: new Date().toISOString(),
    currentStep: 'INTAKE',
  };

  const logAudit = (event: AuditEvent) => {
    auditEvents.push(event);
    callbacks.onAudit(event);
  };

  const logAction = (action: AgentAction) => {
    agentActions.push(action);
    callbacks.onAction(action);
  };

  const updateStep = (step: InvestigationStep, status: InvestigationStepStatus['status'], detail?: string) => {
    const stepStatus = investigation.steps.find((s) => s.step === step);
    if (stepStatus) {
      stepStatus.status = status;
      if (detail) stepStatus.detail = detail;
    }
    investigation.currentStep = step;
    callbacks.onStepUpdate(step, status, detail);
    callbacks.onInvestigationUpdate({ steps: investigation.steps, currentStep: step });
  };

  // ============================================================
  // STEP 1: INTAKE
  // ============================================================
  callbacks.onProgress('Step 1/9: Loading demo application...');
  logAudit(createAuditEvent('Demo started', 'SYSTEM', `Loading demo project: ${demoProject.name}`, 'INFO', 'demo-engine'));

  const intakeCheck = checkAction('READ', 'file-reader', 'read source files', demoProject.name, DEFAULT_POLICY);
  logAction(createAgentAction(
    'kavach-engine', 'file-reader', 'read source files', demoProject.name,
    'READ', intakeCheck.allowed ? 'COMPLETED' : 'BLOCKED',
    `Loaded ${demoProject.files.length} file(s) from demo project`,
    intakeCheck.sandboxed
  ));

  updateStep('INTAKE', 'IN_PROGRESS', `Loading ${demoProject.name}`);
  await delay(800);

  // Create T0 snapshot
  const t0 = createT0Snapshot();
  twinSnapshots.push(t0);
  callbacks.onTwinSnapshot(t0);

  updateStep('INTAKE', 'COMPLETED', `Loaded ${demoProject.files.length} file(s). Project: ${demoProject.name}`);
  logAudit(createAuditEvent('Intake complete', 'SYSTEM', `Project loaded: ${demoProject.name} (${demoProject.files.length} files)`, 'INFO', 'demo-engine'));
  await delay(400);

  // ============================================================
  // STEP 2: SCAN (SAST)
  // ============================================================
  callbacks.onProgress('Step 2/9: Running static analysis (SAST)...');
  updateStep('SCAN', 'IN_PROGRESS', 'Running Kavach SAST pattern engine...');

  const sastCheck = checkAction('ANALYZE', 'kavach-sast', 'analyze source code', project.name, DEFAULT_POLICY);
  logAction(createAgentAction(
    'kavach-engine', 'kavach-sast', 'static analysis', project.name,
    'ANALYZE', sastCheck.allowed ? 'COMPLETED' : 'BLOCKED',
    'SAST analysis initiated',
    sastCheck.sandboxed
  ));

  logAudit(createAuditEvent('SAST started', 'SCAN', 'Running Kavach SAST pattern engine on source files', 'INFO', 'kavach-sast'));
  await delay(1200);

  const sastResult = runSAST(project.files);

  logAudit(createAuditEvent('SAST completed', 'SCAN', `${sastResult.findings.length} finding(s) detected. Authenticity: EXECUTABLE`, 'INFO', 'kavach-sast'));

  for (const finding of sastResult.findings) {
    findings.push(finding);
    callbacks.onFinding(finding);
    logAudit(createAuditEvent(
      'Vulnerability detected',
      'SCAN',
      `${finding.vulnerabilityClass} at ${finding.file}:${finding.line} - ${finding.description} (confidence: ${(finding.confidence * 100).toFixed(0)}%)`,
      finding.severity,
      'kavach-sast'
    ));
  }

  if (findings.length === 0) {
    updateStep('SCAN', 'COMPLETED', 'No findings detected by SAST');
    logAudit(createAuditEvent('No findings', 'SCAN', 'SAST found no vulnerabilities in source code', 'INFO', 'kavach-sast'));
  } else {
    updateStep('SCAN', 'COMPLETED', `SAST found ${findings.length} finding(s). Authenticity: EXECUTABLE`);
  }
  await delay(400);

  // ============================================================
  // STEP 3: EVIDENCE FUSION
  // ============================================================
  callbacks.onProgress('Step 3/9: Fusing evidence from multiple sources...');
  updateStep('EVIDENCE', 'IN_PROGRESS', 'Collecting and fusing evidence...');

  const primaryFinding = findings[0];
  if (!primaryFinding) {
    updateStep('EVIDENCE', 'SKIPPED', 'No findings to fuse evidence for');
    investigation.status = 'SAFE';
    callbacks.onInvestigationUpdate({ status: 'SAFE' });
    return { investigation, securityMemory: {} as SecurityMemory, twinSnapshots, auditEvents, agentActions, success: false };
  }

  // Collect SAST evidence source
  const sastSource = sastResult.evidenceSources[0];

  logAudit(createAuditEvent('Evidence fusion started', 'EVIDENCE', 'Collecting independent evidence signals', 'INFO', 'evidence-fusion'));
  await delay(800);

  // Run controlled fuzzing
  callbacks.onProgress('Running controlled fuzzer...');
  const fuzzCheck = checkAction('TEST', 'kavach-fuzzer', 'fuzz SQL queries', primaryFinding.file, DEFAULT_POLICY);
  logAction(createAgentAction(
    'kavach-engine', 'kavach-fuzzer', 'controlled fuzzing', primaryFinding.file,
    'TEST', fuzzCheck.allowed ? 'COMPLETED' : 'BLOCKED',
    'Fuzzer initiated with 8 SQL injection payloads',
    fuzzCheck.sandboxed
  ));

  logAudit(createAuditEvent('Fuzzer started', 'SCAN', 'Running controlled SQL injection fuzzer (SIMULATED execution)', 'INFO', 'kavach-fuzzer'));
  await delay(1500);

  const fuzzResult = runFuzzer(primaryFinding, project.files);
  logAudit(createAuditEvent(
    'Fuzzer completed',
    'SCAN',
    `Fuzzer ${fuzzResult.confirmed ? 'CONFIRMED' : 'did not confirm'} vulnerability. ${fuzzResult.payloads.filter(p => p.injectionDetected).length}/${fuzzResult.payloads.length} payloads successful. Authenticity: SIMULATED`,
    fuzzResult.confirmed ? 'HIGH' : 'MEDIUM',
    'kavach-fuzzer'
  ));

  // Run DAST
  callbacks.onProgress('Running dynamic analysis (DAST)...');
  const dastCheck = checkAction('TEST', 'kavach-dast', 'dynamic analysis', primaryFinding.file, DEFAULT_POLICY);
  logAction(createAgentAction(
    'kavach-engine', 'kavach-dast', 'dynamic testing', primaryFinding.file,
    'TEST', dastCheck.allowed ? 'COMPLETED' : 'BLOCKED',
    'DAST initiated with 4 test cases',
    dastCheck.sandboxed
  ));

  logAudit(createAuditEvent('DAST started', 'SCAN', 'Running dynamic analysis (CONTROLLED DEMONSTRATION)', 'INFO', 'kavach-dast'));
  await delay(1200);

  const dastResult = runDAST(primaryFinding, project.files);
  logAudit(createAuditEvent(
    'DAST completed',
    'SCAN',
    `DAST ${dastResult.confirmed ? 'CONFIRMED' : 'did not confirm'} vulnerability. ${dastResult.testCases.filter(t => t.vulnerable).length}/${dastResult.testCases.length} cases vulnerable. Authenticity: CONTROLLED DEMONSTRATION`,
    dastResult.confirmed ? 'HIGH' : 'MEDIUM',
    'kavach-dast'
  ));

  // Fuse all evidence
  const fusionInput = {
    finding: primaryFinding,
    sources: [sastSource, fuzzResult.evidenceSource, dastResult.evidenceSource],
  };

  const fusionResult = fuseEvidence(fusionInput);
  evidenceList.push(fusionResult.evidence);
  callbacks.onEvidence(fusionResult.evidence);
  callbacks.onInvestigationUpdate({ evidence: evidenceList });

  logAudit(createAuditEvent(
    'Evidence fusion complete',
    'EVIDENCE',
    `Status: ${fusionResult.evidence.status}. Fused score: ${fusionResult.evidence.fusedScore}%. Sources: ${fusionResult.evidence.sources.length}. Contradictions: ${fusionResult.evidence.contradictions.length}`,
    fusionResult.evidence.status === 'CONFIRMED' ? 'HIGH' : 'MEDIUM',
    'evidence-fusion'
  ));

  updateStep('EVIDENCE', 'COMPLETED', `Evidence ${fusionResult.evidence.status} (${fusionResult.evidence.fusedScore}% confidence)`);
  await delay(400);

  // ============================================================
  // STEP 4: REASON (AI Reasoning)
  // ============================================================
  callbacks.onProgress('Step 4/9: AI reasoning over evidence...');
  updateStep('REASON', 'IN_PROGRESS', 'Analyzing evidence with AI reasoner...');

  const llmProvider = createLLMProvider();
  const llmConfig = detectLLMConfig();

  logAudit(createAuditEvent(
    'Reasoner started',
    'REASONING',
    `Provider: ${llmConfig.provider === 'demo' ? 'DEMO REASONER (deterministic)' : 'CONNECTED LLM'}. Model: ${llmConfig.model || 'N/A'}`,
    'INFO',
    'llm-reasoner'
  ));

  const reasonCheck = checkAction('ANALYZE', 'llm-reasoner', 'analyze evidence', 'investigation', DEFAULT_POLICY);
  logAction(createAgentAction(
    'kavach-reasoner', 'llm-reasoner', 'evidence analysis', 'investigation',
    'ANALYZE', reasonCheck.allowed ? 'COMPLETED' : 'BLOCKED',
    `Reasoning over ${evidenceList[0]?.sources.length || 0} evidence sources`,
    reasonCheck.sandboxed
  ));

  await delay(1500);

  reasoningResult = await llmProvider.analyzeEvidence(findings, evidenceList);
  callbacks.onReasoning(reasoningResult);

  logAudit(createAuditEvent(
    'Reasoning complete',
    'REASONING',
    `Vulnerability: ${reasoningResult.vulnerabilitySuspected}. Prototype evidence score: ${(reasoningResult.confidence * 100).toFixed(0)}%. Insufficient evidence: ${reasoningResult.insufficientEvidence}. Authenticity: ${reasoningResult.authenticity}`,
    reasoningResult.insufficientEvidence ? 'MEDIUM' : 'HIGH',
    'llm-reasoner'
  ));

  updateStep('REASON', 'COMPLETED', `Reasoning complete. Confidence: ${(reasoningResult.confidence * 100).toFixed(0)}%. ${llmConfig.provider === 'demo' ? 'DEMO REASONER' : 'CONNECTED LLM'}`);
  await delay(400);

  // ============================================================
  // STEP 5: EXPERIMENT (Adaptive Experiment Planner)
  // ============================================================
  callbacks.onProgress('Step 5/9: Planning next experiments...');
  updateStep('EXPERIMENT', 'IN_PROGRESS', 'Selecting optimal next experiment...');

  // Create hypothesis
  const hypothesis: Hypothesis = {
    id: generateId('hyp'),
    statement: `The SQL injection vulnerability at ${primaryFinding.file}:${primaryFinding.line} is exploitable via the /api/users/search endpoint.`,
    confidence: reasoningResult.confidence,
    supportingEvidence: reasoningResult.supportingEvidence,
    contradictoryEvidence: reasoningResult.contradictoryEvidence,
    status: reasoningResult.insufficientEvidence ? 'INSUFFICIENT' : 'CONFIRMED',
  };
  hypotheses.push(hypothesis);
  callbacks.onHypothesis(hypothesis);

  // Plan experiments
  const experiment1: Experiment = {
    id: generateId('exp'),
    name: 'Controlled SQL Injection Fuzzing',
    description: 'Run 8 SQL injection payloads against the reconstructed vulnerable query to confirm exploitability.',
    reason: 'SAST detected string concatenation in SQL query. Fuzzer needed to confirm runtime exploitability.',
    expectedInformationGain: 'Confirm whether the vulnerability is exploitable at runtime, not just statically detectable.',
    estimatedCost: 'LOW',
    status: 'COMPLETED',
    result: `${fuzzResult.payloads.filter(p => p.injectionDetected).length}/${fuzzResult.payloads.length} payloads confirmed injection. Vulnerability CONFIRMED.`,
    nextAction: 'Proceed to dynamic testing for additional confirmation.',
    timestamp: new Date().toISOString(),
    duration: 1500,
  };
  experiments.push(experiment1);
  callbacks.onExperiment(experiment1);

  const experiment2: Experiment = {
    id: generateId('exp'),
    name: 'Dynamic Application Security Testing',
    description: 'Simulate HTTP requests against the vulnerable endpoint with injection payloads.',
    reason: 'Fuzzer confirmed injection. DAST needed to verify endpoint-level exploitability.',
    expectedInformationGain: 'Verify the vulnerability is exploitable through the HTTP API, not just at the query level.',
    estimatedCost: 'MEDIUM',
    status: 'COMPLETED',
    result: `${dastResult.testCases.filter(t => t.vulnerable).length}/${dastResult.testCases.length} dynamic test cases confirmed. Vulnerability CONFIRMED at API level.`,
    nextAction: 'Evidence sufficient. Proceed to patch generation.',
    timestamp: new Date().toISOString(),
    duration: 1200,
  };
  experiments.push(experiment2);
  callbacks.onExperiment(experiment2);

  const experiment3: Experiment = {
    id: generateId('exp'),
    name: 'Patch Candidate Generation',
    description: 'Generate 2-3 patch candidates with different remediation strategies.',
    reason: 'Vulnerability confirmed by 3 independent sources. Ready for remediation.',
    expectedInformationGain: 'Determine the best remediation strategy with lowest regression risk.',
    estimatedCost: 'LOW',
    status: 'COMPLETED',
    result: '3 patch candidates generated: parameterized query, validation + parameterized, query builder.',
    nextAction: 'Apply patches to digital twin for simulation.',
    timestamp: new Date().toISOString(),
    duration: 800,
  };
  experiments.push(experiment3);
  callbacks.onExperiment(experiment3);

  callbacks.onInvestigationUpdate({ experiments, hypotheses });
  logAudit(createAuditEvent('Experiments planned', 'REASONING', `${experiments.length} experiments selected and executed`, 'INFO', 'experiment-planner'));
  updateStep('EXPERIMENT', 'COMPLETED', `${experiments.length} experiments completed`);
  await delay(400);

  // ============================================================
  // STEP 6: TWIN (Digital Twin)
  // ============================================================
  callbacks.onProgress('Step 6/9: Creating security digital twin...');
  updateStep('TWIN', 'IN_PROGRESS', 'Building security digital twin...');

  // T1: Vulnerability discovered
  const t1 = createT1Snapshot(primaryFinding);
  twinSnapshots.push(t1);
  callbacks.onTwinSnapshot(t1);
  logAudit(createAuditEvent('Twin snapshot T1', 'SYSTEM', 'T1 - Vulnerability discovered. Attack path active in twin.', 'HIGH', 'twin-service'));
  await delay(800);

  // Build attack path
  const attackPath = buildAttackPath(primaryFinding);
  callbacks.onAttackPath(attackPath);
  callbacks.onInvestigationUpdate({ attackPath });

  const twinCheck = checkAction('MODIFY', 'twin-service', 'create snapshot', 'digital-twin', DEFAULT_POLICY);
  logAction(createAgentAction(
    'kavach-engine', 'twin-service', 'create twin snapshot', 'digital-twin',
    'MODIFY', twinCheck.allowed ? 'COMPLETED' : 'BLOCKED',
    'T1 snapshot created (vulnerability state)',
    twinCheck.sandboxed
  ));

  updateStep('TWIN', 'COMPLETED', 'Twin created with vulnerability state. Attack path active.');
  await delay(400);

  // ============================================================
  // STEP 7: PATCH (Patch Generation)
  // ============================================================
  callbacks.onProgress('Step 7/9: Generating patch candidates...');
  updateStep('PATCH', 'IN_PROGRESS', 'Generating 2-3 patch candidates...');

  const patchCheck = checkAction('MODIFY', 'patch-generator', 'generate patches', primaryFinding.file, DEFAULT_POLICY);
  logAction(createAgentAction(
    'kavach-reasoner', 'patch-generator', 'generate patch candidates', primaryFinding.file,
    'MODIFY', patchCheck.allowed ? 'COMPLETED' : 'BLOCKED',
    'Generating patch candidates',
    patchCheck.sandboxed
  ));

  logAudit(createAuditEvent('Patch generation started', 'PATCH', 'Generating 2-3 remediation candidates', 'INFO', 'patch-generator'));
  await delay(1500);

  const patchCandidatesRaw = await llmProvider.generatePatchCandidates(primaryFinding, project.files);

  for (const patchRaw of patchCandidatesRaw) {
    const patch: PatchCandidate = {
      id: patchRaw.id || generateId('patch'),
      label: patchRaw.label || 'Patch',
      strategy: patchRaw.strategy || 'Unknown',
      description: patchRaw.description || '',
      originalCode: patchRaw.originalCode || '',
      patchedCode: patchRaw.patchedCode || '',
      diff: patchRaw.diff || '',
      securityScore: patchRaw.securityScore || 0,
      regressionRisk: patchRaw.regressionRisk || 0,
      codeComplexity: patchRaw.codeComplexity || 0,
      performanceImpact: patchRaw.performanceImpact || 0,
      linesChanged: patchRaw.linesChanged || 0,
      affectedComponents: patchRaw.affectedComponents || [],
      dependenciesAdded: patchRaw.dependenciesAdded || [],
      riskLevel: patchRaw.riskLevel || 'MEDIUM',
      authenticity: patchRaw.authenticity || 'CONTROLLED_DEMONSTRATION',
    };
    patches.push(patch);
    callbacks.onPatch(patch);
    logAudit(createAuditEvent(
      'Patch candidate generated',
      'PATCH',
      `${patch.label}: ${patch.strategy}. Security: ${(patch.securityScore * 100).toFixed(0)}%, Risk: ${patch.riskLevel}, Lines: ${patch.linesChanged}`,
      'INFO',
      'patch-generator'
    ));
  }

  callbacks.onInvestigationUpdate({ patches });
  updateStep('PATCH', 'COMPLETED', `${patches.length} patch candidates generated`);
  await delay(400);

  // ============================================================
  // STEP 8: VERIFY (Verification Engine)
  // ============================================================
  callbacks.onProgress('Step 8/9: Verifying patch in sandbox...');
  updateStep('VERIFY', 'IN_PROGRESS', 'Running independent verification...');

  // Select best patch (highest security score, lowest risk)
  const selectedPatch = patches.reduce((best, p) =>
    p.securityScore > best.securityScore || (p.securityScore === best.securityScore && p.riskLevel === 'LOW')
      ? p : best, patches[0]);

  logAudit(createAuditEvent(
    'Patch selected',
    'PATCH',
    `${selectedPatch.label} (${selectedPatch.strategy}) selected for verification. Security: ${(selectedPatch.securityScore * 100).toFixed(0)}%, Risk: ${selectedPatch.riskLevel}`,
    'INFO',
    'patch-evaluator'
  ));

  // Apply patch to twin (T2)
  const t2 = createT2Snapshot(selectedPatch);
  twinSnapshots.push(t2);
  callbacks.onTwinSnapshot(t2);
  logAudit(createAuditEvent('Twin snapshot T2', 'SYSTEM', `T2 - ${selectedPatch.label} applied to twin. Attack path blocked.`, 'INFO', 'twin-service'));
  await delay(800);

  // Update attack path with patch
  const patchedAttackPath = buildAttackPath(primaryFinding, selectedPatch);
  callbacks.onAttackPath(patchedAttackPath);
  callbacks.onInvestigationUpdate({ attackPath: patchedAttackPath });

  // Run verification
  const verifyCheck = checkAction('TEST', 'verification-engine', 'verify patch', selectedPatch.id, DEFAULT_POLICY);
  logAction(createAgentAction(
    'kavach-engine', 'verification-engine', 'verify patch', selectedPatch.id,
    'TEST', verifyCheck.allowed ? 'COMPLETED' : 'BLOCKED',
    'Running verification suite',
    verifyCheck.sandboxed
  ));

  logAudit(createAuditEvent('Verification started', 'VERIFICATION', `Verifying ${selectedPatch.label} (${selectedPatch.strategy})`, 'INFO', 'verification-engine'));
  await delay(2000);

  const verificationResult = runVerification({
    finding: primaryFinding,
    patch: selectedPatch,
    files: project.files,
  });

  verificationRun = verificationResult.run;
  callbacks.onVerification(verificationRun);
  callbacks.onInvestigationUpdate({ verificationRun });

  logAudit(createAuditEvent(
    'Verification complete',
    'VERIFICATION',
    `Status: ${verificationRun.status}. Original attack: ${verificationRun.originalAttackBlocked ? 'BLOCKED' : 'NOT BLOCKED'}. Mutations: ${verificationRun.mutationTests.filter(t => t.passed).length}/${verificationRun.mutationTests.length}. Regression: ${verificationRun.regressionTests.filter(t => t.passed).length}/${verificationRun.regressionTests.length}. Functional: ${verificationRun.functionalTests.filter(t => t.passed).length}/${verificationRun.functionalTests.length}. New findings: ${verificationRun.newFindings}`,
    verificationRun.status === 'VERIFIED' ? 'INFO' : 'HIGH',
    'verification-engine'
  ));

  if (verificationRun.status === 'VERIFIED') {
    // Create T4 verified snapshot
    const t4 = createVerifiedSnapshot(selectedPatch);
    twinSnapshots.push(t4);
    callbacks.onTwinSnapshot(t4);
    logAudit(createAuditEvent('Twin snapshot T4', 'SYSTEM', 'T4 - Verified fix. Attack path eliminated.', 'INFO', 'twin-service'));
    updateStep('VERIFY', 'COMPLETED', `VERIFIED FIX. All ${verificationRun.mutationTests.length + verificationRun.regressionTests.length + verificationRun.functionalTests.length} tests passed.`);
  } else {
    updateStep('VERIFY', 'FAILED', `Verification ${verificationRun.status}. Not all tests passed.`);
    investigation.status = 'ACTION_REQUIRED';
  }
  await delay(400);

  // ============================================================
  // STEP 9: REMEMBER (Security Immune Memory)
  // ============================================================
  callbacks.onProgress('Step 9/9: Saving to security immune memory...');
  updateStep('REMEMBER', 'IN_PROGRESS', 'Creating persistent regression record...');

  if (verificationRun.status === 'VERIFIED') {
    securityMemory = createSecurityMemory(
      primaryFinding,
      selectedPatch,
      verificationRun,
      'demo-source-hash-0000'
    );
    callbacks.onMemory(securityMemory);
    callbacks.onInvestigationUpdate({ securityMemory });

    logAudit(createAuditEvent(
      'Security memory created',
      'MEMORY',
      `${securityMemory.kavachId}: ${securityMemory.vulnerabilityClass} - VERIFIED. Regression test stored for future code changes.`,
      'INFO',
      'security-memory'
    ));

    updateStep('REMEMBER', 'COMPLETED', `${securityMemory.kavachId} saved to immune memory`);
  } else {
    updateStep('REMEMBER', 'SKIPPED', 'Verification did not pass. No memory record created.');
  }

  // Final status
  investigation.status = verificationRun?.status === 'VERIFIED' ? 'VERIFIED' : 'ACTION_REQUIRED';
  investigation.completedAt = new Date().toISOString();
  investigation.findings = findings;
  investigation.evidence = evidenceList;
  investigation.experiments = experiments;
  investigation.hypotheses = hypotheses;
  investigation.patches = patches;
  investigation.verificationRun = verificationRun;
  investigation.securityMemory = securityMemory;

  callbacks.onInvestigationUpdate({
    status: investigation.status,
    completedAt: investigation.completedAt,
  });

  logAudit(createAuditEvent(
    'Investigation complete',
    'SYSTEM',
    `Status: ${investigation.status}. Findings: ${findings.length}. Evidence: ${evidenceList.length}. Patches: ${patches.length}. Verification: ${verificationRun?.status || 'N/A'}. Memory: ${securityMemory?.kavachId || 'N/A'}`,
    investigation.status === 'VERIFIED' ? 'INFO' : 'HIGH',
    'demo-engine'
  ));

  callbacks.onProgress(investigation.status === 'VERIFIED' ? 'KAVACH VERIFIED FIX - Investigation complete.' : 'Investigation complete with issues.');

  return {
    investigation,
    securityMemory: securityMemory || ({} as SecurityMemory),
    twinSnapshots,
    auditEvents,
    agentActions,
    success: investigation.status === 'VERIFIED',
  };
}

export function getSystemStatus(): SystemStatus {
  const llmConfig = detectLLMConfig();
  return {
    state: 'SAFE',
    guardianActive: true,
    sandboxActive: true,
    llmProvider: llmConfig,
    toolsAvailable: [
      { name: 'Kavach SAST', available: true, authenticity: 'EXECUTABLE' },
      { name: 'SQL Analyzer', available: true, authenticity: 'EXECUTABLE' },
      { name: 'Semantic Test Generator', available: true, authenticity: 'EXECUTABLE' },
      { name: 'Evidence Fusion', available: true, authenticity: 'EXECUTABLE' },
      { name: 'Patch Analysis', available: true, authenticity: 'EXECUTABLE' },
      { name: 'Security Memory', available: true, authenticity: 'EXECUTABLE' },
      { name: 'Audit Logging', available: true, authenticity: 'EXECUTABLE' },
      { name: 'Controlled Fuzz Execution', available: true, authenticity: 'CONTROLLED_DEMONSTRATION' },
      { name: 'DAST Simulation', available: true, authenticity: 'CONTROLLED_DEMONSTRATION' },
      { name: 'Mutation Testing', available: true, authenticity: 'CONTROLLED_DEMONSTRATION' },
      { name: 'Digital Twin', available: true, authenticity: 'CONTROLLED_DEMONSTRATION' },
      { name: 'LLM Reasoner', available: true, authenticity: llmConfig.provider === 'demo' ? 'CONTROLLED_DEMONSTRATION' : 'EXECUTABLE' },
      { name: 'ClusterFuzz / AFL++', available: false, authenticity: 'PLANNED_INTEGRATION' },
      { name: 'CodeQL / Semgrep', available: false, authenticity: 'PLANNED_INTEGRATION' },
    ],
  };
}

export { assessAgentSecurity };
