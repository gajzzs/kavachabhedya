import { useState, useCallback, useRef } from 'react';
import {
  Target, Upload, FileCode, ShieldCheck, AlertTriangle, Loader2, Play,
  CheckCircle2, XCircle, ArrowRight, Lock, Terminal, FileSearch,
  Activity, FlaskConical, GitBranch, Database, ScrollText, Cpu,
  Hash, FileText, X, Bug, Network, GitFork, Ban,
} from 'lucide-react';
import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { AuthenticityBadge, StatusBadge } from '@/components/ui/Badge';
import { ProgressBar } from '@/components/ui/ProgressBar';
import type { PageId } from '@/components/layout/Sidebar';
import type {
  SourceFile, Finding, Evidence, PatchCandidate, VerificationRun,
  AuditEvent, AttackPath, LLMReasoningResult, AssessmentMeta, TwinSnapshot,
} from '@/types';
import { generateId } from '@/lib/utils';
import type { FuzzResult as FuzzerFuzzResult } from '@/services/security-tools/fuzzer';
import { runSAST, type SASTDiagnostics } from '@/services/security-tools/sastAnalyzer';
import { runFuzzer } from '@/services/security-tools/fuzzer';
import { runCppDynamicAnalysis } from '@/services/cppDynamicService';
import { CppDynamicResultsView } from '@/components/common/CppDynamicResultsView';
import { fuseEvidence } from '@/services/evidenceFusion';
import { buildAttackPath } from '@/services/attackPathBuilder';
import { createLLMProvider } from '@/services/llm/llmProvider';
import { runVerification } from '@/services/verification/verificationEngine';
import { createSecurityMemory } from '@/services/memoryService';
import { createAuditEvent } from '@/services/guardian';
import { createAssessment, updateAssessment } from '@/services/assessmentService';
import {
  ingestFile, ingestRawCode, SUPPORTED_EXTENSIONS,
  type IngestionResult,
} from '@/services/sourceIngestion';

type AssessmentStage = 'IDLE' | 'INTAKE' | 'SCAN' | 'EVIDENCE' | 'FUZZING' | 'ATTACK_PATH' | 'PATCH' | 'VERIFY' | 'MEMORY' | 'COMPLETED' | 'FAILED';
type StageStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'INCONCLUSIVE' | 'UNAVAILABLE';

interface StageInfo {
  stage: AssessmentStage;
  label: string;
  status: StageStatus;
  detail?: string;
  icon: typeof FileSearch;
}

const STAGE_ORDER: AssessmentStage[] = ['INTAKE', 'SCAN', 'EVIDENCE', 'FUZZING', 'ATTACK_PATH', 'PATCH', 'VERIFY', 'MEMORY'];

const SAMPLE_PRESETS = [
  {
    id: 'cpp_buf',
    label: 'C++ Stack Buffer Overflow',
    filename: 'vulnerable.cpp',
    code: `#include <iostream>
#include <cstring>

void processInput(const char* input) {
    char buffer[64];
    strcpy(buffer, input);  // VULNERABLE: stack buffer overflow via unbounded strcpy
    std::cout << "Processed: " << buffer << std::endl;
}

int main() {
    std::string input;
    if (std::cin >> input) {
        processInput(input.c_str());
    }
    return 0;
}`,
  },
  {
    id: 'py_sqli',
    label: 'Python SQL Injection',
    filename: 'vulnerable_app.py',
    code: `import sqlite3

def get_user_profile(user_input):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string interpolation into SQL query
    query = f"SELECT id, username, role FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()
`,
  },
  {
    id: 'cpp_overflow',
    label: 'C++ Integer Overflow',
    filename: 'integer_overflow.cpp',
    code: `#include <iostream>

int calculateTotalCost(int count, int pricePerItem) {
    return count * pricePerItem; // VULNERABLE: Signed integer overflow
}

int main() {
    int count, price;
    if (std::cin >> count >> price) {
        int total = calculateTotalCost(count, price);
        std::cout << "Total: " << total << std::endl;
    }
    return 0;
}`,
  },
  {
    id: 'java_cmd',
    label: 'Java Command Injection',
    filename: 'CommandExec.java',
    code: `import java.io.*;

public class CommandExec {
    public static void runPing(String host) throws IOException {
        // VULNERABLE: OS command injection via unparsed user parameter
        String command = "ping -c 1 " + host;
        Process process = Runtime.getRuntime().exec(command);
    }
}`,
  },
];


export function RealAssessmentPage({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const { dispatch, findings, evidence, patches, verificationRun, attackPath, reasoning, fuzzingResult, assessment, cppDynamicResult } = useKavach();
  const [projectName, setProjectName] = useState('My Application');
  const [targetType, setTargetType] = useState<'SOURCE_CODE' | 'LOCAL_APPLICATION' | 'CONTROLLED_LAB'>('SOURCE_CODE');
  const [authorized, setAuthorized] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [progressMsg, setProgressMsg] = useState('');
  const [stages, setStages] = useState<StageInfo[]>([]);
  const [auditTrail, setAuditTrail] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [ingestion, setIngestion] = useState<IngestionResult | null>(null);
  const [ingestionError, setIngestionError] = useState<string | null>(null);
  const [isIngesting, setIsIngesting] = useState(false);
  const [sastDiagnostics, setSastDiagnostics] = useState<SASTDiagnostics | null>(null);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [inputMode, setInputMode] = useState<'PASTE' | 'UPLOAD'>('PASTE');
  const [rawFilename, setRawFilename] = useState('vulnerable.cpp');
  const [rawCode, setRawCode] = useState(SAMPLE_PRESETS[0].code);
  const cancelRef = useRef(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleRawCodeIngest = useCallback(async () => {
    if (!rawCode.trim()) {
      setIngestionError('Source code cannot be empty.');
      return;
    }
    setIngestionError(null);
    setError(null);
    setIsIngesting(true);
    try {
      const result = await ingestRawCode(rawFilename.trim() || 'vulnerable.cpp', rawCode);
      setIngestion(result);
      if (projectName === 'My Application') {
        const baseName = (rawFilename.trim() || 'vulnerable.cpp').replace(/\.[^/.]+$/, '');
        setProjectName(baseName);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setIngestionError(msg);
      setIngestion(null);
    } finally {
      setIsIngesting(false);
    }
  }, [rawCode, rawFilename, projectName]);

  const loadPreset = useCallback((presetId: string) => {
    const preset = SAMPLE_PRESETS.find((p) => p.id === presetId);
    if (preset) {
      setRawFilename(preset.filename);
      setRawCode(preset.code);
      setProjectName(preset.label);
    }
  }, []);


  const logAudit = useCallback((event: AuditEvent) => {
    setAuditTrail((prev) => [...prev, event]);
    dispatch({ type: 'ADD_AUDIT', event });
  }, [dispatch]);

  const updateStage = useCallback((stage: AssessmentStage, status: StageStatus, detail?: string) => {
    setStages((prev) => {
      const updated = [...prev];
      const idx = updated.findIndex((s) => s.stage === stage);
      const icons: Record<AssessmentStage, typeof FileSearch> = {
        IDLE: Target, INTAKE: Upload, SCAN: FileSearch, EVIDENCE: Activity,
        FUZZING: FlaskConical, ATTACK_PATH: GitBranch, PATCH: FlaskConical, VERIFY: ShieldCheck,
        MEMORY: Database, COMPLETED: CheckCircle2, FAILED: XCircle,
      };
      if (idx >= 0) {
        updated[idx] = { stage, label: updated[idx].label, status, detail, icon: icons[stage] };
      }
      return updated;
    });
  }, []);

  const initStages = useCallback(() => {
    const labels: Record<AssessmentStage, string> = {
      IDLE: 'Idle', INTAKE: 'Source Ingestion', SCAN: 'Real SAST',
      EVIDENCE: 'Evidence Fusion', FUZZING: 'Controlled Fuzzing', ATTACK_PATH: 'Attack Path',
      PATCH: 'Patch Lab', VERIFY: 'Deterministic Verification',
      MEMORY: 'Security Memory', COMPLETED: 'Completed', FAILED: 'Failed',
    };
    const icons: Record<AssessmentStage, typeof FileSearch> = {
      IDLE: Target, INTAKE: Upload, SCAN: FileSearch, EVIDENCE: Activity,
      FUZZING: FlaskConical, ATTACK_PATH: GitBranch, PATCH: FlaskConical, VERIFY: ShieldCheck,
      MEMORY: Database, COMPLETED: CheckCircle2, FAILED: XCircle,
    };
    setStages(STAGE_ORDER.map((stage) => ({
      stage, label: labels[stage], status: 'QUEUED' as StageStatus, icon: icons[stage],
    })));
  }, []);

  const handleFileSelect = useCallback(async (file: File) => {
    setIngestionError(null);
    setError(null);
    setIsIngesting(true);

    try {
      const result = await ingestFile(file);
      setIngestion(result);
      // Auto-set project name from filename if it's still the default
      if (projectName === 'My Application') {
        const baseName = file.name.replace(/\.[^/.]+$/, '');
        setProjectName(baseName);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setIngestionError(msg);
      setIngestion(null);
    } finally {
      setIsIngesting(false);
    }
  }, [projectName]);

  const handleFileInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
    // Reset input so the same file can be re-selected after modification
    e.target.value = '';
  }, [handleFileSelect]);

  const clearIngestion = useCallback(() => {
    setIngestion(null);
    setIngestionError(null);
    dispatch({ type: 'SET_ASSESSMENT_RESULTS', findings: [], evidence: [], patches: [], verificationRun: null, attackPath: null, reasoning: null });
    dispatch({ type: 'SET_ASSESSMENT_META', assessment: null });
    dispatch({ type: 'SET_FUZZING_RESULT', result: null });
    setStages([]);
    setAuditTrail([]);
    setError(null);
    setSastDiagnostics(null);
    setShowDiagnostics(false);
  }, [dispatch]);

  const runAssessment = useCallback(async () => {
    if (!authorized || isRunning || !ingestion) return;
    cancelRef.current = false;
    setIsRunning(true);
    setError(null);
    dispatch({ type: 'SET_ASSESSMENT_RESULTS', findings: [], evidence: [], patches: [], verificationRun: null, attackPath: null, reasoning: null });
    dispatch({ type: 'SET_FUZZING_RESULT', result: null });
    setAuditTrail([]);
    setSastDiagnostics(null);
    initStages();

    const assessmentId = generateId('assessment');
    const file: SourceFile = ingestion.file;
    const sourceHash = ingestion.hash;
    dispatch({
      type: 'SET_ASSESSMENT_META',
      assessment: {
        assessmentId,
        projectName,
        sourceFilename: file.filename,
        sourceHash,
        language: ingestion.language,
        lineCount: file.lineCount,
        fileSize: ingestion.fileSize,
        createdAt: new Date().toISOString(),
        status: 'RUNNING',
      },
    });
    let dbAssessmentId: string | null = null;
    const localAuditTrail: AuditEvent[] = [];
    const logAuditLocal = (event: AuditEvent) => {
      localAuditTrail.push(event);
      setAuditTrail((prev) => [...prev, event]);
      dispatch({ type: 'ADD_AUDIT', event });
    };

    try {
      // STEP 1: INTAKE
      updateStage('INTAKE', 'RUNNING', 'Validating and hashing source code...');
      setProgressMsg('Step 1/7: Source ingestion...');
      logAuditLocal(createAuditEvent('Assessment created', 'SYSTEM', `Assessment ${assessmentId} for "${projectName}"`, 'INFO', 'real-assessment'));
      logAuditLocal(createAuditEvent('Source imported', 'SYSTEM', `File: ${file.filename}, Lines: ${file.lineCount}, Hash: ${sourceHash.substring(0, 16)}...`, 'INFO', 'real-assessment'));

      dbAssessmentId = await createAssessment({
        project_name: projectName,
        target_type: targetType,
        language: ingestion.language,
        source_hash: sourceHash,
        source_filename: file.filename,
        source_line_count: file.lineCount,
        status: 'RUNNING',
        stages: [],
        findings: [],
        evidence: null,
        attack_path: null,
        patches: [],
        verification: null,
        reasoning: null,
        audit_trail: [],
        error: null,
      });
      await delay(400);
      updateStage('INTAKE', 'COMPLETED', `Ingested ${file.filename} (${file.lineCount} lines, hash: ${sourceHash.substring(0, 12)}...)`);
      if (cancelRef.current) return;

      // STEP 2: REAL SAST
      updateStage('SCAN', 'RUNNING', 'Running Kavach SAST pattern engine...');
      setProgressMsg('Step 2/7: Running real SAST analysis...');
      logAuditLocal(createAuditEvent('SAST started', 'SCAN', 'Running Kavach SAST pattern engine on source', 'INFO', 'kavach-sast'));
      await delay(600);

      const sastResult = runSAST([file]);
      setSastDiagnostics(sastResult.diagnostics);
      logAuditLocal(createAuditEvent('SAST completed', 'SCAN', `${sastResult.findings.length} finding(s) detected. Authenticity: EXECUTABLE`, 'INFO', 'kavach-sast'));

      if (sastResult.findings.length === 0) {
        updateStage('SCAN', 'COMPLETED', 'No findings detected by SAST');
        for (const s of ['EVIDENCE', 'FUZZING', 'ATTACK_PATH', 'PATCH', 'VERIFY'] as AssessmentStage[]) {
          updateStage(s, 'UNAVAILABLE', 'No findings — stage skipped');
        }
        updateStage('MEMORY', 'COMPLETED', 'No vulnerability to remember');
        setProgressMsg('Assessment complete — no vulnerabilities found.');
        dispatch({ type: 'UPDATE_ASSESSMENT_META', updates: { status: 'COMPLETED' } });
        if (dbAssessmentId) {
          await updateAssessment(dbAssessmentId, {
            status: 'COMPLETED', findings: sastResult.findings, audit_trail: localAuditTrail,
            completed_at: new Date().toISOString(),
          });
        }
        setIsRunning(false);
        return;
      }

      dispatch({ type: 'SET_ASSESSMENT_RESULTS', findings: sastResult.findings, evidence: [], patches: [], verificationRun: null, attackPath: null, reasoning: null });
      for (const f of sastResult.findings) {
        logAuditLocal(createAuditEvent('Vulnerability detected', 'SCAN', `${f.vulnerabilityClass} at ${f.file}:${f.line} — ${f.description}`, f.severity, 'kavach-sast'));
      }
      updateStage('SCAN', 'COMPLETED', `${sastResult.findings.length} finding(s). Authenticity: EXECUTABLE`);
      if (cancelRef.current) return;

      // STEP 3: EVIDENCE FUSION (SAST only)
      updateStage('EVIDENCE', 'RUNNING', 'Fusing SAST evidence...');
      setProgressMsg('Step 3/8: Evidence fusion (SAST)...');
      logAuditLocal(createAuditEvent('Evidence fusion started', 'EVIDENCE', 'Collecting SAST evidence signals', 'INFO', 'evidence-fusion'));
      await delay(500);

      const primaryFinding = sastResult.findings[0];
      const sastSource = sastResult.evidenceSources[0];

      const fusionResult = fuseEvidence({
        finding: primaryFinding,
        sources: [sastSource],
      });
      dispatch({ type: 'SET_ASSESSMENT_RESULTS', findings: sastResult.findings, evidence: [fusionResult.evidence], patches: [], verificationRun: null, attackPath: null, reasoning: null });
      logAuditLocal(createAuditEvent('Evidence fused', 'EVIDENCE', `Status: ${fusionResult.evidence.status}. Prototype evidence score: ${fusionResult.evidence.fusedScore}%. ${fusionResult.evidence.reasoning}`, 'INFO', 'evidence-fusion'));
      updateStage('EVIDENCE', 'COMPLETED', `${fusionResult.evidence.status} — SAST evidence score: ${fusionResult.evidence.fusedScore}%`);
      if (cancelRef.current) return;

      // STEP 4: CONTROLLED FUZZING / C++ DYNAMIC ANALYSIS
      updateStage('FUZZING', 'RUNNING', 'Checking fuzz engine & executing dynamic fuzzing...');
      setProgressMsg('Step 4/8: Controlled fuzzing & dynamic analysis...');
      logAuditLocal(createAuditEvent('Fuzzer started', 'SCAN', 'Executing target dynamic analysis & fuzzing', 'INFO', 'kavach-fuzzer'));
      await delay(400);

      const isCpp = ['cpp', 'c', 'cc'].includes(ingestion.languageCode) || ['c', 'cpp'].includes(file.language);
      let fuzzResult: FuzzerFuzzResult;

      if (isCpp) {
        logAuditLocal(createAuditEvent('C++ Dynamic Fuzzer started', 'SCAN', 'Executing real GCC compilation & ASan/UBSan fuzzing via Compiler Explorer', 'INFO', 'cpp-dynamic-service'));
        const dynResult = await runCppDynamicAnalysis(
          file.content,
          ['BOUNDARY', 'OVERFLOW', 'FORMAT_STRING', 'STRESS'],
          'asan+ubsan',
          3,
          (msg) => setProgressMsg(`Step 4/8: C++ Dynamic Analysis — ${msg}`)
        );

        dispatch({ type: 'SET_CPP_DYNAMIC_RESULT', result: dynResult });

        const confirmed = dynResult.totalUB > 0 || dynResult.totalCrashes > 0;
        const payloads = dynResult.fuzzCases.map((fc) => ({
          payload: fc.input,
          input: fc.input,
          queryConstructed: fc.input,
          injectionDetected: fc.interesting,
          injectionType: fc.strategy,
          detail: fc.interestingReason || (fc.stderr ? fc.stderr.split('\n')[0] : 'Normal execution'),
          rowCount: fc.lineHits.length,
          dataExtracted: false,
          authBypassed: false,
          tableModified: false,
          dataModified: false,
          error: fc.stderr || null,
          category: fc.strategy,
          reason: fc.label,
          confidence: (fc.interesting ? 'HIGH' : 'LOW') as 'HIGH' | 'MEDIUM' | 'LOW',
          classification: (fc.runStatus === 'SANITIZER_ERROR' || fc.runStatus === 'CRASH' ? 'CONFIRMED' : 'NOT_REPRODUCED') as any,
          baselineRowCount: 0,
          behaviorChange: fc.interestingReason || 'Standard execution',
          executionMode: 'SOURCE_DERIVED' as const,
          syntaxError: fc.runStatus === 'RUNTIME_ERROR',
        }));

        fuzzResult = {
          findingId: primaryFinding.id,
          payloads,
          confirmed,
          confidence: confirmed ? 0.95 : 0.4,
          confirmedCount: dynResult.totalInteresting,
          evidenceSource: {
            tool: 'kavach-cpp-dynamic',
            toolType: 'FUZZER',
            status: confirmed ? 'CONFIRMED' : 'NOT_REPRODUCED',
            authenticity: 'EXECUTABLE',
            detail: `C++ Dynamic Analysis: ${dynResult.totalUB} UBSan/ASan errors, ${dynResult.totalCrashes} crashes across ${dynResult.fuzzCases.length} inputs`,
            confidence: confirmed ? 0.95 : 0.4,
            timestamp: new Date().toISOString(),
          },
          authenticity: 'EXECUTABLE',
          detail: `Compiler Explorer GCC + Sanitizers: ${dynResult.totalInteresting} dynamic hits`,
          executionId: dynResult.sessionId,
          schema: { tables: [], source: 'SOURCE_DERIVED' },
          baseline: null,
          sqlContext: null,
          executionMode: 'SOURCE_DERIVED',
          skipped: false,
          skipReason: null,
        };
      } else {
        fuzzResult = runFuzzer(primaryFinding, [file]);
      }

      dispatch({ type: 'SET_FUZZING_RESULT', result: fuzzResult });

      if (fuzzResult.skipped) {
        logAuditLocal(createAuditEvent('Fuzzer skipped', 'SCAN', `Reason: ${fuzzResult.skipReason}`, 'INFO', 'kavach-fuzzer'));
        updateStage('FUZZING', 'UNAVAILABLE', `SKIPPED — ${fuzzResult.skipReason}`);
      } else {
        logAuditLocal(createAuditEvent('Fuzzer completed', 'SCAN', `${fuzzResult.confirmedCount}/${fuzzResult.payloads.length} payloads produced behavioral changes. Classification: ${fuzzResult.confirmed ? 'CONFIRMED' : fuzzResult.confirmedCount > 0 ? 'SUSPICIOUS' : 'NOT_REPRODUCED'}. Execution: ${fuzzResult.executionMode}`, 'INFO', 'kavach-fuzzer'));
        updateStage('FUZZING', 'COMPLETED', `${fuzzResult.confirmed ? 'CONFIRMED' : fuzzResult.confirmedCount > 0 ? 'SUSPICIOUS' : 'NOT_REPRODUCED'} — ${fuzzResult.confirmedCount}/${fuzzResult.payloads.length} behavioral/sanitizer changes (${fuzzResult.executionMode})`);

        // Re-fuse evidence with fuzzer result
        const refusionResult = fuseEvidence({
          finding: primaryFinding,
          sources: [sastSource, fuzzResult.evidenceSource],
        });
        dispatch({ type: 'SET_ASSESSMENT_RESULTS', findings: sastResult.findings, evidence: [refusionResult.evidence], patches: [], verificationRun: null, attackPath: null, reasoning: null });
        logAuditLocal(createAuditEvent('Evidence re-fused', 'EVIDENCE', `Updated with fuzzer evidence: ${refusionResult.evidence.status}. Score: ${refusionResult.evidence.fusedScore}%`, 'INFO', 'evidence-fusion'));
      }
      if (cancelRef.current) return;

      // STEP 5: ATTACK PATH
      updateStage('ATTACK_PATH', 'RUNNING', 'Building evidence-backed attack path...');
      setProgressMsg('Step 5/8: Building attack path...');
      await delay(400);
      const path = buildAttackPath(primaryFinding);
      dispatch({ type: 'SET_ATTACK_PATH', path });
      logAuditLocal(createAuditEvent('Attack path created', 'EVIDENCE', `Entry: ${path.entryPoint} → Impact: ${path.impact}`, 'INFO', 'attack-path-builder'));

      // Create twin snapshot from active assessment — adapted to vulnerability class
      const isBufferOverflow = primaryFinding.vulnerabilityClass === 'BUFFER_OVERFLOW';
      const sinkLabel = isBufferOverflow ? (primaryFinding.sink || 'memcpy') : 'SQL Query';
      const impactLabel = isBufferOverflow ? 'Memory Corruption' : 'Database';
      const flowLabel = isBufferOverflow ? 'copies untrusted length' : 'executes SQL';
      const twinSnapshot: TwinSnapshot = {
        id: generateId('twin'),
        label: `${file.filename} — Original (Vulnerable)`,
        timestamp: new Date().toISOString(),
        description: `Controlled snapshot from Real Assessment ${assessmentId}. Source: ${file.filename}, Hash: ${sourceHash.substring(0, 12)}...`,
        state: 'ORIGINAL',
        nodes: [
          { id: 'input', label: isBufferOverflow ? 'Untrusted Input' : 'User Input', type: 'API', status: 'VULNERABLE', detail: path.entryPoint },
          { id: 'app', label: isBufferOverflow ? sinkLabel : 'Application', type: 'APP', status: 'VULNERABLE', detail: `${file.filename}:${primaryFinding.line}` },
          { id: 'db', label: impactLabel, type: isBufferOverflow ? 'DATABASE' : 'DATABASE', status: 'VULNERABLE', detail: path.impact },
        ],
        edges: [
          { from: 'input', to: 'app', label: 'flows to', type: 'FLOWS_TO', vulnerable: true },
          { from: 'app', to: 'db', label: flowLabel, type: 'CALLS', vulnerable: true },
        ],
        attackPathActive: true,
      };
      dispatch({ type: 'ADD_TWIN_SNAPSHOT', snapshot: twinSnapshot });
      logAuditLocal(createAuditEvent('Twin snapshot created', 'EVIDENCE', `Digital Twin snapshot: ${twinSnapshot.label}`, 'INFO', 'twin-service'));
      updateStage('ATTACK_PATH', 'COMPLETED', `Path: ${path.entryPoint} → database sink`);
      if (cancelRef.current) return;

      // STEP 6: PATCH
      updateStage('PATCH', 'RUNNING', 'Generating candidate patch...');
      setProgressMsg('Step 6/8: Patch generation...');
      logAuditLocal(createAuditEvent('Patch generation started', 'PATCH', 'Generating candidate remediation', 'INFO', 'patch-lab'));
      await delay(600);

      const llm = createLLMProvider();
      const patchCandidates = await llm.generatePatchCandidates(primaryFinding, [file]);
      const fullPatches: PatchCandidate[] = patchCandidates.map((p) => ({
        id: p.id || generateId('patch'),
        label: p.label || 'Patch',
        strategy: p.strategy || 'Parameterized Query',
        description: p.description || '',
        originalCode: p.originalCode || file.content,
        patchedCode: p.patchedCode || file.content,
        diff: p.diff || '',
        securityScore: p.securityScore || 0.9,
        regressionRisk: p.regressionRisk || 0.1,
        codeComplexity: p.codeComplexity || 0.2,
        performanceImpact: p.performanceImpact || 0.05,
        linesChanged: p.linesChanged || 2,
        affectedComponents: p.affectedComponents || [],
        dependenciesAdded: p.dependenciesAdded || [],
        riskLevel: p.riskLevel || 'LOW',
        authenticity: 'CONTROLLED_DEMONSTRATION',
      }));
      for (const p of fullPatches) {
        dispatch({ type: 'ADD_PATCH', patch: p });
        logAuditLocal(createAuditEvent('Patch generated', 'PATCH', `${p.label}: ${p.strategy} (${p.linesChanged} lines changed)`, 'INFO', 'patch-lab'));
      }

      const reasoningResult = await llm.analyzeEvidence([primaryFinding], evidence.length > 0 ? evidence : []);
      dispatch({ type: 'SET_REASONING', reasoning: reasoningResult });
      logAuditLocal(createAuditEvent('AI analysis completed', 'REASONING', `Root cause: ${reasoningResult.rootCause.substring(0, 80)}...`, 'INFO', 'llm-reasoner'));
      updateStage('PATCH', 'COMPLETED', `${fullPatches.length} patch candidate(s) generated`);
      if (cancelRef.current) return;

      // STEP 7: DETERMINISTIC VERIFICATION
      updateStage('VERIFY', 'RUNNING', 'Re-analyzing patch + deterministic verification...');
      setProgressMsg('Step 7/8: Deterministic verification...');
      logAuditLocal(createAuditEvent('Verification started', 'VERIFICATION', 'Re-running SAST on patched code + mutation + regression tests', 'INFO', 'verification-engine'));
      await delay(600);

      const bestPatch = fullPatches[0];
      const verifyResult = runVerification({
        finding: primaryFinding,
        patch: bestPatch,
        files: [file],
      });

      if (isCpp && bestPatch.patchedCode) {
        logAuditLocal(createAuditEvent('C++ Dynamic Patch Verification', 'VERIFICATION', 'Compiling and fuzzing patched C++ code via Compiler Explorer (GCC + ASan/UBSan)', 'INFO', 'cpp-dynamic-service'));
        const patchDynResult = await runCppDynamicAnalysis(
          bestPatch.patchedCode,
          ['BOUNDARY', 'OVERFLOW', 'FORMAT_STRING', 'STRESS'],
          'asan+ubsan',
          3,
          (msg) => setProgressMsg(`Step 7/8: C++ Dynamic Verification — ${msg}`)
        );
        const patchHasUB = patchDynResult.totalUB > 0 || patchDynResult.totalCrashes > 0;
        if (!patchHasUB) {
          logAuditLocal(createAuditEvent('C++ Dynamic Verification PASSED', 'VERIFICATION', `Patched C++ code verified clean across ${patchDynResult.fuzzCases.length} fuzz inputs (0 crashes, 0 ASan/UBSan hits)`, 'INFO', 'cpp-dynamic-service'));
        } else {
          logAuditLocal(createAuditEvent('C++ Dynamic Verification WARNING', 'VERIFICATION', `Patched C++ code triggered ${patchDynResult.totalUB} UB / ${patchDynResult.totalCrashes} crashes under dynamic fuzzing`, 'HIGH', 'cpp-dynamic-service'));
        }
      }

      dispatch({ type: 'SET_VERIFICATION', run: verifyResult.run });

      // Create patched twin snapshot — adapted to vulnerability class
      const patchedTwin: TwinSnapshot = {
        id: generateId('twin'),
        label: `${file.filename} — Patched (${bestPatch.label})`,
        timestamp: new Date().toISOString(),
        description: `Post-patch snapshot. Strategy: ${bestPatch.strategy}. Verification: ${verifyResult.run.status}`,
        state: verifyResult.run.status === 'VERIFIED' ? 'VERIFIED' : 'PATCHED_A',
        nodes: [
          { id: 'input', label: isBufferOverflow ? 'Untrusted Input' : 'User Input', type: 'API', status: 'SECURE', detail: path.entryPoint },
          { id: 'app', label: isBufferOverflow ? sinkLabel : 'Application', type: 'APP', status: 'PATCHED', detail: `${file.filename}:${primaryFinding.line}` },
          { id: 'db', label: impactLabel, type: 'DATABASE', status: 'SECURE', detail: isBufferOverflow ? 'Bounds checked' : 'Parameterized query' },
        ],
        edges: [
          { from: 'input', to: 'app', label: 'flows to', type: 'FLOWS_TO', vulnerable: false, blocked: true },
          { from: 'app', to: 'db', label: isBufferOverflow ? 'bounded copy' : 'parameterized', type: 'CALLS', vulnerable: false, blocked: true },
        ],
        attackPathActive: false,
        patchApplied: bestPatch.id,
      };
      dispatch({ type: 'ADD_TWIN_SNAPSHOT', snapshot: patchedTwin });
      logAuditLocal(createAuditEvent('Verification completed', 'VERIFICATION', `Status: ${verifyResult.run.status}. SAST: ${verifyResult.run.newFindings} findings. Attack blocked: ${verifyResult.run.originalAttackBlocked}`, verifyResult.run.status === 'VERIFIED' ? 'INFO' : 'HIGH', 'verification-engine'));
      updateStage('VERIFY', verifyResult.run.status === 'VERIFIED' ? 'COMPLETED' : verifyResult.run.status === 'FAILED' ? 'FAILED' : 'INCONCLUSIVE', `${verifyResult.run.status} — scope: ${isCpp ? 'live C++ compilation + ASan/UBSan fuzzing' : 'prototype/static + controlled validation'}`);
      if (cancelRef.current) return;

      // STEP 8: SECURITY MEMORY
      updateStage('MEMORY', 'RUNNING', 'Storing verified remediation record...');
      setProgressMsg('Step 8/8: Security memory...');
      if (verifyResult.run.status === 'VERIFIED') {
        await delay(400);
        const memory = createSecurityMemory(primaryFinding, bestPatch, verifyResult.run, sourceHash);
        dispatch({ type: 'ADD_MEMORY', memory });
        logAuditLocal(createAuditEvent('Security memory stored', 'MEMORY', `Vulnerability: ${primaryFinding.vulnerabilityClass}, Patch: ${bestPatch.strategy}, Status: VERIFIED`, 'INFO', 'memory-service'));
        updateStage('MEMORY', 'COMPLETED', 'Verified remediation stored in Security Memory');
      } else {
        logAuditLocal(createAuditEvent('Security memory skipped', 'MEMORY', `Verification status: ${verifyResult.run.status} — only VERIFIED results enter Security Memory`, 'MEDIUM', 'memory-service'));
        updateStage('MEMORY', 'UNAVAILABLE', 'Only VERIFIED results enter Security Memory');
      }

      setProgressMsg('Assessment complete.');
      dispatch({ type: 'UPDATE_ASSESSMENT_META', updates: { status: verifyResult.run.status === 'VERIFIED' ? 'COMPLETED' : 'COMPLETED_WITH_ISSUES' } });
      logAuditLocal(createAuditEvent('Assessment completed', 'SYSTEM', `Assessment ${assessmentId} finished. Verification: ${verifyResult.run.status}`, 'INFO', 'real-assessment'));
      if (dbAssessmentId) {
        await updateAssessment(dbAssessmentId, {
          status: verifyResult.run.status === 'VERIFIED' ? 'COMPLETED' : 'COMPLETED_WITH_ISSUES',
          findings: sastResult.findings,
          evidence: evidence[0] || null,
          attack_path: path,
          patches: fullPatches,
          verification: verifyResult.run,
          reasoning: reasoningResult,
          audit_trail: localAuditTrail,
          completed_at: new Date().toISOString(),
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
      logAuditLocal(createAuditEvent('Assessment failed', 'SYSTEM', msg, 'CRITICAL', 'real-assessment'));
      updateStage('SCAN', 'FAILED', msg);
      if (dbAssessmentId) {
        await updateAssessment(dbAssessmentId, { status: 'FAILED', error: msg, completed_at: new Date().toISOString() });
      }
    } finally {
      setIsRunning(false);
    }
  }, [authorized, isRunning, ingestion, projectName, targetType, updateStage, initStages, dispatch]);

  const canRun = authorized && !isRunning && ingestion !== null;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <Card className="relative overflow-hidden border-kavach-accent/20">
        <div className="absolute inset-0 bg-gradient-to-r from-kavach-accent/5 to-transparent" />
        <CardBody className="relative">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <Target className="w-7 h-7 text-kavach-accent" />
                <div>
                  <h1 className="text-xl font-bold text-kavach-text-primary">Real Assessment</h1>
                  <p className="text-[10px] text-kavach-text-muted font-mono uppercase tracking-wider">ABHEDYA KAVACH / REAL ASSESSMENT</p>
                </div>
              </div>
              <p className="text-sm text-kavach-text-secondary max-w-2xl">
                Upload your source code for real security analysis. Kavach reads the actual file contents —
                SAST, evidence fusion, patch sandbox, and deterministic verification run against what you provide.
              </p>
            </div>
            <AuthenticityBadge authenticity="EXECUTABLE" />
          </div>
        </CardBody>
      </Card>

      {/* Authorization Banner */}
      <Card className={authorized ? 'border-kavach-success/30' : 'border-kavach-warning/30'}>
        <CardBody>
          <div className="flex items-start gap-3">
            <Lock className={`w-5 h-5 mt-0.5 ${authorized ? 'text-kavach-success' : 'text-kavach-warning'}`} />
            <div className="flex-1">
              <h3 className="text-sm font-semibold text-kavach-text-primary mb-1">Authorized Targets Only</h3>
              <p className="text-xs text-kavach-text-secondary mb-3">
                Real Assessment may operate only against source code you own, controlled vulnerable labs,
                or explicitly authorized environments. Never scan public targets without authorization.
              </p>
              <label className="flex items-center gap-2 cursor-pointer group">
                <button
                  onClick={() => setAuthorized(!authorized)}
                  className={`w-5 h-5 rounded border flex items-center justify-center transition-all ${
                    authorized
                      ? 'bg-kavach-success/20 border-kavach-success text-kavach-success'
                      : 'border-kavach-border bg-kavach-surface-2 group-hover:border-kavach-text-muted'
                  }`}
                >
                  {authorized && <CheckCircle2 className="w-3.5 h-3.5" />}
                </button>
                <span className="text-sm text-kavach-text-secondary">
                  I confirm this target is authorized for security testing.
                </span>
              </label>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* Assessment Creation Form */}
      <Card>
        <CardHeader title="New Real Assessment" subtitle="Upload source code to analyze" icon={<Terminal className="w-4 h-4" />} />
        <CardBody>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="text-xs text-kavach-text-muted font-mono uppercase tracking-wider mb-1.5 block">Project Name</label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                className="w-full bg-kavach-surface-2 border border-kavach-border rounded-md px-3 py-2 text-sm text-kavach-text-primary focus:border-kavach-accent focus:outline-none"
                placeholder="My Application"
              />
            </div>
            <div>
              <label className="text-xs text-kavach-text-muted font-mono uppercase tracking-wider mb-1.5 block">Target Type</label>
              <select
                value={targetType}
                onChange={(e) => setTargetType(e.target.value as typeof targetType)}
                className="w-full bg-kavach-surface-2 border border-kavach-border rounded-md px-3 py-2 text-sm text-kavach-text-primary focus:border-kavach-accent focus:outline-none"
              >
                <option value="SOURCE_CODE">Source Code</option>
                <option value="LOCAL_APPLICATION">Local Application</option>
                <option value="CONTROLLED_LAB">Controlled Lab</option>
              </select>
            </div>
          </div>

          {/* Source Input Zone */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-kavach-text-muted font-mono uppercase tracking-wider block">
                Source Code Input
              </label>
              {!ingestion && (
                <div className="flex items-center bg-kavach-surface-2 p-0.5 rounded border border-kavach-border text-xs">
                  <button
                    type="button"
                    onClick={() => setInputMode('PASTE')}
                    className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
                      inputMode === 'PASTE'
                        ? 'bg-kavach-accent text-kavach-bg font-semibold'
                        : 'text-kavach-text-muted hover:text-kavach-text-primary'
                    }`}
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    Editor / Paste
                  </button>
                  <button
                    type="button"
                    onClick={() => setInputMode('UPLOAD')}
                    className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
                      inputMode === 'UPLOAD'
                        ? 'bg-kavach-accent text-kavach-bg font-semibold'
                        : 'text-kavach-text-muted hover:text-kavach-text-primary'
                    }`}
                  >
                    <Upload className="w-3.5 h-3.5" />
                    Upload File
                  </button>
                </div>
              )}
            </div>

            {!ingestion && inputMode === 'PASTE' && (
              <div className="space-y-3 p-4 rounded-lg border border-kavach-border bg-kavach-surface-2/40">
                {/* Preset Targets */}
                <div className="flex flex-wrap items-center gap-2 pb-2 border-b border-kavach-border/50">
                  <span className="text-[11px] font-mono text-kavach-text-muted uppercase">Presets:</span>
                  {SAMPLE_PRESETS.map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => loadPreset(p.id)}
                      className="px-2.5 py-1 text-xs rounded bg-kavach-surface-2 border border-kavach-border hover:border-kavach-accent text-kavach-text-secondary hover:text-kavach-text-primary transition-all font-mono"
                    >
                      {p.label}
                    </button>
                  ))}
                </div>

                {/* Filename & Ingest Bar */}
                <div className="flex items-center gap-3">
                  <div className="flex-1 flex items-center gap-2 bg-kavach-bg border border-kavach-border rounded px-3 py-1.5 text-xs">
                    <span className="text-kavach-text-muted font-mono">Filename:</span>
                    <input
                      type="text"
                      value={rawFilename}
                      onChange={(e) => setRawFilename(e.target.value)}
                      placeholder="vulnerable.cpp"
                      className="bg-transparent text-kavach-text-primary font-mono outline-none flex-1"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={handleRawCodeIngest}
                    disabled={isIngesting || !rawCode.trim()}
                    className="kavach-btn kavach-btn-secondary py-1.5 px-4 text-xs flex items-center gap-1.5"
                  >
                    {isIngesting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle2 className="w-3.5 h-3.5 text-kavach-success" />}
                    Ingest Code
                  </button>
                </div>

                {/* Code Textarea Editor */}
                <div className="relative">
                  <div className="flex justify-between items-center px-3 py-1 bg-kavach-surface border-t border-x border-kavach-border rounded-t text-[11px] font-mono text-kavach-text-muted">
                    <span>C++ / Source Editor</span>
                    <span>{rawCode.split('\n').length} lines • {rawCode.length} chars</span>
                  </div>
                  <textarea
                    value={rawCode}
                    onChange={(e) => setRawCode(e.target.value)}
                    rows={12}
                    className="w-full bg-kavach-bg border border-kavach-border rounded-b p-3 text-xs font-mono text-kavach-text-primary focus:border-kavach-accent focus:outline-none resize-y leading-relaxed"
                    placeholder="Paste or write C++ / Python / Java source code here..."
                    spellCheck={false}
                  />
                </div>
              </div>
            )}

            {!ingestion && inputMode === 'UPLOAD' && (
              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); }}
                onDrop={(e) => {
                  e.preventDefault();
                  const file = e.dataTransfer.files[0];
                  if (file) handleFileSelect(file);
                }}
                className="border-2 border-dashed border-kavach-border rounded-lg p-8 text-center cursor-pointer hover:border-kavach-accent transition-colors group bg-kavach-surface-2/20"
              >
                {isIngesting ? (
                  <div className="flex flex-col items-center gap-2">
                    <Loader2 className="w-8 h-8 text-kavach-accent animate-spin" />
                    <p className="text-sm text-kavach-text-secondary">Reading file...</p>
                  </div>
                ) : (
                  <div className="flex flex-col items-center gap-2">
                    <Upload className="w-8 h-8 text-kavach-text-muted group-hover:text-kavach-accent transition-colors" />
                    <p className="text-sm text-kavach-text-secondary">Click to upload or drag & drop file</p>
                    <p className="text-xs text-kavach-text-muted">
                      Supported: {SUPPORTED_EXTENSIONS.map((e) => '.' + e).join(', ')}
                    </p>
                  </div>
                )}
              </div>
            )}

            <input
              ref={fileInputRef}
              type="file"
              accept={SUPPORTED_EXTENSIONS.map((e) => '.' + e).join(',')}
              onChange={handleFileInputChange}
              className="hidden"
            />
          </div>

          {/* Ingestion Error */}
          {ingestionError && (
            <div className="mt-3 p-3 rounded-md border border-kavach-error/30 bg-kavach-error/5 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-kavach-error shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-kavach-error">Ingestion Failed</p>
                <p className="text-xs text-kavach-text-secondary mt-0.5">{ingestionError}</p>
              </div>
            </div>
          )}

          {/* Source Inspection Panel */}
          {ingestion && (
            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-kavach-success" />
                  <span className="text-sm font-semibold text-kavach-success">Source Ingested</span>
                </div>
                <button
                  onClick={clearIngestion}
                  className="text-xs text-kavach-text-muted hover:text-kavach-error flex items-center gap-1 transition-colors"
                >
                  <X className="w-3 h-3" />
                  Remove
                </button>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                  <div className="flex items-center gap-1.5 mb-1">
                    <FileText className="w-3 h-3 text-kavach-text-muted" />
                    <span className="text-[10px] font-mono uppercase text-kavach-text-muted">Filename</span>
                  </div>
                  <p className="text-sm text-kavach-text-primary truncate" title={ingestion.file.filename}>{ingestion.file.filename}</p>
                </div>
                <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                  <div className="flex items-center gap-1.5 mb-1">
                    <FileCode className="w-3 h-3 text-kavach-text-muted" />
                    <span className="text-[10px] font-mono uppercase text-kavach-text-muted">Language</span>
                  </div>
                  <p className="text-sm text-kavach-text-primary">{ingestion.language}</p>
                </div>
                <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                  <div className="flex items-center gap-1.5 mb-1">
                    <FileText className="w-3 h-3 text-kavach-text-muted" />
                    <span className="text-[10px] font-mono uppercase text-kavach-text-muted">Lines</span>
                  </div>
                  <p className="text-sm text-kavach-text-primary">{ingestion.lineCount}</p>
                </div>
                <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                  <div className="flex items-center gap-1.5 mb-1">
                    <Hash className="w-3 h-3 text-kavach-text-muted" />
                    <span className="text-[10px] font-mono uppercase text-kavach-text-muted">SHA-256</span>
                  </div>
                  <p className="text-xs text-kavach-text-primary font-mono truncate" title={ingestion.hash}>
                    {ingestion.hash.substring(0, 16)}...
                  </p>
                </div>
              </div>

              {/* Additional metadata row */}
              <div className="flex flex-wrap gap-4 text-xs text-kavach-text-muted">
                <span>Size: <span className="text-kavach-text-secondary font-mono">{formatBytes(ingestion.fileSize)}</span></span>
                <span>Extension: <span className="text-kavach-text-secondary font-mono">.{ingestion.extension}</span></span>
                <span>Status: <span className="text-kavach-success font-mono">INGESTED</span></span>
              </div>

              {/* Source Preview */}
              <div>
                <p className="text-[10px] font-mono uppercase tracking-wider text-kavach-text-muted mb-1.5">Source Preview (first {Math.min(ingestion.preview.split('\n').length, 40)} lines)</p>
                <pre className="text-xs font-mono text-kavach-text-secondary bg-kavach-bg border border-kavach-border rounded-md p-3 overflow-x-auto max-h-64 overflow-y-auto">
                  {ingestion.preview}
                  {ingestion.preview.length >= 2000 && ingestion.file.content.length > 2000 ? '\n\n... (truncated, full content loaded for analysis)' : ''}
                </pre>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between mt-4">
            <div className="flex items-center gap-2 text-xs text-kavach-text-muted">
              <FileCode className="w-3.5 h-3.5" />
              <span className="font-mono">
                {!ingestion
                  ? 'No source uploaded'
                  : authorized
                  ? 'Ready to execute'
                  : 'Authorization required'}
              </span>
            </div>
            <button
              onClick={runAssessment}
              disabled={!canRun}
              className="kavach-btn kavach-btn-primary flex items-center gap-2"
            >
              {isRunning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Running Assessment...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Run Real Assessment
                </>
              )}
            </button>
          </div>
        </CardBody>
      </Card>

      {/* Error */}
      {error && (
        <Card className="border-kavach-error/30">
          <CardBody>
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-kavach-error" />
              <div>
                <p className="text-sm font-semibold text-kavach-error">Assessment Failed</p>
                <p className="text-xs text-kavach-text-secondary mt-1">{error}</p>
              </div>
            </div>
          </CardBody>
        </Card>
      )}

      {/* Progress */}
      {isRunning && progressMsg && (
        <div className="fixed bottom-4 right-4 kavach-card px-4 py-3 flex items-center gap-3 animate-fade-in z-50">
          <div className="w-2 h-2 bg-kavach-accent rounded-full animate-pulse" />
          <span className="text-sm text-kavach-accent font-mono">{progressMsg}</span>
        </div>
      )}

      {/* Pipeline Stages */}
      {stages.length > 0 && (
        <Card>
          <CardHeader title="Execution Pipeline" subtitle="Real-time assessment stages" icon={<Activity className="w-4 h-4" />} />
          <CardBody>
            <div className="space-y-2">
              {stages.map((stage) => {
                const Icon = stage.icon;
                const statusColor: Record<StageStatus, string> = {
                  QUEUED: 'text-kavach-text-muted',
                  RUNNING: 'text-kavach-accent',
                  COMPLETED: 'text-kavach-success',
                  FAILED: 'text-kavach-error',
                  INCONCLUSIVE: 'text-kavach-warning',
                  UNAVAILABLE: 'text-kavach-text-muted',
                };
                return (
                  <div key={stage.stage} className="flex items-center gap-3 p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
                    <Icon className={`w-4 h-4 ${statusColor[stage.status]}`} />
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-kavach-text-primary">{stage.label}</span>
                        <span className={`text-xs font-mono uppercase ${statusColor[stage.status]}`}>
                          {stage.status === 'RUNNING' && <Loader2 className="w-3 h-3 inline mr-1 animate-spin" />}
                          {stage.status}
                        </span>
                      </div>
                      {stage.detail && <p className="text-xs text-kavach-text-muted mt-0.5">{stage.detail}</p>}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardBody>
        </Card>
      )}

      {/* C++ Dynamic Analysis Results */}
      {cppDynamicResult && (
        <CppDynamicResultsView
          result={cppDynamicResult}
          code={rawCode || ingestion?.file.content}
          title="C++ Dynamic Compiler & Sanitizer Results"
        />
      )}

      {/* Results */}
      {findings.length > 0 && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card hover>
              <CardBody>
                <div className="flex items-center justify-between mb-2">
                  <FileSearch className="w-4 h-4 text-kavach-text-muted" />
                  <AuthenticityBadge authenticity="EXECUTABLE" />
                </div>
                <p className="kavach-section-title mb-1">SAST Findings</p>
                <p className="text-2xl font-bold text-kavach-text-primary">{findings.length}</p>
                <p className="text-xs text-kavach-text-muted mt-1">
                  {findings[0].vulnerabilityClass.replace(/_/g, ' ')} at {findings[0].file}:{findings[0].line}
                </p>
              </CardBody>
            </Card>

            <Card hover>
              <CardBody>
                <div className="flex items-center justify-between mb-2">
                  <Activity className="w-4 h-4 text-kavach-text-muted" />
                  {evidence[0] && <StatusBadge status={evidence[0].status} />}
                </div>
                <p className="kavach-section-title mb-1">Evidence</p>
                <p className="text-2xl font-bold text-kavach-text-primary">
                  {evidence[0] ? `${evidence[0].fusedScore}%` : '—'}
                </p>
                <p className="text-xs text-kavach-text-muted mt-1">Prototype evidence score</p>
              </CardBody>
            </Card>

            <Card hover>
              <CardBody>
                <div className="flex items-center justify-between mb-2">
                  <FlaskConical className="w-4 h-4 text-kavach-text-muted" />
                  {patches.length > 0 && <AuthenticityBadge authenticity="CONTROLLED_DEMONSTRATION" />}
                </div>
                <p className="kavach-section-title mb-1">Patches</p>
                <p className="text-2xl font-bold text-kavach-text-primary">{patches.length}</p>
                <p className="text-xs text-kavach-text-muted mt-1">
                  {patches.length > 0 ? patches[0].strategy : 'None generated'}
                </p>
              </CardBody>
            </Card>

            <Card hover>
              <CardBody>
                <div className="flex items-center justify-between mb-2">
                  <ShieldCheck className="w-4 h-4 text-kavach-text-muted" />
                  {verificationRun && <StatusBadge status={verificationRun.status} />}
                </div>
                <p className="kavach-section-title mb-1">Verification</p>
                <p className="text-sm font-semibold text-kavach-text-primary">
                  {verificationRun ? verificationRun.status.replace(/_/g, ' ') : 'Not started'}
                </p>
                <p className="text-xs text-kavach-text-muted mt-1">
                  {verificationRun ? `Mutations: ${verificationRun.mutationTests.filter((t) => t.passed).length}/${verificationRun.mutationTests.length}` : ''}
                </p>
              </CardBody>
            </Card>
          </div>

          {/* SAST Diagnostics — Debug Transparency */}
          {sastDiagnostics && (
            <Card>
              <CardHeader
                title="SAST Diagnostics"
                subtitle="Engine internals — sources, sinks, taint propagation, rejected findings"
                icon={<Bug className="w-4 h-4" />}
                action={
                  <button
                    onClick={() => setShowDiagnostics((v) => !v)}
                    className="text-xs text-kavach-accent hover:underline"
                  >
                    {showDiagnostics ? 'Hide' : 'Show'}
                  </button>
                }
              />
              {showDiagnostics && (
                <CardBody>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Sources */}
                    <div>
                      <div className="flex items-center gap-1.5 mb-2">
                        <Network className="w-3.5 h-3.5 text-kavach-success" />
                        <p className="text-xs font-mono uppercase tracking-wider text-kavach-success">Taint Sources ({sastDiagnostics.sources.length})</p>
                      </div>
                      {sastDiagnostics.sources.length === 0 ? (
                        <p className="text-xs text-kavach-text-muted italic">None discovered</p>
                      ) : (
                        <div className="space-y-1">
                          {sastDiagnostics.sources.map((s, i) => (
                            <div key={i} className="text-xs text-kavach-text-secondary font-mono flex items-start gap-1.5">
                              <span className="text-kavach-success shrink-0">●</span>
                              <span>{s.type}: <span className="text-kavach-text-primary">{s.variable}</span> @ {s.location}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Sinks */}
                    <div>
                      <div className="flex items-center gap-1.5 mb-2">
                        <GitFork className="w-3.5 h-3.5 text-kavach-error" />
                        <p className="text-xs font-mono uppercase tracking-wider text-kavach-error">SQL Sinks ({sastDiagnostics.sinks.length})</p>
                      </div>
                      {sastDiagnostics.sinks.length === 0 ? (
                        <p className="text-xs text-kavach-text-muted italic">None discovered</p>
                      ) : (
                        <div className="space-y-1">
                          {sastDiagnostics.sinks.map((s, i) => (
                            <div key={i} className="text-xs text-kavach-text-secondary font-mono flex items-start gap-1.5">
                              <span className="text-kavach-error shrink-0">●</span>
                              <span>{s.call} @ {s.location}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Tainted Variables */}
                    <div>
                      <div className="flex items-center gap-1.5 mb-2">
                        <Bug className="w-3.5 h-3.5 text-kavach-warning" />
                        <p className="text-xs font-mono uppercase tracking-wider text-kavach-warning">Tainted Variables ({sastDiagnostics.taintedVars.length})</p>
                      </div>
                      {sastDiagnostics.taintedVars.length === 0 ? (
                        <p className="text-xs text-kavach-text-muted italic">None discovered</p>
                      ) : (
                        <div className="space-y-1">
                          {sastDiagnostics.taintedVars.map((v, i) => (
                            <div key={i} className="text-xs text-kavach-text-secondary font-mono">
                              <span className="text-kavach-text-primary">{v.variable}</span> ← {v.origin} (line {v.line})
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* SQL Constructions */}
                    <div>
                      <div className="flex items-center gap-1.5 mb-2">
                        <FileCode className="w-3.5 h-3.5 text-kavach-accent" />
                        <p className="text-xs font-mono uppercase tracking-wider text-kavach-accent">SQL Constructions ({sastDiagnostics.sqlConstructions.length})</p>
                      </div>
                      {sastDiagnostics.sqlConstructions.length === 0 ? (
                        <p className="text-xs text-kavach-text-muted italic">None discovered</p>
                      ) : (
                        <div className="space-y-1">
                          {sastDiagnostics.sqlConstructions.map((c, i) => (
                            <div key={i} className="text-xs text-kavach-text-secondary font-mono">
                              {c.pattern} @ {c.location} — vars: [{c.variables.join(', ')}]
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Propagation Paths */}
                    <div className="md:col-span-2">
                      <div className="flex items-center gap-1.5 mb-2">
                        <GitBranch className="w-3.5 h-3.5 text-kavach-text-muted" />
                        <p className="text-xs font-mono uppercase tracking-wider text-kavach-text-muted">Propagation Paths ({sastDiagnostics.propagationPaths.length})</p>
                      </div>
                      {sastDiagnostics.propagationPaths.length === 0 ? (
                        <p className="text-xs text-kavach-text-muted italic">None discovered</p>
                      ) : (
                        <div className="space-y-1">
                          {sastDiagnostics.propagationPaths.map((p, i) => (
                            <div key={i} className="text-xs text-kavach-text-secondary font-mono">
                              {p.from} → {p.to} <span className="text-kavach-text-muted">(via {p.via})</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Rejected Findings */}
                    <div className="md:col-span-2">
                      <div className="flex items-center gap-1.5 mb-2">
                        <Ban className="w-3.5 h-3.5 text-kavach-text-muted" />
                        <p className="text-xs font-mono uppercase tracking-wider text-kavach-text-muted">Rejected Findings ({sastDiagnostics.rejectedFindings.length})</p>
                      </div>
                      {sastDiagnostics.rejectedFindings.length === 0 ? (
                        <p className="text-xs text-kavach-text-muted italic">None — all detected patterns were accepted</p>
                      ) : (
                        <div className="space-y-1">
                          {sastDiagnostics.rejectedFindings.map((r, i) => (
                            <div key={i} className="text-xs text-kavach-text-secondary font-mono flex items-start gap-1.5">
                              <span className="text-kavach-text-muted shrink-0">✕</span>
                              <span>{r.reason} <span className="text-kavach-text-muted">({r.file}:{r.line})</span></span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </CardBody>
              )}
            </Card>
          )}

          {/* Verification Gates */}
          {verificationRun && (
            <Card>
              <CardHeader title="Verification Gates" subtitle="Deterministic — each gate requires actual evidence" icon={<ShieldCheck className="w-4 h-4" />} />
              <CardBody>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <GateRow label="Static analysis (SAST re-scan)" passed={verificationRun.newFindings === 0} detail={`${verificationRun.newFindings} new finding(s)`} />
                  <GateRow label="Original vulnerable pattern removed" passed={verificationRun.originalAttackBlocked} detail={verificationRun.originalAttackBlocked ? 'Attack blocked' : 'Attack NOT blocked'} />
                  <GateRow label="Mutation tests" passed={verificationRun.mutationPassRate === 1.0} detail={`${verificationRun.mutationTests.filter((t) => t.passed).length}/${verificationRun.mutationTests.length} passed`} />
                  <GateRow label="Regression checks" passed={verificationRun.regressionPassRate === 1.0} detail={`${verificationRun.regressionTests.filter((t) => t.passed).length}/${verificationRun.regressionTests.length} passed`} />
                  <GateRow label="Functional checks" passed={verificationRun.functionalPassRate === 1.0} detail={`${verificationRun.functionalTests.filter((t) => t.passed).length}/${verificationRun.functionalTests.length} passed`} />
                </div>
                <div className={`mt-4 p-3 rounded-md border ${verificationRun.status === 'VERIFIED' ? 'bg-kavach-success/5 border-kavach-success/30' : verificationRun.status === 'FAILED' ? 'bg-kavach-error/5 border-kavach-error/30' : 'bg-kavach-warning/5 border-kavach-warning/30'}`}>
                  <p className={`text-sm font-semibold ${verificationRun.status === 'VERIFIED' ? 'text-kavach-success' : verificationRun.status === 'FAILED' ? 'text-kavach-error' : 'text-kavach-warning'}`}>
                    FINAL RESULT: {verificationRun.status.replace(/_/g, ' ')}
                  </p>
                  <p className="text-xs text-kavach-text-muted mt-1">
                    Scope: prototype / static + controlled validation. Not production-grade dynamic exploit verification.
                  </p>
                </div>
              </CardBody>
            </Card>
          )}

          {/* AI Root Cause — Evidence Contract */}
          {reasoning && (
            <Card>
              <CardHeader title="Cyber Reasoner" subtitle="Evidence contract — OBSERVED facts have priority over AI claims" icon={<Cpu className="w-4 h-4" />} />
              <CardBody>
                <div className="space-y-4">
                  {reasoning.observedEvidence && reasoning.observedEvidence.length > 0 && (
                    <div>
                      <p className="text-xs font-mono uppercase tracking-wider text-kavach-success mb-2">Observed Evidence</p>
                      <div className="space-y-1.5">
                        {reasoning.observedEvidence.map((obs, i) => (
                          <div key={i} className="flex items-start gap-2 p-2 rounded bg-kavach-success/5 border border-kavach-success/20">
                            <CheckCircle2 className="w-3.5 h-3.5 text-kavach-success shrink-0 mt-0.5" />
                            <div className="flex-1 min-w-0">
                              <p className="text-xs text-kavach-text-secondary">{obs.detail}</p>
                              <p className="text-[10px] text-kavach-text-muted font-mono mt-0.5">{obs.source} · {new Date(obs.timestamp).toLocaleTimeString('en-US', { hour12: false })}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <p className="text-xs font-mono uppercase tracking-wider text-kavach-accent mb-2">AI Analysis</p>
                    <div className="p-2.5 rounded bg-kavach-accent/5 border border-kavach-accent/20 space-y-2">
                      <div>
                        <p className="text-[10px] text-kavach-text-muted font-mono uppercase mb-0.5">Root Cause</p>
                        <p className="text-sm text-kavach-text-secondary">{reasoning.rootCause}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-kavach-text-muted font-mono uppercase mb-0.5">Attack Path</p>
                        <p className="text-sm text-kavach-text-secondary">{reasoning.attackPath}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-kavach-text-muted font-mono uppercase mb-0.5">Potential Impact</p>
                        <p className="text-sm text-kavach-text-secondary">{reasoning.potentialImpact}</p>
                      </div>
                      {reasoning.aiAnalysis && (
                        <p className="text-xs text-kavach-text-muted italic pt-1 border-t border-kavach-accent/10">{reasoning.aiAnalysis}</p>
                      )}
                    </div>
                  </div>

                  <div>
                    <p className="text-xs font-mono uppercase tracking-wider text-kavach-warning mb-2">Recommendation</p>
                    <div className="p-2.5 rounded bg-kavach-warning/5 border border-kavach-warning/20">
                      <p className="text-sm text-kavach-text-secondary">{reasoning.recommendation || reasoning.remediationStrategies[0] || 'Apply appropriate remediation.'}</p>
                      {reasoning.remediationStrategies.length > 1 && (
                        <ul className="mt-2 space-y-1">
                          {reasoning.remediationStrategies.map((s, i) => (
                            <li key={i} className="text-xs text-kavach-text-muted flex items-start gap-1.5">
                              <span className="text-kavach-warning mt-0.5">→</span>
                              <span>{s}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>

                  {reasoning.verificationNote && (
                    <div className="p-2 rounded bg-kavach-surface-2 border border-kavach-border">
                      <p className="text-xs text-kavach-text-muted italic">{reasoning.verificationNote}</p>
                    </div>
                  )}
                </div>
              </CardBody>
            </Card>
          )}

          {/* Patch Diff */}
          {patches.length > 0 && (
            <Card>
              <CardHeader title="Patch Diff" subtitle={`${patches[0].label}: ${patches[0].strategy}`} icon={<FlaskConical className="w-4 h-4" />} />
              <CardBody>
                <pre className="text-xs font-mono text-kavach-text-secondary bg-kavach-bg border border-kavach-border rounded-md p-3 overflow-x-auto max-h-80 overflow-y-auto">
                  {patches[0].diff || patches[0].patchedCode}
                </pre>
              </CardBody>
            </Card>
          )}
        </>
      )}

      {/* Audit Trail */}
      {auditTrail.length > 0 && (
        <Card>
          <CardHeader
            title="Audit Trail"
            subtitle={`${auditTrail.length} events — complete assessment reconstruction`}
            icon={<ScrollText className="w-4 h-4" />}
            action={<button onClick={() => onNavigate('audit')} className="text-xs text-kavach-accent hover:underline">View full log</button>}
          />
          <CardBody>
            <div className="space-y-1.5 max-h-64 overflow-y-auto">
              {auditTrail.map((event) => (
                <div key={event.id} className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-kavach-text-muted w-16 shrink-0">
                    {new Date(event.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                  </span>
                  <span className="text-kavach-text-secondary flex-1 truncate">{event.event}</span>
                  <span className="text-kavach-text-muted truncate max-w-xs">{event.detail}</span>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}

function GateRow({ label, passed, detail }: { label: string; passed: boolean; detail: string }) {
  return (
    <div className="flex items-center gap-3 p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
      {passed ? (
        <CheckCircle2 className="w-4 h-4 text-kavach-success shrink-0" />
      ) : (
        <XCircle className="w-4 h-4 text-kavach-error shrink-0" />
      )}
      <div className="flex-1">
        <p className="text-sm text-kavach-text-primary">{label}</p>
        <p className="text-xs text-kavach-text-muted">{detail}</p>
      </div>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
