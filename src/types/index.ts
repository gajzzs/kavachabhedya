// ============================================================
// KAVACH - Core Type Definitions
// Evidence-Driven Adaptive Cyber Reasoning & Verified Remediation
// ============================================================

// --- Evidence Authenticity ---
export type EvidenceAuthenticity = 'EXECUTABLE' | 'CONTROLLED_DEMONSTRATION' | 'PLANNED_INTEGRATION' | 'UNAVAILABLE';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type VulnerabilityClass =
  | 'SQL_INJECTION'
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'SSRF'
  | 'XSS'
  | 'INSECURE_AUTH'
  | 'UNSAFE_DESERIALIZATION'
  | 'HARDCODED_SECRET'
  | 'WEAK_CRYPTO'
  | 'BUFFER_OVERFLOW'
  | 'UNKNOWN';

// --- Project & Source Code ---
export interface SourceFile {
  id: string;
  filename: string;
  path: string;
  language: string;
  content: string;
  lineCount: number;
}

export interface DemoProject {
  id: string;
  name: string;
  description: string;
  language: string;
  framework: string;
  files: SourceFile[];
  vulnerable: boolean;
  vulnerabilityClass?: VulnerabilityClass;
  tags: string[];
}

export interface Project {
  id: string;
  name: string;
  description: string;
  source: 'demo' | 'upload';
  demoProjectId?: string;
  files: SourceFile[];
  createdAt: string;
}

// --- Assessment Metadata ---
export interface AssessmentMeta {
  assessmentId: string;
  projectName: string;
  sourceFilename: string;
  sourceHash: string;
  language: string;
  lineCount: number;
  fileSize: number;
  createdAt: string;
  status: 'RUNNING' | 'COMPLETED' | 'COMPLETED_WITH_ISSUES' | 'FAILED';
}

// --- Findings ---
export interface Finding {
  id: string;
  assessmentId?: string;
  vulnerabilityClass: VulnerabilityClass;
  severity: Severity;
  confidence: number;
  title: string;
  file: string;
  line: number;
  lineEnd?: number;
  column?: number;
  evidence: string;
  description: string;
  codeSnippet?: string;
  source?: string;
  sink?: string;
  inputSource?: string;
  destination?: string;
  destinationCapacity?: number;
  dataFlow?: string[];
  impact?: string;
  status?: 'CONFIRMED' | 'POTENTIAL' | 'INCONCLUSIVE' | 'INFO';
  cwe?: string;
  tool: string;
  authenticity: EvidenceAuthenticity;
}

// --- Evidence ---
export interface EvidenceSource {
  tool: string;
  toolType: 'SAST' | 'FUZZER' | 'DAST' | 'DEPENDENCY' | 'MANUAL' | 'REGRESSION';
  status: 'CONFIRMED' | 'SUSPICIOUS' | 'NOT_REPRODUCED' | 'UNAVAILABLE' | 'ERROR';
  authenticity: EvidenceAuthenticity;
  detail: string;
  confidence: number;
  timestamp: string;
}

export interface Evidence {
  id: string;
  findingId: string;
  sources: EvidenceSource[];
  fusedScore: number;
  fusedConfidence: number;
  contradictions: string[];
  missingEvidence: string[];
  recommendation: string;
  status: 'CONFIRMED' | 'UNCONFIRMED' | 'INSUFFICIENT';
  reasoning: string;
  timestamp: string;
}

// --- Experiments ---
export interface Experiment {
  id: string;
  name: string;
  description: string;
  reason: string;
  expectedInformationGain: string;
  estimatedCost: 'LOW' | 'MEDIUM' | 'HIGH';
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'SKIPPED';
  result?: string;
  nextAction?: string;
  timestamp: string;
  duration?: number;
}

export interface Hypothesis {
  id: string;
  statement: string;
  confidence: number;
  supportingEvidence: string[];
  contradictoryEvidence: string[];
  status: 'PROPOSED' | 'TESTING' | 'CONFIRMED' | 'REFUTED' | 'INSUFFICIENT';
}

// --- Attack Path ---
export interface AttackPathNode {
  id: string;
  label: string;
  type: 'INPUT' | 'API' | 'FUNCTION' | 'VARIABLE' | 'DATABASE' | 'DEPENDENCY' | 'VULNERABILITY' | 'CONTROL' | 'PATCH' | 'VERIFICATION';
  detail?: string;
  vulnerable?: boolean;
  blocked?: boolean;
}

export interface AttackPathEdge {
  from: string;
  to: string;
  label: string;
  type: 'FLOWS_TO' | 'CALLS' | 'REACHES' | 'TRIGGERS' | 'DETECTED_BY' | 'VERIFIED_BY' | 'FIXED_BY';
}

export interface AttackPath {
  id: string;
  findingId: string;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  entryPoint: string;
  impact: string;
  blockedAfterPatch: boolean;
  authenticity: EvidenceAuthenticity;
}

// --- Patch ---
export interface PatchCandidate {
  id: string;
  label: string;
  strategy: string;
  description: string;
  originalCode: string;
  patchedCode: string;
  diff: string;
  securityScore: number;
  regressionRisk: number;
  codeComplexity: number;
  performanceImpact: number;
  linesChanged: number;
  affectedComponents: string[];
  dependenciesAdded: string[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  authenticity: EvidenceAuthenticity;
}

export interface PatchEvaluation {
  patchId: string;
  securityScore: number;
  regressionRisk: number;
  complexity: number;
  performance: number;
  recommendation: string;
  canAutoApply: boolean;
  requiresHumanApproval: boolean;
}

// --- Verification ---
export interface MutationTest {
  id: string;
  name: string;
  input: string;
  originalBlocked: boolean;
  patchBlocked: boolean;
  passed: boolean;
  detail: string;
}

export interface VerificationRun {
  id: string;
  findingId: string;
  patchId: string;
  originalAttackBlocked: boolean;
  mutationTests: MutationTest[];
  mutationPassRate: number;
  regressionTests: { name: string; passed: boolean }[];
  regressionPassRate: number;
  functionalTests: { name: string; passed: boolean }[];
  functionalPassRate: number;
  newFindings: number;
  status: 'VERIFIED' | 'PARTIALLY_VERIFIED' | 'FAILED' | 'INCONCLUSIVE';
  report: string;
  timestamp: string;
  authenticity: EvidenceAuthenticity;
}

// --- Security Memory ---
export interface SecurityMemory {
  id: string;
  kavachId: string;
  vulnerabilityClass: VulnerabilityClass;
  status: 'VERIFIED' | 'REGRESSION_DETECTED' | 'MONITORING';
  originalEvidence: string;
  attackPattern: string;
  patchApplied: string;
  verificationResult: string;
  regressionTest: string;
  timestamp: string;
  projectVersion: string;
  sourceHash: string;
  revalidationState: 'CURRENT' | 'REVALIDATION_REQUIRED' | 'STALE';
}

// --- Guardian ---
export type ActionClass = 'READ' | 'ANALYZE' | 'TEST' | 'MODIFY' | 'EXECUTE' | 'NETWORK';

export interface AgentAction {
  id: string;
  timestamp: string;
  agent: string;
  tool: string;
  action: string;
  target: string;
  actionClass: ActionClass;
  status: 'ALLOWED' | 'BLOCKED' | 'PENDING_APPROVAL' | 'COMPLETED' | 'FAILED';
  result: string;
  sandboxed: boolean;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  event: string;
  category: 'SCAN' | 'EVIDENCE' | 'REASONING' | 'PATCH' | 'VERIFICATION' | 'GUARDIAN' | 'SYSTEM' | 'MEMORY';
  detail: string;
  severity: Severity;
  source: string;
}

// --- Digital Twin ---
export interface TwinSnapshot {
  id: string;
  label: string;
  timestamp: string;
  description: string;
  state: 'ORIGINAL' | 'VULNERABLE' | 'PATCHED_A' | 'PATCHED_B' | 'PATCHED_C' | 'VERIFIED' | 'RESET';
  nodes: TwinNode[];
  edges: TwinEdge[];
  attackPathActive: boolean;
  patchApplied?: string;
}

export interface TwinNode {
  id: string;
  label: string;
  type: 'APP' | 'API' | 'FUNCTION' | 'DATABASE' | 'DEPENDENCY' | 'TRUST_BOUNDARY' | 'CONTROL';
  status: 'SECURE' | 'VULNERABLE' | 'PATCHED' | 'ISOLATED' | 'UNKNOWN';
  detail?: string;
}

export interface TwinEdge {
  from: string;
  to: string;
  label: string;
  type: 'CALLS' | 'FLOWS_TO' | 'CONNECTS' | 'TRUST_BOUNDARY';
  vulnerable?: boolean;
  blocked?: boolean;
}

// --- Security Policy ---
export interface SecurityPolicy {
  defaultAllowed: ActionClass[];
  sandboxOnly: ActionClass[];
  blockedByDefault: ActionClass[];
  executionTimeoutMs: number;
  networkRestricted: boolean;
  destructiveBlocked: boolean;
  credentialAccessBlocked: boolean;
}

// --- LLM ---
export type LLMProvider = 'demo' | 'openai' | 'anthropic' | 'custom';

export interface LLMConfig {
  provider: LLMProvider;
  model?: string;
  apiKeyConfigured: boolean;
}

export interface ObservedEvidence {
  source: string;
  detail: string;
  timestamp: string;
}

export interface LLMReasoningResult {
  vulnerabilitySuspected: VulnerabilityClass;
  supportingEvidence: string[];
  contradictoryEvidence: string[];
  rootCause: string;
  attackPath: string;
  potentialImpact: string;
  confidence: number;
  confidenceReason: string;
  nextInvestigation: string;
  remediationStrategies: string[];
  verificationPlan: string[];
  insufficientEvidence: boolean;
  authenticity: EvidenceAuthenticity;
  // Evidence contract — clearly separates observed facts from AI claims
  observedEvidence: ObservedEvidence[];
  aiAnalysis: string;
  recommendation: string;
  verificationNote: string;
}

// --- Investigation ---
export type InvestigationStep =
  | 'INTAKE'
  | 'SCAN'
  | 'EVIDENCE'
  | 'FUZZ'
  | 'REASON'
  | 'EXPERIMENT'
  | 'TWIN'
  | 'ATTACK_PATH'
  | 'PATCH'
  | 'VERIFY'
  | 'REMEMBER';

export interface InvestigationStepStatus {
  step: InvestigationStep;
  label: string;
  status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' | 'SKIPPED';
  duration?: number;
  detail?: string;
  evidenceAuthenticity?: EvidenceAuthenticity;
}

export interface Investigation {
  id: string;
  projectId: string;
  projectName: string;
  vulnerabilityClass: VulnerabilityClass;
  status: 'IDLE' | 'INVESTIGATING' | 'ACTION_REQUIRED' | 'VERIFIED' | 'FAILED' | 'SAFE';
  steps: InvestigationStepStatus[];
  findings: Finding[];
  evidence: Evidence[];
  experiments: Experiment[];
  hypotheses: Hypothesis[];
  attackPath?: AttackPath;
  patches: PatchCandidate[];
  verificationRun?: VerificationRun;
  securityMemory?: SecurityMemory;
  startedAt: string;
  completedAt?: string;
  currentStep?: InvestigationStep;
}

// --- System Status ---
export interface SystemStatus {
  state: 'SAFE' | 'INVESTIGATING' | 'ACTION_REQUIRED';
  guardianActive: boolean;
  sandboxActive: boolean;
  llmProvider: LLMConfig;
  toolsAvailable: { name: string; available: boolean; authenticity: EvidenceAuthenticity }[];
}

// --- Fuzzing ---
export type FuzzTargetType = 'SQL' | 'API' | 'SOURCE_CODE' | 'JSON' | 'HTTP';
export type FuzzStrategy =
  | 'LLM_SEMANTIC'
  | 'BOUNDARY'
  | 'MUTATION'
  | 'SQL_INJECTION'
  | 'INPUT_VALIDATION'
  | 'ENCODING';

export interface FuzzTestCase {
  id: string;
  payload: string;
  category: string;
  reason: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  injectionDetected: boolean;
  behaviorChange: string;
  isInteresting: boolean;
}

export interface FuzzMetrics {
  iterations: number;
  generatedInputs: number;
  uniqueTestCases: number;
  interestingInputs: number;
  potentialFindings: number;
  coverage: number;
}

export interface FuzzResult {
  id: string;
 targetType: FuzzTargetType;
  strategy: FuzzStrategy;
  inputQuery: string;
  testCases: FuzzTestCase[];
  metrics: FuzzMetrics;
  vulnerabilityDetected: boolean;
  findingSummary: string;
  timestamp: string;
  authenticity: EvidenceAuthenticity;
}

// --- PoC ---
export interface ProofOfConcept {
  id: string;
  findingId: string;
  vulnerability: VulnerabilityClass;
  attackInput: string;
  affectedLocation: string;
  executionPath: string[];
  expectedBehavior: string;
  observedBehavior: string;
  evidence: string;
  timestamp: string;
  authenticity: EvidenceAuthenticity;
}

// --- SARIF ---
export interface SARIFFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  file: string;
  line: number;
  severity: Severity;
  description: string;
  reachability: 'REACHABLE' | 'NOT_REACHABLE' | 'UNCERTAIN';
  evidence: string;
  validationDecision: 'CORRECT_FINDING' | 'FALSE_POSITIVE' | 'UNCERTAIN';
  validationReason: string;
  authenticity: EvidenceAuthenticity;
}

export interface SARIFReport {
  id: string;
  source: string;
  findings: SARIFFinding[];
  totalFindings: number;
  correctFindings: number;
  falsePositives: number;
  uncertain: number;
  timestamp: string;
  authenticity: EvidenceAuthenticity;
}

// --- Agent Architecture ---
export type AgentRole =
  | 'RECON'
  | 'CODE_ANALYST'
  | 'FUZZING'
  | 'POC'
  | 'CYBER_REASONING'
  | 'PATCH'
  | 'VERIFICATION'
  | 'MEMORY';

export interface AgentInfo {
  id: string;
  role: AgentRole;
  name: string;
  status: 'IDLE' | 'ACTIVE' | 'BLOCKED' | 'COMPLETED';
  permissions: string[];
  currentTask: string;
  actionsLogged: number;
}

// --- Reachability ---
export interface ReachabilityNode {
  id: string;
  label: string;
  type: 'ENTRY_POINT' | 'CONTROLLER' | 'FUNCTION' | 'VALIDATION' | 'SINK' | 'DATABASE';
  file?: string;
  line?: number;
  reachable: boolean;
  detail: string;
}

export interface ReachabilityResult {
  id: string;
  findingId: string;
  status: 'REACHABLE' | 'NOT_REACHABLE' | 'UNCERTAIN';
  nodes: ReachabilityNode[];
  pathDescription: string;
  authenticity: EvidenceAuthenticity;
}
