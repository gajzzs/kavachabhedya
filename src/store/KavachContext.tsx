import { createContext, useContext, useReducer, useCallback, type ReactNode } from 'react';
import type {
  Investigation,
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
  AttackPath,
  LLMReasoningResult,
  SystemStatus,
  Project,
  AssessmentMeta,
  FuzzResult,
} from '@/types';
import type { FuzzResult as FuzzerFuzzResult } from '@/services/security-tools/fuzzer';
import { getSystemStatus, assessAgentSecurity } from '@/services/demoEngine';
import { DEFAULT_POLICY } from '@/services/guardian';

import type { CppDynamicResult } from '@/services/cppDynamicService';

// ============================================================
// KAVACH Global State Management
// ============================================================

interface KavachState {
  systemStatus: SystemStatus;
  mode: 'demo' | 'real' | null;
  investigation: Investigation | null;
  assessment: AssessmentMeta | null;
  findings: Finding[];
  evidence: Evidence[];
  fuzzingResult: FuzzerFuzzResult | null;
  fuzzingResults: FuzzResult[];
  cppDynamicResult: CppDynamicResult | null;
  experiments: Experiment[];
  hypotheses: Hypothesis[];
  patches: PatchCandidate[];
  verificationRun: VerificationRun | null;
  securityMemory: SecurityMemory[];
  auditEvents: AuditEvent[];
  agentActions: AgentAction[];
  twinSnapshots: TwinSnapshot[];
  attackPath: AttackPath | null;
  reasoning: LLMReasoningResult | null;
  currentProject: Project | null;
  isRunning: boolean;
  progressMessage: string;
  selectedPatchId: string | null;
  selectedTwinSnapshotId: string | null;
}

type KavachAction =
  | { type: 'SET_MODE'; mode: 'demo' | 'real' }
  | { type: 'SET_RUNNING'; isRunning: boolean; progressMessage?: string }
  | { type: 'SET_PROJECT'; project: Project }
  | { type: 'SET_ASSESSMENT_META'; assessment: AssessmentMeta | null }
  | { type: 'UPDATE_ASSESSMENT_META'; updates: Partial<AssessmentMeta> }
  | { type: 'ADD_FINDING'; finding: Finding }
  | { type: 'ADD_EVIDENCE'; evidence: Evidence }
  | { type: 'SET_FUZZING_RESULT'; result: FuzzerFuzzResult | null }
  | { type: 'ADD_FUZZING_RESULT'; result: FuzzResult }
  | { type: 'SET_CPP_DYNAMIC_RESULT'; result: CppDynamicResult | null }
  | { type: 'ADD_EXPERIMENT'; experiment: Experiment }
  | { type: 'ADD_HYPOTHESIS'; hypothesis: Hypothesis }
  | { type: 'ADD_PATCH'; patch: PatchCandidate }
  | { type: 'SET_VERIFICATION'; run: VerificationRun }
  | { type: 'ADD_MEMORY'; memory: SecurityMemory }
  | { type: 'ADD_AUDIT'; event: AuditEvent }
  | { type: 'ADD_ACTION'; action: AgentAction }
  | { type: 'ADD_TWIN_SNAPSHOT'; snapshot: TwinSnapshot }
  | { type: 'SET_ATTACK_PATH'; path: AttackPath }
  | { type: 'SET_REASONING'; reasoning: LLMReasoningResult }
  | { type: 'UPDATE_INVESTIGATION'; updates: Partial<Investigation> }
  | { type: 'SET_INVESTIGATION'; investigation: Investigation }
  | { type: 'SET_SELECTED_PATCH'; patchId: string | null }
  | { type: 'SET_SELECTED_TWIN'; snapshotId: string | null }
  | { type: 'SET_ASSESSMENT_RESULTS'; findings: Finding[]; evidence: Evidence[]; patches: PatchCandidate[]; verificationRun: VerificationRun | null; attackPath: AttackPath | null; reasoning: LLMReasoningResult | null }
  | { type: 'RESET' };

const initialState: KavachState = {
  systemStatus: getSystemStatus(),
  mode: null,
  investigation: null,
  assessment: null,
  findings: [],
  evidence: [],
  fuzzingResult: null,
  fuzzingResults: [],
  cppDynamicResult: null,
  experiments: [],
  hypotheses: [],
  patches: [],
  verificationRun: null,
  securityMemory: [],
  auditEvents: [],
  agentActions: [],
  twinSnapshots: [],
  attackPath: null,
  reasoning: null,
  currentProject: null,
  isRunning: false,
  progressMessage: '',
  selectedPatchId: null,
  selectedTwinSnapshotId: null,
};

function reducer(state: KavachState, action: KavachAction): KavachState {
  switch (action.type) {
    case 'SET_MODE':
      return { ...state, mode: action.mode };
    case 'SET_RUNNING':
      return { ...state, isRunning: action.isRunning, progressMessage: action.progressMessage || '' };
    case 'SET_PROJECT':
      return { ...state, currentProject: action.project };
    case 'SET_ASSESSMENT_META':
      return { ...state, assessment: action.assessment };
    case 'UPDATE_ASSESSMENT_META':
      return state.assessment
        ? { ...state, assessment: { ...state.assessment, ...action.updates } }
        : state;
    case 'ADD_FINDING':
      return { ...state, findings: [...state.findings, action.finding] };
    case 'ADD_EVIDENCE':
      return { ...state, evidence: [...state.evidence, action.evidence] };
    case 'SET_FUZZING_RESULT':
      return { ...state, fuzzingResult: action.result };
    case 'ADD_FUZZING_RESULT':
      return { ...state, fuzzingResults: [...state.fuzzingResults, action.result] };
    case 'SET_CPP_DYNAMIC_RESULT':
      return { ...state, cppDynamicResult: action.result };
    case 'ADD_EXPERIMENT':
      return { ...state, experiments: [...state.experiments, action.experiment] };
    case 'ADD_HYPOTHESIS':
      return { ...state, hypotheses: [...state.hypotheses, action.hypothesis] };
    case 'ADD_PATCH':
      return {
        ...state,
        patches: [...state.patches, action.patch],
        selectedPatchId: state.selectedPatchId || action.patch.id,
      };
    case 'SET_VERIFICATION':
      return { ...state, verificationRun: action.run };
    case 'ADD_MEMORY':
      return { ...state, securityMemory: [...state.securityMemory, action.memory] };
    case 'ADD_AUDIT':
      return { ...state, auditEvents: [...state.auditEvents, action.event] };
    case 'ADD_ACTION':
      return { ...state, agentActions: [...state.agentActions, action.action] };
    case 'ADD_TWIN_SNAPSHOT':
      return {
        ...state,
        twinSnapshots: [...state.twinSnapshots, action.snapshot],
        selectedTwinSnapshotId: state.selectedTwinSnapshotId || action.snapshot.id,
      };
    case 'SET_ATTACK_PATH':
      return { ...state, attackPath: action.path };
    case 'SET_REASONING':
      return { ...state, reasoning: action.reasoning };
    case 'UPDATE_INVESTIGATION':
      return state.investigation
        ? { ...state, investigation: { ...state.investigation, ...action.updates } }
        : state;
    case 'SET_INVESTIGATION':
      return { ...state, investigation: action.investigation };
    case 'SET_SELECTED_PATCH':
      return { ...state, selectedPatchId: action.patchId };
    case 'SET_SELECTED_TWIN':
      return { ...state, selectedTwinSnapshotId: action.snapshotId };
    case 'SET_ASSESSMENT_RESULTS':
      return {
        ...state,
        findings: action.findings,
        evidence: action.evidence,
        patches: action.patches,
        verificationRun: action.verificationRun,
        attackPath: action.attackPath,
        reasoning: action.reasoning,
        selectedPatchId: action.patches.length > 0 ? action.patches[0].id : null,
      };
    case 'RESET':
      return {
        ...initialState,
        systemStatus: getSystemStatus(),
        mode: state.mode,
      };
    default:
      return state;
  }
}

interface KavachContextValue extends KavachState {
  dispatch: React.Dispatch<KavachAction>;
  agentSecurity: ReturnType<typeof assessAgentSecurity>;
  policy: typeof DEFAULT_POLICY;
}

const KavachContext = createContext<KavachContextValue | null>(null);

export function KavachProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const agentSecurity = assessAgentSecurity();

  const value: KavachContextValue = {
    ...state,
    dispatch,
    agentSecurity,
    policy: DEFAULT_POLICY,
  };

  return <KavachContext.Provider value={value}>{children}</KavachContext.Provider>;
}

export function useKavach() {
  const ctx = useContext(KavachContext);
  if (!ctx) throw new Error('useKavach must be used within KavachProvider');
  return ctx;
}

// Convenience dispatch helpers
export function useDispatch() {
  const { dispatch } = useKavach();
  return dispatch;
}
