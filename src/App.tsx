import { useState, useCallback } from 'react';
import { KavachProvider, useKavach } from '@/store/KavachContext';
import { Sidebar, type PageId } from '@/components/layout/Sidebar';
import { TopBar } from '@/components/layout/TopBar';
import { SplashScreen } from '@/components/common/SplashScreen';
import { ModeSelectionPage } from '@/pages/ModeSelectionPage';
import { RealAssessmentPage } from '@/pages/RealAssessmentPage';
import { OverviewPage } from '@/pages/OverviewPage';
import { InvestigationsPage } from '@/pages/InvestigationsPage';
import { FuzzingLabPage } from '@/pages/FuzzingLabPage';
import { DigitalTwinPage } from '@/pages/DigitalTwinPage';
import { EvidenceGraphPage } from '@/pages/EvidenceGraphPage';
import { AttackPathsPage } from '@/pages/AttackPathsPage';
import { PatchLabPage } from '@/pages/PatchLabPage';
import { VerificationPage } from '@/pages/VerificationPage';
import { SarifPage } from '@/pages/SarifPage';
import { SecurityMemoryPage } from '@/pages/SecurityMemoryPage';
import { AgentGuardianPage } from '@/pages/AgentGuardianPage';
import { AuditLogPage } from '@/pages/AuditLogPage';
import { CppDynamicLabPage } from '@/pages/CppDynamicLabPage';
import { runFullDemo } from '@/services/demoEngine';
import { demoProjects } from '@/services/demoProjects';
import type { AuditEvent, AgentAction, Finding, Evidence, Experiment, Hypothesis, PatchCandidate, VerificationRun, SecurityMemory, TwinSnapshot, AttackPath, LLMReasoningResult, InvestigationStep, InvestigationStepStatus } from '@/types';

const PAGE_TITLES: Record<PageId, string> = {
  'real-assessment': 'Real Assessment',
  'overview': 'Overview',
  'investigations': 'Investigations',
  'fuzzing': 'Fuzzing Lab',
  'cpp-dynamic': 'C++ Dynamic Lab',
  'twin': 'Digital Twin',
  'evidence-graph': 'Evidence Graph',
  'attack-paths': 'Attack Paths',
  'patch-lab': 'Patch Lab',
  'verification': 'Verification',
  'sarif': 'SARIF Analysis',
  'memory': 'Security Memory',
  'guardian': 'Agent Guardian',
  'audit': 'Audit Log',
};

function KavachApp() {
  const [currentPage, setCurrentPage] = useState<PageId>('overview');
  const [showSplash, setShowSplash] = useState(true);
  const { dispatch, isRunning, mode } = useKavach();

  const handleRunDemo = useCallback(async () => {
    if (isRunning) return;

    const demoProject = demoProjects[0];
    dispatch({ type: 'SET_RUNNING', isRunning: true, progressMessage: 'Initializing Kavach demo...' });
    dispatch({ type: 'RESET' });

    try {
      await runFullDemo(demoProject.id, {
        onAudit: (event: AuditEvent) => dispatch({ type: 'ADD_AUDIT', event }),
        onAction: (action: AgentAction) => dispatch({ type: 'ADD_ACTION', action }),
        onStepUpdate: (step: InvestigationStep, status: InvestigationStepStatus['status'], detail?: string) => {
          dispatch({ type: 'UPDATE_INVESTIGATION', updates: {} });
        },
        onFinding: (finding: Finding) => dispatch({ type: 'ADD_FINDING', finding }),
        onEvidence: (evidence: Evidence) => dispatch({ type: 'ADD_EVIDENCE', evidence }),
        onExperiment: (experiment: Experiment) => dispatch({ type: 'ADD_EXPERIMENT', experiment }),
        onHypothesis: (hypothesis: Hypothesis) => dispatch({ type: 'ADD_HYPOTHESIS', hypothesis }),
        onReasoning: (reasoning: LLMReasoningResult) => dispatch({ type: 'SET_REASONING', reasoning }),
        onPatch: (patch: PatchCandidate) => dispatch({ type: 'ADD_PATCH', patch }),
        onVerification: (run: VerificationRun) => dispatch({ type: 'SET_VERIFICATION', run }),
        onMemory: (memory: SecurityMemory) => dispatch({ type: 'ADD_MEMORY', memory }),
        onTwinSnapshot: (snapshot: TwinSnapshot) => dispatch({ type: 'ADD_TWIN_SNAPSHOT', snapshot }),
        onAttackPath: (path: AttackPath) => dispatch({ type: 'SET_ATTACK_PATH', path }),
        onInvestigationUpdate: (updates) => dispatch({ type: 'UPDATE_INVESTIGATION', updates }),
        onProgress: (message: string) => dispatch({ type: 'SET_RUNNING', isRunning: true, progressMessage: message }),
      });
    } catch (err) {
      dispatch({ type: 'ADD_AUDIT', event: {
        id: 'err-' + Date.now(),
        timestamp: new Date().toISOString(),
        event: 'Demo error',
        category: 'SYSTEM',
        detail: String(err),
        severity: 'CRITICAL',
        source: 'demo-engine',
      }});
    } finally {
      dispatch({ type: 'SET_RUNNING', isRunning: false, progressMessage: '' });
    }
  }, [dispatch, isRunning]);

  if (showSplash) {
    return <SplashScreen onComplete={() => setShowSplash(false)} />;
  }

  if (!mode) {
    return (
      <div className="h-screen bg-kavach-bg overflow-hidden">
        <ModeSelectionPage />
      </div>
    );
  }

  const renderPage = () => {
    switch (currentPage) {
      case 'overview': return <OverviewPage onNavigate={setCurrentPage} />;
      case 'real-assessment': return <RealAssessmentPage onNavigate={setCurrentPage} />;
      case 'investigations': return <InvestigationsPage />;
      case 'fuzzing': return <FuzzingLabPage />;
      case 'cpp-dynamic': return <CppDynamicLabPage />;
      case 'twin': return <DigitalTwinPage />;
      case 'evidence-graph': return <EvidenceGraphPage />;
      case 'attack-paths': return <AttackPathsPage />;
      case 'patch-lab': return <PatchLabPage />;
      case 'verification': return <VerificationPage />;
      case 'sarif': return <SarifPage />;
      case 'memory': return <SecurityMemoryPage />;
      case 'guardian': return <AgentGuardianPage />;
      case 'audit': return <AuditLogPage />;
      default: return <OverviewPage onNavigate={setCurrentPage} />;
    }
  };

  return (
    <div className="flex h-screen bg-kavach-bg overflow-hidden">
      <Sidebar currentPage={currentPage} onNavigate={setCurrentPage} />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar onRunDemo={handleRunDemo} title={PAGE_TITLES[currentPage]} onReplaySplash={() => setShowSplash(true)} />
        <main className="flex-1 overflow-y-auto p-6">
          {renderPage()}
        </main>
      </div>
    </div>
  );
}

function App() {
  return (
    <KavachProvider>
      <KavachApp />
    </KavachProvider>
  );
}

export default App;
