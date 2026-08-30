import { Shield, Search, GitBranch, FlaskConical, CheckCircle, Database, Lock, ScrollText, ArrowRight, Activity, Cpu, Box, Target } from 'lucide-react';
import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { StatusBadge, AuthenticityBadge } from '@/components/ui/Badge';
import { ProgressBar } from '@/components/ui/ProgressBar';
import { CppDynamicResultsView } from '@/components/common/CppDynamicResultsView';
import type { PageId } from '@/components/layout/Sidebar';

export function OverviewPage({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const { findings, evidence, patches, verificationRun, securityMemory, auditEvents, twinSnapshots, isRunning, progressMessage, systemStatus, reasoning, assessment, fuzzingResult, attackPath, cppDynamicResult } = useKavach();

  const hasAssessment = !!assessment;
  const hasData = findings.length > 0;
  const primaryEvidence = evidence[0];
  const primaryFinding = findings[0];
  const verified = verificationRun?.status === 'VERIFIED';
  const hasRealAssessment = hasAssessment;

  const systemState = !hasRealAssessment ? 'SAFE' : !hasData ? 'SAFE' : verified ? 'VERIFIED' : isRunning ? 'INVESTIGATING' : 'ACTION_REQUIRED';

  const steps = [
    { label: 'Find', icon: Search, done: findings.length > 0 },
    { label: 'Evidence', icon: Activity, done: evidence.length > 0 },
    { label: 'Reason', icon: Cpu, done: !!reasoning },
    { label: 'Simulate', icon: Box, done: twinSnapshots.length > 1 },
    { label: 'Patch', icon: FlaskConical, done: patches.length > 0 },
    { label: 'Attack Patch', icon: GitBranch, done: !!verificationRun },
    { label: 'Verify', icon: CheckCircle, done: verified },
    { label: 'Remember', icon: Database, done: securityMemory.length > 0 },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Hero */}
      <Card className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-kavach-accent/5 to-transparent" />
        <CardBody className="relative">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <Shield className="w-8 h-8 text-kavach-accent" />
                <h1 className="text-2xl font-bold text-kavach-text-primary">ABHEDYA KAVACH</h1>
              </div>
              <p className="text-sm text-kavach-text-secondary max-w-2xl">
                Evidence-driven cyber reasoning and verified remediation. The AI does not get to declare that a vulnerability is fixed — independent verification must prove it.
              </p>
            </div>
            <div className="text-right">
              <StatusBadge status={systemState} />
              <p className="text-xs text-kavach-text-muted mt-2 font-mono">
                {systemStatus.llmProvider.provider === 'demo' ? 'DEMO REASONER' : 'CONNECTED LLM'}
              </p>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* Pipeline Flow */}
      {!hasRealAssessment ? (
        <Card className="border-kavach-warning/20">
          <CardBody className="text-center py-8">
            <Shield className="w-10 h-10 text-kavach-warning mx-auto mb-3" />
            <p className="text-sm font-semibold text-kavach-text-primary">NO REAL ASSESSMENTS YET</p>
            <p className="text-xs text-kavach-text-muted mt-2 max-w-md mx-auto">
              No real security assessments have been executed. Run a Real Assessment to detect vulnerabilities,
              generate evidence, and verify remediations.
            </p>
          </CardBody>
        </Card>
      ) : (
      <>
      {/* Assessment Summary */}
      {assessment && (
        <Card>
          <CardHeader title="Real Assessment Summary" subtitle={assessment.assessmentId} icon={<Target className="w-4 h-4" />} />
          <CardBody>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
              <SummaryItem label="Project" value={assessment.projectName} />
              <SummaryItem label="Source" value={assessment.sourceFilename} />
              <SummaryItem label="Language" value={assessment.language} />
              <SummaryItem label="Lines" value={String(assessment.lineCount)} />
              <SummaryItem label="SHA-256" value={assessment.sourceHash.substring(0, 16) + '...'} mono />
              <SummaryItem label="Status" value={assessment.status.replace(/_/g, ' ')} />
            </div>
          </CardBody>
        </Card>
      )}

      <Card>
        <CardHeader title="Investigation Pipeline" subtitle="FIND → EVIDENCE → REASON → SIMULATE → PATCH → ATTACK PATCH → VERIFY → REMEMBER" icon={<Activity className="w-4 h-4" />} />
        <CardBody>
          <div className="flex items-center gap-1 flex-wrap">
            {steps.map((step, i) => {
              const Icon = step.icon;
              return (
                <div key={step.label} className="flex items-center gap-1">
                  <div className={`flex flex-col items-center gap-1 px-3 py-2 rounded-md border transition-all ${
                    step.done
                      ? 'border-kavach-success/30 bg-kavach-success/5 text-kavach-success'
                      : 'border-kavach-border bg-kavach-surface-2 text-kavach-text-muted'
                  }`}>
                    <Icon className="w-4 h-4" />
                    <span className="text-[10px] font-mono uppercase">{step.label}</span>
                  </div>
                  {i < steps.length - 1 && <ArrowRight className="w-3 h-3 text-kavach-text-muted" />}
                </div>
              );
            })}
          </div>
        </CardBody>
      </Card>

      {/* C++ Dynamic Compiler & Fuzzing Results */}
      {cppDynamicResult && (
        <CppDynamicResultsView
          result={cppDynamicResult}
          title="Real Assessment — C++ Dynamic Compiler & Sanitizer Results"
        />
      )}
      </>
      )}

      {/* Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Vulnerability */}
        <Card hover>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <Search className="w-4 h-4 text-kavach-text-muted" />
              <AuthenticityBadge authenticity="EXECUTABLE" />
            </div>
            <p className="kavach-section-title mb-1">Vulnerability</p>
            <p className="text-sm font-semibold text-kavach-text-primary">
              {primaryFinding ? primaryFinding.vulnerabilityClass.replace(/_/g, ' ') : 'None detected'}
            </p>
            <p className="text-xs text-kavach-text-muted mt-1">
              {primaryFinding ? `${primaryFinding.file}:${primaryFinding.line}` : 'No findings'}
            </p>
          </CardBody>
        </Card>

        {/* Evidence */}
        <Card hover>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <Activity className="w-4 h-4 text-kavach-text-muted" />
              {primaryEvidence && <StatusBadge status={primaryEvidence.status} />}
            </div>
            <p className="kavach-section-title mb-1">Evidence</p>
            <p className="text-2xl font-bold text-kavach-text-primary">
              {primaryEvidence ? `${primaryEvidence.fusedScore}%` : '—'}
            </p>
            {primaryEvidence && <ProgressBar value={primaryEvidence.fusedScore} color="accent" label="Fused confidence" />}
          </CardBody>
        </Card>

        {/* Patches */}
        <Card hover>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <FlaskConical className="w-4 h-4 text-kavach-text-muted" />
              {patches.length > 0 && <AuthenticityBadge authenticity="CONTROLLED_DEMONSTRATION" />}
            </div>
            <p className="kavach-section-title mb-1">Patch Candidates</p>
            <p className="text-2xl font-bold text-kavach-text-primary">{patches.length}</p>
            <p className="text-xs text-kavach-text-muted mt-1">
              {patches.length > 0 ? patches.map(p => p.label).join(', ') : 'No patches generated'}
            </p>
          </CardBody>
        </Card>

        {/* Verification */}
        <Card hover>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <CheckCircle className="w-4 h-4 text-kavach-text-muted" />
              {verificationRun && <StatusBadge status={verificationRun.status} />}
            </div>
            <p className="kavach-section-title mb-1">Verification</p>
            <p className="text-sm font-semibold text-kavach-text-primary">
              {verificationRun ? verificationRun.status.replace(/_/g, ' ') : 'Not started'}
            </p>
            {verificationRun && (
              <p className="text-xs text-kavach-text-muted mt-1">
                Mutations: {verificationRun.mutationTests.filter(t => t.passed).length}/{verificationRun.mutationTests.length}
              </p>
            )}
          </CardBody>
        </Card>
      </div>

      {/* Tools Available */}
      <Card>
        <CardHeader title="System Status" subtitle="Tool availability and authenticity" icon={<Cpu className="w-4 h-4" />} />
        <CardBody>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {systemStatus.toolsAvailable.map((tool) => (
              <div key={tool.name} className="flex items-center justify-between p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <span className="text-xs text-kavach-text-secondary">{tool.name}</span>
                <AuthenticityBadge authenticity={tool.authenticity} />
              </div>
            ))}
          </div>
        </CardBody>
      </Card>

      {/* Quick Nav */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { id: 'investigations' as PageId, label: 'Investigations', icon: Search },
          { id: 'twin' as PageId, label: 'Digital Twin', icon: Box },
          { id: 'patch-lab' as PageId, label: 'Patch Lab', icon: FlaskConical },
          { id: 'verification' as PageId, label: 'Verification', icon: CheckCircle },
          { id: 'guardian' as PageId, label: 'Guardian', icon: Lock },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className="kavach-card kavach-card-hover p-4 flex flex-col items-center gap-2 group"
            >
              <Icon className="w-5 h-5 text-kavach-text-muted group-hover:text-kavach-accent transition-colors" />
              <span className="text-xs text-kavach-text-secondary group-hover:text-kavach-text-primary">{item.label}</span>
            </button>
          );
        })}
      </div>

      {/* Recent Activity */}
      {auditEvents.length > 0 && (
        <Card>
          <CardHeader title="Recent Activity" subtitle={`${auditEvents.length} events`} icon={<ScrollText className="w-4 h-4" />} action={
            <button onClick={() => onNavigate('audit')} className="text-xs text-kavach-accent hover:underline">View all</button>
          } />
          <CardBody>
            <div className="space-y-2">
              {auditEvents.slice(-5).reverse().map((event) => (
                <div key={event.id} className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-kavach-text-muted w-16">{new Date(event.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
                  <span className="text-kavach-text-secondary flex-1">{event.event}</span>
                  <span className="text-kavach-text-muted truncate max-w-xs">{event.detail}</span>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      )}

      {isRunning && progressMessage && (
        <div className="fixed bottom-4 right-4 kavach-card px-4 py-3 flex items-center gap-3 animate-fade-in">
          <div className="w-2 h-2 bg-kavach-accent rounded-full animate-pulse" />
          <span className="text-sm text-kavach-accent font-mono">{progressMessage}</span>
        </div>
      )}
    </div>
  );
}

function SummaryItem({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
      <p className="text-[10px] font-mono uppercase text-kavach-text-muted mb-1">{label}</p>
      <p className={`text-sm text-kavach-text-primary truncate ${mono ? 'font-mono' : ''}`} title={value}>{value}</p>
    </div>
  );
}
