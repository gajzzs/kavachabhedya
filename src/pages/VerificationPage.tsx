import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { StatusBadge, AuthenticityBadge } from '@/components/ui/Badge';
import { ProgressBar } from '@/components/ui/ProgressBar';
import { CheckCircle2, XCircle, AlertCircle, Loader2, ShieldCheck, Bug, FlaskConical, RotateCcw, FileCheck } from 'lucide-react';
import type { VerificationRun } from '@/types';

export function VerificationPage() {
  const { verificationRun, patches, findings, isRunning } = useKavach();

  if (!verificationRun && !isRunning) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardBody className="text-center">
            <ShieldCheck className="w-12 h-12 text-kavach-text-muted mx-auto mb-3" />
            <p className="text-sm text-kavach-text-secondary">No verification run yet.</p>
            <p className="text-xs text-kavach-text-muted mt-1">Run a Real Assessment or the Kavach demo to execute the verification pipeline.</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  if (isRunning && !verificationRun) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardBody className="text-center">
            <Loader2 className="w-12 h-12 text-kavach-accent mx-auto mb-3 animate-spin" />
            <p className="text-sm text-kavach-accent">Verification in progress...</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  const run = verificationRun!;
  const patch = patches.find(p => p.id === run.patchId);
  const finding = findings.find(f => f.id === run.findingId);

  const stages = [
    { label: 'Vulnerability', icon: Bug, state: 'info' as const },
    { label: 'Orig. Test', icon: ShieldCheck, state: run.originalAttackBlocked ? 'passed' as const : 'failed' as const },
    { label: 'Patch Applied', icon: FlaskConical, state: 'info' as const },
    { label: 'SAST Re-scan', icon: ShieldCheck, state: run.newFindings === 0 ? 'passed' as const : 'failed' as const },
    { label: 'Mutations', icon: RotateCcw, state: run.mutationPassRate === 1 ? 'passed' as const : run.mutationPassRate >= 0.8 ? 'warning' as const : 'failed' as const },
    { label: 'Regression', icon: FileCheck, state: run.regressionPassRate === 1 ? 'passed' as const : run.regressionPassRate >= 0.9 ? 'warning' as const : 'failed' as const },
    { label: 'Functional', icon: FileCheck, state: run.functionalPassRate === 1 ? 'passed' as const : run.functionalPassRate >= 0.9 ? 'warning' as const : 'failed' as const },
    { label: 'Final', icon: ShieldCheck, state: run.status === 'VERIFIED' ? 'passed' as const : run.status === 'PARTIALLY_VERIFIED' ? 'warning' as const : 'failed' as const },
  ];

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Verification Pipeline</h2>
          <p className="text-sm text-kavach-text-secondary">Independent verification. The AI does not declare a fix is verified — this pipeline proves it.</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={run.status} />
          <AuthenticityBadge authenticity={run.authenticity} />
        </div>
      </div>

      {/* Pipeline Flow */}
      <Card>
        <CardBody>
          <div className="flex items-center gap-1 flex-wrap">
            {stages.map((stage, i) => {
              const Icon = stage.icon;
              return (
                <div key={stage.label} className="flex items-center gap-1">
                  <div className={`flex flex-col items-center gap-1 px-3 py-2 rounded-md border transition-all ${
                    stage.state === 'passed' ? 'border-kavach-success/30 bg-kavach-success/5 text-kavach-success'
                      : stage.state === 'failed' ? 'border-kavach-danger/30 bg-kavach-danger/5 text-kavach-danger'
                      : stage.state === 'warning' ? 'border-amber-500/30 bg-amber-500/5 text-amber-400'
                      : 'border-kavach-border bg-kavach-surface-2 text-kavach-text-muted'
                  }`}>
                    <Icon className="w-4 h-4" />
                    <span className="text-[10px] font-mono uppercase text-center">{stage.label}</span>
                  </div>
                  {i < stages.length - 1 && <span className="text-kavach-text-muted">→</span>}
                </div>
              );
            })}
          </div>
        </CardBody>
      </Card>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card hover>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <Bug className="w-4 h-4 text-kavach-text-muted" />
              <span className="text-xs text-kavach-text-muted font-mono">SAST RE-SCAN</span>
            </div>
            <p className="text-2xl font-bold text-kavach-text-primary">{run.newFindings}</p>
            <p className="text-xs text-kavach-text-muted">new findings in patched code</p>
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <RotateCcw className="w-4 h-4 text-kavach-text-muted" />
              <span className="text-xs text-kavach-text-muted font-mono">ORIG. ATTACK</span>
            </div>
            <p className={`text-sm font-semibold ${run.originalAttackBlocked ? 'text-kavach-success' : 'text-kavach-danger'}`}>
              {run.originalAttackBlocked ? 'BLOCKED' : 'NOT BLOCKED'}
            </p>
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <FlaskConical className="w-4 h-4 text-kavach-text-muted" />
              <span className="text-xs text-kavach-text-muted font-mono">MUTATIONS</span>
            </div>
            <p className="text-2xl font-bold text-kavach-text-primary">
              {run.mutationTests.filter(t => t.passed).length}/{run.mutationTests.length}
            </p>
            <ProgressBar value={run.mutationPassRate * 100} color="success" />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <FileCheck className="w-4 h-4 text-kavach-text-muted" />
              <span className="text-xs text-kavach-text-muted font-mono">REGRESSION</span>
            </div>
            <p className="text-2xl font-bold text-kavach-text-primary">
              {run.regressionTests.filter(t => t.passed).length}/{run.regressionTests.length}
            </p>
            <ProgressBar value={run.regressionPassRate * 100} color="warning" />
          </CardBody>
        </Card>
      </div>

      {/* Stage Details */}
      <Card>
        <CardHeader title="Verification Stage Details" subtitle="Evidence for each stage of the verification pipeline" />
        <CardBody>
          <div className="space-y-3">
            <StageRow icon={<Bug className="w-4 h-4" />} label="Original Vulnerability" status="info"
              detail={finding ? `${finding.vulnerabilityClass.replace(/_/g, ' ')} at ${finding.file}:${finding.line}` : 'N/A'} />

            <StageRow icon={<ShieldCheck className="w-4 h-4" />} label="Original Security Test" status={run.originalAttackBlocked ? 'passed' : 'failed'}
              detail={run.originalAttackBlocked ? 'Original attack payload is now blocked by the patched code.' : 'Original attack payload still succeeds — patch does not block the known exploit.'} />

            <StageRow icon={<FlaskConical className="w-4 h-4" />} label="Patch Applied in Sandbox" status="info"
              detail={patch ? `${patch.label}: ${patch.strategy}` : 'N/A'} />

            <StageRow icon={<ShieldCheck className="w-4 h-4" />} label="SAST Re-scan of Patched Code" status={run.newFindings === 0 ? 'passed' : 'failed'}
              detail={run.newFindings === 0 ? 'SAST found 0 vulnerabilities in patched code. Injection patterns eliminated.' : `SAST found ${run.newFindings} issue(s) in patched code.`} />

            {/* Mutation Tests */}
            <div className="space-y-1">
              <StageRow icon={<RotateCcw className="w-4 h-4" />} label="Mutation Tests" status={run.mutationPassRate === 1 ? 'passed' : run.mutationPassRate >= 0.8 ? 'warning' : 'failed'}
                detail={`${run.mutationTests.filter(t => t.passed).length}/${run.mutationTests.length} mutation variants blocked by patch`} />
              <div className="ml-8 space-y-1">
                {run.mutationTests.map((test) => (
                  <div key={test.id} className="flex items-center gap-2 text-xs p-1.5 rounded bg-kavach-surface-2">
                    {test.passed ? <CheckCircle2 className="w-3 h-3 text-kavach-success flex-shrink-0" /> : <XCircle className="w-3 h-3 text-kavach-danger flex-shrink-0" />}
                    <span className="text-kavach-text-secondary flex-1 truncate">{test.name}</span>
                    <span className="font-mono text-kavach-text-muted truncate max-w-[200px]">{test.input.substring(0, 30)}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Regression Tests */}
            <div className="space-y-1">
              <StageRow icon={<FileCheck className="w-4 h-4" />} label="Regression Tests" status={run.regressionPassRate === 1 ? 'passed' : run.regressionPassRate >= 0.9 ? 'warning' : 'failed'}
                detail={`${run.regressionTests.filter(t => t.passed).length}/${run.regressionTests.length} regression tests passed`} />
              <div className="ml-8 space-y-1">
                {run.regressionTests.map((test, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs p-1.5 rounded bg-kavach-surface-2">
                    {test.passed ? <CheckCircle2 className="w-3 h-3 text-kavach-success flex-shrink-0" /> : <XCircle className="w-3 h-3 text-kavach-danger flex-shrink-0" />}
                    <span className="text-kavach-text-secondary">{test.name}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Functional Tests */}
            <div className="space-y-1">
              <StageRow icon={<FileCheck className="w-4 h-4" />} label="Functional Tests" status={run.functionalPassRate === 1 ? 'passed' : run.functionalPassRate >= 0.9 ? 'warning' : 'failed'}
                detail={`${run.functionalTests.filter(t => t.passed).length}/${run.functionalTests.length} functional tests passed`} />
              <div className="ml-8 space-y-1">
                {run.functionalTests.map((test, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs p-1.5 rounded bg-kavach-surface-2">
                    {test.passed ? <CheckCircle2 className="w-3 h-3 text-kavach-success flex-shrink-0" /> : <XCircle className="w-3 h-3 text-kavach-danger flex-shrink-0" />}
                    <span className="text-kavach-text-secondary">{test.name}</span>
                  </div>
                ))}
              </div>
            </div>

            <StageRow icon={<ShieldCheck className="w-4 h-4" />} label="Final Verification" status={run.status === 'VERIFIED' ? 'passed' : run.status === 'PARTIALLY_VERIFIED' ? 'warning' : 'failed'}
              detail={run.status.replace(/_/g, ' ')} />
          </div>
        </CardBody>
      </Card>

      {/* Full Report */}
      <Card>
        <CardHeader title="Verification Report" subtitle="Generated by the independent verification engine" />
        <CardBody>
          <pre className="text-xs font-mono text-kavach-text-secondary whitespace-pre-wrap">{run.report}</pre>
        </CardBody>
      </Card>
    </div>
  );
}

function StageRow({ icon, label, status, detail }: { icon: React.ReactNode; label: string; status: 'passed' | 'failed' | 'warning' | 'info'; detail: string }) {
  const colors = { passed: 'text-kavach-success', failed: 'text-kavach-danger', warning: 'text-amber-400', info: 'text-kavach-text-muted' };
  const icons = {
    passed: <CheckCircle2 className="w-4 h-4 text-kavach-success" />,
    failed: <XCircle className="w-4 h-4 text-kavach-danger" />,
    warning: <AlertCircle className="w-4 h-4 text-amber-400" />,
    info: icon,
  };
  return (
    <div className="flex items-start gap-3 p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
      <div className="flex-shrink-0 mt-0.5">{icons[status]}</div>
      <div className="flex-1">
        <p className={`text-sm font-medium ${colors[status]}`}>{label}</p>
        <p className="text-xs text-kavach-text-secondary mt-0.5">{detail}</p>
      </div>
    </div>
  );
}
