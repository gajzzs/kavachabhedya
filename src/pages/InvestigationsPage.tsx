import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { StatusBadge, AuthenticityBadge, SeverityBadge } from '@/components/ui/Badge';
import { CheckCircle2, Circle, Loader2, XCircle, ChevronRight, MinusCircle } from 'lucide-react';
import type { InvestigationStepStatus } from '@/types';

export function InvestigationsPage() {
  const { assessment, findings, evidence, fuzzingResult, experiments, hypotheses, patches, reasoning, isRunning, twinSnapshots, verificationRun, securityMemory, attackPath } = useKavach();

  const hasAssessment = !!assessment;
  const hasFindings = findings.length > 0;
  const isCompleted = assessment?.status === 'COMPLETED' || assessment?.status === 'COMPLETED_WITH_ISSUES';

  // Derive step statuses from actual data
  const steps: InvestigationStepStatus[] = [
    { step: 'INTAKE', label: 'Source Intake', status: hasAssessment ? 'COMPLETED' : 'PENDING', detail: assessment ? `${assessment.sourceFilename} · ${assessment.lineCount} lines · ${assessment.language}` : undefined },
    { step: 'SCAN', label: 'Security Scan (SAST)', status: hasAssessment ? (hasFindings ? 'COMPLETED' : isCompleted ? 'COMPLETED' : 'IN_PROGRESS') : 'PENDING', detail: hasFindings ? `${findings.length} finding(s)` : hasAssessment && isCompleted ? 'No findings detected' : undefined },
    { step: 'EVIDENCE', label: 'Evidence Fusion', status: evidence.length > 0 ? 'COMPLETED' : !hasFindings && hasAssessment ? 'SKIPPED' : hasAssessment ? 'IN_PROGRESS' : 'PENDING', detail: evidence[0] ? `${evidence[0].fusedScore}% confidence` : !hasFindings && hasAssessment ? 'No findings — not applicable' : undefined },
    { step: 'FUZZ', label: 'Context-Aware Fuzzing', status: fuzzingResult ? (fuzzingResult.skipped ? 'SKIPPED' : 'COMPLETED') : !hasFindings && hasAssessment ? 'SKIPPED' : hasFindings && hasAssessment ? 'IN_PROGRESS' : 'PENDING', detail: fuzzingResult ? (fuzzingResult.skipped ? `SKIPPED — ${fuzzingResult.skipReason}` : `${fuzzingResult.confirmedCount}/${fuzzingResult.payloads.length - 1} payloads confirmed — ${fuzzingResult.confirmed ? 'CONFIRMED' : fuzzingResult.confirmedCount > 0 ? 'SUSPICIOUS' : 'NOT_REPRODUCED'} (${fuzzingResult.executionMode})`) : !hasFindings && hasAssessment ? 'No findings — not applicable' : undefined },
    { step: 'REASON', label: 'AI Reasoning', status: reasoning ? 'COMPLETED' : !hasFindings && hasAssessment ? 'SKIPPED' : hasFindings && hasAssessment ? 'IN_PROGRESS' : 'PENDING', detail: reasoning ? `${(reasoning.confidence * 100).toFixed(0)}% confidence` : !hasFindings && hasAssessment ? 'No findings — not applicable' : undefined },
    { step: 'ATTACK_PATH', label: 'Attack Path', status: attackPath ? 'COMPLETED' : !hasFindings && hasAssessment ? 'SKIPPED' : hasFindings && hasAssessment ? 'IN_PROGRESS' : 'PENDING', detail: attackPath ? `${attackPath.entryPoint} → ${attackPath.impact}` : !hasFindings && hasAssessment ? 'No findings — not applicable' : undefined },
    { step: 'TWIN', label: 'Digital Twin', status: twinSnapshots.length > 0 ? 'COMPLETED' : !hasFindings && hasAssessment ? 'SKIPPED' : hasAssessment ? 'IN_PROGRESS' : 'PENDING', detail: twinSnapshots.length > 0 ? `${twinSnapshots.length} snapshot(s)` : !hasFindings && hasAssessment ? 'No findings — not applicable' : undefined },
    { step: 'PATCH', label: 'Patch Generation', status: patches.length > 0 ? 'COMPLETED' : !hasFindings && hasAssessment ? 'SKIPPED' : hasFindings && hasAssessment ? 'IN_PROGRESS' : 'PENDING', detail: patches.length > 0 ? `${patches.length} candidate(s)` : !hasFindings && hasAssessment ? 'No findings — not applicable' : undefined },
    { step: 'VERIFY', label: 'Verification', status: verificationRun ? 'COMPLETED' : !hasFindings && hasAssessment ? 'SKIPPED' : hasFindings && hasAssessment ? 'IN_PROGRESS' : 'PENDING', detail: verificationRun ? verificationRun.status : !hasFindings && hasAssessment ? 'No findings — not applicable' : undefined },
    { step: 'REMEMBER', label: 'Security Memory', status: securityMemory.length > 0 ? 'COMPLETED' : !hasFindings && hasAssessment ? 'SKIPPED' : hasAssessment && isCompleted ? 'PENDING' : 'PENDING', detail: securityMemory[0] ? securityMemory[0].kavachId : !hasFindings && hasAssessment ? 'No findings — not applicable' : undefined },
  ];

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div>
        <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Investigation Workflow</h2>
        <p className="text-sm text-kavach-text-secondary">Step-by-step visual workflow of the complete security investigation.</p>
        {assessment && (
          <p className="text-xs text-kavach-text-muted font-mono mt-2">
            Assessment: {assessment.assessmentId} · {assessment.projectName} · {assessment.sourceFilename}
          </p>
        )}
      </div>

      {/* Empty State */}
      {!hasAssessment && (
        <Card className="border-kavach-warning/20">
          <CardBody className="text-center py-8">
            <Circle className="w-10 h-10 text-kavach-text-muted mx-auto mb-3" />
            <p className="text-sm font-semibold text-kavach-text-primary">NO ACTIVE ASSESSMENT</p>
            <p className="text-xs text-kavach-text-muted mt-2 max-w-md mx-auto">
              Run a Real Assessment or the Kavach demo to populate the investigation workflow.
            </p>
          </CardBody>
        </Card>
      )}

      {/* Steps Timeline */}
      {hasAssessment && (
        <Card>
          <CardBody>
            <div className="space-y-1">
              {steps.map((step, i) => {
                const icon = step.status === 'COMPLETED' ? <CheckCircle2 className="w-5 h-5 text-kavach-success" />
                  : step.status === 'IN_PROGRESS' ? <Loader2 className="w-5 h-5 text-kavach-accent animate-spin" />
                  : step.status === 'FAILED' ? <XCircle className="w-5 h-5 text-kavach-danger" />
                  : step.status === 'SKIPPED' ? <MinusCircle className="w-5 h-5 text-kavach-text-muted" />
                  : <Circle className="w-5 h-5 text-kavach-text-muted" />;
                return (
                  <div key={step.step} className="flex items-center gap-3 py-2">
                    <div className="flex items-center gap-3 flex-1">
                      {icon}
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-kavach-text-primary">{step.label}</span>
                          <StatusBadge status={step.status} />
                        </div>
                        {step.detail && <p className="text-xs text-kavach-text-muted mt-0.5">{step.detail}</p>}
                      </div>
                    </div>
                    {i < steps.length - 1 && <ChevronRight className="w-4 h-4 text-kavach-text-muted rotate-90" />}
                  </div>
                );
              })}
            </div>
          </CardBody>
        </Card>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <Card>
          <CardHeader title="Findings" subtitle={`${findings.length} vulnerability finding(s)`} />
          <CardBody>
            <div className="space-y-3">
              {findings.map((finding) => (
                <div key={finding.id} className="p-3 rounded-md bg-kavach-surface-2 border border-kavach-border">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <span className="text-sm font-medium text-kavach-text-primary">{finding.vulnerabilityClass.replace(/_/g, ' ')}</span>
                    </div>
                    <AuthenticityBadge authenticity={finding.authenticity} />
                  </div>
                  <p className="text-xs text-kavach-text-secondary mb-2">{finding.description}</p>
                  <div className="flex items-center gap-3 text-xs text-kavach-text-muted font-mono">
                    <span>{finding.file}:{finding.line}</span>
                    <span>•</span>
                    <span>{finding.cwe}</span>
                    <span>•</span>
                    <span>Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
                  </div>
                  {finding.codeSnippet && (
                    <pre className="mt-2 p-2 bg-kavach-bg rounded text-xs font-mono text-kavach-text-secondary overflow-x-auto">{finding.codeSnippet}</pre>
                  )}
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      )}

      {/* Evidence */}
      {evidence.length > 0 && (
        <Card>
          <CardHeader title="Evidence Fusion" subtitle="Independent signals combined" />
          <CardBody>
            {evidence.map((ev) => (
              <div key={ev.id} className="space-y-3">
                <div className="flex items-center justify-between">
                  <StatusBadge status={ev.status} />
                  <span className="text-2xl font-bold text-kavach-text-primary">{ev.fusedScore}%</span>
                </div>
                <p className="text-xs text-kavach-text-secondary">{ev.reasoning}</p>
                <div className="space-y-1">
                  {ev.sources.map((src, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <span className="font-mono text-kavach-text-muted w-16">{src.toolType}</span>
                      <StatusBadge status={src.status} />
                      <AuthenticityBadge authenticity={src.authenticity} />
                      <span className="text-kavach-text-secondary flex-1 truncate">{src.detail}</span>
                    </div>
                  ))}
                </div>
                {ev.contradictions.length > 0 && (
                  <div className="p-2 rounded bg-amber-500/5 border border-amber-500/20">
                    <p className="text-xs text-amber-400 font-medium mb-1">Contradictions:</p>
                    {ev.contradictions.map((c, i) => <p key={i} className="text-xs text-amber-400/80">{c}</p>)}
                  </div>
                )}
                {ev.missingEvidence.length > 0 && (
                  <div className="p-2 rounded bg-kavach-surface-2 border border-kavach-border">
                    <p className="text-xs text-kavach-text-muted font-medium mb-1">Missing evidence:</p>
                    {ev.missingEvidence.map((m, i) => <p key={i} className="text-xs text-kavach-text-muted">{m}</p>)}
                  </div>
                )}
              </div>
            ))}
          </CardBody>
        </Card>
      )}

      {/* AI Reasoning */}
      {reasoning && (
        <Card>
          <CardHeader title="AI Reasoning Summary" subtitle={reasoning.authenticity === 'CONTROLLED_DEMONSTRATION' ? 'DEMO REASONER' : 'CONNECTED LLM'} />
          <CardBody>
            <div className="space-y-3">
              <div>
                <p className="kavach-section-title mb-1">Root Cause</p>
                <p className="text-sm text-kavach-text-secondary">{reasoning.rootCause}</p>
              </div>
              <div>
                <p className="kavach-section-title mb-1">Attack Path</p>
                <p className="text-sm text-kavach-text-secondary font-mono">{reasoning.attackPath}</p>
              </div>
              <div>
                <p className="kavach-section-title mb-1">Potential Impact</p>
                <p className="text-sm text-kavach-text-secondary">{reasoning.potentialImpact}</p>
              </div>
              <div>
                <p className="kavach-section-title mb-1">Confidence: {(reasoning.confidence * 100).toFixed(0)}%</p>
                <p className="text-sm text-kavach-text-secondary">{reasoning.confidenceReason}</p>
              </div>
              <div>
                <p className="kavach-section-title mb-1">Next Investigation</p>
                <p className="text-sm text-kavach-text-secondary">{reasoning.nextInvestigation}</p>
              </div>
              {reasoning.insufficientEvidence && (
                <div className="p-2 rounded bg-amber-500/5 border border-amber-500/20">
                  <p className="text-xs text-amber-400">INSUFFICIENT EVIDENCE — The reasoner determined there is not enough evidence for a confident diagnosis.</p>
                </div>
              )}
            </div>
          </CardBody>
        </Card>
      )}

      {/* Experiments */}
      {experiments.length > 0 && (
        <Card>
          <CardHeader title="Experiment Planner" subtitle="Adaptive experiment selection" />
          <CardBody>
            <div className="space-y-2">
              {experiments.map((exp) => (
                <div key={exp.id} className="p-3 rounded-md bg-kavach-surface-2 border border-kavach-border">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-kavach-text-primary">{exp.name}</span>
                    <StatusBadge status={exp.status} />
                  </div>
                  <p className="text-xs text-kavach-text-muted mb-1"><span className="text-kavach-text-secondary">Reason:</span> {exp.reason}</p>
                  <p className="text-xs text-kavach-text-muted mb-1"><span className="text-kavach-text-secondary">Expected gain:</span> {exp.expectedInformationGain}</p>
                  {exp.result && <p className="text-xs text-kavach-success">{exp.result}</p>}
                  {exp.nextAction && <p className="text-xs text-kavach-accent">Next: {exp.nextAction}</p>}
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
