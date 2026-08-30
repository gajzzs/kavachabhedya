import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { AuthenticityBadge, StatusBadge } from '@/components/ui/Badge';
import { ProgressBar } from '@/components/ui/ProgressBar';
import { FlaskConical, Shield, AlertTriangle, Code2 } from 'lucide-react';
import { useState, useEffect } from 'react';

export function PatchLabPage() {
  const { patches, selectedPatchId, dispatch, verificationRun } = useKavach();
  const [activeTab, setActiveTab] = useState(0);

  useEffect(() => {
    if (patches.length > 0 && selectedPatchId) {
      const idx = patches.findIndex(p => p.id === selectedPatchId);
      if (idx >= 0) setActiveTab(idx);
    }
  }, [patches, selectedPatchId]);

  if (patches.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardBody className="text-center">
            <FlaskConical className="w-12 h-12 text-kavach-text-muted mx-auto mb-3" />
            <p className="text-sm text-kavach-text-secondary">No patch candidates yet.</p>
            <p className="text-xs text-kavach-text-muted mt-1">Run a Real Assessment or the Kavach demo to generate patches.</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  const patch = patches[activeTab] || patches[0];
  const isVerified = verificationRun?.patchId === patch.id && verificationRun?.status === 'VERIFIED';

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Patch Lab</h2>
          <p className="text-sm text-kavach-text-secondary">Candidate remediation strategies. Never shown as SAFE until verification succeeds.</p>
        </div>
        <AuthenticityBadge authenticity="CONTROLLED_DEMONSTRATION" />
      </div>

      {/* Patch Tabs */}
      <div className="flex gap-2">
        {patches.map((p, i) => (
          <button
            key={p.id}
            onClick={() => { setActiveTab(i); dispatch({ type: 'SET_SELECTED_PATCH', patchId: p.id }); }}
            className={`kavach-btn ${i === activeTab ? 'kavach-btn-primary' : 'kavach-btn-secondary'}`}
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Patch Details */}
        <div className="space-y-4">
          <Card>
            <CardHeader title={patch.label} subtitle={patch.strategy} icon={<FlaskConical className="w-4 h-4" />} />
            <CardBody>
              <p className="text-sm text-kavach-text-secondary mb-4">{patch.description}</p>
              <div className="space-y-3">
                <ProgressBar label="Security Score" value={patch.securityScore * 100} color="success" />
                <ProgressBar label="Regression Risk" value={patch.regressionRisk * 100} color="warning" />
                <ProgressBar label="Code Complexity" value={patch.codeComplexity * 100} color="accent" />
                <ProgressBar label="Performance Impact" value={patch.performanceImpact * 100} color="accent" />
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
                <div><span className="text-kavach-text-muted">Lines changed:</span> <span className="text-kavach-text-primary font-mono">{patch.linesChanged}</span></div>
                <div><span className="text-kavach-text-muted">Risk level:</span> <StatusBadge status={patch.riskLevel} /></div>
                <div><span className="text-kavach-text-muted">Components:</span> <span className="text-kavach-text-secondary">{patch.affectedComponents.join(', ')}</span></div>
                <div><span className="text-kavach-text-muted">Dependencies:</span> <span className="text-kavach-text-secondary">{patch.dependenciesAdded.length > 0 ? patch.dependenciesAdded.join(', ') : 'None'}</span></div>
              </div>
            </CardBody>
          </Card>

          {/* Risk Gate */}
          <Card>
            <CardHeader title="Patch Risk Gate" subtitle="Classification before applying" icon={<Shield className="w-4 h-4" />} />
            <CardBody>
              <div className="flex items-center gap-3">
                <div className={`p-3 rounded-md border ${
                  patch.riskLevel === 'LOW' ? 'bg-emerald-500/5 border-emerald-500/20' :
                  patch.riskLevel === 'MEDIUM' ? 'bg-amber-500/5 border-amber-500/20' :
                  patch.riskLevel === 'HIGH' ? 'bg-orange-500/5 border-orange-500/20' :
                  'bg-red-500/5 border-red-500/20'
                }`}>
                  <AlertTriangle className={`w-6 h-6 ${
                    patch.riskLevel === 'LOW' ? 'text-emerald-400' :
                    patch.riskLevel === 'MEDIUM' ? 'text-amber-400' :
                    patch.riskLevel === 'HIGH' ? 'text-orange-400' : 'text-red-400'
                  }`} />
                </div>
                <div>
                  <p className="text-sm font-semibold text-kavach-text-primary">{patch.riskLevel} RISK</p>
                  <p className="text-xs text-kavach-text-muted">
                    {patch.riskLevel === 'LOW' && 'Can execute in sandbox automatically.'}
                    {patch.riskLevel === 'MEDIUM' && 'Sandbox execution + stronger verification required.'}
                    {patch.riskLevel === 'HIGH' && 'Human approval required before applying.'}
                    {patch.riskLevel === 'CRITICAL' && 'Never automatically apply outside isolated demo.'}
                  </p>
                </div>
              </div>
            </CardBody>
          </Card>

          {/* Verification Status */}
          {verificationRun && verificationRun.patchId === patch.id && (
            <Card>
              <CardHeader title="Verification Status" />
              <CardBody>
                <div className="flex items-center gap-2 mb-2">
                  <StatusBadge status={verificationRun.status} />
                  {isVerified && <AuthenticityBadge authenticity="CONTROLLED_DEMONSTRATION" />}
                </div                >
                <p className="text-xs text-kavach-text-secondary">{verificationRun.report.split('\n')[0]}</p>
              </CardBody>
            </Card>
          )}
        </div>

        {/* Code Diff */}
        <Card>
          <CardHeader title="Code Diff" subtitle={`${patch.linesChanged} lines changed`} icon={<Code2 className="w-4 h-4" />} />
          <CardBody>
            <div className="bg-kavach-bg rounded-md p-3 overflow-auto max-h-96">
              <pre className="code-block text-kavach-text-secondary whitespace-pre-wrap">
                {patch.diff.split('\n').map((line, i) => (
                  <div key={i} className={
                    line.startsWith('- ') ? 'diff-remove' :
                    line.startsWith('+ ') ? 'diff-add' : ''
                  }>
                    {line}
                  </div>
                ))}
              </pre>
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
