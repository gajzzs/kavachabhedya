import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { StatusBadge, AuthenticityBadge } from '@/components/ui/Badge';
import { Database, ShieldCheck, Bug, GitBranch, FileCheck, Hash, RefreshCw, AlertTriangle } from 'lucide-react';
import type { SecurityMemory } from '@/types';

export function SecurityMemoryPage() {
  const { securityMemory } = useKavach();

  if (securityMemory.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardBody className="text-center">
            <Database className="w-12 h-12 text-kavach-text-muted mx-auto mb-3" />
            <p className="text-sm text-kavach-text-secondary">No security memory records yet.</p>
            <p className="text-xs text-kavach-text-muted mt-1">Only VERIFIED vulnerabilities are stored here. Run a Real Assessment to generate verified remediation records.</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div>
        <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Security Immune Memory</h2>
        <p className="text-sm text-kavach-text-secondary">
          Only VERIFIED outcomes enter Security Memory. Each record stores the source hash — if the source changes, revalidation is required. Never blindly reuse historical patches.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {securityMemory.map((mem) => (
          <MemoryCard key={mem.id} memory={mem} />
        ))}
      </div>
    </div>
  );
}

function MemoryCard({ memory }: { memory: SecurityMemory }) {
  const revalidationColor =
    memory.revalidationState === 'CURRENT'
      ? 'text-kavach-success'
      : memory.revalidationState === 'REVALIDATION_REQUIRED'
      ? 'text-kavach-warning'
      : 'text-kavach-text-muted';

  const revalidationIcon =
    memory.revalidationState === 'CURRENT' ? <ShieldCheck className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />;

  return (
    <Card hover>
      <CardHeader
        title={memory.kavachId}
        subtitle={memory.vulnerabilityClass.replace(/_/g, ' ')}
        icon={<Database className="w-4 h-4" />}
        action={<StatusBadge status={memory.status} />}
      />
      <CardBody>
        <div className="space-y-3 text-xs">
          <div>
            <p className="kavach-section-title mb-1 flex items-center gap-1"><Bug className="w-3 h-3" /> Original Evidence</p>
            <p className="text-kavach-text-secondary">{memory.originalEvidence}</p>
          </div>
          <div>
            <p className="kavach-section-title mb-1 flex items-center gap-1"><GitBranch className="w-3 h-3" /> Attack Pattern</p>
            <p className="text-kavach-text-secondary">{memory.attackPattern}</p>
          </div>
          <div>
            <p className="kavach-section-title mb-1 flex items-center gap-1"><ShieldCheck className="w-3 h-3" /> Patch Applied</p>
            <p className="text-kavach-text-secondary">{memory.patchApplied}</p>
          </div>
          <div>
            <p className="kavach-section-title mb-1 flex items-center gap-1"><FileCheck className="w-3 h-3" /> Regression Test</p>
            <p className="text-kavach-text-secondary">{memory.regressionTest}</p>
          </div>

          {/* Source Hash */}
          <div className="flex items-center gap-2 pt-2 border-t border-kavach-border">
            <Hash className="w-3 h-3 text-kavach-text-muted" />
            <span className="text-kavach-text-muted font-mono">source: {memory.sourceHash.substring(0, 16)}</span>
          </div>

          {/* Revalidation State */}
          <div className={`flex items-center gap-2 ${revalidationColor}`}>
            {revalidationIcon}
            <span className="font-mono uppercase tracking-wider">
              {memory.revalidationState === 'CURRENT'
                ? 'Source current — memory valid'
                : memory.revalidationState === 'REVALIDATION_REQUIRED'
                ? 'REVALIDATION REQUIRED — source changed'
                : 'STALE — re-run assessment'}
            </span>
            {memory.revalidationState !== 'CURRENT' && <RefreshCw className="w-3 h-3" />}
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-kavach-border">
            <span className="text-kavach-text-muted font-mono">v{memory.projectVersion}</span>
            <span className="text-kavach-text-muted font-mono">{new Date(memory.timestamp).toLocaleString()}</span>
          </div>
        </div>
      </CardBody>
    </Card>
  );
}
