import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { StatusBadge } from '@/components/ui/Badge';
import { Lock, Shield, CheckCircle2, XCircle, Network, KeyRound, FileWarning } from 'lucide-react';

export function AgentGuardianPage() {
  const { agentSecurity, policy, agentActions } = useKavach();

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div>
        <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Agent Guardian</h2>
        <p className="text-sm text-kavach-text-secondary">Safety layer for all AI agent actions. Every tool call is classified and checked against policy before execution.</p>
      </div>

      {/* Policy Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card hover><CardBody>
          <Lock className="w-4 h-4 text-kavach-success mb-2" />
          <p className="kavach-section-title mb-1">Guardian</p>
          <p className="text-sm font-semibold text-kavach-success">ACTIVE</p>
        </CardBody></Card>
        <Card hover><CardBody>
          <Network className="w-4 h-4 text-kavach-danger mb-2" />
          <p className="kavach-section-title mb-1">Network</p>
          <p className="text-sm font-semibold text-kavach-danger">{policy.networkRestricted ? 'RESTRICTED' : 'ALLOWED'}</p>
        </CardBody></Card>
        <Card hover><CardBody>
          <KeyRound className="w-4 h-4 text-kavach-danger mb-2" />
          <p className="kavach-section-title mb-1">Credential Access</p>
          <p className="text-sm font-semibold text-kavach-danger">{policy.credentialAccessBlocked ? 'BLOCKED' : 'ALLOWED'}</p>
        </CardBody></Card>
        <Card hover><CardBody>
          <FileWarning className="w-4 h-4 text-kavach-danger mb-2" />
          <p className="kavach-section-title mb-1">Destructive Ops</p>
          <p className="text-sm font-semibold text-kavach-danger">{policy.destructiveBlocked ? 'BLOCKED' : 'ALLOWED'}</p>
        </CardBody></Card>
      </div>

      {/* Tool Permissions */}
      <Card>
        <CardHeader title="Tool Permissions" subtitle="Classification and access control for each tool" icon={<Shield className="w-4 h-4" />} />
        <CardBody>
          <div className="space-y-2">
            {agentSecurity.toolPermissions.map((perm) => (
              <div key={perm.tool} className="flex items-center justify-between p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <div className="flex items-center gap-2">
                  {perm.allowed ? <CheckCircle2 className="w-4 h-4 text-kavach-success" /> : <XCircle className="w-4 h-4 text-kavach-danger" />}
                  <span className="text-sm text-kavach-text-primary">{perm.tool}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-kavach-text-muted">{perm.class}</span>
                  <StatusBadge status={perm.allowed ? 'ALLOWED' : 'BLOCKED'} />
                </div>
              </div>
            ))}
          </div>
        </CardBody>
      </Card>

      {/* Security Assessment */}
      <Card>
        <CardHeader title="Security Assessment" subtitle="Agent self-security evaluation" />
        <CardBody>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
            <AssessmentItem label="Prompt Injection Risk" value={agentSecurity.promptInjectionRisk} />
            <AssessmentItem label="Secret Exposure Risk" value={agentSecurity.secretExposureRisk} />
            <AssessmentItem label="Network Access" value={agentSecurity.networkAccess} />
            <AssessmentItem label="Excessive Privilege" value={agentSecurity.excessivePrivilege ? 'YES' : 'NO'} />
            <AssessmentItem label="Unsafe Tool Output" value={agentSecurity.unsafeToolOutput ? 'YES' : 'NO'} />
            <AssessmentItem label="Untrusted Input Handling" value={agentSecurity.untrustedInputHandling ? 'YES' : 'NO'} />
          </div>
          <div className="mt-4 space-y-1">
            {agentSecurity.notes.map((note, i) => (
              <p key={i} className="text-xs text-kavach-text-muted flex items-start gap-2">
                <span className="text-kavach-accent mt-0.5">•</span>{note}
              </p>
            ))}
          </div>
        </CardBody>
      </Card>

      {/* Action Log */}
      {agentActions.length > 0 && (
        <Card>
          <CardHeader title="Agent Actions" subtitle={`${agentActions.length} action(s) logged`} />
          <CardBody>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {agentActions.map((action) => (
                <div key={action.id} className="flex items-center gap-3 p-2 rounded-md bg-kavach-surface-2 border border-kavach-border text-xs">
                  <span className="font-mono text-kavach-text-muted w-16">{new Date(action.timestamp).toLocaleTimeString('en-US', { hour12: false })}</span>
                  <span className="text-kavach-text-secondary flex-1">{action.agent} → {action.tool}: {action.action}</span>
                  <StatusBadge status={action.status} />
                  {action.sandboxed && <span className="text-kavach-accent font-mono">SANDBOXED</span>}
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}

function AssessmentItem({ label, value }: { label: string; value: string }) {
  const isGood = value === 'LOW' || value === 'NO' || value === 'RESTRICTED';
  const isBad = value === 'HIGH' || value === 'YES' || value === 'ALLOWED';
  return (
    <div className="p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
      <p className="text-kavach-text-muted mb-1">{label}</p>
      <p className={`font-semibold ${isGood ? 'text-kavach-success' : isBad ? 'text-kavach-danger' : 'text-amber-400'}`}>{value}</p>
    </div>
  );
}
