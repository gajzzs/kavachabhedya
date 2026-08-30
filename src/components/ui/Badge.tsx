import type { EvidenceAuthenticity, Severity } from '@/types';
import { getAuthenticityBg, getSeverityBg } from '@/lib/utils';

const AUTH_LABELS: Record<EvidenceAuthenticity, string> = {
  EXECUTABLE: 'EXECUTABLE',
  CONTROLLED_DEMONSTRATION: 'CONTROLLED DEMO',
  PLANNED_INTEGRATION: 'PLANNED',
  UNAVAILABLE: 'UNAVAILABLE',
};

export function AuthenticityBadge({ authenticity }: { authenticity: EvidenceAuthenticity }) {
  return (
    <span className={`kavach-badge ${getAuthenticityBg(authenticity)}`}>
      {AUTH_LABELS[authenticity] || authenticity}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`kavach-badge ${getSeverityBg(severity)}`}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    VERIFIED: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    CONFIRMED: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    COMPLETED: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    PASSED: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    SAFE: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    SECURE: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    FAILED: 'bg-red-500/10 border-red-500/30 text-red-400',
    BLOCKED: 'bg-red-500/10 border-red-500/30 text-red-400',
    CRITICAL: 'bg-red-500/10 border-red-500/30 text-red-400',
    ERROR: 'bg-red-500/10 border-red-500/30 text-red-400',
    IN_PROGRESS: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
    RUNNING: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
    INVESTIGATING: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
    PENDING: 'bg-slate-500/10 border-slate-500/30 text-slate-400',
    INCONCLUSIVE: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    INSUFFICIENT: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    UNCONFIRMED: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    SUSPICIOUS: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    SKIPPED: 'bg-slate-600/10 border-slate-600/30 text-slate-500',
    ACTION_REQUIRED: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
    PARTIALLY_VERIFIED: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
  };

  const colorClass = colors[status.toUpperCase()] || 'bg-slate-500/10 border-slate-500/30 text-slate-400';

  return (
    <span className={`kavach-badge ${colorClass}`}>
      {status.replace(/_/g, ' ')}
    </span>
  );
}
