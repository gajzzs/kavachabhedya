// ============================================================
// KAVACH - Utility Functions
// ============================================================

export function generateId(prefix: string = ''): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 8);
  return prefix ? `${prefix}-${ts}${rand}` : `${ts}${rand}`;
}

export function generateKavachId(): string {
  const num = Math.floor(Math.random() * 9999) + 1;
  return `KAV-${String(num).padStart(3, '0')}`;
}

export function formatTimestamp(ts: string | Date): string {
  const d = typeof ts === 'string' ? new Date(ts) : ts;
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return 'text-red-400';
    case 'HIGH': return 'text-orange-400';
    case 'MEDIUM': return 'text-amber-400';
    case 'LOW': return 'text-blue-400';
    default: return 'text-slate-400';
  }
}

export function getSeverityBg(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return 'bg-red-500/10 border-red-500/30';
    case 'HIGH': return 'bg-orange-500/10 border-orange-500/30';
    case 'MEDIUM': return 'bg-amber-500/10 border-amber-500/30';
    case 'LOW': return 'bg-blue-500/10 border-blue-500/30';
    default: return 'bg-slate-500/10 border-slate-500/30';
  }
}

export function getAuthenticityColor(authenticity: string): string {
  switch (authenticity) {
    case 'EXECUTABLE': return 'text-emerald-400';
    case 'CONTROLLED_DEMONSTRATION': return 'text-cyan-400';
    case 'PLANNED_INTEGRATION': return 'text-amber-400';
    case 'UNAVAILABLE': return 'text-slate-500';
    default: return 'text-slate-400';
  }
}

export function getAuthenticityBg(authenticity: string): string {
  switch (authenticity) {
    case 'EXECUTABLE': return 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
    case 'CONTROLLED_DEMONSTRATION': return 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400';
    case 'PLANNED_INTEGRATION': return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
    case 'UNAVAILABLE': return 'bg-slate-700 border-slate-600 text-slate-500';
    default: return 'bg-slate-700 border-slate-600 text-slate-400';
  }
}

export function getStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case 'verified':
    case 'confirmed':
    case 'completed':
    case 'pass':
    case 'passed':
    case 'safe':
    case 'secure':
    case 'reachable':
      return 'text-emerald-400';
    case 'failed':
    case 'blocked':
    case 'critical':
    case 'error':
    case 'not_reachable':
      return 'text-red-400';
    case 'in_progress':
    case 'running':
    case 'investigating':
    case 'pending':
      return 'text-cyan-400';
    case 'inconclusive':
    case 'insufficient':
    case 'unconfirmed':
    case 'suspicious':
    case 'skipped':
    case 'uncertain':
      return 'text-amber-400';
    default:
      return 'text-slate-400';
  }
}
