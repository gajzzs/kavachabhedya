import { useKavach } from '@/store/KavachContext';
import { Card, CardBody } from '@/components/ui/Card';
import { SeverityBadge } from '@/components/ui/Badge';
import { ScrollText } from 'lucide-react';
import type { AuditEvent } from '@/types';

export function AuditLogPage() {
  const { auditEvents } = useKavach();

  if (auditEvents.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardBody className="text-center">
            <ScrollText className="w-12 h-12 text-kavach-text-muted mx-auto mb-3" />
            <p className="text-sm text-kavach-text-secondary">No audit events yet.</p>
            <p className="text-xs text-kavach-text-muted mt-1">Run a Real Assessment or the Kavach demo to generate audit trail entries.</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  const reversed = [...auditEvents].reverse();

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <div>
        <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Audit Log</h2>
        <p className="text-sm text-kavach-text-secondary">Complete audit trail of all system events. {auditEvents.length} event(s) total.</p>
      </div>

      <Card>
        <CardBody>
          <div className="space-y-1 max-h-[calc(100vh-200px)] overflow-y-auto">
            {reversed.map((event) => (
              <AuditRow key={event.id} event={event} />
            ))}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

function AuditRow({ event }: { event: AuditEvent }) {
  return (
    <div className="flex items-start gap-3 p-2 rounded-md hover:bg-kavach-surface-2 border border-transparent hover:border-kavach-border text-xs">
      <span className="font-mono text-kavach-text-muted w-20 flex-shrink-0">
        {new Date(event.timestamp).toLocaleTimeString('en-US', { hour12: false })}
      </span>
      <SeverityBadge severity={event.severity} />
      <span className="font-mono text-kavach-text-muted w-20 flex-shrink-0">{event.category}</span>
      <div className="flex-1 min-w-0">
        <p className="text-kavach-text-primary font-medium">{event.event}</p>
        <p className="text-kavach-text-secondary mt-0.5">{event.detail}</p>
        <p className="text-kavach-text-muted mt-0.5 font-mono">source: {event.source}</p>
      </div>
    </div>
  );
}
