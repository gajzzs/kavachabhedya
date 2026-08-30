import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { StatusBadge, AuthenticityBadge } from '@/components/ui/Badge';
import { Box, RotateCcw, Layers } from 'lucide-react';
import { useState } from 'react';
import type { TwinSnapshot, TwinNode } from '@/types';

export function DigitalTwinPage() {
  const { twinSnapshots, selectedTwinSnapshotId, dispatch, patches, findings } = useKavach();
  const [showLabels, setShowLabels] = useState(true);

  const selected = twinSnapshots.find(s => s.id === selectedTwinSnapshotId) || twinSnapshots[twinSnapshots.length - 1];

  if (twinSnapshots.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardBody className="text-center">
            <Box className="w-12 h-12 text-kavach-text-muted mx-auto mb-3" />
            <p className="text-sm text-kavach-text-secondary">No digital twin snapshots yet.</p>
            <p className="text-xs text-kavach-text-muted mt-1">Run a Real Assessment or the Kavach demo to create twin snapshots.</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  const nodeColors: Record<string, string> = {
    APP: '#06b6d4',
    API: '#22d3ee',
    FUNCTION: '#0ea5e9',
    DATABASE: '#f59e0b',
    DEPENDENCY: '#94a3b8',
    TRUST_BOUNDARY: '#64748b',
    CONTROL: '#10b981',
  };

  const statusColors: Record<string, string> = {
    SECURE: '#10b981',
    VULNERABLE: '#ef4444',
    PATCHED: '#06b6d4',
    ISOLATED: '#f59e0b',
    UNKNOWN: '#64748b',
  };

  const getNodeColor = (node: TwinNode) => statusColors[node.status] || nodeColors[node.type] || '#64748b';

  // Simple SVG layout
  const nodePositions: Record<string, { x: number; y: number }> = {};
  const width = 700;
  const height = 400;
  const centerX = width / 2;
  const centerY = height / 2;

  // Position nodes in a hierarchical layout
  selected?.nodes.forEach((node, i) => {
    const angle = (i / selected.nodes.length) * Math.PI * 2;
    const radius = 120 + (i % 2) * 40;
    nodePositions[node.id] = {
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius,
    };
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Security Digital Twin</h2>
          <p className="text-sm text-kavach-text-secondary">Sandboxed application/security replica. CONTROLLED DEMONSTRATION environment.</p>
        </div>
        <AuthenticityBadge authenticity="CONTROLLED_DEMONSTRATION" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Twin Visualization */}
        <div className="lg:col-span-3">
          <Card>
            <CardHeader
              title={selected?.label || 'Twin'}
              subtitle={selected?.description}
              icon={<Box className="w-4 h-4" />}
              action={
                <button
                  onClick={() => setShowLabels(!showLabels)}
                  className="text-xs text-kavach-accent hover:underline"
                >
                  {showLabels ? 'Hide' : 'Show'} labels
                </button>
              }
            />
            <CardBody>
              <div className="relative bg-kavach-bg rounded-md overflow-hidden" style={{ minHeight: '420px' }}>
                <svg width="100%" height="420" viewBox={`0 0 ${width} ${height}`}>
                  {/* Edges */}
                  {selected?.edges.map((edge, i) => {
                    const from = nodePositions[edge.from];
                    const to = nodePositions[edge.to];
                    if (!from || !to) return null;
                    return (
                      <g key={i}>
                        <line
                          x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                          stroke={edge.vulnerable ? '#ef4444' : edge.blocked ? '#10b981' : '#334155'}
                          strokeWidth={edge.vulnerable ? 2 : 1}
                          strokeDasharray={edge.blocked ? '4 4' : 'none'}
                          opacity={0.6}
                        />
                        {showLabels && (
                          <text
                            x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 4}
                            fill={edge.vulnerable ? '#ef4444' : '#64748b'}
                            fontSize="9"
                            textAnchor="middle"
                            fontFamily="monospace"
                          >
                            {edge.label}
                          </text>
                        )}
                      </g>
                    );
                  })}
                  {/* Nodes */}
                  {selected?.nodes.map((node) => {
                    const pos = nodePositions[node.id];
                    if (!pos) return null;
                    const color = getNodeColor(node);
                    return (
                      <g key={node.id} className="graph-node">
                        <circle
                          cx={pos.x} cy={pos.y} r={20}
                          fill={color} fillOpacity={0.15}
                          stroke={color} strokeWidth={2}
                        />
                        {node.status === 'VULNERABLE' && (
                          <circle cx={pos.x} cy={pos.y} r={24} fill="none" stroke="#ef4444" strokeWidth={1} strokeDasharray="2 2" opacity={0.5}>
                            <animate attributeName="r" values="24;28;24" dur="2s" repeatCount="indefinite" />
                          </circle>
                        )}
                        {showLabels && (
                          <text
                            x={pos.x} y={pos.y + 35}
                            fill="#e2e8f0"
                            fontSize="10"
                            textAnchor="middle"
                            fontFamily="monospace"
                          >
                            {node.label.length > 20 ? node.label.substring(0, 18) + '..' : node.label}
                          </text>
                        )}
                      </g>
                    );
                  })}
                </svg>
                {selected?.attackPathActive && (
                  <div className="absolute top-2 right-2 px-2 py-1 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400 font-mono">
                    ATTACK PATH ACTIVE
                  </div>
                )}
                {!selected?.attackPathActive && selected?.state !== 'ORIGINAL' && (
                  <div className="absolute top-2 right-2 px-2 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-400 font-mono">
                    ATTACK PATH BLOCKED
                  </div>
                )}
              </div>
            </CardBody>
          </Card>
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          <Card>
            <CardHeader title="Twin Status" icon={<Box className="w-4 h-4" />} />
            <CardBody>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between"><span className="text-kavach-text-muted">Replica</span><span className="text-kavach-success font-mono">READY</span></div>
                <div className="flex justify-between"><span className="text-kavach-text-muted">Isolation</span><span className="text-kavach-accent font-mono">ACTIVE</span></div>
                <div className="flex justify-between"><span className="text-kavach-text-muted">Network</span><span className="text-kavach-warning font-mono">RESTRICTED</span></div>
                <div className="flex justify-between"><span className="text-kavach-text-muted">Snapshot</span><span className="text-kavach-text-primary font-mono">{selected?.label.split(' - ')[0] || 'T0'}</span></div>
              </div>
            </CardBody>
          </Card>

          {/* Snapshots */}
          <Card>
            <CardHeader title="Snapshots" subtitle={`${twinSnapshots.length} total`} icon={<Layers className="w-4 h-4" />} />
            <CardBody>
              <div className="space-y-1">
                {twinSnapshots.map((snap) => (
                  <button
                    key={snap.id}
                    onClick={() => dispatch({ type: 'SET_SELECTED_TWIN', snapshotId: snap.id })}
                    className={`w-full text-left p-2 rounded-md text-xs transition-all ${
                      snap.id === selectedTwinSnapshotId
                        ? 'bg-kavach-accent/10 border border-kavach-accent/20 text-kavach-accent'
                        : 'bg-kavach-surface-2 border border-kavach-border text-kavach-text-secondary hover:border-kavach-border-light'
                    }`}
                  >
                    <div className="font-mono font-medium">{snap.label}</div>
                    <div className="text-kavach-text-muted mt-0.5">{snap.state}</div>
                  </button>
                ))}
              </div>
            </CardBody>
          </Card>

          {/* Legend */}
          <Card>
            <CardHeader title="Legend" />
            <CardBody>
              <div className="space-y-1.5 text-xs">
                {Object.entries(statusColors).map(([status, color]) => (
                  <div key={status} className="flex items-center gap-2">
                    <span className="w-3 h-3 rounded-full" style={{ backgroundColor: color, opacity: 0.3, border: `1px solid ${color}` }} />
                    <span className="text-kavach-text-secondary">{status}</span>
                  </div>
                ))}
              </div>
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  );
}
