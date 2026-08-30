import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { AuthenticityBadge, StatusBadge } from '@/components/ui/Badge';
import { Network } from 'lucide-react';
import { useState } from 'react';

export function EvidenceGraphPage() {
  const { findings, evidence, patches, verificationRun, attackPath } = useKavach();
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  if (findings.length === 0) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardBody className="text-center">
            <Network className="w-12 h-12 text-kavach-text-muted mx-auto mb-3" />
            <p className="text-sm text-kavach-text-secondary">No evidence graph yet.</p>
            <p className="text-xs text-kavach-text-muted mt-1">Run a Real Assessment or the Kavach demo to generate evidence.</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  // Build graph from attack path if available
  const nodes = attackPath?.nodes || [];
  const edges = attackPath?.edges || [];

  const nodeTypeIcons: Record<string, string> = {
    INPUT: 'I', API: 'A', FUNCTION: 'F', VARIABLE: 'V',
    DATABASE: 'D', DEPENDENCY: 'D', VULNERABILITY: '!',
    CONTROL: 'C', PATCH: 'P', VERIFICATION: 'V',
  };

  const nodeTypeColors: Record<string, string> = {
    INPUT: '#f59e0b', API: '#22d3ee', FUNCTION: '#0ea5e9',
    VARIABLE: '#94a3b8', DATABASE: '#f59e0b', DEPENDENCY: '#64748b',
    VULNERABILITY: '#ef4444', CONTROL: '#10b981', PATCH: '#06b6d4',
    VERIFICATION: '#10b981',
  };

  const width = 800;
  const height = 450;
  const nodePositions: Record<string, { x: number; y: number }> = {};
  nodes.forEach((node, i) => {
    const cols = 4;
    const col = i % cols;
    const row = Math.floor(i / cols);
    nodePositions[node.id] = {
      x: 80 + col * 200,
      y: 60 + row * 120,
    };
  });

  const selectedNodeData = nodes.find(n => n.id === selectedNode);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div>
        <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Evidence Graph</h2>
        <p className="text-sm text-kavach-text-secondary">Visual representation of data flow from user input to vulnerability.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3">
          <Card>
            <CardHeader title="Data Flow Graph" subtitle="Click nodes to inspect evidence" icon={<Network className="w-4 h-4" />} />
            <CardBody>
              <div className="bg-kavach-bg rounded-md overflow-auto">
                <svg width="100%" height="450" viewBox={`0 0 ${width} ${height}`}>
                  {/* Edges */}
                  {edges.map((edge, i) => {
                    const from = nodePositions[edge.from];
                    const to = nodePositions[edge.to];
                    if (!from || !to) return null;
                    const isVuln = nodes.find(n => n.id === edge.from)?.vulnerable;
                    const isBlocked = nodes.find(n => n.id === edge.from)?.blocked;
                    return (
                      <g key={i}>
                        <line
                          x1={from.x + 25} y1={from.y}
                          x2={to.x - 25} y2={to.y}
                          stroke={isBlocked ? '#10b981' : isVuln ? '#ef4444' : '#334155'}
                          strokeWidth={isVuln ? 2 : 1}
                          strokeDasharray={isBlocked ? '4 4' : 'none'}
                          opacity={0.7}
                        />
                        <text
                          x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 4}
                          fill="#64748b" fontSize="9" textAnchor="middle" fontFamily="monospace"
                        >
                          {edge.label}
                        </text>
                      </g>
                    );
                  })}
                  {/* Nodes */}
                  {nodes.map((node) => {
                    const pos = nodePositions[node.id];
                    if (!pos) return null;
                    const color = nodeTypeColors[node.type] || '#64748b';
                    const isSelected = selectedNode === node.id;
                    return (
                      <g key={node.id} className="graph-node" onClick={() => setSelectedNode(node.id)} style={{ cursor: 'pointer' }}>
                        <circle
                          cx={pos.x} cy={pos.y} r={isSelected ? 28 : 25}
                          fill={color} fillOpacity={isSelected ? 0.25 : 0.12}
                          stroke={color} strokeWidth={isSelected ? 3 : 2}
                        />
                        {node.vulnerable && (
                          <circle cx={pos.x} cy={pos.y} r={30} fill="none" stroke="#ef4444" strokeWidth={1} strokeDasharray="3 3" opacity={0.5}>
                            <animate attributeName="r" values="30;34;30" dur="2s" repeatCount="indefinite" />
                          </circle>
                        )}
                        <text x={pos.x} y={pos.y + 4} fill={color} fontSize="12" textAnchor="middle" fontFamily="monospace" fontWeight="bold">
                          {nodeTypeIcons[node.type] || '?'}
                        </text>
                        <text x={pos.x} y={pos.y + 42} fill="#e2e8f0" fontSize="9" textAnchor="middle" fontFamily="monospace">
                          {node.label.length > 22 ? node.label.substring(0, 20) + '..' : node.label}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            </CardBody>
          </Card>
        </div>

        <div className="space-y-4">
          {/* Node Detail */}
          <Card>
            <CardHeader title="Node Detail" />
            <CardBody>
              {selectedNodeData ? (
                <div className="space-y-2 text-xs">
                  <div><span className="text-kavach-text-muted">Label:</span> <span className="text-kavach-text-primary">{selectedNodeData.label}</span></div>
                  <div><span className="text-kavach-text-muted">Type:</span> <span className="text-kavach-text-primary font-mono">{selectedNodeData.type}</span></div>
                  {selectedNodeData.detail && <div><span className="text-kavach-text-muted">Detail:</span> <span className="text-kavach-text-secondary">{selectedNodeData.detail}</span></div>}
                  {selectedNodeData.vulnerable && <div><StatusBadge status="VULNERABLE" /></div>}
                  {selectedNodeData.blocked && <div><StatusBadge status="BLOCKED" /></div>}
                </div>
              ) : (
                <p className="text-xs text-kavach-text-muted">Click a node to inspect its evidence.</p>
              )}
            </CardBody>
          </Card>

          {/* Evidence Sources */}
          {evidence.length > 0 && (
            <Card>
              <CardHeader title="Evidence Sources" />
              <CardBody>
                <div className="space-y-2">
                  {evidence[0].sources.map((src, i) => (
                    <div key={i} className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-kavach-text-muted">{src.toolType}</span>
                        <StatusBadge status={src.status} />
                      </div>
                      <AuthenticityBadge authenticity={src.authenticity} />
                      <p className="text-xs text-kavach-text-secondary">{src.detail}</p>
                    </div>
                  ))}
                </div>
              </CardBody>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
