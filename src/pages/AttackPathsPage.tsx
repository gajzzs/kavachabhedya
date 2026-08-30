import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { StatusBadge, AuthenticityBadge } from '@/components/ui/Badge';
import { GitBranch } from 'lucide-react';
import { useState } from 'react';

export function AttackPathsPage() {
  const { attackPath, findings, patches } = useKavach();
  const [showAfterPatch, setShowAfterPatch] = useState(false);

  if (!attackPath) {
    return (
      <div className="flex items-center justify-center h-full">
        <Card className="max-w-md">
          <CardBody className="text-center">
            <GitBranch className="w-12 h-12 text-kavach-text-muted mx-auto mb-3" />
            <p className="text-sm text-kavach-text-secondary">No attack path data yet.</p>
            <p className="text-xs text-kavach-text-muted mt-1">Run a Real Assessment or the Kavach demo to generate attack paths.</p>
          </CardBody>
        </Card>
      </div>
    );
  }

  const hasPatch = attackPath.blockedAfterPatch || patches.length > 0;
  const nodes = attackPath.nodes;
  const edges = attackPath.edges;

  // Linear layout for attack path
  const width = 800;
  const height = 200;
  const pathNodes = nodes.filter(n => ['INPUT', 'API', 'FUNCTION', 'VARIABLE', 'DATABASE', 'VULNERABILITY', 'PATCH', 'VERIFICATION'].includes(n.type));
  const nodeSpacing = width / (pathNodes.length + 1);
  const nodePositions: Record<string, { x: number; y: number }> = {};
  pathNodes.forEach((node, i) => {
    nodePositions[node.id] = { x: nodeSpacing * (i + 1), y: height / 2 };
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Attack Path</h2>
          <p className="text-sm text-kavach-text-secondary">Visual representation of how a vulnerability affects the system.</p>
        </div>
        {hasPatch && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowAfterPatch(false)}
              className={`kavach-btn ${!showAfterPatch ? 'kavach-btn-primary' : 'kavach-btn-secondary'}`}
            >
              Before Patch
            </button>
            <button
              onClick={() => setShowAfterPatch(true)}
              className={`kavach-btn ${showAfterPatch ? 'kavach-btn-primary' : 'kavach-btn-secondary'}`}
            >
              After Patch
            </button>
          </div>
        )}
      </div>

      <Card>
        <CardHeader title="Attack Path Visualization" subtitle={showAfterPatch ? 'Attack path is BLOCKED after patch' : 'Attack path is ACTIVE'} icon={<GitBranch className="w-4 h-4" />} />
        <CardBody>
          <div className="bg-kavach-bg rounded-md overflow-auto">
            <svg width="100%" height="220" viewBox={`0 0 ${width} ${height + 20}`}>
              {/* Edges */}
              {edges.map((edge, i) => {
                const from = nodePositions[edge.from];
                const to = nodePositions[edge.to];
                if (!from || !to) return null;
                const showAsBlocked = showAfterPatch && (edge.type === 'FIXED_BY' || edge.type === 'VERIFIED_BY');
                const showVuln = !showAfterPatch || !['PATCH', 'VERIFICATION'].includes(
                  nodes.find(n => n.id === edge.from)?.type || ''
                );
                const color = showAsBlocked ? '#10b981' : showVuln ? '#ef4444' : '#334155';
                return (
                  <g key={i}>
                    <line
                      x1={from.x + 25} y1={from.y}
                      x2={to.x - 25} y2={to.y}
                      stroke={color}
                      strokeWidth={2}
                      strokeDasharray={showAsBlocked ? '4 4' : 'none'}
                      opacity={0.7}
                    />
                    <text x={(from.x + to.x) / 2} y={from.y - 8} fill={color} fontSize="9" textAnchor="middle" fontFamily="monospace">
                      {edge.label}
                    </text>
                  </g>
                );
              })}
              {/* Nodes */}
              {pathNodes.map((node) => {
                const pos = nodePositions[node.id];
                if (!pos) return null;
                const isVuln = node.vulnerable && (!showAfterPatch || !['PATCH', 'VERIFICATION'].includes(node.type));
                const isBlocked = showAfterPatch && (node.blocked || ['PATCH', 'VERIFICATION'].includes(node.type));
                const color = isBlocked ? '#10b981' : isVuln ? '#ef4444' : '#06b6d4';
                return (
                  <g key={node.id}>
                    <circle cx={pos.x} cy={pos.y} r={25} fill={color} fillOpacity={0.15} stroke={color} strokeWidth={2} />
                    <text x={pos.x} y={pos.y + 45} fill="#e2e8f0" fontSize="9" textAnchor="middle" fontFamily="monospace">
                      {node.label.length > 18 ? node.label.substring(0, 16) + '..' : node.label}
                    </text>
                    {isVuln && (
                      <circle cx={pos.x} cy={pos.y} r={30} fill="none" stroke="#ef4444" strokeWidth={1} strokeDasharray="3 3" opacity={0.5}>
                        <animate attributeName="r" values="30;34;30" dur="2s" repeatCount="indefinite" />
                      </circle>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
        </CardBody>
      </Card>

      {/* Path Details */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardBody>
            <p className="kavach-section-title mb-1">Entry Point</p>
            <p className="text-sm text-kavach-text-primary">{attackPath.entryPoint}</p>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <p className="kavach-section-title mb-1">Impact</p>
            <p className="text-sm text-kavach-text-primary">{attackPath.impact}</p>
          </CardBody>
        </Card>
        <Card>
          <CardBody>
            <p className="kavach-section-title mb-1">Status</p>
            <StatusBadge status={showAfterPatch ? 'BLOCKED' : 'VULNERABLE'} />
          </CardBody>
        </Card>
      </div>

      {/* Path Steps */}
      <Card>
        <CardHeader title="Path Steps" subtitle="Detailed breakdown of the attack path" />
        <CardBody>
          <div className="space-y-2">
            {pathNodes.map((node, i) => (
              <div key={node.id} className="flex items-center gap-3 p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <span className="text-xs font-mono text-kavach-text-muted w-6">{i + 1}</span>
                <div className="flex-1">
                  <span className="text-sm text-kavach-text-primary">{node.label}</span>
                  {node.detail && <p className="text-xs text-kavach-text-muted mt-0.5">{node.detail}</p>}
                </div>
                {node.vulnerable && !showAfterPatch && <StatusBadge status="VULNERABLE" />}
                {node.blocked && showAfterPatch && <StatusBadge status="BLOCKED" />}
              </div>
            ))}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
