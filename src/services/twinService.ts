import type { TwinSnapshot, TwinNode, TwinEdge, Finding, PatchCandidate, AttackPath } from '@/types';
import { generateId } from '@/lib/utils';

// ============================================================
// Security Digital Twin Service
// Represents a safe, isolated replica of the demo application.
// Supports snapshots and what-if simulations.
// This is a SANDBOXED application/security twin, NOT a real
// infrastructure twin.
// ============================================================

function createBaseNodes(): TwinNode[] {
  return [
    { id: 'client', label: 'HTTP Client', type: 'TRUST_BOUNDARY', status: 'UNKNOWN', detail: 'External request source' },
    { id: 'api', label: 'FastAPI App', type: 'APP', status: 'SECURE', detail: 'Web application server' },
    { id: 'search-endpoint', label: 'GET /api/users/search', type: 'API', status: 'SECURE', detail: 'User search endpoint' },
    { id: 'get-endpoint', label: 'GET /api/users/{id}', type: 'API', status: 'SECURE', detail: 'User by ID endpoint' },
    { id: 'search-handler', label: 'search_users()', type: 'FUNCTION', status: 'SECURE', detail: 'Search handler function' },
    { id: 'get-handler', label: 'get_user()', type: 'FUNCTION', status: 'SECURE', detail: 'Get user handler' },
    { id: 'query-builder', label: 'SQL Query Construction', type: 'FUNCTION', status: 'SECURE', detail: 'Builds SQL query' },
    { id: 'db-exec', label: 'Database Execute', type: 'FUNCTION', status: 'SECURE', detail: 'Executes SQL' },
    { id: 'database', label: 'SQLite Database', type: 'DATABASE', status: 'SECURE', detail: 'In-memory SQLite' },
    { id: 'input-validation', label: 'Input Validation', type: 'CONTROL', status: 'SECURE', detail: 'Input sanitization layer' },
  ];
}

function createBaseEdges(): TwinEdge[] {
  return [
    { from: 'client', to: 'api', label: 'HTTP request', type: 'FLOWS_TO' },
    { from: 'api', to: 'search-endpoint', label: 'routes to', type: 'CALLS' },
    { from: 'api', to: 'get-endpoint', label: 'routes to', type: 'CALLS' },
    { from: 'search-endpoint', to: 'search-handler', label: 'invokes', type: 'CALLS' },
    { from: 'get-endpoint', to: 'get-handler', label: 'invokes', type: 'CALLS' },
    { from: 'search-handler', to: 'query-builder', label: 'constructs query', type: 'FLOWS_TO' },
    { from: 'query-builder', to: 'db-exec', label: 'passes query', type: 'FLOWS_TO' },
    { from: 'db-exec', to: 'database', label: 'executes SQL', type: 'FLOWS_TO' },
    { from: 'get-handler', to: 'db-exec', label: 'parameterized query', type: 'FLOWS_TO' },
  ];
}

function markVulnerable(nodes: TwinNode[], edges: TwinEdge[]): void {
  const searchHandler = nodes.find((n) => n.id === 'search-handler');
  if (searchHandler) {
    searchHandler.status = 'VULNERABLE';
    searchHandler.detail = 'VULNERABLE: User input concatenated into SQL query';
  }
  const queryBuilder = nodes.find((n) => n.id === 'query-builder');
  if (queryBuilder) {
    queryBuilder.status = 'VULNERABLE';
    queryBuilder.detail = 'VULNERABLE: f-string interpolation of user input into SQL';
  }
  const searchEndpoint = nodes.find((n) => n.id === 'search-endpoint');
  if (searchEndpoint) {
    searchEndpoint.status = 'VULNERABLE';
    searchEndpoint.detail = 'VULNERABLE: Exposed to SQL injection';
  }

  const edge = edges.find((e) => e.from === 'search-handler' && e.to === 'query-builder');
  if (edge) {
    edge.vulnerable = true;
    edge.label = 'UNSANITIZED user input';
  }
  const edge2 = edges.find((e) => e.from === 'query-builder' && e.to === 'db-exec');
  if (edge2) {
    edge2.vulnerable = true;
    edge2.label = 'Unsafe SQL string';
  }
}

function markPatched(nodes: TwinNode[], edges: TwinEdge[], patch: PatchCandidate): void {
  const searchHandler = nodes.find((n) => n.id === 'search-handler');
  if (searchHandler) {
    searchHandler.status = 'PATCHED';
    searchHandler.detail = `PATCHED: ${patch.strategy}`;
  }
  const queryBuilder = nodes.find((n) => n.id === 'query-builder');
  if (queryBuilder) {
    queryBuilder.status = 'PATCHED';
    queryBuilder.detail = `PATCHED: Parameterized query with placeholder`;
  }
  const searchEndpoint = nodes.find((n) => n.id === 'search-endpoint');
  if (searchEndpoint) {
    searchEndpoint.status = 'PATCHED';
    searchEndpoint.detail = 'PATCHED: SQL injection remediated';
  }

  // Block the vulnerable edges
  const edge = edges.find((e) => e.from === 'search-handler' && e.to === 'query-builder');
  if (edge) {
    edge.vulnerable = false;
    edge.blocked = true;
    edge.label = 'Sanitized input → parameterized';
  }
  const edge2 = edges.find((e) => e.from === 'query-builder' && e.to === 'db-exec');
  if (edge2) {
    edge2.vulnerable = false;
    edge2.blocked = true;
    edge2.label = 'Parameterized SQL (safe)';
  }

  // If patch B, activate input validation
  if (patch.strategy.includes('Input Validation')) {
    const validation = nodes.find((n) => n.id === 'input-validation');
    if (validation) {
      validation.status = 'SECURE';
      validation.detail = 'ACTIVE: Input validation rejecting malicious patterns';
    }
    // Add edge from search-handler to validation
    if (!edges.find((e) => e.from === 'search-handler' && e.to === 'input-validation')) {
      edges.push({
        from: 'search-handler',
        to: 'input-validation',
        label: 'validates input',
        type: 'FLOWS_TO',
        blocked: true,
      });
    }
  }
}

export function createT0Snapshot(): TwinSnapshot {
  const nodes = createBaseNodes();
  const edges = createBaseEdges();
  return {
    id: generateId('twin'),
    label: 'T0 - Original State',
    timestamp: new Date().toISOString(),
    description: 'Initial application state before any security analysis. All components assumed secure.',
    state: 'ORIGINAL',
    nodes,
    edges,
    attackPathActive: false,
  };
}

export function createT1Snapshot(finding: Finding): TwinSnapshot {
  const nodes = createBaseNodes();
  const edges = createBaseEdges();
  markVulnerable(nodes, edges);
  return {
    id: generateId('twin'),
    label: 'T1 - Vulnerability Discovered',
    timestamp: new Date().toISOString(),
    description: `Vulnerability detected: ${finding.vulnerabilityClass} at ${finding.file}:${finding.line}. Attack path is active.`,
    state: 'VULNERABLE',
    nodes,
    edges,
    attackPathActive: true,
  };
}

export function createT2Snapshot(patch: PatchCandidate): TwinSnapshot {
  const nodes = createBaseNodes();
  const edges = createBaseEdges();
  markVulnerable(nodes, edges);
  markPatched(nodes, edges, patch);
  return {
    id: generateId('twin'),
    label: `T2 - ${patch.label} Applied`,
    timestamp: new Date().toISOString(),
    description: `Patch candidate applied to sandbox: ${patch.strategy}. Attack path is blocked.`,
    state: 'PATCHED_A',
    nodes,
    edges,
    attackPathActive: false,
    patchApplied: patch.id,
  };
}

export function createVerifiedSnapshot(patch: PatchCandidate): TwinSnapshot {
  const nodes = createBaseNodes();
  const edges = createBaseEdges();
  markPatched(nodes, edges, patch);
  // Mark all as secure
  nodes.forEach((n) => {
    if (n.status === 'VULNERABLE') n.status = 'PATCHED';
  });
  return {
    id: generateId('twin'),
    label: 'T4 - Verified Fix',
    timestamp: new Date().toISOString(),
    description: `Patch verified by independent verification engine. ${patch.strategy} confirmed as effective.`,
    state: 'VERIFIED',
    nodes,
    edges,
    attackPathActive: false,
    patchApplied: patch.id,
  };
}

export function resetTwin(): TwinSnapshot {
  return createT0Snapshot();
}
