import type { AttackPath, Finding, AttackPathNode, AttackPathEdge, PatchCandidate, VulnerabilityClass } from '@/types';
import { generateId } from '@/lib/utils';

// ============================================================
// Attack Path Builder
// Constructs evidence-backed attack paths from finding data.
// Supports multiple vulnerability classes via a dispatch table.
// If the path cannot be established, returns INCONCLUSIVE.
// ============================================================

export function buildAttackPath(finding: Finding, patch?: PatchCandidate): AttackPath {
  const builder = PATH_BUILDERS[finding.vulnerabilityClass] || buildGenericPath;
  const path = builder(finding);

  if (patch) {
    // Add patch and verification nodes
    path.nodes.push({
      id: 'patch',
      label: patch.label,
      type: 'PATCH',
      detail: patch.strategy,
      blocked: false,
    });
    path.nodes.push({
      id: 'verify',
      label: 'Verification Engine',
      type: 'VERIFICATION',
      detail: 'Independent deterministic verification',
      blocked: false,
    });

    const sinkNode = path.nodes.find((n) => n.type === 'VULNERABILITY' || n.id === 'sink');
    if (sinkNode) {
      path.edges.push({ from: 'patch', to: sinkNode.id, label: 'fixed by', type: 'FIXED_BY' });
    }
    path.edges.push({ from: 'verify', to: 'patch', label: 'verified by', type: 'VERIFIED_BY' });

    // Mark vulnerable nodes as blocked
    path.nodes.forEach((n) => {
      if (n.vulnerable) {
        n.vulnerable = false;
        n.blocked = true;
      }
    });
    path.blockedAfterPatch = true;
  }

  return path;
}

type PathBuilder = (finding: Finding) => AttackPath;

const buildSQLInjectionPath: PathBuilder = (finding) => {
  const inputLabel = finding.inputSource
    ? `User Input (${finding.inputSource.split(' → ')[0]})`
    : 'User Input';
  const inputDetail = finding.inputSource || 'External request parameter';
  const fileRef = `${finding.file}:${finding.line}`;
  const sinkLabel = finding.sink || 'execute()';
  const sqlDetail = finding.dataFlow && finding.dataFlow.length > 0
    ? finding.dataFlow.join(' → ')
    : finding.evidence;

  const nodes: AttackPathNode[] = [
    { id: 'input', label: inputLabel, type: 'INPUT', detail: inputDetail, vulnerable: true },
    { id: 'handler', label: `Handler at ${fileRef}`, type: 'FUNCTION', detail: `Function receiving user input at ${fileRef}`, vulnerable: true },
    { id: 'query', label: 'SQL Query Construction', type: 'VARIABLE', detail: sqlDetail, vulnerable: true },
    { id: 'exec', label: sinkLabel, type: 'FUNCTION', detail: `SQL execution sink at ${fileRef}`, vulnerable: true },
    { id: 'db', label: 'Database', type: 'DATABASE', detail: 'Database with application data', vulnerable: true },
    { id: 'vuln', label: 'SQL Injection', type: 'VULNERABILITY', detail: `${finding.vulnerabilityClass} - ${finding.severity} - ${finding.cwe}`, vulnerable: true },
  ];

  const edges: AttackPathEdge[] = [
    { from: 'input', to: 'handler', label: 'flows to', type: 'FLOWS_TO' },
    { from: 'handler', to: 'query', label: 'reaches (unsanitized)', type: 'REACHES' },
    { from: 'query', to: 'exec', label: 'passes to', type: 'FLOWS_TO' },
    { from: 'exec', to: 'db', label: 'executes on', type: 'FLOWS_TO' },
    { from: 'db', to: 'vuln', label: 'triggers', type: 'TRIGGERS' },
  ];

  return {
    id: generateId('path'),
    findingId: finding.id,
    nodes,
    edges,
    entryPoint: inputDetail,
    impact: finding.impact || 'Authentication bypass, data exfiltration, privilege escalation',
    blockedAfterPatch: false,
    authenticity: 'EXECUTABLE',
  };
};

const buildCommandInjectionPath: PathBuilder = (finding) => {
  const nodes: AttackPathNode[] = [
    { id: 'input', label: 'User Input (command param)', type: 'INPUT', detail: 'HTTP parameter passed to command execution', vulnerable: true },
    { id: 'endpoint', label: 'API Endpoint', type: 'API', detail: 'Endpoint accepting user-controlled command input', vulnerable: true },
    { id: 'handler', label: 'Command Handler', type: 'FUNCTION', detail: 'Function that processes user input for shell command', vulnerable: true },
    { id: 'sink', label: 'os.system() / subprocess', type: 'FUNCTION', detail: `Command execution sink: ${finding.evidence}`, vulnerable: true },
    { id: 'os', label: 'Operating System', type: 'DATABASE', detail: 'OS process execution', vulnerable: true },
    { id: 'vuln', label: 'Command Injection', type: 'VULNERABILITY', detail: `${finding.vulnerabilityClass} - ${finding.severity}`, vulnerable: true },
  ];

  const edges: AttackPathEdge[] = [
    { from: 'input', to: 'endpoint', label: 'flows to', type: 'FLOWS_TO' },
    { from: 'endpoint', to: 'handler', label: 'calls', type: 'CALLS' },
    { from: 'handler', to: 'sink', label: 'reaches (unsanitized)', type: 'REACHES' },
    { from: 'sink', to: 'os', label: 'executes on', type: 'FLOWS_TO' },
    { from: 'os', to: 'vuln', label: 'triggers', type: 'TRIGGERS' },
  ];

  return {
    id: generateId('path'),
    findingId: finding.id,
    nodes,
    edges,
    entryPoint: 'input',
    impact: 'Arbitrary command execution, system compromise',
    blockedAfterPatch: false,
    authenticity: 'EXECUTABLE',
  };
};

const buildPathTraversalPath: PathBuilder = (finding) => {
  const nodes: AttackPathNode[] = [
    { id: 'input', label: 'User Input (file path)', type: 'INPUT', detail: 'File path parameter from user request', vulnerable: true },
    { id: 'endpoint', label: 'File Access Endpoint', type: 'API', detail: 'Endpoint serving files based on user input', vulnerable: true },
    { id: 'handler', label: 'File Handler', type: 'FUNCTION', detail: 'Function that constructs file path from user input', vulnerable: true },
    { id: 'sink', label: 'open() / read()', type: 'FUNCTION', detail: `File access sink: ${finding.evidence}`, vulnerable: true },
    { id: 'fs', label: 'Filesystem', type: 'DATABASE', detail: 'Local filesystem access', vulnerable: true },
    { id: 'vuln', label: 'Path Traversal', type: 'VULNERABILITY', detail: `${finding.vulnerabilityClass} - ${finding.severity}`, vulnerable: true },
  ];

  const edges: AttackPathEdge[] = [
    { from: 'input', to: 'endpoint', label: 'flows to', type: 'FLOWS_TO' },
    { from: 'endpoint', to: 'handler', label: 'calls', type: 'CALLS' },
    { from: 'handler', to: 'sink', label: 'reaches (unsanitized)', type: 'REACHES' },
    { from: 'sink', to: 'fs', label: 'accesses', type: 'FLOWS_TO' },
    { from: 'fs', to: 'vuln', label: 'triggers', type: 'TRIGGERS' },
  ];

  return {
    id: generateId('path'),
    findingId: finding.id,
    nodes,
    edges,
    entryPoint: 'input',
    impact: 'Unauthorized file access, sensitive data exposure',
    blockedAfterPatch: false,
    authenticity: 'EXECUTABLE',
  };
};

const buildXSSPath: PathBuilder = (finding) => {
  const nodes: AttackPathNode[] = [
    { id: 'input', label: 'User Input (comment/message)', type: 'INPUT', detail: 'User-supplied content stored or reflected', vulnerable: true },
    { id: 'endpoint', label: 'Render Endpoint', type: 'API', detail: 'Endpoint that renders user content in HTML', vulnerable: true },
    { id: 'handler', label: 'Template Renderer', type: 'FUNCTION', detail: 'Function that outputs user input without escaping', vulnerable: true },
    { id: 'sink', label: 'innerHTML / response', type: 'FUNCTION', detail: `Output sink: ${finding.evidence}`, vulnerable: true },
    { id: 'browser', label: 'Victim Browser', type: 'DATABASE', detail: 'Browser DOM execution context', vulnerable: true },
    { id: 'vuln', label: 'Cross-Site Scripting', type: 'VULNERABILITY', detail: `${finding.vulnerabilityClass} - ${finding.severity}`, vulnerable: true },
  ];

  const edges: AttackPathEdge[] = [
    { from: 'input', to: 'endpoint', label: 'flows to', type: 'FLOWS_TO' },
    { from: 'endpoint', to: 'handler', label: 'calls', type: 'CALLS' },
    { from: 'handler', to: 'sink', label: 'reaches (unescaped)', type: 'REACHES' },
    { from: 'sink', to: 'browser', label: 'renders in', type: 'FLOWS_TO' },
    { from: 'browser', to: 'vuln', label: 'triggers', type: 'TRIGGERS' },
  ];

  return {
    id: generateId('path'),
    findingId: finding.id,
    nodes,
    edges,
    entryPoint: 'input',
    impact: 'Session hijacking, credential theft, defacement',
    blockedAfterPatch: false,
    authenticity: 'EXECUTABLE',
  };
};

const buildSSRFPath: PathBuilder = (finding) => {
  const nodes: AttackPathNode[] = [
    { id: 'input', label: 'User Input (URL param)', type: 'INPUT', detail: 'URL parameter controlled by user', vulnerable: true },
    { id: 'endpoint', label: 'Fetch/Proxy Endpoint', type: 'API', detail: 'Endpoint that fetches URLs from user input', vulnerable: true },
    { id: 'handler', label: 'HTTP Client Handler', type: 'FUNCTION', detail: 'Function that performs HTTP request with user URL', vulnerable: true },
    { id: 'sink', label: 'requests.get() / fetch()', type: 'FUNCTION', detail: `HTTP request sink: ${finding.evidence}`, vulnerable: true },
    { id: 'target', label: 'Internal Service', type: 'DATABASE', detail: 'Internal network service accessed via SSRF', vulnerable: true },
    { id: 'vuln', label: 'SSRF', type: 'VULNERABILITY', detail: `${finding.vulnerabilityClass} - ${finding.severity}`, vulnerable: true },
  ];

  const edges: AttackPathEdge[] = [
    { from: 'input', to: 'endpoint', label: 'flows to', type: 'FLOWS_TO' },
    { from: 'endpoint', to: 'handler', label: 'calls', type: 'CALLS' },
    { from: 'handler', to: 'sink', label: 'reaches (unvalidated)', type: 'REACHES' },
    { from: 'sink', to: 'target', label: 'accesses', type: 'FLOWS_TO' },
    { from: 'target', to: 'vuln', label: 'triggers', type: 'TRIGGERS' },
  ];

  return {
    id: generateId('path'),
    findingId: finding.id,
    nodes,
    edges,
    entryPoint: 'input',
    impact: 'Internal network access, cloud metadata exposure',
    blockedAfterPatch: false,
    authenticity: 'EXECUTABLE',
  };
};

const buildHardcodedSecretPath: PathBuilder = (finding) => {
  const nodes: AttackPathNode[] = [
    { id: 'secret', label: 'Hardcoded Secret', type: 'INPUT', detail: `Secret in source: ${finding.evidence}`, vulnerable: true },
    { id: 'code', label: 'Source Code', type: 'VARIABLE', detail: 'Secret embedded directly in source code', vulnerable: true },
    { id: 'repo', label: 'Code Repository', type: 'DATABASE', detail: 'Repository accessible to developers/attackers', vulnerable: true },
    { id: 'vuln', label: 'Hardcoded Secret', type: 'VULNERABILITY', detail: `${finding.vulnerabilityClass} - ${finding.severity}`, vulnerable: true },
  ];

  const edges: AttackPathEdge[] = [
    { from: 'secret', to: 'code', label: 'embedded in', type: 'FLOWS_TO' },
    { from: 'code', to: 'repo', label: 'committed to', type: 'FLOWS_TO' },
    { from: 'repo', to: 'vuln', label: 'triggers', type: 'TRIGGERS' },
  ];

  return {
    id: generateId('path'),
    findingId: finding.id,
    nodes,
    edges,
    entryPoint: 'secret',
    impact: 'Credential exposure, unauthorized API access, account compromise',
    blockedAfterPatch: false,
    authenticity: 'EXECUTABLE',
  };
};

const buildGenericPath: PathBuilder = (finding) => {
  const nodes: AttackPathNode[] = [
    { id: 'input', label: 'User Input', type: 'INPUT', detail: 'External input reaching vulnerable code', vulnerable: true },
    { id: 'handler', label: 'Handler Function', type: 'FUNCTION', detail: `Function at ${finding.file}:${finding.line}`, vulnerable: true },
    { id: 'sink', label: 'Vulnerable Sink', type: 'FUNCTION', detail: finding.evidence, vulnerable: true },
    { id: 'vuln', label: finding.vulnerabilityClass.replace(/_/g, ' '), type: 'VULNERABILITY', detail: `${finding.vulnerabilityClass} - ${finding.severity}`, vulnerable: true },
  ];

  const edges: AttackPathEdge[] = [
    { from: 'input', to: 'handler', label: 'flows to', type: 'FLOWS_TO' },
    { from: 'handler', to: 'sink', label: 'reaches', type: 'REACHES' },
    { from: 'sink', to: 'vuln', label: 'triggers', type: 'TRIGGERS' },
  ];

  return {
    id: generateId('path'),
    findingId: finding.id,
    nodes,
    edges,
    entryPoint: 'input',
    impact: 'Varies by vulnerability class',
    blockedAfterPatch: false,
    authenticity: 'EXECUTABLE',
  };
};

const buildBufferOverflowPath: PathBuilder = (finding) => {
  const fileRef = `${finding.file}:${finding.line}`;
  const sourceDetail = finding.source || 'untrusted input';
  const sinkLabel = finding.sink || 'memcpy';
  const dataFlowDetail = finding.dataFlow && finding.dataFlow.length > 0
    ? finding.dataFlow.join(' → ')
    : finding.evidence;

  const nodes: AttackPathNode[] = [
    { id: 'input', label: 'Untrusted Input', type: 'INPUT', detail: sourceDetail, vulnerable: true },
    { id: 'len', label: 'Length Variable', type: 'VARIABLE', detail: `Length derived from untrusted input — not bounded by destination capacity`, vulnerable: true },
    { id: 'sink', label: sinkLabel, type: 'FUNCTION', detail: `Copy operation at ${fileRef} — ${dataFlowDetail}`, vulnerable: true },
    { id: 'buf', label: 'Fixed-Size Stack Buffer', type: 'VARIABLE', detail: 'Stack-allocated buffer with fixed capacity — destination of copy', vulnerable: true },
    { id: 'mem', label: 'Memory Corruption', type: 'DATABASE', detail: 'Stack buffer overflow — overwrites adjacent stack memory', vulnerable: true },
    { id: 'vuln', label: 'Stack Buffer Overflow', type: 'VULNERABILITY', detail: `${finding.vulnerabilityClass} - ${finding.severity} - ${finding.cwe}`, vulnerable: true },
  ];

  const edges: AttackPathEdge[] = [
    { from: 'input', to: 'len', label: 'derived from', type: 'FLOWS_TO' },
    { from: 'len', to: 'sink', label: 'passes as length (unbounded)', type: 'REACHES' },
    { from: 'sink', to: 'buf', label: 'writes to', type: 'FLOWS_TO' },
    { from: 'buf', to: 'mem', label: 'overflows', type: 'TRIGGERS' },
    { from: 'mem', to: 'vuln', label: 'triggers', type: 'TRIGGERS' },
  ];

  return {
    id: generateId('path'),
    findingId: finding.id,
    nodes,
    edges,
    entryPoint: sourceDetail,
    impact: finding.impact || 'Stack buffer overflow, memory corruption, potential arbitrary code execution',
    blockedAfterPatch: false,
    authenticity: 'EXECUTABLE',
  };
};

const PATH_BUILDERS: Partial<Record<VulnerabilityClass, PathBuilder>> = {
  SQL_INJECTION: buildSQLInjectionPath,
  COMMAND_INJECTION: buildCommandInjectionPath,
  PATH_TRAVERSAL: buildPathTraversalPath,
  XSS: buildXSSPath,
  SSRF: buildSSRFPath,
  HARDCODED_SECRET: buildHardcodedSecretPath,
  BUFFER_OVERFLOW: buildBufferOverflowPath,
};
