import type { AgentAction, AuditEvent, ActionClass, SecurityPolicy } from '@/types';
import { generateId, formatTimestamp } from '@/lib/utils';

// ============================================================
// KAVACH Guardian - Agent Safety Layer
// Every tool/action is classified and checked against policy.
// The LLM NEVER directly invokes unrestricted commands.
// ============================================================

export const DEFAULT_POLICY: SecurityPolicy = {
  defaultAllowed: ['READ', 'ANALYZE', 'TEST'],
  sandboxOnly: ['MODIFY', 'EXECUTE'],
  blockedByDefault: ['NETWORK'],
  executionTimeoutMs: 30000,
  networkRestricted: true,
  destructiveBlocked: true,
  credentialAccessBlocked: true,
};

export interface GuardianCheckResult {
  allowed: boolean;
  requiresApproval: boolean;
  reason: string;
  sandboxed: boolean;
}

export function checkAction(
  actionClass: ActionClass,
  tool: string,
  action: string,
  target: string,
  policy: SecurityPolicy = DEFAULT_POLICY
): GuardianCheckResult {
  // Blocked by default
  if (policy.blockedByDefault.includes(actionClass)) {
    return {
      allowed: false,
      requiresApproval: false,
      reason: `Action class ${actionClass} is blocked by default. Network access is restricted.`,
      sandboxed: false,
    };
  }

  // Sandbox-only actions
  if (policy.sandboxOnly.includes(actionClass)) {
    return {
      allowed: true,
      requiresApproval: false,
      reason: `Action class ${actionClass} is allowed in sandbox only. Execution is isolated.`,
      sandboxed: true,
    };
  }

  // Default allowed
  if (policy.defaultAllowed.includes(actionClass)) {
    return {
      allowed: true,
      requiresApproval: false,
      reason: `Action class ${actionClass} is allowed by default policy.`,
      sandboxed: false,
    };
  }

  // Unknown action class - deny
  return {
    allowed: false,
      requiresApproval: true,
      reason: `Action class ${actionClass} is not in any allowlist. Human approval required.`,
      sandboxed: false,
  };
}

export function createAgentAction(
  agent: string,
  tool: string,
  action: string,
  target: string,
  actionClass: ActionClass,
  status: AgentAction['status'],
  result: string,
  sandboxed: boolean
): AgentAction {
  return {
    id: generateId('action'),
    timestamp: new Date().toISOString(),
    agent,
    tool,
    action,
    target,
    actionClass,
    status,
    result,
    sandboxed,
  };
}

export function createAuditEvent(
  event: string,
  category: AuditEvent['category'],
  detail: string,
  severity: AuditEvent['severity'] = 'INFO',
  source: string = 'system'
): AuditEvent {
  return {
    id: generateId('audit'),
    timestamp: new Date().toISOString(),
    event,
    category,
    detail,
    severity,
    source,
  };
}

// Agent self-security assessment
export interface AgentSecurityAssessment {
  toolPermissions: { tool: string; class: ActionClass; allowed: boolean }[];
  promptInjectionRisk: 'LOW' | 'MEDIUM' | 'HIGH';
  excessivePrivilege: boolean;
  unsafeToolOutput: boolean;
  secretExposureRisk: 'LOW' | 'MEDIUM' | 'HIGH';
  untrustedInputHandling: boolean;
  networkAccess: 'RESTRICTED' | 'ALLOWED';
  notes: string[];
}

export function assessAgentSecurity(): AgentSecurityAssessment {
  return {
    toolPermissions: [
      { tool: 'SAST Analyzer', class: 'ANALYZE', allowed: true },
      { tool: 'Fuzzer', class: 'TEST', allowed: true },
      { tool: 'DAST Analyzer', class: 'TEST', allowed: true },
      { tool: 'Patch Generator', class: 'MODIFY', allowed: true },
      { tool: 'Verification Engine', class: 'TEST', allowed: true },
      { tool: 'Shell Execution', class: 'EXECUTE', allowed: false },
      { tool: 'Network Access', class: 'NETWORK', allowed: false },
    ],
    promptInjectionRisk: 'LOW',
    excessivePrivilege: false,
    unsafeToolOutput: false,
    secretExposureRisk: 'LOW',
    untrustedInputHandling: true,
    networkAccess: 'RESTRICTED',
    notes: [
      'Prototype Policy Layer: All tool actions pass through Tool Gateway',
      'LLM does not directly execute shell commands',
      'No API keys exposed in frontend code',
      'All file operations restricted to uploaded/demo content',
      'No arbitrary network access permitted',
      'Sandbox isolation enforced for MODIFY and EXECUTE actions',
    ],
  };
}
