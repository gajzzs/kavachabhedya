import type { SecurityMemory, Finding, PatchCandidate, VerificationRun } from '@/types';
import { generateId, generateKavachId } from '@/lib/utils';

// ============================================================
// Security Immune Memory Service
// Only VERIFIED outcomes become trusted memories.
// Stores source hash so revalidation can be triggered when
// the source changes. Never blindly reuses historical patches.
// ============================================================

export function createSecurityMemory(
  finding: Finding,
  patch: PatchCandidate,
  verification: VerificationRun,
  sourceHash: string
): SecurityMemory {
  return {
    id: generateId('memory'),
    kavachId: generateKavachId(),
    vulnerabilityClass: finding.vulnerabilityClass,
    status: 'VERIFIED',
    originalEvidence: `${finding.vulnerabilityClass} detected at ${finding.file}:${finding.line}. Evidence: ${finding.evidence}`,
    attackPattern: `SQL injection via string concatenation: ' OR '1'='1 and variants. ${verification.mutationTests.length} mutation payloads tested.`,
    patchApplied: `${patch.label}: ${patch.strategy}. ${patch.description}`,
    verificationResult: verification.report,
    regressionTest: `Automated regression test: Re-run SAST + fuzzer against patched code. Verify no SQL injection patterns remain. ${verification.regressionTests.length} regression tests, ${verification.mutationTests.length} mutation tests.`,
    timestamp: new Date().toISOString(),
    projectVersion: sourceHash.substring(0, 12),
    sourceHash,
    revalidationState: 'CURRENT',
  };
}

export function checkRegression(
  memory: SecurityMemory,
  currentFindings: Finding[]
): { regression: boolean; detail: string } {
  const matchingFindings = currentFindings.filter(
    (f) => f.vulnerabilityClass === memory.vulnerabilityClass
  );

  if (matchingFindings.length > 0) {
    return {
      regression: true,
      detail: `REGRESSION DETECTED: ${matchingFindings.length} ${memory.vulnerabilityClass} finding(s) detected. Previously verified fix (${memory.kavachId}) is no longer effective. Review the code changes that reintroduced this vulnerability.`,
    };
  }

  return {
    regression: false,
    detail: `No regression detected. ${memory.vulnerabilityClass} has not returned.`,
  };
}

// Check if a memory record needs revalidation based on source hash
export function checkRevalidation(
  memory: SecurityMemory,
  currentSourceHash: string
): { needsRevalidation: boolean; detail: string } {
  if (memory.sourceHash !== currentSourceHash) {
    return {
      needsRevalidation: true,
      detail: `REVALIDATION REQUIRED: Source has changed since this remediation was verified. Memory record ${memory.kavachId} was verified against source hash ${memory.sourceHash.substring(0, 12)} but current source hash is ${currentSourceHash.substring(0, 12)}. Do not blindly reuse the historical patch — re-run the assessment.`,
    };
  }

  return {
    needsRevalidation: false,
    detail: `Source unchanged. Memory record ${memory.kavachId} is still valid.`,
  };
}

// Look up whether a vulnerability pattern has been seen and verified before
export function findMatchingMemory(
  memories: SecurityMemory[],
  vulnerabilityClass: string,
  sourceHash: string
): SecurityMemory | null {
  return memories.find(
    (m) => m.vulnerabilityClass === vulnerabilityClass && m.sourceHash === sourceHash && m.status === 'VERIFIED'
  ) || null;
}
