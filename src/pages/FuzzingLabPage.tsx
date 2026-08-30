import { useState, useCallback, useMemo } from 'react';
import {
  Bug,
  Play,
  Loader2,
  Terminal,
  Lightbulb,
  Target,
  Zap,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Info,
  Code2,
  Link2,
} from 'lucide-react';
import { useKavach } from '@/store/KavachContext';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { AuthenticityBadge, StatusBadge } from '@/components/ui/Badge';
import {
  runFuzzing,
  analyzeSQLQuery,
  getDemoSQLQuery,
  getVulnerableDemoQuery,
  getSecureDemoQuery,
  type SQLAnalysisResult,
} from '@/services/fuzzingService';
import type { FuzzResult, FuzzTargetType, FuzzStrategy, FuzzTestCase } from '@/types';

const TARGET_TYPES: { id: FuzzTargetType; label: string }[] = [
  { id: 'SQL', label: 'SQL' },
  { id: 'API', label: 'API' },
  { id: 'SOURCE_CODE', label: 'Source Code' },
  { id: 'JSON', label: 'JSON' },
  { id: 'HTTP', label: 'HTTP Request' },
];

const STRATEGIES: { id: FuzzStrategy; label: string }[] = [
  { id: 'LLM_SEMANTIC', label: 'LLM Semantic Generation' },
  { id: 'BOUNDARY', label: 'Boundary Testing' },
  { id: 'MUTATION', label: 'Mutation Testing' },
  { id: 'SQL_INJECTION', label: 'SQL Injection Testing' },
  { id: 'INPUT_VALIDATION', label: 'Input Validation Testing' },
  { id: 'ENCODING', label: 'Encoding/Normalization' },
];

export function FuzzingLabPage() {
  const { findings, fuzzingResult, assessment } = useKavach();

  const activeFinding = findings[0] || null;
  const hasActiveAssessment = !!assessment && findings.length > 0;

  const [mode, setMode] = useState<'ACTIVE' | 'MANUAL'>(hasActiveAssessment ? 'ACTIVE' : 'MANUAL');
  const [targetType, setTargetType] = useState<FuzzTargetType>('SQL');
  const [strategy, setStrategy] = useState<FuzzStrategy>('SQL_INJECTION');
  const [inputQuery, setInputQuery] = useState(getDemoSQLQuery());
  const [result, setResult] = useState<FuzzResult | null>(null);
  const [analysis, setAnalysis] = useState<SQLAnalysisResult | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [selectedCase, setSelectedCase] = useState<FuzzTestCase | null>(null);

  const useActiveFinding = useCallback(() => {
    if (!activeFinding) return;
    setMode('ACTIVE');
    setTargetType('SQL');
    setStrategy('SQL_INJECTION');
    // Build a representative SQL context from the finding's source snippet
    const snippet = activeFinding.codeSnippet || '';
    const queryMatch = snippet.match(/(?:SELECT|INSERT|UPDATE|DELETE)\s+.*/i);
    const contextQuery = queryMatch
      ? queryMatch[0].replace(/\n/g, ' ').trim()
      : `SELECT * FROM users WHERE username = '<INPUT>'`;
    setInputQuery(contextQuery);
    setResult(null);
    setAnalysis(null);
    setSelectedCase(null);
  }, [activeFinding]);

  const handleRun = useCallback(async () => {
    setIsRunning(true);
    setResult(null);
    setSelectedCase(null);

    const analysisResult = analyzeSQLQuery(inputQuery);
    setAnalysis(analysisResult);

    await new Promise((r) => setTimeout(r, 1500));

    const fuzzResult = runFuzzing(targetType, strategy, inputQuery);
    setResult(fuzzResult);
    setIsRunning(false);
  }, [targetType, strategy, inputQuery]);

  const loadVulnerableDemo = () => {
    setMode('MANUAL');
    setInputQuery(getVulnerableDemoQuery());
    setResult(null);
    setAnalysis(null);
  };

  const loadSecureDemo = () => {
    setMode('MANUAL');
    setInputQuery(getSecureDemoQuery());
    setResult(null);
    setAnalysis(null);
  };

  const loadBasicDemo = () => {
    setMode('MANUAL');
    setInputQuery(getDemoSQLQuery());
    setResult(null);
    setAnalysis(null);
  };

  const activeFindingLabel = useMemo(() => {
    if (!activeFinding) return null;
    return `${activeFinding.file}:${activeFinding.line} — ${activeFinding.vulnerabilityClass.replace(/_/g, ' ')}`;
  }, [activeFinding]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-kavach-text-primary mb-1">Kavach Fuzzing Lab</h2>
          <p className="text-sm text-kavach-text-secondary">
            Semantic test case generation and controlled SQL injection simulation. LLM-guided fuzzing prioritizes vulnerability-oriented inputs.
          </p>
        </div>
        <AuthenticityBadge authenticity="CONTROLLED_DEMONSTRATION" />
      </div>

      {/* Active Assessment Link */}
      {hasActiveAssessment && (
        <Card className="border-kavach-accent/20">
          <CardBody>
            <div className="flex items-start gap-3">
              <Link2 className="w-5 h-5 text-kavach-accent shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm font-semibold text-kavach-text-primary mb-1">Active Real Assessment Finding</p>
                {activeFindingLabel && (
                  <p className="text-xs text-kavach-text-secondary font-mono mb-2">{activeFindingLabel}</p>
                )}
                <p className="text-xs text-kavach-text-muted mb-3">
                  Assessment: {assessment?.assessmentId} · Source: {assessment?.sourceFilename} · Hash: {assessment?.sourceHash.substring(0, 16)}...
                </p>
                <div className="flex items-center gap-2">
                  <button
                    onClick={useActiveFinding}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                      mode === 'ACTIVE'
                        ? 'bg-kavach-accent/10 text-kavach-accent border-kavach-accent/30'
                        : 'bg-kavach-surface-2 text-kavach-text-secondary border-kavach-border hover:border-kavach-accent/20'
                    }`}
                  >
                    Use Active Finding
                  </button>
                  <button
                    onClick={() => setMode('MANUAL')}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                      mode === 'MANUAL'
                        ? 'bg-kavach-accent/10 text-kavach-accent border-kavach-accent/30'
                        : 'bg-kavach-surface-2 text-kavach-text-secondary border-kavach-border hover:border-kavach-accent/20'
                    }`}
                  >
                    Manual Mode
                  </button>
                </div>
              </div>
            </div>
          </CardBody>
        </Card>
      )}

      {/* Pipeline Fuzzer Results (from Real Assessment) */}
      {fuzzingResult && mode === 'ACTIVE' && (
        <Card className={fuzzingResult.skipped ? 'border-kavach-warning/20' : 'border-kavach-success/20'}>
          <CardHeader
            title="Pipeline Fuzzer Results"
            subtitle={fuzzingResult.skipped ? `SKIPPED — ${fuzzingResult.skipReason}` : `From Real Assessment — CONTROLLED execution (${fuzzingResult.executionMode === 'SOURCE_DERIVED' ? 'source-derived schema' : 'controlled fixture'})`}
            icon={<Zap className="w-4 h-4" />}
          />
          <CardBody>
            {/* Skipped notice */}
            {fuzzingResult.skipped && (
              <div className="p-3 rounded-md bg-kavach-warning/5 border border-kavach-warning/20 flex items-start gap-2 mb-3">
                <AlertTriangle className="w-4 h-4 text-kavach-warning shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-semibold text-kavach-warning">Fuzzing Not Applicable</p>
                  <p className="text-xs text-kavach-text-secondary mt-1">{fuzzingResult.skipReason}</p>
                  <p className="text-xs text-kavach-text-muted mt-1">The finding was still recorded from SAST and downstream stages (attack path, patch, verification) proceed based on static evidence.</p>
                </div>
              </div>
            )}
            {/* SQL Context */}
            {fuzzingResult.sqlContext && (
              <div className="mb-3 p-2.5 rounded-md bg-kavach-bg border border-kavach-border">
                <p className="text-[10px] font-mono uppercase tracking-wider text-kavach-text-muted mb-1">SQL Context (from source)</p>
                <code className="text-xs font-mono text-kavach-accent">{fuzzingResult.sqlContext}</code>
              </div>
            )}

            {/* Finding / Source / Sink */}
            {activeFinding && (
              <div className="mb-3 grid grid-cols-2 gap-2 text-[10px] font-mono">
                <div className="p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
                  <span className="text-kavach-text-muted uppercase">Finding</span>
                  <p className="text-kavach-text-secondary">{activeFinding.file}:{activeFinding.line} — {activeFinding.vulnerabilityClass.replace(/_/g, ' ')}</p>
                </div>
                <div className="p-2 rounded-md bg-kavach-surface-2 border border-kavach-border">
                  <span className="text-kavach-text-muted uppercase">Source / Sink</span>
                  <p className="text-kavach-text-secondary">{activeFinding.source || 'input'} → {activeFinding.sink || 'execute()'}</p>
                </div>
              </div>
            )}

            {/* Baseline */}
            {fuzzingResult.baseline && (
              <div className="mb-3 p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <div className="flex items-center gap-2 mb-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-kavach-success" />
                  <p className="text-[10px] font-mono uppercase tracking-wider text-kavach-success">Baseline Execution</p>
                </div>
                {fuzzingResult.baseline.executed ? (
                  <div className="text-xs text-kavach-text-secondary font-mono">
                    Input: <span className="text-kavach-text-primary">{fuzzingResult.baseline.input}</span>
                    {' → '}
                    {fuzzingResult.baseline.rowCount} row(s)
                    {fuzzingResult.baseline.error ? ` · error: ${fuzzingResult.baseline.error}` : ''}
                  </div>
                ) : (
                  <div className="text-xs text-kavach-error font-mono">Baseline could not execute: {fuzzingResult.baseline.error}</div>
                )}
              </div>
            )}

            {/* Summary metrics */}
            {!fuzzingResult.skipped && (
            <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
              <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <p className="text-[10px] font-mono uppercase text-kavach-text-muted">Payloads</p>
                <p className="text-xl font-bold text-kavach-text-primary">{fuzzingResult.payloads.length}</p>
              </div>
              <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <p className="text-[10px] font-mono uppercase text-kavach-text-muted">Confirmed</p>
                <p className={`text-xl font-bold ${fuzzingResult.confirmedCount > 0 ? 'text-red-400' : 'text-kavach-text-primary'}`}>{fuzzingResult.confirmedCount}</p>
              </div>
              <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <p className="text-[10px] font-mono uppercase text-kavach-text-muted">Confidence</p>
                <p className="text-xl font-bold text-kavach-text-primary">{(fuzzingResult.confidence * 100).toFixed(0)}%</p>
              </div>
              <div className="p-2.5 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <p className="text-[10px] font-mono uppercase text-kavach-text-muted">Status</p>
                <p className={`text-sm font-bold ${fuzzingResult.confirmed ? 'text-red-400' : fuzzingResult.confirmedCount > 0 ? 'text-amber-400' : 'text-kavach-text-muted'}`}>
                  {fuzzingResult.confirmed ? 'CONFIRMED' : fuzzingResult.confirmedCount > 0 ? 'SUSPICIOUS' : 'NOT_REPRODUCED'}
                </p>
              </div>
            </div>

            {/* Detailed payload results with baseline comparison */}
            <div className="space-y-1.5 max-h-96 overflow-y-auto">
              {fuzzingResult.payloads.map((p, i) => (
                <div key={i} className={`p-2.5 rounded-md border ${
                  p.classification === 'CONFIRMED' ? 'bg-red-500/5 border-red-500/20' :
                  p.classification === 'SUSPICIOUS' ? 'bg-amber-500/5 border-amber-500/20' :
                  p.classification === 'FAILED' ? 'bg-kavach-error/5 border-kavach-error/20' :
                  'bg-kavach-surface-2 border-kavach-border'
                }`}>
                  <div className="flex items-center gap-2 mb-1">
                    {p.classification === 'CONFIRMED' ? (
                      <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                    ) : p.classification === 'SUSPICIOUS' ? (
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    ) : p.classification === 'FAILED' ? (
                      <XCircle className="w-3.5 h-3.5 text-kavach-error shrink-0" />
                    ) : (
                      <CheckCircle2 className="w-3.5 h-3.5 text-kavach-success shrink-0" />
                    )}
                    <code className={`text-xs font-mono flex-1 truncate ${
                      p.classification === 'CONFIRMED' ? 'text-red-400' :
                      p.classification === 'SUSPICIOUS' ? 'text-amber-400' :
                      'text-kavach-text-secondary'
                    }`}>{p.payload || '(empty)'}</code>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded shrink-0 ${
                      p.classification === 'CONFIRMED' ? 'bg-red-500/10 text-red-400' :
                      p.classification === 'SUSPICIOUS' ? 'bg-amber-500/10 text-amber-400' :
                      p.classification === 'FAILED' ? 'bg-kavach-error/10 text-kavach-error' :
                      'bg-slate-500/10 text-slate-400'
                    }`}>{p.classification}</span>
                  </div>
                  <div className="flex items-center gap-3 text-[10px] font-mono text-kavach-text-muted">
                    <span>{p.category.replace(/_/g, ' ')}</span>
                    <span>baseline: {p.baselineRowCount} rows</span>
                    <span>mutation: {p.rowCount} rows</span>
                    <span className="text-kavach-text-muted">{p.executionMode}</span>
                    <span className={
                      p.confidence === 'HIGH' ? 'text-red-400' :
                      p.confidence === 'MEDIUM' ? 'text-amber-400' :
                      'text-kavach-text-muted'
                    }>{p.confidence}</span>
                  </div>
                  {p.behaviorChange !== 'No behavioral change vs baseline' && p.classification !== 'NOT_REPRODUCED' && (
                    <p className="text-[10px] text-kavach-text-secondary mt-1">{p.behaviorChange}</p>
                  )}
                  {p.classification === 'NOT_REPRODUCED' && p.category !== 'SAFE_CONTROL' && (
                    <p className="text-[10px] text-kavach-text-muted mt-1">
                      Reason: {p.behaviorChange === 'No behavioral change vs baseline' ? 'no behavioral difference from baseline' : p.behaviorChange}. {p.error ? `Error: ${p.error}. ` : ''}Classification: execution succeeded but no meaningful SQL behavior change observed.
                    </p>
                  )}
                </div>
              ))}
            </div>
            </>
            )}
          </CardBody>
        </Card>
      )}

      {/* Configuration */}
      <Card>
        <CardHeader title="Fuzzing Configuration" subtitle={mode === 'ACTIVE' ? 'Populated from active Real Assessment finding' : 'Manual controlled SQL analysis'} icon={<Target className="w-4 h-4" />} />
        <CardBody>
          <div className="space-y-4">
            {/* Target Type */}
            <div>
              <label className="kavach-section-title mb-2 block">Target Type</label>
              <div className="flex flex-wrap gap-2">
                {TARGET_TYPES.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => setTargetType(t.id)}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                      targetType === t.id
                        ? 'bg-kavach-accent/10 text-kavach-accent border-kavach-accent/30'
                        : 'bg-kavach-surface-2 text-kavach-text-secondary border-kavach-border hover:border-kavach-accent/20'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Strategy */}
            <div>
              <label className="kavach-section-title mb-2 block">Fuzzing Strategy</label>
              <div className="flex flex-wrap gap-2">
                {STRATEGIES.map((s) => (
                  <button
                    key={s.id}
                    onClick={() => setStrategy(s.id)}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                      strategy === s.id
                        ? 'bg-kavach-accent/10 text-kavach-accent border-kavach-accent/30'
                        : 'bg-kavach-surface-2 text-kavach-text-secondary border-kavach-border hover:border-kavach-accent/20'
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            {/* SQL Input */}
            {targetType === 'SQL' && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="kavach-section-title">SQL Query Input</label>
                  <div className="flex gap-2">
                    <button onClick={loadBasicDemo} className="text-xs text-kavach-accent hover:underline">Basic Demo</button>
                    <button onClick={loadVulnerableDemo} className="text-xs text-amber-400 hover:underline">Vulnerable Code</button>
                    <button onClick={loadSecureDemo} className="text-xs text-kavach-success hover:underline">Secure Code</button>
                  </div>
                </div>
                <textarea
                  value={inputQuery}
                  onChange={(e) => setInputQuery(e.target.value)}
                  rows={3}
                  className="w-full bg-kavach-bg border border-kavach-border rounded-md p-3 text-sm font-mono text-kavach-text-primary focus:border-kavach-accent focus:outline-none resize-y"
                  placeholder="SELECT * FROM users WHERE username = '<INPUT>'"
                />
                <p className="text-xs text-kavach-text-muted mt-1">
                  Use <code className="text-kavach-accent">{'<INPUT>'}</code> as the injection point marker.
                </p>
              </div>
            )}

            {/* Run Button */}
            <div className="flex items-center gap-3">
              <button
                onClick={handleRun}
                disabled={isRunning}
                className="flex items-center gap-2 px-4 py-2 rounded-md bg-kavach-accent/10 text-kavach-accent border border-kavach-accent/30 hover:bg-kavach-accent/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                <span className="text-sm font-medium">{isRunning ? 'Fuzzing...' : 'Run Fuzzer'}</span>
              </button>
              <span className="text-xs text-kavach-text-muted">Controlled Demonstration — no live execution</span>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* SQL Analysis */}
      {analysis && (
        <Card>
          <CardHeader title="SQL Analyzer" subtitle="Real pattern detection on query structure" icon={<Code2 className="w-4 h-4" />} />
          <CardBody>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
              <AnalysisChip label="Concatenation" detected={analysis.hasConcatenation} />
              <AnalysisChip label="F-String" detected={analysis.hasFString} />
              <AnalysisChip label="Parameterized" detected={analysis.hasParameterized} />
              <AnalysisChip label="Vulnerable" detected={analysis.vulnerable} danger={analysis.vulnerable} />
            </div>
            <div className={`p-3 rounded-md border ${analysis.vulnerable ? 'bg-red-500/5 border-red-500/20' : 'bg-kavach-success/5 border-kavach-success/20'}`}>
              <p className={`text-sm ${analysis.vulnerable ? 'text-red-400' : 'text-kavach-success'}`}>{analysis.detail}</p>
            </div>
          </CardBody>
        </Card>
      )}

      {/* Metrics */}
      {result && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <MetricCard icon={<Zap className="w-4 h-4" />} label="Iterations" value={result.metrics.iterations} />
            <MetricCard icon={<Terminal className="w-4 h-4" />} label="Generated Inputs" value={result.metrics.generatedInputs} />
            <MetricCard icon={<CheckCircle2 className="w-4 h-4" />} label="Unique Cases" value={result.metrics.uniqueTestCases} />
            <MetricCard icon={<Lightbulb className="w-4 h-4" />} label="Interesting" value={result.metrics.interestingInputs} highlight />
            <MetricCard icon={<Bug className="w-4 h-4" />} label="Findings" value={result.metrics.potentialFindings} danger={result.metrics.potentialFindings > 0} />
            <MetricCard icon={<TrendingUp className="w-4 h-4" />} label="Coverage" value={`${result.metrics.coverage}%`} />
          </div>
          <p className="text-xs text-amber-400/80 text-center">
            All metrics are deterministic demonstration values — not from live fuzzing infrastructure.
          </p>
        </>
      )}

      {/* Finding Summary */}
      {result && (
        <Card className={result.vulnerabilityDetected ? 'border-red-500/30' : 'border-kavach-success/30'}>
          <CardBody>
            <div className="flex items-start gap-3">
              {result.vulnerabilityDetected ? (
                <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              ) : (
                <CheckCircle2 className="w-5 h-5 text-kavach-success flex-shrink-0 mt-0.5" />
              )}
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-sm font-semibold ${result.vulnerabilityDetected ? 'text-red-400' : 'text-kavach-success'}`}>
                    {result.vulnerabilityDetected ? 'Vulnerability Confirmed' : 'No Vulnerability Detected'}
                  </span>
                  <StatusBadge status={result.vulnerabilityDetected ? 'CONFIRMED' : 'SAFE'} />
                </div>
                <p className="text-sm text-kavach-text-secondary">{result.findingSummary}</p>
              </div>
            </div>
          </CardBody>
        </Card>
      )}

      {/* Traditional vs Semantic Comparison */}
      {result && (
        <Card>
          <CardHeader title="Traditional vs Kavach Semantic Fuzzing" subtitle="Why semantic generation matters" icon={<Lightbulb className="w-4 h-4" />} />
          <CardBody>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3 rounded-md bg-kavach-surface-2 border border-kavach-border">
                <p className="text-xs font-mono text-kavach-text-muted uppercase mb-2">Traditional Mutation</p>
                <p className="text-sm text-kavach-text-secondary mb-2">Random / structural mutation of input characters.</p>
                <p className="text-xs text-kavach-text-muted">Generates inputs like: <code className="text-kavach-text-secondary">aflsdjf, !!@#$, 12345678</code></p>
                <p className="text-xs text-kavach-text-muted mt-1">Low signal-to-noise ratio. Most inputs are uninteresting.</p>
              </div>
              <div className="p-3 rounded-md bg-kavach-accent/5 border border-kavach-accent/20">
                <p className="text-xs font-mono text-kavach-accent uppercase mb-2">Kavach Semantic Mutation</p>
                <p className="text-sm text-kavach-text-secondary mb-2">Understands input context and generates vulnerability-oriented test cases.</p>
                <p className="text-xs text-kavach-text-muted">Generates inputs like: <code className="text-kavach-accent">' OR '1'='1, admin'--, UNION SELECT</code></p>
                <p className="text-xs text-kavach-text-muted mt-1">High signal-to-noise ratio. Every input targets a specific vulnerability class.</p>
              </div>
            </div>
          </CardBody>
        </Card>
      )}

      {/* Test Cases + WHY THIS INPUT */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader title="Generated Test Cases" subtitle={`${result.testCases.length} semantic payloads`} icon={<Terminal className="w-4 h-4" />} />
            <CardBody>
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {result.testCases.map((tc) => (
                  <button
                    key={tc.id}
                    onClick={() => setSelectedCase(tc)}
                    className={`w-full text-left p-2.5 rounded-md border transition-all ${
                      selectedCase?.id === tc.id
                        ? 'bg-kavach-accent/10 border-kavach-accent/30'
                        : 'bg-kavach-surface-2 border-kavach-border hover:border-kavach-accent/20'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      {tc.injectionDetected ? (
                        <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5 text-kavach-success flex-shrink-0" />
                      )}
                      <code className={`text-xs font-mono flex-1 ${tc.injectionDetected ? 'text-red-400' : 'text-kavach-text-secondary'}`}>
                        {tc.payload}
                      </code>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        tc.confidence === 'HIGH' ? 'bg-red-500/10 text-red-400' :
                        tc.confidence === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400' :
                        'bg-slate-500/10 text-slate-400'
                      }`}>{tc.confidence}</span>
                    </div>
                    <p className="text-[10px] text-kavach-text-muted">{tc.category.replace(/_/g, ' ')}</p>
                  </button>
                ))}
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Why This Input?" subtitle="Semantic reasoning for each test case" icon={<Info className="w-4 h-4" />} />
            <CardBody>
              {selectedCase ? (
                <div className="space-y-3">
                  <div>
                    <p className="kavach-section-title mb-1">Payload</p>
                    <pre className="p-2 bg-kavach-bg rounded text-sm font-mono text-kavach-accent overflow-x-auto">{selectedCase.payload}</pre>
                  </div>
                  <div>
                    <p className="kavach-section-title mb-1">Reason</p>
                    <p className="text-sm text-kavach-text-secondary">{selectedCase.reason}</p>
                  </div>
                  <div>
                    <p className="kavach-section-title mb-1">Confidence</p>
                    <div className="flex items-center gap-2">
                      <span className={`text-sm font-medium ${
                        selectedCase.confidence === 'HIGH' ? 'text-red-400' :
                        selectedCase.confidence === 'MEDIUM' ? 'text-amber-400' :
                        'text-slate-400'
                      }`}>{selectedCase.confidence}</span>
                    </div>
                  </div>
                  <div>
                    <p className="kavach-section-title mb-1">Simulated Behavior</p>
                    <div className={`p-2 rounded text-xs ${selectedCase.injectionDetected ? 'bg-red-500/5 text-red-400' : 'bg-kavach-success/5 text-kavach-success'}`}>
                      {selectedCase.behaviorChange}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-kavach-text-muted">Injection detected:</span>
                    {selectedCase.injectionDetected ? (
                      <span className="text-xs text-red-400 font-medium">YES</span>
                    ) : (
                      <span className="text-xs text-kavach-success font-medium">NO</span>
                    )}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-center py-8">
                  <Info className="w-8 h-8 text-kavach-text-muted mb-2" />
                  <p className="text-sm text-kavach-text-muted">Select a test case to see the semantic reasoning.</p>
                </div>
              )}
            </CardBody>
          </Card>
        </div>
      )}

      {/* Authorization Notice */}
      <Card>
        <CardBody>
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-xs text-amber-400 font-medium mb-1">Safety Notice</p>
              <p className="text-xs text-kavach-text-muted">
                Kavach Fuzzing Lab operates in a controlled sandbox. Test cases are generated and simulated locally — no payloads are sent to external systems.
                For live API testing, explicit authorization is required: "I confirm that I am authorized to test this target."
              </p>
            </div>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

function AnalysisChip({ label, detected, danger }: { label: string; detected: boolean; danger?: boolean }) {
  return (
    <div className={`p-2 rounded-md border text-center ${
      detected
        ? danger ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-kavach-accent/10 border-kavach-accent/30 text-kavach-accent'
        : 'bg-kavach-surface-2 border-kavach-border text-kavach-text-muted'
    }`}>
      <p className="text-xs font-medium">{label}</p>
      <p className="text-[10px] font-mono mt-0.5">{detected ? 'DETECTED' : 'NOT FOUND'}</p>
    </div>
  );
}

function MetricCard({ icon, label, value, highlight, danger }: { icon: React.ReactNode; label: string; value: string | number; highlight?: boolean; danger?: boolean }) {
  return (
    <div className={`p-3 rounded-md border ${
      danger ? 'bg-red-500/5 border-red-500/20' :
      highlight ? 'bg-amber-500/5 border-amber-500/20' :
      'bg-kavach-surface-2 border-kavach-border'
    }`}>
      <div className="flex items-center gap-2 mb-1">
        <span className={danger ? 'text-red-400' : highlight ? 'text-amber-400' : 'text-kavach-text-muted'}>{icon}</span>
        <span className="text-[10px] font-mono text-kavach-text-muted uppercase">{label}</span>
      </div>
      <p className={`text-xl font-bold ${danger ? 'text-red-400' : highlight ? 'text-amber-400' : 'text-kavach-text-primary'}`}>{value}</p>
    </div>
  );
}
