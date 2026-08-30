import { useState, useCallback, useRef } from 'react';
import { Play, Loader2, Cpu, Zap } from 'lucide-react';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import { CppDynamicResultsView } from '@/components/common/CppDynamicResultsView';
import {
  runCppDynamicAnalysis,
  CPP_DEMO_PROGRAMS,
  type CppDynamicResult,
  type CppFuzzStrategy,
  type CppSanitizer,
} from '@/services/cppDynamicService';

const STRATEGIES: { id: CppFuzzStrategy; label: string; desc: string }[] = [
  { id: 'BOUNDARY', label: 'Boundary', desc: 'INT_MAX, -1, empty, 0' },
  { id: 'OVERFLOW', label: 'Overflow', desc: 'Long strings, buffer fillers' },
  { id: 'FORMAT_STRING', label: 'Format String', desc: '%s %n %x payloads' },
  { id: 'NEGATIVE', label: 'Negative', desc: 'Negative int/float values' },
  { id: 'STRESS', label: 'Stress', desc: 'Exponentially growing inputs' },
  { id: 'RANDOM', label: 'Random', desc: 'Random mutations' },
];

const SANITIZERS: { id: CppSanitizer; label: string }[] = [
  { id: 'none', label: 'None' },
  { id: 'ubsan', label: 'UBSan' },
  { id: 'asan', label: 'ASan' },
  { id: 'asan+ubsan', label: 'ASan + UBSan' },
];

export function CppDynamicLabPage() {
  const [code, setCode] = useState(CPP_DEMO_PROGRAMS.buffer_overflow.code);
  const [selectedStrategies, setSelectedStrategies] = useState<Set<CppFuzzStrategy>>(
    new Set(['BOUNDARY', 'OVERFLOW'])
  );
  const [sanitizer, setSanitizer] = useState<CppSanitizer>('ubsan');
  const [inputsPerStrategy, setInputsPerStrategy] = useState(5);
  const [result, setResult] = useState<CppDynamicResult | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState('');
  const [progressDone, setProgressDone] = useState(0);
  const [progressTotal, setProgressTotal] = useState(0);
  const abortRef = useRef(false);

  const toggleStrategy = (s: CppFuzzStrategy) => {
    setSelectedStrategies(prev => {
      const next = new Set(prev);
      next.has(s) ? next.delete(s) : next.add(s);
      return next;
    });
  };

  const handleRun = useCallback(async () => {
    if (isRunning) return;
    setIsRunning(true);
    setResult(null);
    abortRef.current = false;

    try {
      const r = await runCppDynamicAnalysis(
        code,
        Array.from(selectedStrategies),
        sanitizer,
        inputsPerStrategy,
        (msg, done, total) => {
          setProgress(msg);
          setProgressDone(done);
          setProgressTotal(total);
        }
      );
      setResult(r);
    } finally {
      setIsRunning(false);
      setProgress('');
    }
  }, [code, selectedStrategies, sanitizer, inputsPerStrategy, isRunning]);

  const loadDemo = (key: string) => {
    const d = CPP_DEMO_PROGRAMS[key];
    if (d) setCode(d.code);
    setResult(null);
  };

  return (
    <div className="space-y-5 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-kavach-text-primary mb-1 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-kavach-accent" />
            C++ Dynamic Analysis Lab
          </h2>
          <p className="text-sm text-kavach-text-secondary">
            C++ compilation · Fuzz input testing · Sanitizer-based line matching
          </p>
        </div>
        <span className="text-[10px] font-mono px-2 py-1 rounded border border-kavach-accent/30 bg-kavach-accent/5 text-kavach-accent uppercase tracking-wider">
          Live Execution
        </span>
      </div>

      {/* Demo templates */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(CPP_DEMO_PROGRAMS).map(([key, d]) => (
          <button
            key={key}
            onClick={() => loadDemo(key)}
            className="px-3 py-1.5 rounded-md text-xs font-medium border bg-kavach-surface-2 text-kavach-text-secondary border-kavach-border hover:border-kavach-accent/30 hover:text-kavach-accent transition-all"
          >
            {d.label}
          </button>
        ))}
      </div>

      {/* Main layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left column: Configuration */}
        <div className="lg:col-span-1 space-y-4">
          <Card>
            <CardHeader title="Fuzz Configuration" subtitle="Select strategies and sanitizer" icon={<Zap className="w-4 h-4" />} />
            <CardBody>
              <div className="space-y-4">
                {/* Strategies */}
                <div>
                  <label className="kavach-section-title mb-2 block">Fuzz Strategies</label>
                  <div className="flex flex-wrap gap-2">
                    {STRATEGIES.map(s => (
                      <button
                        key={s.id}
                        onClick={() => toggleStrategy(s.id)}
                        title={s.desc}
                        className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                          selectedStrategies.has(s.id)
                            ? 'bg-kavach-accent/10 text-kavach-accent border-kavach-accent/30'
                            : 'bg-kavach-surface-2 text-kavach-text-secondary border-kavach-border hover:border-kavach-accent/20'
                        }`}
                      >
                        {s.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Sanitizer */}
                <div>
                  <label className="kavach-section-title mb-2 block">Sanitizer</label>
                  <div className="flex flex-wrap gap-2">
                    {SANITIZERS.map(s => (
                      <button
                        key={s.id}
                        onClick={() => setSanitizer(s.id)}
                        className={`px-3 py-1.5 rounded-md text-xs font-medium border transition-all ${
                          sanitizer === s.id
                            ? 'bg-kavach-accent/10 text-kavach-accent border-kavach-accent/30'
                            : 'bg-kavach-surface-2 text-kavach-text-secondary border-kavach-border hover:border-kavach-accent/20'
                        }`}
                      >
                        {s.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Inputs per strategy */}
                <div>
                  <label className="kavach-section-title mb-2 block">
                    Inputs per Strategy: <span className="text-kavach-accent">{inputsPerStrategy}</span>
                  </label>
                  <input
                    type="range" min={2} max={10} value={inputsPerStrategy}
                    onChange={e => setInputsPerStrategy(Number(e.target.value))}
                    className="w-full accent-sky-500"
                  />
                  <div className="flex justify-between text-[10px] text-kavach-text-muted mt-1">
                    <span>2 (fast)</span>
                    <span>~{selectedStrategies.size * inputsPerStrategy} total API calls</span>
                    <span>10 (thorough)</span>
                  </div>
                </div>

                {/* Run button */}
                <div className="flex items-center gap-3 pt-2">
                  <button
                    onClick={handleRun}
                    disabled={isRunning || selectedStrategies.size === 0}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-md bg-kavach-accent/10 text-kavach-accent border border-kavach-accent/30 hover:bg-kavach-accent/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed w-full justify-center"
                  >
                    {isRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    <span className="text-sm font-medium">{isRunning ? 'Running...' : 'Compile & Fuzz'}</span>
                  </button>
                </div>

                {isRunning && (
                  <div className="space-y-1.5">
                    <p className="text-xs text-kavach-text-muted truncate">{progress}</p>
                    {progressTotal > 0 && (
                      <div className="w-full h-1.5 bg-kavach-surface-2 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-kavach-accent rounded-full transition-all duration-300"
                          style={{ width: `${(progressDone / progressTotal) * 100}%` }}
                        />
                      </div>
                    )}
                  </div>
                )}
              </div>
            </CardBody>
          </Card>
        </div>

        {/* Right column: Execution Results */}
        <div className="lg:col-span-2 space-y-4">
          {result ? (
            <CppDynamicResultsView result={result} code={code} />
          ) : (
            <Card>
              <CardBody className="text-center py-16">
                <Cpu className="w-10 h-10 text-kavach-text-muted mx-auto mb-3" />
                <p className="text-sm font-semibold text-kavach-text-primary">NO EXECUTION RESULTS YET</p>
                <p className="text-xs text-kavach-text-muted mt-2 max-w-sm mx-auto">
                  Click <span className="text-kavach-accent font-mono font-medium">Compile & Fuzz</span> to execute real GCC compilation with AddressSanitizer and UndefinedBehaviorSanitizer line matching via Compiler Explorer API.
                </p>
              </CardBody>
            </Card>
          )}
        </div>
      </div>

      {/* Legend & Infrastructure Credit */}
      <Card>
        <CardBody>
          <div className="flex flex-wrap items-center gap-4 text-xs text-kavach-text-muted">
            <span className="font-medium text-kavach-text-secondary">Legend:</span>
            {[
              { cls: 'bg-red-500/20 border-red-500/40 text-red-400', label: 'CRASH — segfault/signal' },
              { cls: 'bg-orange-500/15 border-orange-500/30 text-orange-400', label: 'UB — undefined behavior (sanitizer)' },
              { cls: 'bg-amber-400/10 border-amber-400/20 text-amber-400', label: 'WARNING' },
              { cls: 'bg-sky-500/5 border-sky-500/40 text-sky-400', label: 'INFO hit' },
            ].map(l => (
              <span key={l.label} className={`px-2 py-0.5 rounded border font-mono ${l.cls}`}>{l.label}</span>
            ))}
          </div>
          <p className="text-[10px] text-kavach-text-muted mt-2">
            Compilation and execution powered by <a href="https://godbolt.org" target="_blank" rel="noopener noreferrer" className="text-kavach-accent hover:underline">Compiler Explorer</a> (GCC 14.1 with AddressSanitizer & UndefinedBehaviorSanitizer flags).
            All code runs in sandboxed execution environment — no local execution.
          </p>
        </CardBody>
      </Card>
    </div>
  );
}
