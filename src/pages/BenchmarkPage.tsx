import { useState } from 'react';
import { AlertTriangle, CheckCircle2, FlaskConical, Play, ShieldCheck, XCircle } from 'lucide-react';
import { runAdversarialBenchmark, type BenchmarkReport } from '@/services/benchmarkService';
import { Card } from '@/components/ui/Card';

export function BenchmarkPage() {
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [running, setRunning] = useState(false);

  const run = () => {
    setRunning(true);
    setTimeout(() => {
      setReport(runAdversarialBenchmark());
      setRunning(false);
    }, 40);
  };

  const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-kavach-accent mb-1">
            <FlaskConical className="w-5 h-5" />
            <span className="text-xs font-mono uppercase tracking-wider">Adversarial Security Benchmark</span>
          </div>
          <h2 className="text-2xl font-bold text-kavach-text-primary">Test the analyzer against its blind spots</h2>
          <p className="text-sm text-kavach-text-muted mt-1 max-w-3xl">
            Runs vulnerable and secure variants covering direct SQL injection, alias chains, function propagation,
            formatting variants and safe controls. Metrics are calculated from the executed benchmark—not hardcoded.
          </p>
        </div>
        <button
          onClick={run}
          disabled={running}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-kavach-accent text-white text-sm font-semibold disabled:opacity-60"
        >
          <Play className="w-4 h-4" />
          {running ? 'Running…' : 'Run Benchmark'}
        </button>
      </div>

      {!report && (
        <Card>
          <div className="py-16 text-center">
            <ShieldCheck className="w-12 h-12 mx-auto text-kavach-accent mb-4" />
            <h3 className="text-lg font-semibold text-kavach-text-primary">No benchmark run yet</h3>
            <p className="text-sm text-kavach-text-muted mt-2">Run the suite to measure precision, recall, F1 and detector blind spots.</p>
          </div>
        </Card>
      )}

      {report && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
            {[
              { label: 'Tests', value: report.total, cls: 'text-kavach-text-primary' },
              { label: 'True Positives', value: report.truePositives, cls: 'text-kavach-success' },
              { label: 'False Positives', value: report.falsePositives, cls: 'text-kavach-danger' },
              { label: 'False Negatives', value: report.falseNegatives, cls: 'text-kavach-danger' },
              { label: 'Precision', value: pct(report.precision), cls: 'text-kavach-accent' },
              { label: 'F1 Score', value: pct(report.f1), cls: 'text-kavach-accent' },
            ].map(({ label, value, cls }) => (
              <Card key={label} className="p-4">
                <div className="text-[10px] uppercase tracking-wider text-kavach-text-muted font-mono">{label}</div>
                <div className={`text-2xl font-bold mt-1 ${cls}`}>{value}</div>
              </Card>
            ))}
          </div>

          <Card>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="font-semibold text-kavach-text-primary">Case-by-case results</h3>
                <p className="text-xs text-kavach-text-muted mt-1">A wrong result is a regression candidate, not something to hide.</p>
              </div>
              <div className="text-xs font-mono text-kavach-text-muted">Recall {pct(report.recall)} · TN {report.trueNegatives} · Inconclusive {report.inconclusive}</div>
            </div>
            <div className="space-y-2">
              {report.results.map((r) => (
                <div key={r.id} className="p-3 rounded-lg border border-kavach-border bg-kavach-surface-2/40">
                  <div className="flex items-center gap-3">
                    {r.correct ? <CheckCircle2 className="w-4 h-4 text-kavach-success" /> : r.observed === 'INCONCLUSIVE' ? <AlertTriangle className="w-4 h-4 text-kavach-warning" /> : <XCircle className="w-4 h-4 text-kavach-danger" />}
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium text-kavach-text-primary">{r.name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded border border-kavach-border text-kavach-text-muted font-mono">{r.category}</span>
                      </div>
                      <p className="text-xs text-kavach-text-muted mt-1">Expected: {r.expected} · Observed: {r.observed} · {r.notes}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
