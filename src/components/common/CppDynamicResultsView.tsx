import { useState } from 'react';
import { Terminal, Bug, CheckCircle2, XCircle, ChevronDown, ChevronRight, Cpu } from 'lucide-react';
import { Card, CardHeader, CardBody } from '@/components/ui/Card';
import type { CppDynamicResult, CppFuzzCase, CppLineHit } from '@/services/cppDynamicService';

function statusIcon(status: CppFuzzCase['runStatus']) {
  switch (status) {
    case 'CLEAN': return <CheckCircle2 className="w-3.5 h-3.5 text-kavach-success shrink-0" />;
    case 'SANITIZER_ERROR': return <Bug className="w-3.5 h-3.5 text-orange-400 shrink-0" />;
    case 'CRASH': return <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />;
    case 'RUNTIME_ERROR': return <XCircle className="w-3.5 h-3.5 text-amber-400 shrink-0" />;
    default: return null;
  }
}

function statusColor(status: CppFuzzCase['runStatus']) {
  switch (status) {
    case 'CLEAN': return 'text-kavach-success border-kavach-success/30';
    case 'SANITIZER_ERROR': return 'text-orange-400 border-orange-400/30';
    case 'CRASH': return 'text-red-400 border-red-400/30';
    case 'RUNTIME_ERROR': return 'text-amber-400 border-amber-400/30';
    default: return 'text-kavach-text-muted';
  }
}

function hitBg(kind: CppLineHit['kind']) {
  switch (kind) {
    case 'CRASH': return 'bg-red-500/20 border-red-500/40 text-red-400';
    case 'UB': return 'bg-orange-500/15 border-orange-500/30 text-orange-400';
    case 'ERROR': return 'bg-red-400/10 border-red-400/20 text-red-300';
    case 'WARNING': return 'bg-amber-400/10 border-amber-400/20 text-amber-400';
    default: return 'bg-kavach-surface-2 border-kavach-border text-kavach-text-secondary';
  }
}

export function AnnotatedSource({
  code,
  heatmap,
}: {
  code: string;
  heatmap: Map<number, CppLineHit[]>;
}) {
  const lines = code.split('\n');
  return (
    <div className="font-mono text-xs overflow-auto max-h-96 rounded-md bg-kavach-bg border border-kavach-border">
      {lines.map((line, i) => {
        const lineNum = i + 1;
        const hits = heatmap.get(lineNum);
        const hasCrash = hits?.some(h => h.kind === 'CRASH' || h.kind === 'UB');
        const hasWarn = hits?.some(h => h.kind === 'WARNING' || h.kind === 'ERROR');
        return (
          <div
            key={i}
            className={`flex group relative ${
              hasCrash ? 'bg-red-500/10 border-l-2 border-red-500' :
              hasWarn  ? 'bg-amber-500/8 border-l-2 border-amber-400' :
              hits     ? 'bg-sky-500/5 border-l-2 border-sky-500/40' :
              'border-l-2 border-transparent'
            }`}
          >
            <span className="select-none text-kavach-text-muted w-10 text-right pr-3 py-0.5 shrink-0 bg-kavach-surface/50">
              {lineNum}
            </span>
            <span className={`flex-1 py-0.5 px-2 whitespace-pre ${hasCrash ? 'text-red-200 font-semibold' : hasWarn ? 'text-amber-200' : 'text-kavach-text-secondary'}`}>
              {line || ' '}
            </span>
            {hits && (
              <span className="hidden group-hover:flex absolute right-2 top-0 bottom-0 items-center gap-1 flex-wrap max-w-xs z-10">
                {hits.map((h, hi) => (
                  <span key={hi} className={`text-[9px] px-1.5 py-0.5 rounded border ${hitBg(h.kind)} truncate max-w-[200px]`}>
                    {h.kind}: {h.message.slice(0, 60)}
                  </span>
                ))}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function FuzzCaseRow({ fc }: { fc: CppFuzzCase }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`rounded-md border transition-all ${fc.interesting ? 'border-red-500/25 bg-red-500/5' : 'border-kavach-border bg-kavach-surface-2'}`}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left"
      >
        {statusIcon(fc.runStatus)}
        <code className="text-xs flex-1 text-kavach-text-secondary truncate font-mono">{JSON.stringify(fc.input).slice(0, 50)}</code>
        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded bg-kavach-bg border ${statusColor(fc.runStatus)}`}>
          {fc.runStatus}
        </span>
        <span className="text-[10px] text-kavach-text-muted font-mono">{fc.label}</span>
        <span className="text-[10px] text-kavach-text-muted">{fc.durationMs}ms</span>
        {open ? <ChevronDown className="w-3.5 h-3.5 text-kavach-text-muted shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 text-kavach-text-muted shrink-0" />}
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-2 border-t border-kavach-border mt-1 pt-2">
          {fc.interestingReason && (
            <p className="text-xs text-red-400 font-medium">{fc.interestingReason}</p>
          )}
          {fc.stdout && (
            <div>
              <p className="text-[10px] text-kavach-text-muted uppercase mb-1 font-mono">stdout</p>
              <pre className="text-[10px] font-mono bg-kavach-bg rounded p-2 text-kavach-success max-h-24 overflow-auto whitespace-pre-wrap">{fc.stdout}</pre>
            </div>
          )}
          {fc.stderr && (
            <div>
              <p className="text-[10px] text-kavach-text-muted uppercase mb-1 font-mono">stderr / sanitizer log</p>
              <pre className="text-[10px] font-mono bg-kavach-bg rounded p-2 text-red-300 max-h-32 overflow-auto whitespace-pre-wrap">{fc.stderr}</pre>
            </div>
          )}
          {fc.lineHits.length > 0 && (
            <div>
              <p className="text-[10px] text-kavach-text-muted uppercase mb-1 font-mono">Line Hits</p>
              <div className="flex flex-wrap gap-1">
                {fc.lineHits.map((h, i) => (
                  <span key={i} className={`text-[10px] px-2 py-0.5 rounded border font-mono ${hitBg(h.kind)}`}>
                    L{h.line}{h.column ? `:${h.column}` : ''} · {h.kind}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function CppDynamicResultsView({
  result,
  code,
  title = "C++ Dynamic Analysis & Sanitizer Output",
}: {
  result: CppDynamicResult;
  code?: string;
  title?: string;
}) {
  const heatmap = result.lineHeatmap ?? new Map();

  return (
    <div className="space-y-4">
      {/* Header card / Compile status */}
      <Card className={result.compileResult.status === 'ERROR' ? 'border-red-500/30' : 'border-kavach-success/20'}>
        <CardHeader
          title={title}
          subtitle={`Compiler Explorer (GCC 14.1) · ${result.sanitizer} · ${result.compileResult.duration}ms`}
          icon={<Cpu className="w-4 h-4 text-kavach-accent" />}
        />
        <CardBody>
          <div className={`flex items-center gap-2 mb-2 text-sm font-medium ${
            result.compileResult.status === 'ERROR' ? 'text-red-400' :
            result.compileResult.status === 'WARNING' ? 'text-amber-400' : 'text-kavach-success'
          }`}>
            {result.compileResult.status === 'ERROR' ? <XCircle className="w-4 h-4" /> : <CheckCircle2 className="w-4 h-4" />}
            Compilation: {result.compileResult.status}
          </div>
          {result.compileResult.compilerOutput && (
            <pre className="text-[10px] font-mono text-kavach-text-secondary bg-kavach-bg rounded p-2.5 max-h-32 overflow-auto whitespace-pre-wrap border border-kavach-border">
              {result.compileResult.compilerOutput}
            </pre>
          )}
        </CardBody>
      </Card>

      {/* Summary metrics */}
      {result.compileResult.status !== 'ERROR' && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Total Cases', value: result.fuzzCases.length, cls: 'text-kavach-text-primary' },
            { label: 'Crashes', value: result.totalCrashes, cls: result.totalCrashes > 0 ? 'text-red-400' : 'text-kavach-text-primary' },
            { label: 'UB / Sanitizer', value: result.totalUB, cls: result.totalUB > 0 ? 'text-orange-400' : 'text-kavach-text-primary' },
            { label: 'Lines Hit', value: result.coverageLines.length, cls: 'text-kavach-accent' },
          ].map(m => (
            <div key={m.label} className="p-3 rounded-md border border-kavach-border bg-kavach-surface-2">
              <p className="text-[10px] font-mono uppercase text-kavach-text-muted mb-1">{m.label}</p>
              <p className={`text-2xl font-bold ${m.cls}`}>{m.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Annotated source with line heatmap */}
      {code && result.compileResult.status !== 'ERROR' && heatmap.size > 0 && (
        <Card>
          <CardHeader
            title="Source Line Heatmap"
            subtitle="Lines highlighted by sanitizer/crash output. Hover for details."
            icon={<Bug className="w-4 h-4" />}
          />
          <CardBody>
            <AnnotatedSource code={code} heatmap={heatmap} />
            {result.coverageLines.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1 items-center">
                <span className="text-[10px] text-kavach-text-muted font-mono">Lines hit:</span>
                {result.coverageLines.map(l => (
                  <span key={l} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">L{l}</span>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      )}

      {/* Fuzz cases list */}
      {result.fuzzCases.length > 0 && (
        <Card>
          <CardHeader
            title="Fuzz Case Execution Results"
            subtitle={`${result.fuzzCases.length} cases executed · ${result.totalInteresting} dynamic hits`}
            icon={<Terminal className="w-4 h-4" />}
          />
          <CardBody>
            <div className="space-y-1.5 max-h-[400px] overflow-y-auto pr-1">
              {result.fuzzCases.map(fc => (
                <FuzzCaseRow key={fc.id} fc={fc} />
              ))}
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
