import { Play, Loader2, AlertCircle, CheckCircle2, Cpu, Target, Sparkles } from 'lucide-react';
import { useKavach } from '@/store/KavachContext';
import { detectLLMConfig } from '@/services/llm/llmProvider';
import { StatusBadge } from '@/components/ui/Badge';

interface TopBarProps {
  onRunDemo: () => void;
  title: string;
  onReplaySplash?: () => void;
}

export function TopBar({ onRunDemo, title, onReplaySplash }: TopBarProps) {
  const { isRunning, progressMessage, investigation, systemStatus, mode } = useKavach();
  const llmConfig = detectLLMConfig();

  const systemState = investigation?.status || systemStatus.state;
  const isDemoMode = mode === 'demo';
  const isRealMode = mode === 'real';

  return (
    <header className="h-14 bg-kavach-surface border-b border-kavach-border flex items-center justify-between px-6">
      <div className="flex items-center gap-4">
        <h2 className="text-base font-semibold text-kavach-text-primary">{title}</h2>
        {investigation && (
          <StatusBadge status={systemState} />
        )}
        {isRealMode && (
          <span className="text-[10px] font-mono uppercase tracking-wider text-kavach-accent bg-kavach-accent/10 px-2 py-0.5 rounded border border-kavach-accent/20">
            Real Assessment
          </span>
        )}
        {isDemoMode && (
          <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
            Demo / Controlled Simulation
          </span>
        )}
      </div>

      <div className="flex items-center gap-4">
        {onReplaySplash && (
          <button
            onClick={onReplaySplash}
            title="Replay Opening Intro Animation"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-kavach-surface-2 hover:bg-kavach-accent/10 text-xs text-kavach-text-muted hover:text-kavach-accent border border-kavach-border transition-all"
          >
            <Sparkles className="w-3.5 h-3.5 text-kavach-accent" />
            <span className="font-mono text-[11px]">Intro</span>
          </button>
        )}

        {/* LLM Status */}
        <div className="flex items-center gap-2 text-xs">
          <Cpu className="w-3.5 h-3.5 text-kavach-text-muted" />
          <span className="font-mono text-kavach-text-muted">
            {llmConfig.provider === 'demo' ? 'DEMO REASONER' : 'CONNECTED LLM'}
          </span>
        </div>

        {/* Progress */}
        {isRunning && progressMessage && (
          <div className="flex items-center gap-2 text-sm text-kavach-accent">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="font-mono text-xs">{progressMessage}</span>
          </div>
        )}

        {/* Action Button - only in demo mode */}
        {isDemoMode && (
          <button
            onClick={onRunDemo}
            disabled={isRunning}
            className="kavach-btn kavach-btn-primary flex items-center gap-2"
          >
            {isRunning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Running...
              </>
            ) : investigation?.status === 'VERIFIED' ? (
              <>
                <CheckCircle2 className="w-4 h-4" />
                Re-run Demo
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Run Full Demo
              </>
            )}
          </button>
        )}
      </div>
    </header>
  );
}

