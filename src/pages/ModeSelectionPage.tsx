import { Shield, Target, Play, ArrowRight, Lock, CheckCircle2, Info } from 'lucide-react';
import { useKavach } from '@/store/KavachContext';

export function ModeSelectionPage() {
  const { dispatch } = useKavach();

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="max-w-3xl w-full">
        {/* Logo */}
        <div className="text-center mb-10">
          <div className="inline-flex flex-col items-center gap-4 mb-3">
            <img 
              src="/logo.png" 
              alt="Kavach Abhedya Logo" 
              className="w-28 h-28 object-contain drop-shadow-[0_0_25px_rgba(14,165,233,0.4)] hover:scale-105 transition-transform" 
            />
            <h1 className="text-3xl font-bold text-kavach-text-primary tracking-tight">KAVACH ABHEDYA</h1>
          </div>
          <p className="text-sm text-kavach-text-secondary">
            Evidence-Driven Cyber Reasoning &amp; Verification Platform
          </p>
          <p className="text-xs text-kavach-text-muted mt-2 max-w-xl mx-auto">
            The AI does not get to declare a vulnerability is fixed. Independent deterministic verification must prove it.
          </p>
        </div>

        {/* Primary: Real Assessment */}
        <button
          onClick={() => dispatch({ type: 'SET_MODE', mode: 'real' })}
          className="kavach-card kavach-card-hover w-full p-6 text-left group flex items-center gap-5 mb-4 border-kavach-accent/30"
        >
          <div className="w-12 h-12 rounded-lg bg-kavach-accent/10 border border-kavach-accent/20 flex items-center justify-center shrink-0">
            <Target className="w-6 h-6 text-kavach-accent" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h2 className="text-lg font-semibold text-kavach-text-primary">Start Real Assessment</h2>
              <span className="text-[10px] font-mono uppercase tracking-wider text-kavach-accent bg-kavach-accent/10 px-2 py-0.5 rounded border border-kavach-accent/20">Primary</span>
            </div>
            <p className="text-sm text-kavach-text-secondary mb-2">
              Execute security analysis against source code you supply. Real SAST, evidence fusion, patch sandbox, and deterministic verification — driven by actual tool output, not hardcoded results.
            </p>
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-kavach-text-muted">
              <span className="flex items-center gap-1"><CheckCircle2 className="w-3 h-3 text-kavach-success" /> Real SAST pattern analysis</span>
              <span className="flex items-center gap-1"><CheckCircle2 className="w-3 h-3 text-kavach-success" /> Evidence fusion</span>
              <span className="flex items-center gap-1"><CheckCircle2 className="w-3 h-3 text-kavach-success" /> Deterministic verification</span>
            </div>
          </div>
          <ArrowRight className="w-5 h-5 text-kavach-accent group-hover:translate-x-1 transition-transform shrink-0" />
        </button>

        {/* Secondary: Demo Mode */}
        <div className="flex items-center gap-3 my-4">
          <div className="h-px bg-kavach-border flex-1" />
          <span className="text-xs font-mono text-kavach-text-muted uppercase tracking-wider">Secondary</span>
          <div className="h-px bg-kavach-border flex-1" />
        </div>

        <button
          onClick={() => dispatch({ type: 'SET_MODE', mode: 'demo' })}
          className="w-full p-4 text-left group flex items-center gap-4 rounded-lg border border-kavach-border bg-kavach-surface-2/50 hover:bg-kavach-surface-2 hover:border-kavach-text-muted/30 transition-all"
        >
          <div className="w-9 h-9 rounded-md bg-kavach-surface-2 border border-kavach-border flex items-center justify-center shrink-0">
            <Play className="w-4 h-4 text-kavach-text-muted" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <h3 className="text-sm font-medium text-kavach-text-secondary">View Demo</h3>
              <span className="text-[10px] font-mono uppercase tracking-wider text-kavach-text-muted bg-kavach-surface border border-kavach-border px-1.5 py-0.5 rounded">DEMO / SIMULATED</span>
            </div>
            <p className="text-xs text-kavach-text-muted">
              Guided walkthrough of the full pipeline against a controlled vulnerable SQL example. For presentations and offline demos.
            </p>
          </div>
          <ArrowRight className="w-4 h-4 text-kavach-text-muted group-hover:text-kavach-text-secondary group-hover:translate-x-0.5 transition-all shrink-0" />
        </button>

        {/* Authorization notice */}
        <div className="mt-6 flex items-start gap-2 text-xs text-kavach-text-muted">
          <Lock className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          <p>Only assess systems you own or are explicitly authorized to test. Real Assessment operates on uploaded source code in a controlled browser environment.</p>
        </div>

        <p className="text-center text-xs text-kavach-text-muted mt-6 font-mono">
          ABHEDYA KAVACH · TCQ 2026 · Prototype Build
        </p>
      </div>
    </div>
  );
}
