import React, { useState, useEffect } from 'react';
import { ArrowRight } from 'lucide-react';

interface SplashScreenProps {
  onComplete: () => void;
}

const STEPS = [
  { at: 350,  progress: 28,  status: 'Loading SAST analysis engine...' },
  { at: 800,  progress: 58,  status: 'Connecting verification modules...' },
  { at: 1250, progress: 82,  status: 'Syncing Security Memory...' },
  { at: 1600, progress: 100, status: 'System ready.' },
];

export function SplashScreen({ onComplete }: SplashScreenProps) {
  const [progress, setProgress] = useState(0);
  const [statusText, setStatusText] = useState('Initializing reasoning engine...');
  const [isFadingOut, setIsFadingOut] = useState(false);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const showTimer = setTimeout(() => setVisible(true), 60);

    const timers = STEPS.map(step =>
      setTimeout(() => {
        setProgress(step.progress);
        setStatusText(step.status);
      }, step.at)
    );

    const fadeOut = setTimeout(() => setIsFadingOut(true), 2200);
    const done    = setTimeout(() => onComplete(), 2650);

    return () => {
      clearTimeout(showTimer);
      timers.forEach(clearTimeout);
      clearTimeout(fadeOut);
      clearTimeout(done);
    };
  }, [onComplete]);

  return (
    <div
      style={{ background: '#07090e' }}
      className={`fixed inset-0 z-50 flex items-center justify-center transition-opacity duration-500 ease-in-out select-none ${
        isFadingOut ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
    >
      {/* Full-screen centered column */}
      <div className="flex flex-col items-center text-center" style={{ width: 280 }}>

        {/* ── Logo + glow ── */}
        <div
          className={`flex items-center justify-center mb-8 transition-all duration-700 ease-out ${
            visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
          }`}
          style={{ position: 'relative', width: 160, height: 160 }}
        >
          {/* Glow: a large blurred circle, centred behind the logo.
              Uses inline style so it truly bleeds outside the parent with no clipping. */}
          <div
            style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              width: 260,
              height: 260,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(14,165,233,0.30) 0%, transparent 70%)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />
          <img
            src="/logo.png"
            alt="Kavach Abhedya"
            style={{
              position: 'relative',
              zIndex: 1,
              width: 144,
              height: 144,
              objectFit: 'contain',
            }}
          />
        </div>

        {/* ── Brand ── */}
        <div
          className={`transition-all duration-700 ease-out ${
            visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
          }`}
          style={{ transitionDelay: '120ms' }}
        >
          <h1
            className="text-white font-semibold mb-2"
            style={{ fontSize: 22, letterSpacing: '0.18em' }}
          >
            KAVACH ABHEDYA
          </h1>
          <p
            className="font-mono text-slate-400 uppercase"
            style={{ fontSize: 10, letterSpacing: '0.22em' }}
          >
            Cyber Reasoning &amp; Verification
          </p>
        </div>

        {/* ── Divider ── */}
        <div
          className={`flex items-center gap-3 transition-all duration-700 ease-out ${
            visible ? 'opacity-100' : 'opacity-0'
          }`}
          style={{ width: '100%', margin: '28px 0', transitionDelay: '200ms' }}
        >
          <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.07)' }} />
          <div style={{ width: 4, height: 4, borderRadius: '50%', background: 'rgba(34,211,238,0.7)' }} />
          <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.07)' }} />
        </div>

        {/* ── Progress ── */}
        <div
          className={`transition-all duration-700 ease-out ${
            visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
          }`}
          style={{ width: '100%', transitionDelay: '200ms' }}
        >
          {/* Track */}
          <div style={{ width: '100%', height: 3, background: 'rgba(255,255,255,0.08)', borderRadius: 999, overflow: 'hidden' }}>
            <div
              style={{
                height: '100%',
                width: `${progress}%`,
                background: 'linear-gradient(to right, #0ea5e9, #22d3ee)',
                borderRadius: 999,
                transition: 'width 500ms ease-out',
              }}
            />
          </div>

          {/* Labels */}
          <div
            className="font-mono"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 8, fontSize: 10.5 }}
          >
            <span className="text-slate-500 truncate">{statusText}</span>
            <span style={{ color: progress === 100 ? '#22d3ee' : '#64748b', fontWeight: 500, fontVariantNumeric: 'tabular-nums' }}>
              {progress}%
            </span>
          </div>
        </div>

        {/* ── Skip ── */}
        <button
          onClick={onComplete}
          className="font-mono text-slate-600 hover:text-slate-300 transition-colors flex items-center gap-1.5 group"
          style={{ marginTop: 32, fontSize: 11, background: 'none', border: 'none', cursor: 'pointer' }}
        >
          <span>Enter app</span>
          <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
        </button>

      </div>
    </div>
  );
}
