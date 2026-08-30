interface ProgressBarProps {
  value: number;
  max?: number;
  label?: string;
  color?: 'accent' | 'success' | 'warning' | 'danger';
  showValue?: boolean;
}

export function ProgressBar({ value, max = 100, label, color = 'accent', showValue = true }: ProgressBarProps) {
  const pct = Math.min((value / max) * 100, 100);
  const colorClass = {
    accent: 'bg-kavach-accent',
    success: 'bg-kavach-success',
    warning: 'bg-kavach-warning',
    danger: 'bg-kavach-danger',
  }[color];

  return (
    <div className="w-full">
      {label && (
        <div className="flex justify-between items-center mb-1">
          <span className="text-xs text-kavach-text-secondary">{label}</span>
          {showValue && <span className="text-xs font-mono text-kavach-text-primary">{Math.round(pct)}%</span>}
        </div>
      )}
      <div className="h-1.5 bg-kavach-bg rounded-full overflow-hidden">
        <div
          className={`h-full ${colorClass} rounded-full transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
