import type { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  hover?: boolean;
}

export function Card({ children, className = '', hover = false }: CardProps) {
  return (
    <div className={`kavach-card ${hover ? 'kavach-card-hover' : ''} ${className}`}>
      {children}
    </div>
  );
}

interface CardHeaderProps {
  title: string;
  subtitle?: string;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function CardHeader({ title, subtitle, icon, action, className = '' }: CardHeaderProps) {
  return (
    <div className={`flex items-center justify-between px-4 py-3 border-b border-kavach-border ${className}`}>
      <div className="flex items-center gap-2">
        {icon && <span className="text-kavach-accent">{icon}</span>}
        <div>
          <h3 className="text-sm font-semibold text-kavach-text-primary">{title}</h3>
          {subtitle && <p className="text-xs text-kavach-text-muted mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {action && <div>{action}</div>}
    </div>
  );
}

export function CardBody({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`p-4 ${className}`}>{children}</div>;
}
