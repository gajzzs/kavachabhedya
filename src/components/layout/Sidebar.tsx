import { Shield, LayoutDashboard, Search, Box, Network, GitBranch, FlaskConical, CheckCircle, Database, Lock, ScrollText, Zap, FileSearch, Target, Cpu } from 'lucide-react';
import { useKavach } from '@/store/KavachContext';

export type PageId = 'overview' | 'investigations' | 'fuzzing' | 'cpp-dynamic' | 'twin' | 'evidence-graph' | 'attack-paths' | 'patch-lab' | 'verification' | 'sarif' | 'memory' | 'guardian' | 'audit' | 'real-assessment';

interface NavItem {
  id: PageId;
  label: string;
  icon: typeof Shield;
  badge?: number;
}

interface SidebarProps {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
}

export function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  const { auditEvents, securityMemory, isRunning } = useKavach();

  const navItems: NavItem[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'real-assessment', label: 'Real Assessment', icon: Target },
    { id: 'investigations', label: 'Investigations', icon: Search },
    { id: 'fuzzing', label: 'Fuzzing Lab', icon: Zap },
    { id: 'cpp-dynamic', label: 'C++ Dynamic Lab', icon: Cpu },
    { id: 'twin', label: 'Digital Twin', icon: Box },
    { id: 'evidence-graph', label: 'Evidence Graph', icon: Network },
    { id: 'attack-paths', label: 'Attack Paths', icon: GitBranch },
    { id: 'patch-lab', label: 'Patch Lab', icon: FlaskConical },
    { id: 'verification', label: 'Verification', icon: CheckCircle },
    { id: 'sarif', label: 'SARIF Analysis', icon: FileSearch },
    { id: 'memory', label: 'Security Memory', icon: Database, badge: securityMemory.length || undefined },
    { id: 'guardian', label: 'Agent Guardian', icon: Lock },
    { id: 'audit', label: 'Audit Log', icon: ScrollText, badge: auditEvents.length || undefined },
  ];

  return (
    <aside className="w-60 bg-kavach-surface border-r border-kavach-border flex flex-col h-full">
      {/* Logo */}
      <div className="px-5 py-4 border-b border-kavach-border">
        <div className="flex items-center gap-3">
          <div className="relative shrink-0">
            <img 
              src="/logo.png" 
              alt="Kavach Abhedya Logo" 
              className="w-9 h-9 object-contain drop-shadow-[0_0_10px_rgba(14,165,233,0.35)]" 
            />
            {isRunning && (
              <span className="absolute top-0 right-0 w-2.5 h-2.5 bg-kavach-accent rounded-full animate-pulse border border-kavach-bg" />
            )}
          </div>
          <div>
            <h1 className="text-sm font-bold text-kavach-text-primary tracking-tight leading-tight">KAVACH ABHEDYA</h1>
            <p className="text-[10px] text-kavach-text-muted font-mono uppercase tracking-wider">Cyber Reasoning</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentPage === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all duration-200 group ${
                isActive
                  ? 'bg-kavach-accent/10 text-kavach-accent border border-kavach-accent/20'
                  : 'text-kavach-text-secondary hover:bg-kavach-surface-2 hover:text-kavach-text-primary border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-kavach-accent' : 'text-kavach-text-muted group-hover:text-kavach-text-secondary'}`} />
              <span className="flex-1 text-left font-medium">{item.label}</span>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="text-xs font-mono bg-kavach-surface-2 text-kavach-text-secondary px-1.5 py-0.5 rounded border border-kavach-border">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-kavach-border">
        <div className="flex items-center gap-2 text-xs">
          <span className="status-dot bg-kavach-success active" />
          <span className="text-kavach-text-muted font-mono">Guardian Active</span>
        </div>
        <div className="flex items-center gap-2 text-xs mt-1.5">
          <span className="status-dot bg-kavach-accent active" />
          <span className="text-kavach-text-muted font-mono">Sandbox Isolated</span>
        </div>
      </div>
    </aside>
  );
}
