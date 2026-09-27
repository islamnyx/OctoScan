import { useState } from 'react';
import { ChevronLeft, FlaskConical, History, LayoutDashboard, Radar, Terminal } from 'lucide-react';
import { cn } from '../lib/utils';

export type NavId = 'overview' | 'launch' | 'history' | 'intel';
const LINKS: { id: NavId; label: string; icon: React.ReactNode; num: string }[] = [
  { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={15} />, num: '01' },
  { id: 'launch', label: 'New scan', icon: <FlaskConical size={15} />, num: '02' },
  { id: 'history', label: 'History', icon: <History size={15} />, num: '03' },
  { id: 'intel', label: 'Severity & coverage', icon: <Radar size={15} />, num: '04' },
];

export function Sidebar({ collapsed, onToggle, onPalette, running, total, active, onNav, onGotoTab }: {
  collapsed: boolean; onToggle: () => void; onPalette: () => void;
  running: number; total: number; active: NavId; onNav: (id: NavId) => void; onGotoTab: (tab: string) => void;
}) {
  const [q, setQ] = useState('');
  return (
    <aside className={cn('fixed left-0 top-0 bottom-0 z-40 flex flex-col gap-0.5 border-r border-border-line bg-surface px-3 py-4 transition-all', collapsed ? 'w-[72px]' : 'w-[248px]', 'max-lg:-translate-x-full')}>
      <div className="flex items-center gap-2.5 border-b border-border-line px-2 pb-3.5">
        <img src="/static/logo.png" alt="OctoScan logo" className="h-[30px] w-[30px] shrink-0 rounded-md object-contain" />
        {!collapsed && <div><b className="block font-heading text-sm leading-tight text-ink">OctoScan</b><span className="font-mono text-[10px] text-ink-dim">console</span></div>}
      </div>
      {!collapsed && <div className="px-2.5 pb-1 pt-3 font-mono text-[10px] text-ink-dim">Navigate</div>}
      {LINKS.map((l) => (
        <button key={l.id} onClick={() => onNav(l.id)}
          className={cn('flex items-center gap-2.5 rounded-md border border-transparent px-2.5 py-2 text-[13px] font-semibold text-ink-dim hover:text-ink', active === l.id && 'bg-[rgba(255,106,44,.1)] text-accent')}>
          <span className={cn('w-[22px] text-center font-mono text-[11px]', active === l.id ? 'text-accent' : 'text-ink-dim')}>{collapsed ? l.icon : l.num}</span>
          {!collapsed && <span>{l.label}</span>}
          {!collapsed && l.id === 'launch' && <span className="ml-auto rounded border border-accent/40 px-1.5 font-mono text-[10px] text-accent">{running} run</span>}
          {!collapsed && l.id === 'history' && <span className="ml-auto rounded border border-border-line px-1.5 font-mono text-[10px] text-ink-dim">{total}</span>}
        </button>
      ))}
      {!collapsed && (
        <div className="ml-8 flex flex-col gap-0.5">
          {[['pane-web', 'Web application'], ['pane-repo', 'Codebase'], ['pane-ai', 'AI provider'], ['pane-apk', 'Mobile APK']].map(([id, label]) => (
            <button key={id} onClick={() => onGotoTab(id)} className="rounded px-2 py-1 text-left text-[12.5px] text-ink-dim hover:text-accent">{label}</button>
          ))}
        </div>
      )}
      {!collapsed && <div className="px-2.5 pb-1 pt-3 font-mono text-[10px] text-ink-dim">Tools</div>}
      <button onClick={onPalette} className="flex w-full items-center gap-2.5 rounded-md border border-border-line bg-background px-2.5 py-2 text-[12.5px] font-semibold text-ink-dim hover:text-ink">
        <Terminal size={14} /><span className={cn(collapsed && 'hidden')}>Command…</span>
        {!collapsed && <kbd className="ml-auto rounded border border-border-line px-1.5 font-mono text-[10px] text-ink-dim">Ctrl K</kbd>}
      </button>
      <div className="mt-auto grid gap-2 border-t border-border-line pt-2.5">
        <button onClick={onToggle} className="flex w-full items-center gap-2.5 rounded-md border border-border-line bg-background px-2.5 py-2 text-[12.5px] font-semibold text-ink-dim hover:text-ink">
          <ChevronLeft size={14} className={cn(collapsed && 'rotate-180')} />{!collapsed && <span>Collapse</span>}
        </button>
        {!collapsed && (
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="/ filter history" onKeyDown={(e) => { if (e.key === 'Enter') onNav('history'); }}
            className="w-full rounded-md border border-border-line bg-background px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-accent" />
        )}
        {!collapsed && <div className="px-2.5 font-mono text-[10px] text-ink-dim">v0.1 · local-first</div>}
      </div>
    </aside>
  );
}
