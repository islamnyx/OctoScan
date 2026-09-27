import type { ReactNode } from 'react';
import { cn } from '../lib/utils';
import { Sidebar, type NavId } from './Sidebar';
import { Topbar } from './Topbar';

export function Layout({ children, collapsed, onToggle, onPalette, running, total, active, onNav, onGotoTab, online, apiKey, onKey }: {
  children: ReactNode; collapsed: boolean; onToggle: () => void; onPalette: () => void;
  running: number; total: number; active: NavId; onNav: (id: NavId) => void; onGotoTab: (t: string) => void;
  online: boolean | null; apiKey: string; onKey: (v: string) => void;
}) {
  return (
    <div className={cn('min-h-screen bg-background text-ink', collapsed && 'lg:[--side:72px]')}>
      <Sidebar collapsed={collapsed} onToggle={onToggle} onPalette={onPalette} running={running} total={total} active={active} onNav={onNav} onGotoTab={onGotoTab} />
      <div className={cn('transition-all', collapsed ? 'lg:ml-[72px]' : 'lg:ml-[248px]')}>
        <Topbar online={online} apiKey={apiKey} onKey={onKey} />
        <main className="mx-auto max-w-[1220px] px-6 pb-[72px] pt-7">{children}</main>
        <footer className="mx-auto max-w-[1220px] px-6 pb-10 font-mono text-xs text-ink-dim">OctoScan by OctoSec Labs · findings are advisory — verify before acting</footer>
      </div>
    </div>
  );
}
