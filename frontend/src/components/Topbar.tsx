import { ShieldCheck, ShieldX } from 'lucide-react';
import { cn } from '../lib/utils';

export function Topbar({ online, apiKey, onKey }: { online: boolean | null; apiKey: string; onKey: (v: string) => void }) {
  return (
    <header className="sticky top-0 z-20 border-b border-border-line bg-surface">
      <div className="mx-auto flex max-w-[1220px] items-center gap-3 px-6 py-3">
        <div className="mr-auto flex items-center gap-2.5">
          <span className="grid h-8 w-8 place-items-center rounded-md bg-accent font-heading font-bold text-[#1a0a02]">O</span>
          <span className="font-heading text-[15px] font-bold text-ink">OctoScan</span>
          <span className="rounded border border-border-line px-2 py-0.5 font-mono text-[10.5px] font-semibold text-ink-dim">Console</span>
        </div>
        <nav className="flex gap-[18px] text-[13px] text-ink-dim max-lg:hidden">
          <a href="#overview" className="hover:text-ink">Overview</a>
          <a href="#launch" className="hover:text-ink">New scan</a>
          <a href="#history" className="hover:text-ink">History</a>
          <a href="#intel" className="hover:text-ink">Coverage</a>
        </nav>
        <span className={cn('flex items-center gap-1.5 rounded-md border border-border-line bg-background px-3 py-1.5 font-mono text-xs text-ink-dim', online === true && 'text-success', online === false && 'text-[#ff7d6b]')}>
          <span className={cn('h-2 w-2 rounded-full bg-ink-dim', online === true && 'bg-success', online === false && 'bg-[#ff7d6b]')} />
          {online == null ? 'connecting…' : online ? <span className="flex items-center gap-1"><ShieldCheck size={12} /> API online</span> : <span className="flex items-center gap-1"><ShieldX size={12} /> API unreachable</span>}
        </span>
        <input value={apiKey} onChange={(e) => onKey(e.target.value)} type="password" placeholder="API key" autoComplete="off"
          className="w-[170px] rounded-md border border-border-line bg-background px-3 py-1.5 font-mono text-[12.5px] text-ink outline-none focus:border-accent" />
      </div>
    </header>
  );
}
