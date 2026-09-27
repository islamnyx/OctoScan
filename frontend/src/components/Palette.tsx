import { useEffect, useMemo, useState } from 'react';
import { Command } from 'cmdk';
import type { RepoJob, WebJob } from '../lib/api';

export function CommandPalette({ open, onOpen, web, repo, onTab }: {
  open: boolean; onOpen: (v: boolean) => void; web: WebJob[]; repo: RepoJob[]; onTab: (id: string) => void;
}) {
  const [q, setQ] = useState('');
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); onOpen(!open); }
      if (e.key === 'Escape') onOpen(false);
      if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test((document.activeElement?.tagName || ''))) { e.preventDefault(); document.getElementById('web-filter-anchor')?.scrollIntoView({ behavior: 'smooth' }); }
    };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [open, onOpen]);
  const latest = (arr: { created_at: string }[]) => [...arr].sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at))[0] as WebJob | RepoJob | undefined;
  const items = useMemo(() => {
    const lw = latest(web) as WebJob | undefined, lr = latest(repo) as RepoJob | undefined;
    const running = [...web, ...repo].find((j) => ['running', 'queued', 'paused'].includes(j.status));
    return [
      { t: 'Go: Overview', k: 'nav', fn: () => document.getElementById('overview')?.scrollIntoView({ behavior: 'smooth' }) },
      { t: 'Go: Launch scan', k: 'nav', fn: () => document.getElementById('launch')?.scrollIntoView({ behavior: 'smooth' }) },
      { t: 'Go: History', k: 'nav', fn: () => document.getElementById('history')?.scrollIntoView({ behavior: 'smooth' }) },
      { t: 'Tab: Web application', k: 'tab', fn: () => onTab('pane-web') },
      { t: 'Tab: Codebase', k: 'tab', fn: () => onTab('pane-repo') },
      { t: 'Tab: AI provider', k: 'tab', fn: () => onTab('pane-ai') },
      { t: 'Tab: Mobile APK', k: 'tab', fn: () => onTab('pane-apk') },
      ...(lw ? [{ t: `Open: latest web — ${String(lw.target_url).slice(0, 42)}`, k: 'open', fn: () => { location.href = '/scans/' + encodeURIComponent(lw.id); } }] : []),
      ...(lr ? [{ t: `Open: latest codebase — ${String(lr.repo_url).slice(0, 42)}`, k: 'open', fn: () => { location.href = '/repos/' + encodeURIComponent(lr.id); } }] : []),
      ...(running ? [{ t: `Watch: running scan ${running.id.slice(0, 8)}`, k: 'open', fn: () => { location.href = ((running as WebJob).target_url ? '/scans/' : '/repos/') + encodeURIComponent(running.id) + '/status'; } }] : []),
    ];
  }, [web, repo, onTab]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[60] bg-black/60" onClick={() => onOpen(false)}>
      <div className="mx-auto mt-[12vh] w-[min(560px,92vw)] overflow-hidden rounded-lg border border-border-line bg-surface" onClick={(e) => e.stopPropagation()}>
        <Command label="Command palette" className="bg-transparent">
          <Command.Input value={q} onValueChange={setQ} placeholder="Type a command…  (web, ai, history)" className="w-full border-0 border-b border-border-line bg-transparent px-4 py-3.5 text-sm text-ink outline-none placeholder:text-ink-dim" />
          <Command.List className="max-h-[320px] overflow-y-auto p-1.5">
            <Command.Empty className="px-3 py-2 text-[13px] text-ink-dim">No match.</Command.Empty>
            {items.filter((a) => a.t.toLowerCase().includes(q.toLowerCase())).map((a) => (
              <Command.Item key={a.t} onSelect={() => { onOpen(false); a.fn(); }} className="flex cursor-pointer items-center gap-2.5 rounded-md px-3 py-2 text-[13px] text-ink-dim aria-selected:bg-[rgba(255,106,44,.12)] aria-selected:text-ink">
                ▸ {a.t}<span className="ml-auto font-mono text-[10px] text-ink-dim">{a.k}</span>
              </Command.Item>
            ))}
          </Command.List>
        </Command>
      </div>
    </div>
  );
}
