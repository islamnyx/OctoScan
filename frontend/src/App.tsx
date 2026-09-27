import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { useApiKey, useClock, useHealth, useJobs } from './hooks/useOcto';
import { Layout } from './components/Layout';
import { CommandPalette } from './components/Palette';
import { CoveragePanel, LiveFeed, KpiCards, SeverityDonut, usePosture } from './components/Dashboard';
import { AttackRadar, VulnSunburst } from './components/Visuals';
import { ScanTabs } from './components/ScanTabs';
import { HistoryTables } from './components/History';
import type { NavId } from './components/Sidebar';
import { Button } from './components/ui/controls';

export default function App() {
  const online = useHealth();
  const clock = useClock();
  const { web, repo } = useJobs();
  const [apiKey, setApiKey] = useApiKey();
  const [collapsed, setCollapsed] = useState(false);
  const [palette, setPalette] = useState(false);
  const [tab, setTab] = useState('pane-web');
  const [active, setActive] = useState<NavId>('overview');
  const { total, totalJobs, score } = usePosture(web, repo);
  const running = [...web, ...repo].filter((j) => ['running', 'queued', 'paused'].includes(j.status)).length;

  const nav = (id: NavId) => { setActive(id); document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' }); };
  const gotoTab = (t: string) => { setTab(t); document.getElementById('launch')?.scrollIntoView({ behavior: 'smooth' }); };

  return (
    <Layout collapsed={collapsed} onToggle={() => setCollapsed((v) => !v)} onPalette={() => setPalette(true)}
      running={running} total={web.length + repo.length} active={active} onNav={nav} onGotoTab={gotoTab}
      online={online} apiKey={apiKey} onKey={setApiKey}>
      {/* HERO + CONSOLE */}
      <section id="overview" className="grid items-center gap-7 py-[26px] lg:grid-cols-[1.05fr_.95fr]">
        <div>
          <span className="inline-flex items-center gap-2 rounded border border-border-line bg-surface-panel px-2.5 py-1 font-mono text-xs text-ink-dim">
            <span className={`h-[7px] w-[7px] rounded-full ${online ? 'bg-success' : 'bg-ink-dim'}`} /> API: {online == null ? 'checking…' : online ? 'online' : 'unreachable'}
          </span>
          <h1 className="mb-2 mt-3.5 font-heading text-[28px] font-bold leading-[1.15] tracking-tight text-ink">Pre-launch security checks,<br />in one place.</h1>
          <p className="mb-[18px] max-w-[54ch] text-[15px] text-ink-dim">Run web, codebase, and AI-assisted scans. Every finding carries severity, evidence, and a recommended fix. Export JSON, text, or PDF when you're done.</p>
          <div className="flex flex-wrap gap-2.5">
            <Button onClick={() => nav('launch')}>New scan</Button>
            <Button variant="ghost" onClick={() => nav('history')}>History</Button>
          </div>
          <div className="mt-5 flex flex-wrap gap-[22px]">
            {[['scans', totalJobs], ['findings', total], ['risk (/100)', score ?? '—']].map(([l, v]) => (
              <div key={l}><b className="block font-heading text-xl tracking-tight text-ink">{v}</b><span className="font-mono text-xs text-ink-dim">{l}</span></div>
            ))}
          </div>
        </div>
        <div id="console" className="overflow-hidden rounded-panel border border-border-line bg-surface-panel">
          <div className="flex items-center gap-2 border-b border-border-line px-3.5 py-2.5 font-heading text-[11.5px] font-bold tracking-wider text-ink-dim">Posture <span className="ml-auto font-mono font-normal">{clock}</span></div>
          <KpiCards web={web} repo={repo} />
          <div className="mx-3.5 mb-3.5 rounded-panel border border-border-line bg-background font-mono text-xs">
            <div className="border-b border-border-line px-3 py-2 text-ink-dim">Latest activity</div>
            <div className="grid gap-1 px-3 py-2.5 text-ink"><LiveFeed web={web} repo={repo} /></div>
          </div>
        </div>
      </section>

      <div className="mb-6 border-y border-border-line"><span className="block px-0.5 py-2 font-mono text-xs text-ink-dim">Notes: ZAP active scan is capped · Nuclei throttled · secrets redacted · scope tracked per finding · gate fails on XSS/SQLi.</span></div>

      {/* INTEL */}
      <p className="mb-2.5 font-mono text-xs text-ink-dim">Severity and coverage</p>
      <div id="intel" className="mb-[18px] grid grid-cols-[1.5fr_1fr] gap-4 max-lg:grid-cols-1">
        <div className="rounded-panel border border-border-line bg-surface-panel">
          <div className="flex items-center gap-2 border-b border-border-line px-4 py-3 font-heading text-xs font-bold tracking-wider text-ink-dim">Severity <span className="font-mono font-normal">· latest 10 scans</span></div>
          <div className="p-4"><SeverityDonut web={web} repo={repo} /></div>
        </div>
        <div className="rounded-panel border border-border-line bg-surface-panel">
          <div className="flex items-center gap-2 border-b border-border-line px-4 py-3 font-heading text-xs font-bold tracking-wider text-ink-dim">Scanner coverage</div>
          <div className="p-4"><CoveragePanel web={web} repo={repo} /></div>
        </div>
      </div>
      <div className="mb-[18px] grid grid-cols-2 gap-4 max-lg:grid-cols-1"><AttackRadar /><VulnSunburst /></div>

      {/* LAUNCH */}
      <p id="launch" className="mb-2.5 font-mono text-xs text-ink-dim">New scan</p>
      <section aria-label="Start a scan" className="mb-[18px]">
        <ScanTabs key={tab} initial={tab} />
      </section>

      {/* HISTORY */}
      <p id="history" className="mb-2.5 mt-[22px] font-mono text-xs text-ink-dim"><span id="web-filter-anchor" />History</p>
      <section aria-label="History"><HistoryTables web={web} repo={repo} /></section>

      <div className="mt-6 flex items-center gap-2 rounded-panel border border-border-line bg-surface-panel p-4 text-[13px] text-ink-dim">
        <ShieldCheck size={15} className="shrink-0 text-success" /> Static scans catch secrets, known CVEs and risky sinks — business-logic flaws need the AI pass or manual review.
      </div>
      <CommandPalette open={palette} onOpen={setPalette} web={web} repo={repo} onTab={gotoTab} />
    </Layout>
  );
}
