import { useMemo, useState } from 'react';
import { Sparkles } from 'lucide-react';
import type { RepoJob, WebJob } from '../lib/api';
import { Badge, cvssTone, statusTone } from './ui/controls';

function JobRow({ label, sub, status, ai, cvss, href }: { label: string; sub: string; status: string; ai?: boolean; cvss?: number | null; href: string }) {
  return (
    <tr className="cursor-pointer hover:bg-[rgba(255,106,44,0.05)]" onClick={() => { location.href = href; }}>
      <td className="border-b border-border-line px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="break-all font-semibold text-ink">{label}</span>
          <Badge tone={statusTone(status)}>{status}</Badge>
          {ai && <span className="rounded bg-accent/10 px-1.5 font-mono text-xs font-semibold text-accent">AI</span>}
          {cvss != null && <Badge tone={cvssTone(cvss)}>CVSS {cvss.toFixed(1)}</Badge>}
        </div>
        <div className="font-mono text-xs text-ink-dim">{sub}</div>
      </td>
    </tr>
  );
}

export function HistoryTables({ web, repo }: { web: WebJob[]; repo: RepoJob[] }) {
  const [wq, setWq] = useState('');
  const [rq, setRq] = useState('');
  const wf = useMemo(() => web.filter((j) => (j.target_url || '').toLowerCase().includes(wq.toLowerCase())).slice(0, 10), [web, wq]);
  const rf = useMemo(() => repo.filter((j) => (j.repo_url || '').toLowerCase().includes(rq.toLowerCase())).slice(0, 10), [repo, rq]);
  const card = 'overflow-hidden rounded-panel border border-border-line bg-surface-panel';
  const head = 'flex items-center gap-2 border-b border-border-line px-4 py-3 font-heading text-xs font-bold tracking-wider text-ink-dim';
  return (
    <div className="grid grid-cols-2 gap-4 max-lg:grid-cols-1">
      <div className={card}>
        <h3 className={head}>WEB SCANS<input value={wq} onChange={(e) => setWq(e.target.value)} placeholder="Filter…" className="ml-auto w-[150px] rounded-md border border-border-line bg-background px-2.5 py-1.5 font-mono text-xs text-ink outline-none focus:border-accent" /></h3>
        <table className="w-full border-collapse text-[12.5px]"><tbody>
          {wf.length ? wf.map((j) => {
            const running = ['running', 'queued', 'paused'].includes(j.status);
            const top = [...(j.findings || [])].sort((a, b) => (b.cvss ?? -1) - (a.cvss ?? -1))[0]?.cvss;
            return <JobRow key={j.id} label={j.target_url} status={j.status} ai={!!j.ai} cvss={top} sub={`${(j.findings || []).length} findings · ${new Date(j.created_at).toLocaleString()}`} href={`/${running ? `scans/${encodeURIComponent(j.id)}/status` : `scans/${encodeURIComponent(j.id)}`}`} />;
          }) : <tr><td className="px-4 py-3.5 text-[12.5px] text-ink-dim">No web scans yet — launch one above.</td></tr>}
        </tbody></table>
      </div>
      <div className={card}>
        <h3 className={head}>CODEBASE SCANS<input value={rq} onChange={(e) => setRq(e.target.value)} placeholder="Filter…" className="ml-auto w-[150px] rounded-md border border-border-line bg-background px-2.5 py-1.5 font-mono text-xs text-ink outline-none focus:border-accent" /></h3>
        <table className="w-full border-collapse text-[12.5px]"><tbody>
          {rf.length ? rf.map((j) => {
            const running = ['running', 'queued', 'paused'].includes(j.status);
            return <JobRow key={j.id} label={j.repo_url} status={j.status} ai={!!j.ai} sub={`${(j.findings || []).length} findings · ${j.files_scanned || 0} files · ${new Date(j.created_at).toLocaleString()}`} href={`/${running ? `repos/${encodeURIComponent(j.id)}/status` : `repos/${encodeURIComponent(j.id)}`}`} />;
          }) : <tr><td className="px-4 py-3.5 text-[12.5px] text-ink-dim">No codebase scans yet.</td></tr>}
        </tbody></table>
      </div>
      <p className="col-span-full m-0 flex items-center gap-1.5 font-mono text-xs text-ink-dim"><Sparkles size={12} /> Tip: press <kbd className="rounded border border-border-line px-1">Ctrl K</kbd> for the command palette, <kbd className="rounded border border-border-line px-1">/</kbd> to focus the web filter.</p>
    </div>
  );
}
