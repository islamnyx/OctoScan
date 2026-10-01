import { useMemo, useState } from 'react';
import type { RepoJob, WebJob } from '../lib/api';

type Job = (WebJob | RepoJob) & { kind: 'web' | 'repo' };
type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';
const SEVS: Sev[] = ['critical', 'high', 'medium', 'low', 'info'];
const WEIGHT: Record<Sev, number> = { critical: 10, high: 5, medium: 2, low: 1, info: 0.5 };

function label(j: Job) {
  const target = j.kind === 'web' ? (j as WebJob).target_url : (j as RepoJob).repo_url;
  const d = new Date(j.created_at).toLocaleString();
  return `${target} · ${j.status} · ${(j.findings || []).length} findings · ${d}`;
}
function fkey(f: { scanner: string; title: string; location?: string }) {
  return `${f.scanner}｜${f.title}｜${f.location || ''}`;
}
function counts(fs: { severity: Sev }[]) {
  const c: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of fs) if (c[f.severity] !== undefined) c[f.severity]++;
  return c;
}
function score(c: Record<Sev, number>) {
  return (Object.keys(c) as Sev[]).reduce((s, k) => s + c[k] * WEIGHT[k], 0);
}

export function Compare({ web, repo }: { web: WebJob[]; repo: RepoJob[] }) {
  const jobs: Job[] = useMemo(
    () => [
      ...web.map((j) => ({ ...j, kind: 'web' as const })),
      ...repo.map((j) => ({ ...j, kind: 'repo' as const })),
    ].sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at)),
    [web, repo],
  );
  const [aid, setAid] = useState('');
  const [bid, setBid] = useState('');
  const a = jobs.find((j) => j.id === aid) || null;
  const b = jobs.find((j) => j.id === bid) || null;

  const diff = useMemo(() => {
    if (!a || !b) return null;
    const af = a.findings || [];
    const bf = b.findings || [];
    const am = new Map(af.map((f) => [fkey(f), f]));
    const bm = new Map(bf.map((f) => [fkey(f), f]));
    const fixed = af.filter((f) => !bm.has(fkey(f)));
    const added = bf.filter((f) => !am.has(fkey(f)));
    const persisting = af.filter((f) => bm.has(fkey(f)));
    const ca = counts(af as { severity: Sev }[]);
    const cb = counts(bf as { severity: Sev }[]);
    const sa = score(ca);
    const sb = score(cb);
    const improvement = sa === 0 ? (sb === 0 ? 0 : -100) : Math.round(((sa - sb) / sa) * 100);
    // per-scanner (each test) breakdown
    const scanners = [...new Set([...af.map((f) => f.scanner), ...bf.map((f) => f.scanner)])].sort();
    const per = scanners.map((s) => ({
      s,
      a: af.filter((f) => f.scanner === s).length,
      b: bf.filter((f) => f.scanner === s).length,
    }));
    return { af, bf, fixed, added, persisting, ca, cb, sa, sb, improvement, per };
  }, [a, b]);

  const pick = 'w-full rounded-md border border-border-line bg-background px-2.5 py-2 font-mono text-xs text-ink outline-none focus:border-accent';
  return (
    <div className="overflow-hidden rounded-panel border border-border-line bg-surface-panel">
      <div className="flex items-center gap-2 border-b border-border-line px-4 py-3 font-heading text-xs font-bold tracking-wider text-ink-dim">
        Test-vs-test compare
        <span className="font-mono font-normal">· baseline → current · fixed / new / persisting</span>
      </div>
      <div className="grid gap-3 p-4">
        {!jobs.length && <div className="text-[12.5px] text-ink-dim">No scans yet — run a web or codebase scan first, then compare two runs here.</div>}
        <div className="grid gap-2.5 lg:grid-cols-2">
          <label className="grid gap-1.5 text-xs font-semibold text-ink-dim">Baseline (before)
            <select className={pick} value={aid} onChange={(e) => setAid(e.target.value)}>
              <option value="">— pick a scan —</option>
              {jobs.map((j) => <option key={j.id} value={j.id}>[{j.kind}] {label(j)}</option>)}
            </select>
          </label>
          <label className="grid gap-1.5 text-xs font-semibold text-ink-dim">Current (after)
            <select className={pick} value={bid} onChange={(e) => setBid(e.target.value)}>
              <option value="">— pick a scan —</option>
              {jobs.map((j) => <option key={j.id} value={j.id}>[{j.kind}] {label(j)}</option>)}
            </select>
          </label>
        </div>

        {diff && (
          <div className="grid gap-3">
            <div className="flex flex-wrap gap-2.5">
              {[['Risk (baseline)', diff.sa.toFixed(1)], ['Risk (current)', diff.sb.toFixed(1)],
                [`Improvement`, `${diff.improvement > 0 ? '−' : ''}${Math.abs(diff.improvement)}%`],
                ['Fixed', diff.fixed.length], ['New', diff.added.length], ['Persisting', diff.persisting.length],
              ].map(([l, v]) => (
                <div key={l} className="rounded-md border border-border-line bg-background px-3 py-2">
                  <b className="block font-heading text-base text-ink">{v}</b>
                  <span className="font-mono text-[11px] text-ink-dim">{l}</span>
                </div>
              ))}
            </div>

            <div className="overflow-x-auto rounded-md border border-border-line">
              <table className="w-full border-collapse text-[12px]">
                <thead><tr className="bg-background text-left font-mono text-[11px] text-ink-dim">
                  <th className="px-3 py-2">Severity</th><th className="px-3 py-2">Baseline</th>
                  <th className="px-3 py-2">Current</th><th className="px-3 py-2">Δ</th>
                </tr></thead>
                <tbody>
                  {SEVS.map((s) => {
                    const d = diff.cb[s] - diff.ca[s];
                    return (
                      <tr key={s} className="border-t border-border-line">
                        <td className="px-3 py-1.5 font-semibold text-ink">{s}</td>
                        <td className="px-3 py-1.5 font-mono text-ink-dim">{diff.ca[s]}</td>
                        <td className="px-3 py-1.5 font-mono text-ink">{diff.cb[s]}</td>
                        <td className={`px-3 py-1.5 font-mono font-bold ${d < 0 ? 'text-success' : d > 0 ? 'text-[#ff7d6b]' : 'text-ink-dim'}`}>
                          {d === 0 ? '±0' : `${d > 0 ? '+' : ''}${d}`}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="overflow-x-auto rounded-md border border-border-line">
              <table className="w-full border-collapse text-[12px]">
                <thead><tr className="bg-background text-left font-mono text-[11px] text-ink-dim">
                  <th className="px-3 py-2">Each test (scanner)</th><th className="px-3 py-2">Baseline</th>
                  <th className="px-3 py-2">Current</th><th className="px-3 py-2">Δ</th>
                </tr></thead>
                <tbody>
                  {diff.per.map((r) => {
                    const d = r.b - r.a;
                    return (
                      <tr key={r.s} className="border-t border-border-line">
                        <td className="px-3 py-1.5 font-mono text-ink">{r.s}</td>
                        <td className="px-3 py-1.5 font-mono text-ink-dim">{r.a}</td>
                        <td className="px-3 py-1.5 font-mono text-ink">{r.b}</td>
                        <td className={`px-3 py-1.5 font-mono font-bold ${d < 0 ? 'text-success' : d > 0 ? 'text-[#ff7d6b]' : 'text-ink-dim'}`}>
                          {d === 0 ? '±0' : `${d > 0 ? '+' : ''}${d}`}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="grid gap-2.5 lg:grid-cols-3">
              {([['Fixed ✓', diff.fixed, 'text-success'], ['New +', diff.added, 'text-[#ff7d6b]'], ['Persisting …', diff.persisting, 'text-ink-dim']] as const).map(([t, rows, cls]) => (
                <div key={t} className="rounded-md border border-border-line bg-background p-2.5">
                  <b className={`font-heading text-[12px] ${cls}`}>{t} ({rows.length})</b>
                  <div className="mt-1.5 grid max-h-[180px] gap-1 overflow-y-auto">
                    {rows.slice(0, 30).map((f) => (
                      <div key={fkey(f)} className="text-[12px] text-ink">
                        <span className="font-mono text-[10px] text-ink-dim">[{f.severity}/{f.scanner}]</span> {f.title}
                      </div>
                    ))}
                    {!rows.length && <span className="text-[12px] text-ink-dim">— none —</span>}
                    {rows.length > 30 && <span className="font-mono text-[11px] text-ink-dim">… +{rows.length - 30} more</span>}
                  </div>
                </div>
              ))}
            </div>
            <p className="m-0 font-mono text-[11px] text-ink-dim">Tip: pick two runs of the SAME target to measure a fix. Risk = 10·crit + 5·high + 2·med + 1·low + 0.5·info.</p>
          </div>
        )}
      </div>
    </div>
  );
}
