import { useMemo } from 'react';
import { Bar, BarChart, Cell, LabelList, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { RepoJob, WebJob } from '../lib/api';
import { riskScore } from '../lib/utils';

const SEV_COLORS: Record<string, string> = {
  critical: '#ff6a2c',
  high: '#ff9a5c',
  medium: '#9a9ca1',
  low: '#55585e',
  info: '#2b2f36',
};
const TIP_STYLE = { background: '#111419', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12, fontFamily: '"IBM Plex Mono", monospace' };

export function usePosture(web: WebJob[], repo: RepoJob[]) {
  return useMemo(() => {
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    [...web.slice(0, 10), ...repo.slice(0, 10)].forEach((j) => (j.findings || []).forEach((f) => { if (c[f.severity] !== undefined) c[f.severity]++; }));
    const total = c.critical + c.high + c.medium + c.low + c.info;
    const totalJobs = web.length + repo.length;
    const done = [...web, ...repo].filter((j) => j.status === 'completed').length;
    const score = totalJobs ? riskScore(c) : null;
    return { c, total, totalJobs, done, score };
  }, [web, repo]);
}

export function KpiCards({ web, repo }: { web: WebJob[]; repo: RepoJob[] }) {
  const { c, total, totalJobs, done, score } = usePosture(web, repo);
  const cards = [
    { label: 'Crit + High', value: c.critical + c.high, sub: `${c.critical} crit · ${c.high} high`, hot: true },
    { label: 'Findings', value: total, sub: `${web.length} web · ${repo.length} code`, hot: false },
    { label: 'Done', value: `${done}/${totalJobs}`, sub: totalJobs ? `${Math.round((done / totalJobs) * 100)}% ok` : 'no scans', hot: false },
    { label: 'Risk', value: score ?? '—', sub: '100 = clean', hot: false },
  ];
  return (
    <div className="grid grid-cols-4 gap-2.5 p-3.5 max-sm:grid-cols-2">
      {cards.map((k) => (
        <div key={k.label} className={`rounded-panel border bg-surface-panel p-3 ${k.hot ? 'border-accent/50' : 'border-border-line'}`}>
          <div className="mb-1 font-mono text-xs text-ink-dim">{k.label}</div>
          <div className="font-heading text-[28px] font-bold leading-none tracking-tight text-ink">{k.value}</div>
          <div className="m-0 mt-1 font-mono text-xs text-ink-dim">{k.sub}</div>
        </div>
      ))}
    </div>
  );
}

export function SeverityDonut({ web, repo }: { web: WebJob[]; repo: RepoJob[] }) {
  const { c, total } = usePosture(web, repo);
  const data = Object.entries(c).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }));
  return (
    <div className="flex items-center gap-4">
      <div className="relative h-[130px] w-[130px] shrink-0">
        {total === 0 ? (
          <div className="grid h-full w-full place-items-center rounded-full border-[12px] border-border-line" />
        ) : (
          <ResponsiveContainer>
            <PieChart>
              <Pie data={data} dataKey="value" nameKey="name" innerRadius={42} outerRadius={62} strokeWidth={0} paddingAngle={2}>
                {data.map((d) => <Cell key={d.name} fill={SEV_COLORS[d.name]} />)}
              </Pie>
              <Tooltip contentStyle={TIP_STYLE} labelStyle={{ color: '#f3efe9' }} />
            </PieChart>
          </ResponsiveContainer>
        )}
        <div className="pointer-events-none absolute inset-0 grid place-items-center">
          <div className="text-center">
            <div className="font-heading text-[22px] font-bold leading-none text-ink">{total}</div>
            <div className="mt-0.5 font-mono text-[10px] text-ink-dim">findings</div>
          </div>
        </div>
      </div>
      <div className="grid gap-1 font-mono text-xs text-ink-dim">
        {Object.entries(c).map(([k, v]) => <span key={k}>▸ {k} <b className="text-ink">{v}</b></span>)}
      </div>
    </div>
  );
}

export function CoveragePanel({ web, repo }: { web: WebJob[]; repo: RepoJob[] }) {
  const all = [...web.slice(0, 10), ...repo.slice(0, 10)];
  const cov: Record<string, number> = {};
  all.forEach((j) => (j.scanners_run || []).forEach((s) => { cov[s] = (cov[s] || 0) + 1; }));
  const names = Object.keys(cov).sort();
  if (!names.length) return <span className="text-[12.5px] text-ink-dim">No scanner data yet.</span>;
  const data = names.map((n) => ({ name: n, pct: Math.round((cov[n] / Math.max(1, all.length)) * 100), count: `${cov[n]}/${all.length}` }));
  return (
    <div>
      <ResponsiveContainer width="100%" height={Math.max(120, data.length * 36)}>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 52, bottom: 0, left: 0 }}>
          <XAxis type="number" domain={[0, 100]} hide />
          <YAxis type="category" dataKey="name" width={112} tick={{ fill: '#9a9ca1', fontSize: 11, fontFamily: '"IBM Plex Mono", monospace' }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={TIP_STYLE} labelStyle={{ color: '#f3efe9' }} formatter={(value) => [`${value}%`, 'coverage']} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
          <Bar dataKey="pct" fill="#ff6a2c" radius={[4, 4, 4, 4]} barSize={8} background={{ fill: 'rgba(255,255,255,0.05)', radius: 4 } as never}>
            <LabelList dataKey="pct" position="right" fill="#9a9ca1" fontSize={11} fontFamily='"IBM Plex Mono", monospace' formatter={(v: React.ReactNode) => `${v}%`} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      <div className="mt-1 grid gap-1">
        {data.map((d) => <div key={d.name} className="flex justify-between font-mono text-xs text-ink-dim"><span>{d.count} scans</span></div>)}
      </div>
    </div>
  );
}

const STATUS_COLOR: Record<string, string> = {
  completed: '#4ADE80',
  failed: '#ff6a2c',
  running: '#ff6a2c',
  queued: '#9a9ca1',
  paused: '#9a9ca1',
};

export function LiveFeed({ web, repo }: { web: WebJob[]; repo: RepoJob[] }) {
  const jobs = [...web, ...repo]
    .sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at))
    .slice(0, 8);
  if (!jobs.length) return <div>No scans yet. Start one below and activity will show here.</div>;
  return (
    <div className="grid gap-2">
      {jobs.map((j) => {
        const lbl = (j as WebJob).target_url || (j as unknown as RepoJob).repo_url || j.id;
        const col = STATUS_COLOR[j.status] ?? '#9a9ca1';
        const meta = [
          (j.scanners_run || []).join(', ') || 'queued',
          `${(j.findings || []).length} findings`,
          (j as WebJob).gate ?? (j as unknown as RepoJob).branch ?? null,
          j.id.slice(0, 8),
        ].filter(Boolean).join(' · ');
        return (
          <div key={j.id} className="border-b border-border-line pb-2 last:border-0 last:pb-0">
            <div>
              <span className="font-semibold" style={{ color: col }}>{j.status.toUpperCase()}</span>
              <span className="text-ink-dim"> — </span>{String(lbl).slice(0, 56)}
            </div>
            <div className="text-ink-dim">{meta}</div>
          </div>
        );
      })}
    </div>
  );
}
