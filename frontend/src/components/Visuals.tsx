import { useMemo } from 'react';
import { Radar as RadarIcon } from 'lucide-react';
import {
  Cell, Pie, PieChart, PolarAngleAxis, PolarGrid,
  Radar, RadarChart, ResponsiveContainer, Tooltip,
} from 'recharts';
import type { RepoJob, WebJob } from '../lib/api';

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';
const SEVS: Sev[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS: Record<Sev, string> = {
  critical: '#ff6a2c',
  high: '#ff9a5c',
  medium: '#9a9ca1',
  low: '#55585e',
  info: '#2b2f36',
};
const TIP_STYLE = { background: '#111419', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, fontSize: 12, fontFamily: '"IBM Plex Mono", monospace' };

interface F { scanner: string; severity: Sev; cve?: string | null }

function allFindings(web: WebJob[], repo: RepoJob[]): F[] {
  const out: F[] = [];
  [...web.slice(0, 10), ...repo.slice(0, 10)].forEach((j) =>
    (j.findings || []).forEach((f) => out.push({ scanner: f.scanner, severity: f.severity, cve: f.cve })),
  );
  return out;
}

// Radar axes: each maps to the scanner(s) that produce that signal.
const AXES: { name: string; scanners: string[]; countCve?: boolean }[] = [
  { name: 'Ports', scanners: ['nmap'] },
  { name: 'TLS', scanners: ['testssl'] },
  { name: 'Headers', scanners: ['headers'] },
  { name: 'Web vulns', scanners: ['zap', 'nikto', 'sensitive-files'] },
  { name: 'CVEs', scanners: ['nuclei', 'osv'], countCve: true },
  { name: 'Secrets', scanners: ['gitleaks'] },
];

export function AttackRadar({ web, repo }: { web: WebJob[]; repo: RepoJob[] }) {
  const jobs = useMemo(() => [...web.slice(0, 10), ...repo.slice(0, 10)], [web, repo]);
  const data = useMemo(() => {
    const fs = allFindings(web, repo);
    const ran: Record<string, number> = {};
    jobs.forEach((j) => (j.scanners_run || []).forEach((s) => { ran[s] = (ran[s] || 0) + 1; }));
    return AXES.map((ax) => {
      const n = fs.filter(
        (f) => ax.scanners.includes(f.scanner) || (ax.countCve && f.cve),
      ).length;
      const ranCount = Math.max(...ax.scanners.map((s) => ran[s] || 0), 0);
      return { axis: ax.name, value: n, detail: `${ax.scanners.join('+')} · ${ranCount}/${Math.max(1, jobs.length)} scans` };
    });
  }, [web, repo, jobs]);
  const max = Math.max(...data.map((d) => d.value), 0);

  return (
    <div className="rounded-panel border border-border-line bg-surface-panel p-4">
      <div className="mb-2 flex items-center gap-2 font-mono text-xs text-ink-dim">
        <RadarIcon size={13} className="text-accent" /> Attack Surface Radar Map
        <span className="font-normal">· latest {jobs.length} scans</span>
      </div>
      {max === 0 ? (
        <div className="py-8 text-center text-[12.5px] text-ink-dim">No findings in recent scans — run a scan to map the surface.</div>
      ) : (
        <ResponsiveContainer width="100%" height={210}>
          <RadarChart data={data} outerRadius="70%">
            <PolarGrid stroke="rgba(255,255,255,0.08)" />
            <PolarAngleAxis dataKey="axis" tick={{ fill: '#9a9ca1', fontSize: 11, fontFamily: '"IBM Plex Mono", monospace' }} />
            <Radar dataKey="value" stroke="#ff6a2c" fill="#ff6a2c" fillOpacity={0.25} />
            <Tooltip contentStyle={TIP_STYLE} labelStyle={{ color: '#f3efe9' }} formatter={(v) => [`${v} findings`, 'signal']} />
          </RadarChart>
        </ResponsiveContainer>
      )}
      <div className="mt-2 grid grid-cols-3 gap-2">
        {data.map((d) => (
          <div key={d.axis} className="rounded-md border border-border-line bg-background p-2.5 text-center">
            <div className="font-mono text-xs text-ink-dim">{d.axis}</div>
            <div className="font-heading text-sm text-ink">{d.value}</div>
            <div className="font-mono text-[10px] text-ink-dim">{d.detail}</div>
          </div>
        ))}
      </div>
      <p className="mt-2 font-mono text-xs text-ink-dim">Signal = findings per surface in the latest scans · sub-line shows scanner coverage.</p>
    </div>
  );
}

export function VulnSunburst({ web, repo }: { web: WebJob[]; repo: RepoJob[] }) {
  const { sevData, scanData, total, scanners } = useMemo(() => {
    const fs = allFindings(web, repo);
    const bySev: Record<Sev, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byScanSev = new Map<string, number>();
    const byScan: Record<string, number> = {};
    fs.forEach((f) => {
      bySev[f.severity]++;
      byScan[f.scanner] = (byScan[f.scanner] || 0) + 1;
      const k = `${f.scanner}｜${f.severity}`;
      byScanSev.set(k, (byScanSev.get(k) || 0) + 1);
    });
    // Outer ring grouped scanner → severity: order segments by severity so each
    // scanner's slices sit together under its dominant band.
    const scanData = [...byScanSev.entries()]
      .sort((a, b) => SEVS.indexOf(a[0].split('｜')[1] as Sev) - SEVS.indexOf(b[0].split('｜')[1] as Sev) || a[0].localeCompare(b[0]))
      .map(([key, value]) => {
        const [scanner, severity] = key.split('｜');
        return { name: `${scanner} · ${severity}`, scanner, severity: severity as Sev, value };
      });
    return {
      sevData: SEVS.map((s) => ({ name: s, value: bySev[s] })).filter((d) => d.value > 0),
      scanData,
      total: fs.length,
      scanners: Object.entries(byScan).sort((a, b) => b[1] - a[1]),
    };
  }, [web, repo]);

  return (
    <div className="rounded-panel border border-border-line bg-surface-panel p-4">
      <div className="mb-2 font-mono text-xs text-ink-dim">Vulnerabilities Sunburst <span className="font-normal">· scanner → severity</span></div>
      {total === 0 ? (
        <div className="py-8 text-center text-[12.5px] text-ink-dim">No findings in recent scans — nothing to break down yet.</div>
      ) : (
        <div className="flex items-center gap-4 max-sm:flex-col">
          <div className="relative h-[210px] w-[210px] shrink-0">
            <ResponsiveContainer>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={38} outerRadius={62} strokeWidth={0} paddingAngle={2}>
                  {sevData.map((d) => <Cell key={d.name} fill={SEV_COLORS[d.name as Sev]} />)}
                </Pie>
                <Pie data={scanData} dataKey="value" nameKey="name" innerRadius={68} outerRadius={88} strokeWidth={1} stroke="#0d0f12" paddingAngle={1}>
                  {scanData.map((d) => <Cell key={d.name} fill={SEV_COLORS[d.severity]} fillOpacity={0.55} />)}
                </Pie>
                <Tooltip contentStyle={TIP_STYLE} labelStyle={{ color: '#f3efe9' }} formatter={(v, _n, p) => [`${v} findings`, (p?.payload as { name?: string })?.name || '']} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 grid place-items-center">
              <div className="text-center">
                <div className="font-heading text-[22px] font-bold leading-none text-ink">{total}</div>
                <div className="mt-0.5 font-mono text-[10px] text-ink-dim">findings</div>
              </div>
            </div>
          </div>
          <div className="grid flex-1 gap-1 font-mono text-xs text-ink-dim">
            <span className="text-[11px]">inner = severity · outer = scanner slice</span>
            {scanners.map(([s, n]) => <span key={s}>▸ {s} <b className="text-ink">{n}</b></span>)}
          </div>
        </div>
      )}
    </div>
  );
}
