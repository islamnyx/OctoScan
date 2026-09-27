import { Radar } from 'lucide-react';

// Placeholders for Aura-template visuals, restyled flat. Wire to real endpoints when available.
export function AttackRadar() {
  const axes = ['Ports', 'TLS', 'Headers', 'Web vulns', 'CVEs', 'Secrets'];
  return (
    <div className="rounded-panel border border-border-line bg-surface-panel p-4">
      <div className="mb-2 flex items-center gap-2 font-mono text-xs text-ink-dim"><Radar size={13} className="text-accent" /> Attack Surface Radar Map</div>
      <div className="grid grid-cols-3 gap-2">
        {axes.map((a) => (
          <div key={a} className="rounded-md border border-border-line bg-background p-2.5 text-center">
            <div className="font-mono text-xs text-ink-dim">{a}</div>
            <div className="font-heading text-sm text-ink">—</div>
          </div>
        ))}
      </div>
      <p className="mt-2 font-mono text-xs text-ink-dim">TODO: feed from /api/scans coverage + nmap/testssl counts.</p>
    </div>
  );
}
export function VulnSunburst() {
  return (
    <div className="rounded-panel border border-border-line bg-surface-panel p-4">
      <div className="mb-2 font-mono text-xs text-ink-dim">Vulnerabilities Sunburst</div>
      <div className="flex items-center justify-center gap-2 py-4">
        {['crit', 'high', 'med'].map((r, i) => (
          <div key={r} className="grid place-items-center rounded-full border border-accent/40 font-mono text-xs text-accent" style={{ width: 72 + i * 28, height: 72 + i * 28, opacity: 1 - i * 0.25 }}>{r}</div>
        ))}
      </div>
      <p className="font-mono text-xs text-ink-dim">TODO: replace with Nivo Sunburst grouped by scanner → severity.</p>
    </div>
  );
}
