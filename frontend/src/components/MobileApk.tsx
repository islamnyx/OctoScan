import { useEffect, useState } from 'react';
import { Button, Input, Select } from './ui/controls';

interface ApkSummary {
  id: string; client_name?: string | null; platform?: string | null;
  app_version?: string | null; status: string; findings: number;
  static_status?: string | null; static_errors: number;
}
interface ApkDetail extends ApkSummary {
  binary_filename?: string | null;
  tools: { tool: string; findings: number; errors: string[] }[];
  notes: string[]; errors: string[];
  findings_detail: { id: string; severity: string; title: string; category?: string | null; source_agent: string }[];
}

function keyHeader(): Record<string, string> {
  const k = (localStorage.getItem('apiKey') || '').trim();
  return k ? { 'X-API-Key': k } : {};
}

export function MobileApk() {
  const [file, setFile] = useState<File | null>(null);
  const [client, setClient] = useState('');
  const [platform, setPlatform] = useState('android');
  const [version, setVersion] = useState('');
  const [list, setList] = useState<ApkSummary[]>([]);
  const [detail, setDetail] = useState<ApkDetail | null>(null);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const r = await fetch('/api/apk/scans', { headers: keyHeader() });
      if (!r.ok) throw new Error(await r.text());
      setList(await r.json());
    } catch { /* offline — list stays empty */ }
  };
  useEffect(() => { load(); }, []);

  const open = async (id: string) => {
    setMsg('');
    try {
      const r = await fetch(`/api/apk/scans/${encodeURIComponent(id)}`, { headers: keyHeader() });
      if (!r.ok) throw new Error((await r.text()).slice(0, 200));
      setDetail(await r.json());
    } catch (e) { setMsg(`Could not load: ${(e as Error).message}`); }
  };

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) { setMsg('Pick an .apk / .ipa / .aab first.'); return; }
    setBusy(true); setMsg('');
    try {
      const fd = new FormData();
      fd.append('file', file);
      fd.append('client_name', client.trim() || 'dashboard-upload');
      fd.append('platform', platform);
      if (version.trim()) fd.append('app_version', version.trim());
      const r = await fetch('/api/apk/scans', { method: 'POST', headers: keyHeader(), body: fd });
      if (!r.ok) throw new Error((await r.text()).slice(0, 250));
      const job: ApkSummary = await r.json();
      setMsg(`Upload accepted — static scan running (${job.id}). Refresh in ~1 min.`);
      setFile(null); await load(); await open(job.id);
    } catch (e) { setMsg(`Upload failed: ${(e as Error).message}`); }
    setBusy(false);
  }

  return (
    <div className="grid gap-4">
      <form onSubmit={submit} className="grid gap-3">
        <div className="rounded-md border border-border-line bg-background p-2.5 text-[13px] text-ink-dim">
          ▣ MOBILE APK — manifest · components · secrets · crypto · permissions. Static only, never executed. Max 300 MB.
        </div>
        <div className="flex flex-wrap gap-2.5">
          <label className="grid flex-1 gap-1.5 text-xs font-semibold text-ink-dim">
            APK / IPA file
            <input type="file" accept=".apk,.ipa,.aab" onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="rounded-md border border-border-line bg-background px-3 py-2 text-[12.5px] font-normal text-ink" />
          </label>
          <label className="grid w-[170px] gap-1.5 text-xs font-semibold text-ink-dim">Platform
            <Select value={platform} onChange={(e) => setPlatform(e.target.value)}>
              <option value="android">android</option><option value="ios">ios</option>
            </Select>
          </label>
        </div>
        <div className="flex flex-wrap gap-2.5">
          <label className="grid flex-1 gap-1.5 text-xs font-semibold text-ink-dim">Client<Input value={client} onChange={(e) => setClient(e.target.value)} placeholder="dashboard-upload" /></label>
          <label className="grid w-[170px] gap-1.5 text-xs font-semibold text-ink-dim">Version<Input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1.0" /></label>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          <Button disabled={busy || !file}>{busy ? 'Uploading…' : 'Scan APK'}</Button>
          <Button type="button" variant="secondary" onClick={load}>Refresh</Button>
          <span className="text-[12.5px] text-ink-dim">{file ? `${file.name} (${(file.size / 1048576).toFixed(1)} MB)` : 'no file picked'}</span>
        </div>
        {msg && <div className="rounded-md border border-border-line bg-background p-2.5 text-[13px] text-ink">{msg}</div>}
      </form>

      <div>
        <h3 className="mb-2 font-heading text-[13px] font-bold uppercase tracking-wider text-ink-dim">
          Recent mobile scans ({list.length})
        </h3>
        {!list.length ? (
          <div className="rounded-panel border border-border-line bg-background p-3 text-[12.5px] text-ink-dim">No mobile scans yet — upload an APK above.</div>
        ) : (
          <table className="w-full border-collapse text-[12.5px]">
            <tbody>
              {list.map((s) => (
                <tr key={s.id} className="border-b border-border-line">
                  <td className="px-3 py-2">
                    <button onClick={() => open(s.id)} className="text-left font-mono text-accent">{s.id}</button>
                    <div className="text-ink">{s.client_name} · {s.platform}{s.app_version ? ` · v${s.app_version}` : ''}</div>
                    <div className="font-mono text-xs text-ink-dim">{s.status} · findings {s.findings}{s.static_status ? ` · static ${s.static_status}` : ''}{s.static_errors ? ` · ${s.static_errors} err` : ''}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {detail && (
        <div className="rounded-panel border border-border-line bg-background p-3">
          <b className="font-mono text-[12.5px] text-ink">{detail.id}</b>
          <div className="text-[12.5px] text-ink-dim">{detail.client_name} · {detail.binary_filename || 'binary'} · {detail.status}</div>
          <div className="mt-2 text-[12.5px] text-ink">Tools: {detail.tools.length ? detail.tools.map((t) => `${t.tool}=${t.findings}`).join(', ') : 'static scan running…'}</div>
          {detail.errors.length > 0 && <div className="mt-1 text-[12.5px] text-[#ff7d6b]">{detail.errors.slice(0, 4).join(' · ')}</div>}
          {detail.notes.length > 0 && <div className="mt-1 text-[12.5px] text-ink-dim">{detail.notes.slice(0, 4).join(' · ')}</div>}
          <div className="mt-1 text-[12.5px] text-ink">Findings: {detail.findings_detail.length || 'none yet (static IR only — run the LLM agent from CLI for Finding rows)'}</div>
        </div>
      )}
    </div>
  );
}
