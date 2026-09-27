import { useEffect, useState } from 'react';
import { api, PRESETS, REPO_SCANNERS, WEB_SCANNERS, type Provider } from '../lib/api';
import { Button, Input, Select } from './ui/controls';
import { Tabs } from './ui/tabs';

function Check({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-border-line bg-background px-2.5 py-1.5 text-[12.5px] text-ink-dim hover:border-accent hover:text-ink"><input type="checkbox" className="h-3.5 w-3.5 accent-[#ff6a2c]" checked={checked} onChange={(e) => onChange(e.target.checked)} />{label}</label>;
}

function WebForm() {
  const [url, setUrl] = useState('');
  const [sel, setSel] = useState<string[]>(WEB_SCANNERS.map((s) => s.id));
  const [auth, setAuth] = useState(false);
  const [cookies, setCookies] = useState('');
  const [hdrs, setHdrs] = useState('');
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; t: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const toggle = (id: string, v: boolean) => setSel((s) => (v ? [...s, id] : s.filter((x) => x !== id)));
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!sel.length) { setMsg({ kind: 'err', t: 'Pick at least one module.' }); return; }
    const ck: Record<string, string> = {}, hh: Record<string, string> = {};
    if (auth) {
      cookies.split(';').forEach((p) => { const i = p.indexOf('='); if (i > 0) { const k = p.slice(0, i).trim(), v = p.slice(i + 1).trim(); if (k && v) ck[k] = v; } });
      hdrs.split('\n').forEach((l) => { const i = l.indexOf(':'); if (i > 0) { const k = l.slice(0, i).trim(), v = l.slice(i + 1).trim(); if (k && v) hh[k] = v; } });
    }
    setBusy(true); setMsg(null);
    try {
      const job = await api.startWeb(url.trim(), sel, Object.keys(ck).length || Object.keys(hh).length ? { cookies: ck, headers: hh } : undefined);
      location.href = `/scans/${encodeURIComponent(job.id)}/status`;
    } catch (err) { setMsg({ kind: 'err', t: `Could not start: ${String((err as Error).message).slice(0, 200)}` }); setBusy(false); }
  }
  return (
    <form onSubmit={submit} className="grid gap-3">
      <label className="grid gap-1.5 text-xs font-semibold text-ink-dim">Target URL<Input type="url" required placeholder="https://example.com" value={url} onChange={(e) => setUrl(e.target.value)} /></label>
      <div className="grid gap-1.5"><span className="text-xs font-semibold text-ink-dim">Scanners <span className="font-normal text-ink-dim/70">(uncheck to skip — all run by default)</span></span>
        <div className="flex flex-wrap gap-2">{WEB_SCANNERS.map((s) => <Check key={s.id} label={s.label} checked={sel.includes(s.id)} onChange={(v) => toggle(s.id, v)} />)}</div>
        <div className="mt-1 flex gap-2"><Button type="button" variant="secondary" onClick={() => setSel(WEB_SCANNERS.map((s) => s.id))}>Select all</Button><Button type="button" variant="secondary" onClick={() => setSel([])}>Clear</Button></div>
      </div>
      <Check label="Authenticated scan (logged-in session → every scanner)" checked={auth} onChange={setAuth} />
      {auth && <div className="flex flex-wrap gap-2.5"><label className="grid flex-1 gap-1.5 text-xs text-ink-dim">Session cookies <span>(name=value; separate with ;)</span><Input value={cookies} onChange={(e) => setCookies(e.target.value)} placeholder="PHPSESSID=abc123; security=low" /></label><label className="grid flex-1 gap-1.5 text-xs text-ink-dim">Extra headers <span>(one per line, Name: value)</span><Input value={hdrs} onChange={(e) => setHdrs(e.target.value)} placeholder="Authorization: Bearer …" /></label></div>}
      <div className="flex flex-wrap items-center gap-2.5"><Button disabled={busy}>{busy ? 'Starting…' : 'Run security scan'}</Button><span className="text-[12.5px] text-ink-dim">opens live status · pause / finish anytime</span></div>
      {msg && <div className={`rounded-md border p-2.5 text-[13px] ${msg.kind === 'err' ? 'border-[#ff7d6b]/40 bg-[#ff7d6b]/10 text-[#ff7d6b]' : 'border-success/40 bg-success/10 text-success'}`}>{msg.t}</div>}
    </form>
  );
}

function RepoForm() {
  const [repo, setRepo] = useState('');
  const [branch, setBranch] = useState('');
  const [sel, setSel] = useState<string[]>(REPO_SCANNERS.map((s) => s.id));
  const [ai, setAi] = useState(false);
  const [models, setModels] = useState<{ id: string; owner?: string }[]>([]);
  const [model, setModel] = useState('');
  const [note, setNote] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!ai) return;
    (async () => {
      try {
        const cfg = await api.aiConfig();
        if (!cfg.configured) { setNote('No AI provider — set one up in the AI provider tab.'); return; }
        const d = await api.aiModels({});
        const entries = d.entries || (d.models || []).map((m) => ({ id: m }));
        setModels(entries); if (entries.length) setModel((cfg.model && entries.some((e) => e.id === cfg.model) ? cfg.model! : entries[0].id));
        setNote(`From ${cfg.provider || 'provider'} · default preselected.`);
      } catch (e) { setNote(`Failed: ${(e as Error).message}`); }
    })();
  }, [ai]);
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!sel.length && !ai) { setMsg('Pick at least one test or enable AI.'); return; }
    if (ai && !model) { setMsg('Pick an AI model (AI provider tab).'); return; }
    setBusy(true); setMsg('');
    try {
      const job = await api.startRepo(repo.trim(), branch.trim() || null, sel, ai, ai ? model : null);
      location.href = `/repos/${encodeURIComponent(job.id)}/status`;
    } catch (e) { setMsg(`Could not start: ${(e as Error).message.slice(0, 250)}`); setBusy(false); }
  }
  return (
    <form onSubmit={submit} className="grid gap-3">
      <div className="flex flex-wrap gap-2.5">
        <label className="grid flex-1 gap-1.5 text-xs font-semibold text-ink-dim">Repository URL<Input type="url" required placeholder="https://github.com/org/repo" value={repo} onChange={(e) => setRepo(e.target.value)} /></label>
        <label className="grid w-[170px] gap-1.5 text-xs font-semibold text-ink-dim">Branch<Input placeholder="default" value={branch} onChange={(e) => setBranch(e.target.value)} /></label>
      </div>
      <div className="grid gap-1.5"><span className="text-xs font-semibold text-ink-dim">Scanners <span className="font-normal text-ink-dim/70">(uncheck to skip — all run by default)</span></span>
        <div className="flex flex-wrap gap-2">{REPO_SCANNERS.map((s) => <Check key={s.id} label={s.label} checked={sel.includes(s.id)} onChange={(v) => setSel((p) => (v ? [...p, s.id] : p.filter((x) => x !== s.id)))} />)}</div></div>
      <div className="flex flex-wrap items-center gap-2.5"><Button disabled={busy}>{busy ? 'Starting…' : 'Scan codebase'}</Button><Check label="AI reads the code too" checked={ai} onChange={setAi} /></div>
      {ai && <label className="grid max-w-[420px] gap-1.5 text-xs text-ink-dim">AI model for this scan<Select value={model} onChange={(e) => setModel(e.target.value)}>{models.length ? models.map((m) => <option key={m.id} value={m.id}>{m.id}</option>) : <option value="">loading…</option>}</Select><span className="text-ink-dim/70">{note}</span></label>}
      {msg && <div className="rounded-md border border-[#ff7d6b]/40 bg-[#ff7d6b]/10 p-2.5 text-[13px] text-[#ff7d6b]">{msg}</div>}
      <p className="m-0 text-[12.5px] text-ink-dim">Shallow-clone · secret + SAST + SCA. Code is never executed.</p>
    </form>
  );
}

function AIProvider() {
  const [list, setList] = useState<Provider[]>([]);
  const [status, setStatus] = useState('');
  const [type, setType] = useState('openai');
  const [name, setName] = useState('openai');
  const [base, setBase] = useState(PRESETS.openai);
  const [key, setKey] = useState('');
  const [models, setModels] = useState<{ id: string; owner?: string }[]>([]);
  const [model, setModel] = useState('');
  const [custom, setCustom] = useState('');
  const [customMode, setCustomMode] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const load = async () => { try { setList((await api.providers()).providers || []); } catch { /* offline */ } };
  useEffect(() => { load(); }, []);
  useEffect(() => {
    const p = PRESETS[type];
    if (p !== undefined && (base.trim() === '' || Object.values(PRESETS).includes(base.trim()))) setBase(p);
    if (!editing) setName(type);
  }, [type]); // eslint-disable-line
  const chosen = customMode ? custom.trim() : model;
  async function loadModels() {
    if (!base.trim()) { setStatus('Set a base URL first.'); return; }
    setStatus('Loading models…');
    try {
      const d = await api.aiModels({ provider: type, base_url: base.trim(), api_key: key });
      const e = d.entries || (d.models || []).map((m) => ({ id: m }));
      setModels(e); setStatus(`Loaded ${e.length} model(s).`);
    } catch (e) { setStatus(`Failed: ${(e as Error).message}`); }
  }
  async function save() {
    if (!name.trim()) { setStatus('Name required.'); return; }
    if (!base.trim()) { setStatus('Base URL required.'); return; }
    if (!chosen) { setStatus('Pick or type a model.'); return; }
    setStatus('Saving…');
    try { await api.saveProvider({ name: name.trim(), provider: type, base_url: base.trim(), api_key: key, model: chosen, activate: true }); setStatus(`"${name}" saved + active.`); setEditing(null); setKey(''); await load(); }
    catch (e) { setStatus(`Save failed: ${(e as Error).message}`); }
  }
  return (
    <div className="grid gap-4">
      <div>
        <h3 className="mb-2 font-heading text-[13px] font-bold uppercase tracking-wider text-ink-dim">Connected providers</h3>
        {!list.length ? <div className="rounded-panel border border-border-line bg-background p-3 text-[12.5px] text-ink-dim">No providers — add one below.</div> : (
          <table className="w-full border-collapse text-[12.5px]">{list.map((p) => (
            <tr key={p.name} className="border-b border-border-line">
              <td className="px-3 py-2"><b className="text-ink">{p.name}</b>{p.active && <span className="ml-1.5 rounded bg-success/10 px-1.5 font-mono text-[10px] font-bold text-success">ACTIVE</span>}<div className="font-mono text-xs text-ink-dim">{p.provider} · {p.base_url.replace(/^https?:\/\//, '')} · {p.model} · {p.has_key ? 'key ✓' : 'no key'}</div></td>
              <td className="whitespace-nowrap px-3 py-2 text-right">
                {!p.active && <Button variant="secondary" className="!px-2.5 !py-1 !text-xs" onClick={() => api.activateProvider(p.name).then(load)}>Use</Button>}
                <Button variant="secondary" className="!px-2.5 !py-1 !text-xs" onClick={() => { setEditing(p.name); setType(PRESETS[p.provider] !== undefined ? p.provider : 'custom'); setName(p.name); setBase(p.base_url); setModels(p.model ? [{ id: p.model }] : []); setModel(p.model || ''); }}>Edit</Button>
                <Button variant="secondary" className="!px-2.5 !py-1 !text-xs !text-[#ff7d6b]" onClick={async () => { if (confirm(`Delete "${p.name}"?`)) { await api.deleteProvider(p.name); await load(); } }}>Delete</Button>
              </td>
            </tr>))}</table>)}
      </div>
      <div>
        <h3 className="mb-2 font-heading text-[13px] font-bold uppercase tracking-wider text-ink-dim">{editing ? `Edit: ${editing}` : 'Add a provider'}</h3>
        <div className="flex flex-wrap gap-2.5">
          <label className="grid w-[170px] gap-1.5 text-xs text-ink-dim">Type<Select value={type} onChange={(e) => setType(e.target.value)}>{Object.keys(PRESETS).map((k) => <option key={k} value={k}>{k}</option>)}</Select></label>
          <label className="grid w-[170px] gap-1.5 text-xs text-ink-dim">Name<Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. groq-work" /></label>
          <label className="grid flex-1 gap-1.5 text-xs text-ink-dim">Base URL<Input type="url" value={base} onChange={(e) => setBase(e.target.value)} placeholder="https://api.groq.com/openai/v1" /></label>
        </div>
        <div className="mt-2.5 flex flex-wrap gap-2.5">
          <label className="grid flex-1 gap-1.5 text-xs text-ink-dim">API key <span>(blank keeps existing)</span><Input type="password" value={key} onChange={(e) => setKey(e.target.value)} placeholder="••••••••" /></label>
          <label className="grid flex-1 gap-1.5 text-xs text-ink-dim">Model <button type="button" onClick={loadModels} className="w-fit p-0 text-left text-[11px] text-accent">↻ load models</button>
            <Select value={customMode ? '__custom__' : model} onChange={(e) => setCustomMode(e.target.value === '__custom__')}>{models.length ? models.map((m) => <option key={m.id} value={m.id}>{m.id}</option>) : <option value="">— load models —</option>}<option value="__custom__">Custom model…</option></Select>
            {customMode && <Input value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="type custom model id…" />}</label>
        </div>
        <div className="mt-3.5 flex flex-wrap items-center gap-2.5"><Button onClick={save}>Save provider</Button><Button variant="secondary" onClick={async () => { setStatus('Testing…'); try { await api.testProvider(editing ? { name: editing } : { provider: type, base_url: base.trim(), api_key: key, model: chosen }); setStatus('Connection works.'); } catch (e) { setStatus(`Test failed: ${(e as Error).message.slice(0, 160)}`); } }}>Test provider</Button><span className="text-[12.5px] text-ink-dim">{status}</span></div>
        <p className="mt-2.5 text-[12.5px] text-ink-dim">Ollama / LM Studio keep excerpts on this machine.</p>
      </div>
    </div>
  );
}

export function ScanTabs({ initial = 'pane-web' }: { initial?: string }) {
  const [tab, setTab] = useState(initial);
  return (
    <div className="overflow-hidden rounded-panel border border-border-line bg-surface-panel">
      <Tabs onChange={setTab} tabs={[{ id: 'pane-web', label: 'Web application' }, { id: 'pane-repo', label: 'Codebase' }, { id: 'pane-ai', label: 'AI provider' }, { id: 'pane-apk', label: 'Mobile APK' }]} initial={initial} />
      <div className="p-5">
        {tab === 'pane-web' && <WebForm />}
        {tab === 'pane-repo' && <RepoForm />}
        {tab === 'pane-ai' && <AIProvider />}
        {tab === 'pane-apk' && (
          <div className="grid gap-3">
            <div className="rounded-md border border-border-line bg-background p-2.5 text-[13px] text-ink-dim">▣ MOBILE APK — incoming. Manifest · components · secrets · crypto · permissions. Static only, never executed.</div>
            <Button disabled title="Coming soon">Scan APK</Button>
          </div>
        )}
      </div>
    </div>
  );
}
