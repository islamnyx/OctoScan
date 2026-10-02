// Typed wrapper around the existing OctoScan FastAPI endpoints.
// Mirrors the vanilla fetch() logic from app/static/index.html.
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface Finding { severity: Severity; scanner: string; title: string; location?: string; cvss?: number | null; cwe?: string[]; cve?: string | null; owasp?: string[]; raw?: { cvss_estimated?:boolean; [k:string]:unknown }; }
export interface WebJob {
  id: string; target_url: string; status: 'queued' | 'running' | 'paused' | 'completed' | 'failed';
  created_at: string; findings: Finding[]; scanners_run: string[]; gate?: string; ai?: boolean;
}
export interface RepoJob {
  id: string; repo_url: string; branch?: string | null; status: WebJob['status'];
  created_at: string; findings: Finding[]; scanners_run: string[]; files_scanned?: number; ai?: boolean;
}
export interface Provider { name: string; provider: string; base_url: string; model: string; active: boolean; has_key: boolean; }
export interface AIConfig { configured: boolean; name?: string; provider?: string; model?: string; }

function apiKey(): string { return localStorage.getItem('apiKey') || ''; }
export function headers(extra: Record<string, string> = {}): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json', ...extra };
  const k = apiKey().trim();
  if (k) h['X-API-Key'] = k;
  return h;
}
async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, headers: headers(init?.headers as Record<string, string>) });
  if (!res.ok) throw new Error((await res.text()).slice(0, 300));
  return res.json() as Promise<T>;
}
export const api = {
  health: () => fetch('/health').then((r) => { if (!r.ok) throw new Error('down'); return r.json(); }),
  webJobs: () => req<WebJob[]>('/api/scans'),
  repoJobs: () => req<RepoJob[]>('/api/repo-scans'),
  startWeb: (target_url: string, scanners: string[], auth?: { cookies: Record<string, string>; headers: Record<string, string> }) =>
    req<WebJob>('/api/scans', { method: 'POST', body: JSON.stringify({ target_url, scanners, ...(auth ? { auth } : {}) }) }),
  startRepo: (repo_url: string, branch: string | null, scanners: string[], include_ai: boolean, ai_model: string | null) =>
    req<RepoJob>('/api/repo-scans', { method: 'POST', body: JSON.stringify({ repo_url, branch, scanners, include_ai, ai_model }) }),
  providers: () => req<{ providers: Provider[] }>('/api/ai/providers'),
  aiConfig: () => req<AIConfig>('/api/ai/config'),
  aiModels: (body: Record<string, string>) => req<{ entries?: { id: string; owner?: string }[]; models?: string[]; provider?: string }>('/api/ai/models', { method: 'POST', body: JSON.stringify(body) }),
  saveProvider: (b: Record<string, unknown>) => req<unknown>('/api/ai/providers', { method: 'POST', body: JSON.stringify(b) }),
  activateProvider: (n: string) => req<unknown>(`/api/ai/providers/${encodeURIComponent(n)}/activate`, { method: 'POST' }),
  deleteProvider: (n: string) => req<unknown>(`/api/ai/providers/${encodeURIComponent(n)}`, { method: 'DELETE' }),
  testProvider: (b: Record<string, unknown>) => req<unknown>('/api/ai/test', { method: 'POST', body: JSON.stringify(b) }),
};
export const PRESETS: Record<string, string> = {
  openai: 'https://api.openai.com/v1', openrouter: 'https://openrouter.ai/api/v1',
  groq: 'https://api.groq.com/openai/v1', together: 'https://api.together.xyz/v1',
  ollama: 'http://localhost:11434/v1', lmstudio: 'http://localhost:1234/v1', custom: '',
};
export const WEB_SCANNERS = [
  { id: 'zap', label: 'ZAP (web vulns)' }, { id: 'nuclei', label: 'Nuclei (CVEs)' },
  { id: 'nikto', label: 'Nikto (misconfigs)' }, { id: 'nmap', label: 'Nmap (ports)' },
  { id: 'headers', label: 'Headers' }, { id: 'testssl', label: 'TLS' },
  { id: 'sensitive-files', label: 'Sensitive files' },
];
export const REPO_SCANNERS = [
  { id: 'gitleaks', label: 'Gitleaks (secrets)' }, { id: 'semgrep', label: 'Semgrep (SAST)' }, { id: 'osv', label: 'OSV (deps/CVEs)' },
];
