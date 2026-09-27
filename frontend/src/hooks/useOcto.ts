import { useCallback, useEffect, useState } from 'react';
import { api, type RepoJob, type WebJob } from '../lib/api';

export function useHealth(pollMs = 15000) {
  const [online, setOnline] = useState<boolean | null>(null);
  const check = useCallback(async () => {
    try { await api.health(); setOnline(true); } catch { setOnline(false); }
  }, []);
  useEffect(() => { check(); const t = setInterval(check, pollMs); return () => clearInterval(t); }, [check, pollMs]);
  return online;
}
export function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  return now.toLocaleTimeString();
}
export function useJobs(pollMs = 15000) {
  const [web, setWeb] = useState<WebJob[]>([]);
  const [repo, setRepo] = useState<RepoJob[]>([]);
  const load = useCallback(async () => {
    try { setWeb(await api.webJobs()); } catch { /* offline */ }
    try { setRepo(await api.repoJobs()); } catch { /* offline */ }
  }, []);
  useEffect(() => { load(); const t = setInterval(load, pollMs); return () => clearInterval(t); }, [load, pollMs]);
  return { web, repo, reload: load };
}
export function useApiKey() {
  const [key, setKey] = useState(() => localStorage.getItem('apiKey') || '');
  useEffect(() => { localStorage.setItem('apiKey', key.trim()); }, [key]);
  return [key, setKey] as const;
}
