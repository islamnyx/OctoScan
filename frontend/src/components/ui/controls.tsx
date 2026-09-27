import { cn } from '../../lib/utils';

export function Button({ className, variant = 'primary', ...p }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'ghost' | 'secondary' }) {
  return (
    <button
      {...p}
      className={cn(
        'rounded-lg px-4 py-2 text-[13.5px] font-semibold border transition disabled:opacity-55 disabled:cursor-not-allowed',
        variant === 'primary' && 'bg-accent text-[#1a0a02] border-transparent hover:brightness-110',
        (variant === 'ghost' || variant === 'secondary') && 'bg-transparent border-border-line text-ink hover:border-accent hover:text-accent',
        className,
      )}
    />
  );
}
export function Input(p: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...p} className={cn('w-full rounded-md border border-border-line bg-background px-3 py-2.5 text-[13.5px] text-ink placeholder:text-ink-dim/60 outline-none focus:border-accent', p.className)} />;
}
export function Select(p: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...p} className={cn('w-full rounded-md border border-border-line bg-background px-3 py-2.5 text-[13.5px] text-ink outline-none focus:border-accent', p.className)} />;
}
export function Badge({ tone = 'muted', className, ...p }: React.HTMLAttributes<HTMLSpanElement> & { tone?: 'ok' | 'err' | 'warn' | 'info' | 'muted' | 'accent' }) {
  const tones: Record<string, string> = {
    ok: 'bg-success/10 text-success',
    err: 'bg-[#ff7d6b]/10 text-[#ff7d6b]',
    warn: 'bg-accent/10 text-accent',
    info: 'bg-white/5 text-ink-dim',
    muted: 'bg-white/5 text-ink-dim',
    accent: 'bg-accent/10 text-accent',
  };
  return <span {...p} className={cn('inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-xs font-semibold', tones[tone], className)} />;
}
export function statusTone(s: string): 'ok' | 'err' | 'warn' | 'info' {
  if (s === 'completed') return 'ok';
  if (s === 'failed') return 'err';
  if (s === 'running' || s === 'queued' || s === 'paused') return 'warn';
  return 'info';
}
export function cvssTone(v: number | null | undefined): 'err' | 'warn' | 'info' | 'muted' {
  if (v == null) return 'muted';
  if (v >= 9) return 'err';
  if (v >= 7) return 'warn';
  if (v >= 4) return 'info';
  return 'muted';
}
