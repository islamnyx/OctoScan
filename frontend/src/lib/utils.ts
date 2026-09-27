import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
export function cn(...inputs: ClassValue[]) { return twMerge(clsx(inputs)); }
export function esc(s: unknown) { return String(s ?? ''); }
export function riskScore(c: Record<string, number>) {
  return Math.max(0, 100 - ((c.critical ?? 0) * 25 + (c.high ?? 0) * 10 + (c.medium ?? 0) * 4 + (c.low ?? 0) * 1));
}
