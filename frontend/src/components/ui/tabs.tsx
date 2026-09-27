import { useState } from 'react';
import { cn } from '../../lib/utils';

export function Tabs({ tabs, initial, onChange }: { tabs: { id: string; label: string }[]; initial?: string; onChange?: (id: string) => void }) {
  const [active, setActive] = useState(initial ?? tabs[0]?.id);
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-border-line px-3 pt-2" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id} role="tab" aria-selected={active === t.id}
          onClick={() => { setActive(t.id); onChange?.(t.id); }}
          className={cn(
            'whitespace-nowrap rounded-t-md border border-transparent border-b-0 px-4 py-2.5 font-heading text-[13px] font-bold text-ink-dim hover:text-ink',
            active === t.id && 'bg-[rgba(255,106,44,.1)] text-accent',
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
