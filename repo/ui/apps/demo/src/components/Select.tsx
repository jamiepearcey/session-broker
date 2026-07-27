// Ported near-verbatim from the ArrowRef console
// (infrastructure/query-cache/repo/ui/src/components/Select.tsx) — the
// canonical listbox. Used by FailureControls for the injected-failure
// status/error-code pickers so this design system never reaches for a
// native <select>.
import { useEffect, useId, useRef, useState } from 'react';
import { cn } from '../lib/utils.js';
import { Check, ChevronsUpDown } from 'lucide-react';

export interface SelectOption {
  value: string;
  label: string;
  description?: string;
  meta?: string;
}

export function Select({
  value,
  onChange,
  options,
  placeholder = 'Choose…',
  disabled,
  className,
  'aria-label': ariaLabel,
}: {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  'aria-label'?: string;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const listId = useId();
  const selected = options.find((o) => o.value === value) ?? null;

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div ref={root} className={cn('relative', className)}>
      <button
        type="button"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        aria-label={ariaLabel}
        onClick={() => setOpen((v) => !v)}
        className={cn(
          'flex w-full items-center gap-3 rounded-lg border bg-surface-panel px-3 py-2.5 text-left transition-colors',
          'border-outline-strong hover:border-outline-strong hover:bg-surface-hover',
          'focus:outline-none focus-visible:border-plane-budget/60 focus-visible:ring-1 focus-visible:ring-plane-budget/40',
          open && 'border-plane-budget/50 bg-surface-hover',
          disabled && 'cursor-not-allowed opacity-50',
        )}
      >
        <div className="min-w-0 flex-1">
          {selected ? (
            <>
              <div className="truncate text-[13px] font-medium text-foreground">{selected.label}</div>
              {selected.description && (
                <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{selected.description}</div>
              )}
            </>
          ) : (
            <div className="text-[13px] text-muted-foreground">{placeholder}</div>
          )}
        </div>
        {selected?.meta && (
          <span className="shrink-0 rounded-md bg-surface-toolbar px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
            {selected.meta}
          </span>
        )}
        <ChevronsUpDown className="h-4 w-4 shrink-0 text-muted-foreground" />
      </button>

      {open && (
        <ul
          id={listId}
          role="listbox"
          className="absolute z-50 mt-1.5 max-h-64 w-full overflow-auto rounded-lg border border-outline-strong bg-surface-sidebar py-1 shadow-lg shadow-black/40"
        >
          {options.map((opt) => {
            const active = opt.value === value;
            return (
              <li key={opt.value} role="option" aria-selected={active}>
                <button
                  type="button"
                  onClick={() => {
                    onChange(opt.value);
                    setOpen(false);
                  }}
                  className={cn(
                    'flex w-full items-start gap-2.5 px-3 py-2.5 text-left transition-colors',
                    active ? 'bg-plane-budget/12' : 'hover:bg-surface-hover',
                  )}
                >
                  <Check
                    className={cn('mt-0.5 h-3.5 w-3.5 shrink-0', active ? 'text-plane-budget' : 'text-transparent')}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className={cn('text-[12.5px] font-medium', active ? 'text-foreground' : 'text-foreground/90')}>
                        {opt.label}
                      </span>
                      {opt.meta && <span className="font-mono text-[10px] text-muted-foreground">{opt.meta}</span>}
                    </div>
                    {opt.description && (
                      <div className="mt-0.5 text-[11px] leading-snug text-muted-foreground">{opt.description}</div>
                    )}
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
