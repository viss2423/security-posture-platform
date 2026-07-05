'use client';

import { Filter, X } from 'lucide-react';
import { useEffect, useMemo, useState, useTransition } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import type { PostureFilters } from '@/lib/api';
import { parsePostureFilters, writePostureFilters } from '@/lib/postureFilters';

const ENV_OPTIONS = ['dev', 'staging', 'prod'];
const CRIT_OPTIONS = ['high', 'medium', 'low'];
const STATUS_OPTIONS = ['green', 'amber', 'red'];

export default function FilterBar() {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [open, setOpen] = useState(false);
  const [isPending, startTransition] = useTransition();

  const currentFilters = useMemo(
    () =>
      parsePostureFilters({
        environment: searchParams.get('environment') ?? undefined,
        criticality: searchParams.get('criticality') ?? undefined,
        owner: searchParams.get('owner') ?? undefined,
        status: searchParams.get('status') ?? undefined,
      }),
    [searchParams]
  );

  const [draft, setDraft] = useState({
    owner: currentFilters.owner ?? '',
    environment: currentFilters.environment ?? '',
    criticality: currentFilters.criticality ?? '',
    status: currentFilters.status ?? '',
  });

  useEffect(() => {
    setDraft({
      owner: currentFilters.owner ?? '',
      environment: currentFilters.environment ?? '',
      criticality: currentFilters.criticality ?? '',
      status: currentFilters.status ?? '',
    });
  }, [currentFilters.criticality, currentFilters.environment, currentFilters.owner, currentFilters.status]);

  const hasAny =
    Boolean(currentFilters.environment) ||
    Boolean(currentFilters.criticality) ||
    Boolean(currentFilters.owner) ||
    Boolean(currentFilters.status);

  const activeChips = [
    currentFilters.owner ? `Owner: ${currentFilters.owner}` : null,
    currentFilters.environment ? `Env: ${currentFilters.environment}` : null,
    currentFilters.criticality ? `Crit: ${currentFilters.criticality}` : null,
    currentFilters.status ? `Status: ${currentFilters.status}` : null,
  ].filter(Boolean) as string[];

  const hasDraftChanges =
    draft.owner !== (currentFilters.owner ?? '') ||
    draft.environment !== (currentFilters.environment ?? '') ||
    draft.criticality !== (currentFilters.criticality ?? '') ||
    draft.status !== (currentFilters.status ?? '');

  const applyFilters = (filters: PostureFilters) => {
    const nextParams = writePostureFilters(new URLSearchParams(searchParams.toString()), filters);
    const query = nextParams.toString();
    startTransition(() => {
      router.push(query ? `${pathname}?${query}` : pathname);
    });
  };

  const handleApply = () => {
    applyFilters({
      owner: draft.owner || undefined,
      environment: draft.environment || undefined,
      criticality: draft.criticality || undefined,
      status: draft.status || undefined,
    });
    setOpen(false);
  };

  const handleReset = () => {
    setDraft({ owner: '', environment: '', criticality: '', status: '' });
    applyFilters({});
    setOpen(false);
  };

  const fieldClass =
    'w-full rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-subtle)] transition focus:outline-none focus:ring-2 focus:ring-[var(--accent-ring)] focus:border-[var(--accent)]';

  return (
    <div className="mb-5">
      {/* Compact toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
            open || hasAny
              ? 'border-[var(--accent)]/30 bg-[var(--accent-dim)] text-[var(--accent)]'
              : 'border-[var(--border)] bg-[var(--surface)] text-[var(--text-muted)] hover:border-[var(--border-strong)] hover:text-[var(--text)]'
          }`}
        >
          <Filter size={12} />
          Filters
          {activeChips.length > 0 && (
            <span className="flex h-4 min-w-[16px] items-center justify-center rounded-full bg-[var(--accent)] px-1 text-[9px] font-bold text-[#07090e]">
              {activeChips.length}
            </span>
          )}
        </button>

        {activeChips.map((chip) => (
          <span
            key={chip}
            className="inline-flex items-center gap-1 rounded-md border border-[var(--border)] bg-[var(--surface-elevated)] px-2 py-1 text-[11px] text-[var(--text-muted)]"
          >
            {chip}
          </span>
        ))}

        {hasAny && (
          <button
            type="button"
            onClick={handleReset}
            disabled={isPending}
            className="inline-flex items-center gap-1 text-[11px] text-[var(--text-subtle)] transition hover:text-[var(--text)]"
          >
            <X size={11} />
            Clear
          </button>
        )}
      </div>

      {/* Expandable panel */}
      {open && (
        <div className="animate-in mt-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4">
          <p className="mb-4 text-xs text-[var(--text-subtle)]">
            Scope the view by owner, environment, criticality, or health state.
          </p>
          <div className="grid gap-4 lg:grid-cols-4">
            <label className="space-y-1.5">
              <span className="block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--text-subtle)]">
                Owner
              </span>
              <input
                className={fieldClass}
                value={draft.owner}
                onChange={(e) => setDraft((c) => ({ ...c, owner: e.target.value }))}
                placeholder="e.g. platform-team"
              />
            </label>
            <label className="space-y-1.5">
              <span className="block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--text-subtle)]">
                Environment
              </span>
              <select
                className={fieldClass}
                value={draft.environment}
                onChange={(e) => setDraft((c) => ({ ...c, environment: e.target.value }))}
              >
                <option value="">All environments</option>
                {ENV_OPTIONS.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1.5">
              <span className="block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--text-subtle)]">
                Criticality
              </span>
              <select
                className={fieldClass}
                value={draft.criticality}
                onChange={(e) => setDraft((c) => ({ ...c, criticality: e.target.value }))}
              >
                <option value="">All criticality</option>
                {CRIT_OPTIONS.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
            <label className="space-y-1.5">
              <span className="block text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--text-subtle)]">
                Health status
              </span>
              <select
                className={fieldClass}
                value={draft.status}
                onChange={(e) => setDraft((c) => ({ ...c, status: e.target.value }))}
              >
                <option value="">All statuses</option>
                {STATUS_OPTIONS.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="mt-4 flex justify-end gap-2 border-t border-[var(--border)] pt-3">
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="btn-secondary text-xs"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleApply}
              disabled={!hasDraftChanges || isPending}
              className="btn-primary text-xs"
            >
              {isPending ? 'Applying...' : 'Apply'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
