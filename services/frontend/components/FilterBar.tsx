'use client';

import { useEffect, useMemo, useState, useTransition } from 'react';
import { ChevronDown, Filter, RotateCcw } from 'lucide-react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import type { PostureFilters } from '@/lib/api';
import { parsePostureFilters, writePostureFilters } from '@/lib/postureFilters';

const ENV_OPTIONS = ['', 'dev', 'staging', 'prod'];
const CRIT_OPTIONS = ['', 'high', 'medium', 'low'];
const STATUS_OPTIONS = ['', 'green', 'amber', 'red'];

export default function FilterBar() {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isPending, startTransition] = useTransition();
  const [expanded, setExpanded] = useState(false);
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
  }, [
    currentFilters.criticality,
    currentFilters.environment,
    currentFilters.owner,
    currentFilters.status,
  ]);

  const hasAny =
    Boolean(currentFilters.environment) ||
    Boolean(currentFilters.criticality) ||
    Boolean(currentFilters.owner) ||
    Boolean(currentFilters.status);
  const controlClass =
    'w-full rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2.5 text-sm text-[var(--text)] transition placeholder:text-[var(--muted)] focus:border-[var(--green)] focus:outline-none focus:ring-2 focus:ring-[var(--green)]/25';
  const activeFilters = [
    currentFilters.owner ? `Owner: ${currentFilters.owner}` : null,
    currentFilters.environment ? `Environment: ${currentFilters.environment}` : null,
    currentFilters.criticality ? `Criticality: ${currentFilters.criticality}` : null,
    currentFilters.status ? `Status: ${currentFilters.status}` : null,
  ].filter(Boolean) as string[];
  const hasDraftChanges =
    draft.owner !== (currentFilters.owner ?? '') ||
    draft.environment !== (currentFilters.environment ?? '') ||
    draft.criticality !== (currentFilters.criticality ?? '') ||
    draft.status !== (currentFilters.status ?? '');

  useEffect(() => {
    if (hasAny) setExpanded(true);
  }, [hasAny]);

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
  };

  const handleReset = () => {
    setDraft({ owner: '', environment: '', criticality: '', status: '' });
    applyFilters({});
  };

  return (
    <div className="sticky top-[4.85rem] z-30 mb-5 lg:top-4">
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)]/94 px-3 py-3 shadow-lg shadow-black/15 backdrop-blur-xl sm:px-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-white/[0.03] px-3 py-2 text-xs font-semibold uppercase tracking-[0.14em] text-[var(--text-muted)] transition hover:border-[var(--green)]/20 hover:text-[var(--text)]"
            >
              <Filter size={14} className="text-[var(--green)]" />
              Filters
              <ChevronDown
                size={14}
                className={`transition ${expanded ? 'rotate-180' : ''}`}
              />
            </button>
            <span className="stat-chip">
              {activeFilters.length === 0 ? 'No active filters' : `${activeFilters.length} active`}
            </span>
            {activeFilters.slice(0, 3).map((filter) => (
              <span key={filter} className="stat-chip max-w-full truncate">
                {filter}
              </span>
            ))}
            {activeFilters.length > 3 && <span className="stat-chip">+{activeFilters.length - 3} more</span>}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {hasAny && (
              <button
                type="button"
                onClick={handleReset}
                disabled={isPending}
                className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-white/[0.03] px-3 py-2 text-sm text-[var(--text-muted)] transition hover:border-[var(--green)]/20 hover:text-[var(--text)]"
              >
                <RotateCcw size={14} />
                Reset
              </button>
            )}
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-muted)] transition hover:border-[var(--green)]/20 hover:text-[var(--text)]"
            >
              {expanded ? 'Hide controls' : 'Edit filters'}
            </button>
          </div>
        </div>

        {expanded && (
          <div className="mt-4 border-t border-[var(--border)] pt-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <label className="space-y-1">
                <span className="block text-xs font-semibold uppercase tracking-[0.1em] text-[var(--muted)]">Owner</span>
                <input
                  className={controlClass}
                  value={draft.owner}
                  onChange={(event) =>
                    setDraft((current) => ({ ...current, owner: event.target.value }))
                  }
                  placeholder="e.g. platform-team"
                  aria-label="Owner"
                />
              </label>

              <label className="space-y-1">
                <span className="block text-xs font-semibold uppercase tracking-[0.1em] text-[var(--muted)]">Environment</span>
                <select
                  className={controlClass}
                  value={draft.environment}
                  onChange={(event) =>
                    setDraft((current) => ({ ...current, environment: event.target.value }))
                  }
                  aria-label="Environment"
                >
                  <option value="">All environments</option>
                  {ENV_OPTIONS.filter(Boolean).map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-1">
                <span className="block text-xs font-semibold uppercase tracking-[0.1em] text-[var(--muted)]">Criticality</span>
                <select
                  className={controlClass}
                  value={draft.criticality}
                  onChange={(event) =>
                    setDraft((current) => ({ ...current, criticality: event.target.value }))
                  }
                  aria-label="Criticality"
                >
                  <option value="">All criticality</option>
                  {CRIT_OPTIONS.filter(Boolean).map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-1">
                <span className="block text-xs font-semibold uppercase tracking-[0.1em] text-[var(--muted)]">Status</span>
                <select
                  className={controlClass}
                  value={draft.status}
                  onChange={(event) =>
                    setDraft((current) => ({ ...current, status: event.target.value }))
                  }
                  aria-label="Status"
                >
                  <option value="">All statuses</option>
                  {STATUS_OPTIONS.filter(Boolean).map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-end gap-2 border-t border-[var(--border)] pt-4">
              <button
                type="button"
                onClick={handleReset}
                disabled={isPending || (!hasAny && !hasDraftChanges)}
                className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-white/[0.03] px-3 py-2 text-sm text-[var(--text-muted)] transition hover:border-[var(--green)]/20 hover:text-[var(--text)] disabled:opacity-50"
              >
                Reset filters
              </button>
              <button
                type="button"
                onClick={handleApply}
                disabled={!hasDraftChanges || isPending}
                className="btn-primary px-4 py-2 text-sm disabled:opacity-50"
              >
                {isPending ? 'Applying...' : 'Apply filters'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
