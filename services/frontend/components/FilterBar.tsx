'use client';

import { ChevronDown, Filter, RotateCcw, SlidersHorizontal, Sparkles } from 'lucide-react';
import { useEffect, useMemo, useState, useTransition } from 'react';
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
  const [expanded, setExpanded] = useState(false);
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

  useEffect(() => {
    if (hasAny) {
      setExpanded(true);
    }
  }, [hasAny]);

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

  const fieldClass =
    'w-full rounded-[1.05rem] border border-[var(--border)] bg-white px-4 py-3 text-sm text-[var(--text)] transition focus:outline-none focus:ring-2 focus:ring-[var(--green)]/25';

  return (
    <section className="rounded-[2rem] border border-[var(--border)] bg-[rgba(255,255,255,0.76)] p-4 shadow-[var(--shadow-soft)] backdrop-blur-2xl sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setExpanded((value) => !value)}
              className="inline-flex items-center gap-2 rounded-full border border-cyan-300/20 bg-cyan-300/10 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.18em] text-[var(--cyan-strong)] transition hover:border-cyan-300/28"
            >
              <Filter size={13} />
              Refine the story
              <ChevronDown
                size={14}
                className={`transition ${expanded ? 'rotate-180' : ''}`}
              />
            </button>
            <span className="stat-chip">
              <SlidersHorizontal size={12} className="text-[var(--cyan-strong)]" />
              {activeFilters.length === 0 ? 'No active filters' : `${activeFilters.length} active`}
            </span>
            <span className="stat-chip">
              <Sparkles size={12} className="text-[var(--cyan-strong)]" />
              Applied across posture-heavy views
            </span>
          </div>

          <p className="mt-3 max-w-3xl text-sm leading-6 text-[var(--text-muted)]">
            Focus the product on a customer segment, owner, environment, or health state before
            you share a story or a report.
          </p>

          {activeFilters.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {activeFilters.map((filter) => (
                <span key={filter} className="command-pill">
                  {filter}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={() => setExpanded((value) => !value)} className="btn-secondary">
            {expanded ? 'Hide filters' : 'Show filters'}
          </button>
          <button
            type="button"
            onClick={handleReset}
            disabled={isPending || (!hasAny && !hasDraftChanges)}
            className="btn-secondary"
          >
            <RotateCcw size={14} />
            Reset
          </button>
          <button
            type="button"
            onClick={handleApply}
            disabled={!hasDraftChanges || isPending}
            className="btn-primary"
          >
            {isPending ? 'Applying...' : 'Apply'}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="mt-5 grid gap-4 border-t border-[var(--border)] pt-5 lg:grid-cols-4">
          <label className="space-y-2">
            <span className="block text-[11px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
              Owner
            </span>
            <input
              className={fieldClass}
              value={draft.owner}
              onChange={(event) => setDraft((current) => ({ ...current, owner: event.target.value }))}
              placeholder="e.g. platform-team"
              aria-label="Owner"
            />
          </label>

          <label className="space-y-2">
            <span className="block text-[11px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
              Environment
            </span>
            <select
              className={fieldClass}
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

          <label className="space-y-2">
            <span className="block text-[11px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
              Criticality
            </span>
            <select
              className={fieldClass}
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

          <label className="space-y-2">
            <span className="block text-[11px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
              Status
            </span>
            <select
              className={fieldClass}
              value={draft.status}
              onChange={(event) => setDraft((current) => ({ ...current, status: event.target.value }))}
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
      )}
    </section>
  );
}
