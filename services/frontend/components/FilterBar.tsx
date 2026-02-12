'use client';

import { useFilters } from '@/contexts/FilterContext';

const ENV_OPTIONS = ['', 'dev', 'staging', 'prod'];
const CRIT_OPTIONS = ['', 'high', 'medium', 'low'];
const STATUS_OPTIONS = ['', 'green', 'amber', 'red'];

export default function FilterBar() {
  const { environment, criticality, status, setFilters, clearFilters } = useFilters();
  const hasAny = environment || criticality || status;

  return (
    <div className="sticky top-0 z-40 border-b border-[var(--border)] bg-[var(--surface-elevated)]/95 px-4 py-2 backdrop-blur-sm">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-3">
        <span className="text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Filters</span>
        <select
          className="rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-1.5 text-sm text-[var(--text)] focus:border-[var(--green)] focus:outline-none focus:ring-1 focus:ring-[var(--green)]"
          value={environment ?? ''}
          onChange={(e) => setFilters({ environment: e.target.value || undefined })}
          aria-label="Environment"
        >
          <option value="">All environments</option>
          {ENV_OPTIONS.filter(Boolean).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        <select
          className="rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-1.5 text-sm text-[var(--text)] focus:border-[var(--green)] focus:outline-none focus:ring-1 focus:ring-[var(--green)]"
          value={criticality ?? ''}
          onChange={(e) => setFilters({ criticality: e.target.value || undefined })}
          aria-label="Criticality"
        >
          <option value="">All criticality</option>
          {CRIT_OPTIONS.filter(Boolean).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        <select
          className="rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-1.5 text-sm text-[var(--text)] focus:border-[var(--green)] focus:outline-none focus:ring-1 focus:ring-[var(--green)]"
          value={status ?? ''}
          onChange={(e) => setFilters({ status: e.target.value || undefined })}
          aria-label="Status"
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.filter(Boolean).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        {hasAny && (
          <button
            type="button"
            onClick={clearFilters}
            className="text-sm text-[var(--muted)] underline hover:text-[var(--text)]"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  );
}
