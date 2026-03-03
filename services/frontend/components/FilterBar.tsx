'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ChevronDown, Filter, RotateCcw } from 'lucide-react';
import { useFilters } from '@/contexts/FilterContext';

const ENV_OPTIONS = ['', 'dev', 'staging', 'prod'];
const CRIT_OPTIONS = ['', 'high', 'medium', 'low'];
const STATUS_OPTIONS = ['', 'green', 'amber', 'red'];

export default function FilterBar() {
  const { environment, criticality, owner, status, setFilters, clearFilters } = useFilters();
  const hasAny = environment || criticality || owner || status;
  const [expanded, setExpanded] = useState(false);
  const controlClass =
    'w-full rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2.5 text-sm text-[var(--text)] transition placeholder:text-[var(--muted)] focus:border-[var(--green)] focus:outline-none focus:ring-2 focus:ring-[var(--green)]/25';
  const activeFilters = [
    owner ? `Owner: ${owner}` : null,
    environment ? `Environment: ${environment}` : null,
    criticality ? `Criticality: ${criticality}` : null,
    status ? `Status: ${status}` : null,
  ].filter(Boolean) as string[];

  useEffect(() => {
    if (hasAny) setExpanded(true);
  }, [hasAny]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.24, ease: 'easeOut' }}
      className="sticky top-[4.85rem] z-30 mb-5 lg:top-4"
    >
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
                onClick={clearFilters}
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
                  value={owner ?? ''}
                  onChange={(e) => setFilters({ owner: e.target.value || undefined })}
                  placeholder="e.g. platform-team"
                  aria-label="Owner"
                />
              </label>

              <label className="space-y-1">
                <span className="block text-xs font-semibold uppercase tracking-[0.1em] text-[var(--muted)]">Environment</span>
                <select
                  className={controlClass}
                  value={environment ?? ''}
                  onChange={(e) => setFilters({ environment: e.target.value || undefined })}
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
                  value={criticality ?? ''}
                  onChange={(e) => setFilters({ criticality: e.target.value || undefined })}
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
                  value={status ?? ''}
                  onChange={(e) => setFilters({ status: e.target.value || undefined })}
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
          </div>
        )}
      </div>
    </motion.div>
  );
}
