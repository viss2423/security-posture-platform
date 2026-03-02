'use client';

import { motion } from 'framer-motion';
import { Filter, RotateCcw } from 'lucide-react';
import { useFilters } from '@/contexts/FilterContext';

const ENV_OPTIONS = ['', 'dev', 'staging', 'prod'];
const CRIT_OPTIONS = ['', 'high', 'medium', 'low'];
const STATUS_OPTIONS = ['', 'green', 'amber', 'red'];

export default function FilterBar() {
  const { environment, criticality, owner, status, setFilters, clearFilters } = useFilters();
  const hasAny = environment || criticality || owner || status;
  const controlClass =
    'w-full rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2.5 text-sm text-[var(--text)] transition placeholder:text-[var(--muted)] focus:border-[var(--green)] focus:outline-none focus:ring-2 focus:ring-[var(--green)]/25';

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.24, ease: 'easeOut' }}
      className="sticky top-[5.1rem] z-30 mb-6 lg:top-4"
    >
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)]/90 p-3 shadow-xl shadow-black/20 backdrop-blur-xl sm:p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="inline-flex items-center gap-2 rounded-xl bg-[var(--surface-elevated)] px-3 py-2 text-xs font-semibold uppercase tracking-[0.12em] text-[var(--text-muted)]">
            <Filter size={14} className="text-[var(--green)]" />
            Global Filters
          </div>
          {hasAny && (
            <button
              type="button"
              onClick={clearFilters}
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] px-3 py-2 text-sm text-[var(--text-muted)] transition hover:border-[var(--green)]/40 hover:text-[var(--text)]"
            >
              <RotateCcw size={14} />
              Reset all
            </button>
          )}
        </div>

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
    </motion.div>
  );
}
