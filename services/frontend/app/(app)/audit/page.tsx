'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { getAuditLog, type AuditEvent, type AuditFilters } from '@/lib/api';
import { formatDateTime } from '@/lib/format';
import { ApiDownHint } from '@/components/EmptyState';
import { EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';

const ACTION_OPTIONS = ['', 'login', 'retention_apply', 'asset_edit'];

export default function AuditPage() {
  const [data, setData] = useState<{ items: AuditEvent[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [userFilter, setUserFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [sinceFilter, setSinceFilter] = useState('');

  const load = useCallback(() => {
    const filters: AuditFilters = { limit: 100 };
    if (userFilter.trim()) filters.user = userFilter.trim();
    if (actionFilter) filters.action = actionFilter;
    if (sinceFilter) {
      const d = new Date(sinceFilter);
      if (!Number.isNaN(d.getTime())) filters.since = d.toISOString();
    }
    getAuditLog(filters)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [userFilter, actionFilter, sinceFilter]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-10">Audit log</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      <div className="mb-6 flex flex-wrap items-center gap-3">
        <label className="text-sm text-[var(--muted)]">
          User
          <input
            type="text"
            value={userFilter}
            onChange={(e) => setUserFilter(e.target.value)}
            placeholder="Filter by user"
            className="ml-2 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1.5 text-sm text-[var(--text)]"
          />
        </label>
        <label className="text-sm text-[var(--muted)]">
          Action
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="ml-2 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1.5 text-sm text-[var(--text)]"
          >
            <option value="">All</option>
            {ACTION_OPTIONS.filter(Boolean).map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm text-[var(--muted)]">
          Since
          <input
            type="datetime-local"
            value={sinceFilter}
            onChange={(e) => setSinceFilter(e.target.value)}
            className="ml-2 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1.5 text-sm text-[var(--text)]"
          />
        </label>
        <button type="button" onClick={load} className="btn-secondary text-sm">
          Apply
        </button>
      </div>

      {data && data.items.length === 0 && (
        <EmptyState
          title="No audit events"
          description="Events will appear here after login, retention runs, or asset edits."
        />
      )}

      {data && data.items.length > 0 && (
        <div className="card overflow-hidden p-0 animate-in">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] bg-[var(--surface-elevated)]">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Time</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Action</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">User</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Asset</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Details</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((ev) => (
                  <tr key={ev.id} className="border-b border-[var(--border)] hover:bg-[var(--border)]/20">
                    <td className="px-4 py-3 text-[var(--muted)] whitespace-nowrap">{formatDateTime(ev.created_at)}</td>
                    <td className="px-4 py-3">
                      <span className="font-medium text-[var(--text)]">{ev.action}</span>
                    </td>
                    <td className="px-4 py-3 text-[var(--muted)]">{ev.user_name ?? '–'}</td>
                    <td className="px-4 py-3">
                      {ev.asset_key ? (
                        <Link href={`/assets/${encodeURIComponent(ev.asset_key)}`} className="text-[var(--green)] hover:underline">
                          {ev.asset_key}
                        </Link>
                      ) : (
                        '–'
                      )}
                    </td>
                    <td className="px-4 py-3 text-[var(--muted)] max-w-[200px] truncate" title={JSON.stringify(ev.details)}>
                      {Object.keys(ev.details || {}).length ? JSON.stringify(ev.details) : '–'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {!data && !error && (
        <div className="card overflow-hidden p-0">
          <div className="animate-pulse space-y-3 p-6">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-10 rounded bg-[var(--border)]/50" />
            ))}
          </div>
        </div>
      )}
    </main>
  );
}
