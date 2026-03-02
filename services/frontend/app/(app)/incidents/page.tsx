'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  getIncidents,
  createIncident,
  type IncidentListItem,
  type IncidentStatus,
  type IncidentSeverity,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

const STATUS_OPTIONS: IncidentStatus[] = ['new', 'triaged', 'contained', 'resolved', 'closed'];
const SEVERITY_OPTIONS: IncidentSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

function severityColor(s: string): string {
  switch (s) {
    case 'critical':
      return 'var(--red)';
    case 'high':
      return 'var(--red)';
    case 'medium':
      return 'var(--amber)';
    case 'low':
    case 'info':
      return 'var(--green)';
    default:
      return 'var(--muted)';
  }
}

export default function IncidentsPage() {
  const { canMutate } = useAuth();
  const [data, setData] = useState<{ total: number; items: IncidentListItem[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [showCreate, setShowCreate] = useState(false);
  const [createTitle, setCreateTitle] = useState('');
  const [createSeverity, setCreateSeverity] = useState<IncidentSeverity>('medium');
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const load = useCallback(() => {
    getIncidents({
      status: statusFilter || undefined,
      severity: severityFilter || undefined,
      limit: 100,
    })
      .then(setData)
      .catch((e) => setError(e.message));
  }, [statusFilter, severityFilter]);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const handleCreate = async () => {
    if (!createTitle.trim()) return;
    setCreateError(null);
    setCreateLoading(true);
    try {
      await createIncident({ title: createTitle.trim(), severity: createSeverity });
      setCreateTitle('');
      setShowCreate(false);
      load();
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : 'Create failed');
    } finally {
      setCreateLoading(false);
    }
  };

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="page-title mb-0">Incidents</h1>
        <div className="flex flex-wrap items-center gap-3">
          <select
            className="rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-2 text-sm text-[var(--text)]"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by status"
          >
            <option value="">All statuses</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            className="rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-2 text-sm text-[var(--text)]"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            aria-label="Filter by severity"
          >
            <option value="">All severities</option>
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          {canMutate && (
            <button type="button" onClick={() => setShowCreate(true)} className="btn-primary">
              New incident
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {canMutate && showCreate && (
        <div className="card mb-6 animate-in">
          <h2 className="section-title mb-3">Create incident</h2>
          {createError && <p className="mb-2 text-sm text-[var(--red)]">{createError}</p>}
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[200px] flex-1">
              <label className="mb-1 block text-xs font-medium text-[var(--muted)]">Title</label>
              <input
                type="text"
                value={createTitle}
                onChange={(e) => setCreateTitle(e.target.value)}
                placeholder="e.g. API latency spike"
                className="input w-full"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-[var(--muted)]">Severity</label>
              <select
                value={createSeverity}
                onChange={(e) => setCreateSeverity(e.target.value as IncidentSeverity)}
                className="input"
              >
                {SEVERITY_OPTIONS.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <button type="button" onClick={handleCreate} disabled={createLoading} className="btn-primary">
              {createLoading ? 'Creating…' : 'Create'}
            </button>
            <button type="button" onClick={() => { setShowCreate(false); setCreateError(null); }} className="btn-secondary">
              Cancel
            </button>
          </div>
        </div>
      )}

      {data && data.items.length === 0 && (
        <div className="card animate-in py-12 text-center">
          <p className="text-[var(--muted)]">
            No incidents yet. Create one from &quot;New incident&quot; or link alerts from the Alerts page.
          </p>
        </div>
      )}

      {data && data.items.length > 0 && (
        <div className="card p-0 animate-in overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] bg-[var(--surface-elevated)]">
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">Title</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">Severity</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">Assigned</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">Alerts</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">SLA due</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">Created</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((inc) => (
                  <tr
                    key={inc.id}
                    className="border-b border-[var(--border)] transition hover:bg-[var(--surface-elevated)]/50"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/incidents/${inc.id}`}
                        className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                      >
                        {inc.title}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className="inline-block rounded px-2 py-0.5 text-xs font-medium capitalize"
                        style={{ backgroundColor: `${severityColor(inc.severity)}20`, color: severityColor(inc.severity) }}
                      >
                        {inc.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 capitalize">{inc.status}</td>
                    <td className="px-4 py-3 text-[var(--muted)]">{inc.assigned_to ?? '–'}</td>
                    <td className="px-4 py-3">{inc.alert_count ?? 0}</td>
                    <td className="px-4 py-3 text-[var(--muted)] tabular-nums">
                      {inc.sla_due_at ? formatDateTime(inc.sla_due_at) : '–'}
                    </td>
                    <td className="px-4 py-3 text-[var(--muted)] tabular-nums">{formatDateTime(inc.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.total > data.items.length && (
            <p className="px-4 py-2 text-xs text-[var(--muted)] border-t border-[var(--border)]">
              Showing {data.items.length} of {data.total} incidents
            </p>
          )}
        </div>
      )}

      {!data && !error && (
        <div className="card animate-in py-12 text-center">
          <p className="text-[var(--muted)]">Loading incidents…</p>
        </div>
      )}
    </main>
  );
}
