'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  getFindings,
  updateFindingStatus,
  acceptFindingRisk,
  type Finding,
  type FindingStatus,
} from '@/lib/api';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-[var(--red)] text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
};

const STATUS_OPTIONS: FindingStatus[] = ['open', 'in_progress', 'remediated', 'accepted_risk'];

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'open':
      return 'bg-[var(--red)]/20 text-[var(--red)]';
    case 'in_progress':
      return 'bg-[var(--amber)]/20 text-[var(--amber)]';
    case 'remediated':
      return 'bg-[var(--green)]/20 text-[var(--green)]';
    case 'accepted_risk':
      return 'bg-[var(--muted)]/30 text-[var(--muted)]';
    default:
      return 'bg-[var(--muted)]/20 text-[var(--muted)]';
  }
}

export default function FindingsPage() {
  const { canMutate } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [updatingId, setUpdatingId] = useState<number | null>(null);
  const [acceptRiskId, setAcceptRiskId] = useState<number | null>(null);
  const [acceptReason, setAcceptReason] = useState('');
  const [acceptExpires, setAcceptExpires] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    getFindings({
      status: statusFilter || undefined,
      source: sourceFilter || undefined,
      limit: 200,
    })
      .then((data) => {
        const sorted = [...data].sort(
          (a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
        );
        setFindings(sorted);
        setError(null);
      })
      .catch((e) => setError(e.message === 'Failed to fetch' ? 'API unreachable' : e.message))
      .finally(() => setLoading(false));
  }, [statusFilter, sourceFilter]);

  useEffect(() => {
    load();
  }, [load]);

  const defaultExpires = () => {
    const d = new Date();
    d.setMonth(d.getMonth() + 3);
    return d.toISOString().slice(0, 10);
  };

  const handleStatusChange = async (finding_id: number, status: FindingStatus) => {
    setError(null);
    setUpdatingId(finding_id);
    try {
      await updateFindingStatus(finding_id, status);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Update failed');
    } finally {
      setUpdatingId(null);
    }
  };

  const openAcceptRisk = (id: number) => {
    setAcceptRiskId(id);
    setAcceptReason('');
    setAcceptExpires(defaultExpires());
  };

  const handleAcceptRisk = async () => {
    if (acceptRiskId == null) return;
    setError(null);
    setUpdatingId(acceptRiskId);
    try {
      await acceptFindingRisk(acceptRiskId, acceptReason, new Date(acceptExpires).toISOString());
      setAcceptRiskId(null);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Accept risk failed');
    } finally {
      setUpdatingId(null);
    }
  };

  const sources = Array.from(new Set(findings.map((f) => f.source).filter((s): s is string => !!s)));

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-8">Findings</h1>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      <div className="mb-6 flex flex-wrap items-center gap-4">
        <label className="flex items-center gap-2 text-sm text-[var(--muted)]">
          Status
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm"
          >
            <option value="">All</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s === 'accepted_risk' ? 'Accepted risk' : s.replace('_', ' ')}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-[var(--muted)]">
          Source
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm"
          >
            <option value="">All</option>
            <option value="tls_scan">TLS scan</option>
            <option value="header_scan">Header scan</option>
            {sources
              .filter((s) => s !== 'tls_scan' && s !== 'header_scan')
              .map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
          </select>
        </label>
      </div>

      {loading ? (
        <p className="text-sm text-[var(--muted)]">Loading...</p>
      ) : findings.length === 0 ? (
        <EmptyState
          title="No findings"
          description="Run the scanner to generate TLS and security header findings, or wait for the scheduled scan."
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[var(--border)] bg-[var(--surface)]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-[var(--muted)]">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Asset</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Status</th>
                {canMutate && <th className="px-4 py-3">Actions</th>}
                <th className="px-4 py-3">First seen</th>
                <th className="px-4 py-3">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {findings.map((f) => (
                <tr key={f.finding_id} className="hover:bg-[var(--surface-elevated)]">
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${SEVERITY_COLORS[f.severity] ?? 'bg-gray-600 text-white'}`}
                    >
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-medium text-[var(--text)]">
                    {f.title}
                    {f.evidence && (
                      <p className="mt-1 text-xs text-[var(--muted)] line-clamp-1">{f.evidence}</p>
                    )}
                    {f.status === 'accepted_risk' && (f.accepted_risk_reason || f.accepted_risk_by || f.accepted_risk_expires_at) && (
                      <p className="mt-1 text-xs text-[var(--muted)]">
                        Accepted{f.accepted_risk_by && ` by ${f.accepted_risk_by}`}
                        {f.accepted_risk_expires_at && ` until ${formatDateTime(f.accepted_risk_expires_at)}`}
                        {f.accepted_risk_reason && `: ${f.accepted_risk_reason}`}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {f.asset_key ? (
                      <Link href={`/assets/${encodeURIComponent(f.asset_key)}`} className="text-[var(--green)] hover:underline">
                        {f.asset_name || f.asset_key}
                      </Link>
                    ) : (
                      <span className="text-[var(--muted)]">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[var(--muted)]">{f.category || '—'}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium capitalize ${statusBadgeClass(f.status)}`}>
                      {f.status.replace('_', ' ')}
                    </span>
                  </td>
                  {canMutate && (
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        <select
                          value={f.status}
                          onChange={(e) => handleStatusChange(f.finding_id, e.target.value as FindingStatus)}
                          disabled={updatingId === f.finding_id}
                          className="rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-xs"
                        >
                          {STATUS_OPTIONS.map((s) => (
                            <option key={s} value={s}>
                              {s.replace('_', ' ')}
                            </option>
                          ))}
                        </select>
                        {f.status !== 'accepted_risk' && (
                          <button
                            type="button"
                            onClick={() => openAcceptRisk(f.finding_id)}
                            disabled={updatingId === f.finding_id}
                            className="rounded border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--muted)] hover:bg-[var(--border)]"
                          >
                            Accept risk
                          </button>
                        )}
                      </div>
                    </td>
                  )}
                  <td className="px-4 py-3 text-[var(--muted)]">{f.first_seen ? formatDateTime(f.first_seen) : '—'}</td>
                  <td className="px-4 py-3 text-[var(--muted)]">{f.last_seen ? formatDateTime(f.last_seen) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {findings.length > 0 && (
        <p className="mt-4 text-xs text-[var(--muted)]">
          Showing {findings.length} finding{findings.length === 1 ? '' : 's'}
          {canMutate && '. Change status or accept risk with expiry; re-review when risk acceptance expires.'}
        </p>
      )}

      {acceptRiskId != null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-labelledby="accept-risk-title">
          <div className="card max-w-md w-full animate-in">
            <h2 id="accept-risk-title" className="section-title mb-3">Accept risk</h2>
            <p className="text-sm text-[var(--muted)] mb-3">Finding will be marked as accepted_risk. Set an expiry date for when it must be reviewed again.</p>
            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-xs font-medium text-[var(--muted)]">Reason</label>
                <textarea
                  value={acceptReason}
                  onChange={(e) => setAcceptReason(e.target.value)}
                  placeholder="e.g. Low impact, will fix in Q2"
                  rows={2}
                  className="input w-full text-sm"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-[var(--muted)]">Review by (date)</label>
                <input
                  type="date"
                  value={acceptExpires}
                  onChange={(e) => setAcceptExpires(e.target.value)}
                  className="input w-full"
                />
              </div>
            </div>
            <div className="mt-4 flex gap-2">
              <button type="button" onClick={handleAcceptRisk} className="btn-primary text-sm">
                Accept risk
              </button>
              <button type="button" onClick={() => setAcceptRiskId(null)} className="btn-secondary text-sm">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
