'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { getFindings, type Finding } from '@/lib/api';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-[var(--red)] text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
};

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [sourceFilter, setSourceFilter] = useState<string>('');

  useEffect(() => {
    setLoading(true);
    getFindings({
      status: statusFilter || undefined,
      source: sourceFilter || undefined,
      limit: 200,
    })
      .then((data) => {
        // Sort by severity
        const sorted = [...data].sort(
          (a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
        );
        setFindings(sorted);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [statusFilter, sourceFilter]);

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
            <option value="open">Open</option>
            <option value="ignored">Ignored</option>
            <option value="remediated">Remediated</option>
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
                  </td>
                  <td className="px-4 py-3">
                    {f.asset_key ? (
                      <Link href={`/assets/${f.asset_key}`} className="text-[var(--green)] hover:underline">
                        {f.asset_name || f.asset_key}
                      </Link>
                    ) : (
                      <span className="text-[var(--muted)]">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[var(--muted)]">{f.category || '—'}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${
                        f.status === 'open'
                          ? 'bg-[var(--red)]/20 text-[var(--red)]'
                          : f.status === 'remediated'
                            ? 'bg-[var(--green)]/20 text-[var(--green)]'
                            : 'bg-[var(--muted)]/20 text-[var(--muted)]'
                      }`}
                    >
                      {f.status}
                    </span>
                  </td>
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
          Showing {findings.length} finding{findings.length === 1 ? '' : 's'}. Remediation tips are in the scanner or asset detail.
        </p>
      )}
    </main>
  );
}
