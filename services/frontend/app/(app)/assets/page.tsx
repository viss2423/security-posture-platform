'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { getPostureList, type AssetPosture } from '@/lib/api';

export default function AssetsPage() {
  const [data, setData] = useState<{ total: number; items: AssetPosture[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getPostureList()
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
      <h1 className="page-title mb-8">Assets</h1>
      {error && (
        <div className="mb-6 rounded-lg bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]" role="alert">
          {error}
        </div>
      )}
      {data && (
        <div className="card overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] border-collapse">
              <thead>
                <tr className="border-b border-[var(--border)] bg-[var(--bg)]/50">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Asset</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Name</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Criticality</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Score</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Owner</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Env</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr
                    key={a.asset_key}
                    className="border-b border-[var(--border)] transition hover:bg-[var(--border)]/30"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/assets/${encodeURIComponent(a.asset_key)}`}
                        className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                      >
                        {a.asset_key}
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-sm">{a.name ?? '–'}</td>
                    <td className="px-4 py-3">
                      <span className={`badge ${(a.status || 'unknown').toLowerCase()}`}>
                        {a.status || 'unknown'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm capitalize">{a.criticality ?? '–'}</td>
                    <td className="px-4 py-3 text-sm">{a.posture_score ?? '–'}</td>
                    <td className="px-4 py-3 text-sm text-[var(--muted)]">{a.owner?.trim() || 'Unassigned'}</td>
                    <td className="px-4 py-3 text-sm">{a.environment ?? '–'}</td>
                    <td className="px-4 py-3 text-sm text-[var(--muted)]">
                      {a.last_seen ? new Date(a.last_seen).toLocaleString() : '–'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {!data && !error && (
        <div className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-4 py-8 text-[var(--muted)]">
          <span className="h-5 w-5 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--green)]" />
          Loading…
        </div>
      )}
    </main>
  );
}
