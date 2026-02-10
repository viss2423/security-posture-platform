'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { getPostureSummary, type PostureSummary } from '@/lib/api';

export default function AlertsPage() {
  const [summary, setSummary] = useState<PostureSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const grafanaUrl = process.env.NEXT_PUBLIC_GRAFANA_URL || 'http://localhost:3001';
  const firing = summary?.down_assets ?? [];

  useEffect(() => {
    getPostureSummary()
      .then(setSummary)
      .catch((e) => setError(e.message));
  }, []);

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-10">Alerts</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {error}
        </div>
      )}

      <section className="mb-12 animate-in">
        <h2 className="section-title">Currently firing (down assets)</h2>
        <p className="mb-4 text-sm text-[var(--muted)]">
          Assets in red state — source of truth from posture API.
        </p>
        <div className="card">
          {firing.length === 0 ? (
            <div className="py-12 text-center">
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-green-subtle">
                <span className="text-2xl font-bold text-[var(--green)]">0</span>
              </div>
              <h3 className="text-lg font-semibold text-[var(--text)]">All clear</h3>
              <p className="mt-2 text-sm text-[var(--muted)]">No firing alerts. All assets are up.</p>
            </div>
          ) : (
            <ul className="space-y-3">
              {firing.map((id) => (
                <li key={id}>
                  <Link href={`/assets/${encodeURIComponent(id)}`} className="font-medium text-[var(--red)] transition hover:underline">
                    {id}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="animate-in animate-in-delay-1">
        <h2 className="section-title">Grafana</h2>
        <p className="mb-4 text-sm text-[var(--muted)]">
          Alert rules and history are managed in Grafana.
        </p>
        <a
          href={`${grafanaUrl}/alerting/list`}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-secondary inline-flex"
        >
          Open Grafana - Alert rules
        </a>
      </section>
    </main>
  );
}
