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
    <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
      <h1 className="page-title mb-8">Alerts</h1>
      {error && (
        <div className="mb-6 rounded-lg bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]" role="alert">
          {error}
        </div>
      )}

      <section className="mb-10">
        <h2 className="section-title">Currently firing (down assets)</h2>
        <p className="mb-4 text-sm text-[var(--muted)]">
          Assets in red state — source of truth from posture API.
        </p>
        <div className="card">
          {firing.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No firing alerts. All assets are up.</p>
          ) : (
            <ul className="space-y-2">
              {firing.map((id) => (
                <li key={id}>
                  <Link href={`/assets/${encodeURIComponent(id)}`} className="font-medium text-[var(--red)] hover:underline">
                    {id}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section>
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
          Open Grafana → Alert rules
        </a>
      </section>
    </main>
  );
}
