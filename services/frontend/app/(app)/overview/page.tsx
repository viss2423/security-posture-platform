'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { getPostureSummary, type PostureSummary } from '@/lib/api';

export default function OverviewPage() {
  const [summary, setSummary] = useState<PostureSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getPostureSummary()
      .then(setSummary)
      .catch((e) => setError(e.message));
    const t = setInterval(() => {
      getPostureSummary().then(setSummary).catch(() => {});
    }, 60000);
    return () => clearInterval(t);
  }, []);

  return (
    <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
      <h1 className="page-title mb-8">Overview</h1>
      {error && (
        <div className="mb-6 rounded-lg bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]" role="alert">
          {error}
        </div>
      )}
      {summary && (
        <>
          <div className="mb-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="card text-center">
              <div className="text-3xl font-bold text-[var(--green)]">{summary.green}</div>
              <div className="mt-1 text-sm text-[var(--muted)]">Green</div>
            </div>
            <div className="card text-center">
              <div className="text-3xl font-bold text-[var(--amber)]">{summary.amber}</div>
              <div className="mt-1 text-sm text-[var(--muted)]">Amber</div>
            </div>
            <div className="card text-center">
              <div className="text-3xl font-bold text-[var(--red)]">{summary.red}</div>
              <div className="mt-1 text-sm text-[var(--muted)]">Red (down)</div>
            </div>
            <div className="card text-center">
              <div className="text-3xl font-bold text-[var(--text)]">{summary.posture_score_avg ?? '–'}</div>
              <div className="mt-1 text-sm text-[var(--muted)]">Posture score (avg)</div>
            </div>
          </div>
          {summary.down_assets && summary.down_assets.length > 0 && (
            <section>
              <h2 className="section-title">Down assets</h2>
              <div className="card">
                <ul className="space-y-2">
                  {summary.down_assets.map((id) => (
                    <li key={id}>
                      <Link
                        href={`/assets/${encodeURIComponent(id)}`}
                        className="font-medium text-[var(--red)] hover:underline"
                      >
                        {id}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          )}
        </>
      )}
      {!summary && !error && (
        <div className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-4 py-8 text-[var(--muted)]">
          <span className="h-5 w-5 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--green)]" />
          Loading…
        </div>
      )}
    </main>
  );
}
