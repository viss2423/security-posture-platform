'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { getPostureSummary, type PostureSummary } from '@/lib/api';
import { OverviewSkeleton } from '@/components/Skeleton';
import { ProgressRing } from '@/components/ProgressRing';

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

  const scoreNum = summary?.posture_score_avg != null ? Number(summary.posture_score_avg) : null;
  const showRing = typeof scoreNum === 'number' && !Number.isNaN(scoreNum) && scoreNum >= 0 && scoreNum <= 100;

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-10">Overview</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {error}
        </div>
      )}
      {summary && (
        <>
          <div className="mb-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
            <div className="metric-card animate-in">
              <div className="text-4xl font-bold text-[var(--green)]">{summary.green}</div>
              <div className="mt-2 text-sm font-medium text-[var(--muted)]">Green</div>
            </div>
            <div className="metric-card amber animate-in animate-in-delay-1">
              <div className="text-4xl font-bold text-[var(--amber)]">{summary.amber}</div>
              <div className="mt-2 text-sm font-medium text-[var(--muted)]">Amber</div>
            </div>
            <div className="metric-card red animate-in animate-in-delay-2">
              <div className="text-4xl font-bold text-[var(--red)]">{summary.red}</div>
              <div className="mt-2 text-sm font-medium text-[var(--muted)]">Red (down)</div>
            </div>
            <div className="metric-card neutral animate-in animate-in-delay-3 flex flex-col items-center justify-center">
              {showRing ? (
                <>
                  <div className="relative">
                    <ProgressRing value={scoreNum} className="block" />
                    <span className="absolute inset-0 flex items-center justify-center text-lg font-bold text-[var(--text)]">
                      {Math.round(scoreNum)}
                    </span>
                  </div>
                  <div className="mt-2 text-sm font-medium text-[var(--muted)]">Posture score (avg)</div>
                </>
              ) : (
                <>
                  <div className="text-4xl font-bold text-[var(--text)]">{summary.posture_score_avg ?? '–'}</div>
                  <div className="mt-2 text-sm font-medium text-[var(--muted)]">Posture score (avg)</div>
                </>
              )}
            </div>
          </div>
          {summary.down_assets && summary.down_assets.length > 0 && (
            <section className="animate-in animate-in-delay-4">
              <h2 className="section-title">Down assets</h2>
              <div className="card" style={{ borderColor: 'var(--red-border-subtle)' }}>
                <ul className="space-y-3">
                  {summary.down_assets.map((id) => (
                    <li key={id}>
                      <Link
                        href={`/assets/${encodeURIComponent(id)}`}
                        className="font-medium text-[var(--red)] transition hover:underline"
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
        <OverviewSkeleton />
      )}
    </main>
  );
}
