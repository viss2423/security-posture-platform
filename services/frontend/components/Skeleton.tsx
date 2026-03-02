'use client';

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden />;
}

export function MetricCardSkeleton() {
  return (
    <div className="metric-card overflow-hidden">
      <Skeleton className="mx-auto h-10 w-16" />
      <Skeleton className="mx-auto mt-3 h-4 w-20" />
    </div>
  );
}

export function TableRowSkeleton({ cols = 8 }: { cols?: number }) {
  return (
    <tr className="border-b border-[var(--border)]">
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-5 py-4">
          <Skeleton className={`h-4 ${i === 0 ? 'w-32' : 'w-20'}`} />
        </td>
      ))}
    </tr>
  );
}

export function OverviewSkeleton() {
  return (
    <div className="mb-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
      {[1, 2, 3, 4].map((i) => (
        <MetricCardSkeleton key={i} />
      ))}
    </div>
  );
}

export function AssetsTableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="card overflow-hidden p-0">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse">
          <thead>
            <tr className="border-b border-[var(--border)] bg-[var(--surface-elevated)]">
              <th className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)]">Asset</th>
              <th className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)]">Name</th>
              <th className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)]">Status</th>
              <th className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)]">Criticality</th>
              <th className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)]">Score</th>
              <th className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)]">Owner</th>
              <th className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)]">Env</th>
              <th className="px-5 py-4 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)]">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }).map((_, i) => (
              <TableRowSkeleton key={i} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function AssetDetailSkeleton() {
  return (
    <div className="space-y-8">
      <div className="card">
        <div className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-4">
          {[1, 2, 3, 4, 5, 6].map((i) => (
            <span key={i} className="col-span-2 flex gap-4 sm:col-span-1">
              <Skeleton className="h-4 w-20 shrink-0" />
              <Skeleton className="h-4 flex-1" />
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
