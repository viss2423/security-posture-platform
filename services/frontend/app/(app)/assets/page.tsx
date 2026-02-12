'use client';

import { useEffect, useState, useMemo } from 'react';
import Link from 'next/link';
import { getPostureList, type AssetPosture } from '@/lib/api';
import { useFilters } from '@/contexts/FilterContext';
import { formatDateTime } from '@/lib/format';
import { AssetsTableSkeleton } from '@/components/Skeleton';
import { EmptyState, ApiDownHint } from '@/components/EmptyState';

type SortKey = 'asset_key' | 'name' | 'status' | 'criticality' | 'posture_score' | 'last_seen' | null;
type SortDir = 'asc' | 'desc';

function ScoreBar({ score }: { score: number | string | null }) {
  const n = score != null ? Number(score) : NaN;
  const pct = Number.isNaN(n) ? 0 : Math.min(100, Math.max(0, n));
  const color = pct >= 80 ? 'var(--green)' : pct >= 50 ? 'var(--amber)' : 'var(--red)';
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="h-1.5 flex-1 rounded-full bg-[var(--border)] overflow-hidden" role="presentation">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-sm font-semibold tabular-nums w-7">{Number.isNaN(n) ? '–' : n}</span>
    </div>
  );
}

function CriticalityCell({ value }: { value: string | null | undefined }) {
  const v = (value ?? '').toLowerCase();
  const dotColor = v === 'high' ? 'var(--red)' : v === 'medium' ? 'var(--amber)' : v === 'low' ? 'var(--green)' : 'var(--muted)';
  return (
    <span className="inline-flex items-center gap-2">
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: dotColor }} aria-hidden />
      <span className="capitalize">{value ?? '–'}</span>
    </span>
  );
}

export default function AssetsPage() {
  const filters = useFilters();
  const [data, setData] = useState<{ total: number; items: AssetPosture[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>(null);
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  const filterParams = useMemo(
    () => ({
      environment: filters.environment ?? undefined,
      criticality: filters.criticality ?? undefined,
      owner: filters.owner ?? undefined,
      status: filters.status ?? undefined,
    }),
    [filters.environment, filters.criticality, filters.owner, filters.status]
  );

  useEffect(() => {
    getPostureList(filterParams)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [filterParams.environment, filterParams.criticality, filterParams.owner, filterParams.status]);

  const filteredAndSorted = useMemo(() => {
    if (!data?.items) return [];
    let list = data.items;
    const q = search.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (a) =>
          (a.asset_key ?? a.asset_id ?? '').toLowerCase().includes(q) ||
          (a.name ?? '').toLowerCase().includes(q) ||
          (a.status ?? '').toLowerCase().includes(q) ||
          (a.environment ?? '').toLowerCase().includes(q)
      );
    }
    if (sortKey) {
      list = [...list].sort((a, b) => {
        const av = a[sortKey as keyof AssetPosture];
        const bv = b[sortKey as keyof AssetPosture];
        if (av == null && bv == null) return 0;
        if (av == null) return sortDir === 'asc' ? 1 : -1;
        if (bv == null) return sortDir === 'asc' ? -1 : 1;
        if (sortKey === 'last_seen') {
          const ta = new Date(av as string).getTime();
          const tb = new Date(bv as string).getTime();
          return sortDir === 'asc' ? ta - tb : tb - ta;
        }
        if (typeof av === 'number' && typeof bv === 'number') return sortDir === 'asc' ? av - bv : bv - av;
        const sa = String(av).toLowerCase();
        const sb = String(bv).toLowerCase();
        const cmp = sa.localeCompare(sb);
        return sortDir === 'asc' ? cmp : -cmp;
      });
    }
    return list;
  }, [data?.items, search, sortKey, sortDir]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const headerClass =
    'px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)] whitespace-nowrap';
  const SortBtn = ({ label, sortKey: sk }: { label: string; sortKey: SortKey }) => (
    <button
      type="button"
      onClick={() => handleSort(sk)}
      className="inline-flex items-center gap-1.5 hover:text-[var(--text)] transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--green)] focus:ring-offset-2 focus:ring-offset-[var(--surface-elevated)] rounded"
    >
      {label}
      {sortKey === sk && (
        <span className="text-[var(--green)] shrink-0" aria-hidden>
          {sortDir === 'asc' ? '\u2191' : '\u2193'}
        </span>
      )}
    </button>
  );

  const assetKey = (a: AssetPosture) => a.asset_key ?? a.asset_id ?? '';
  const gridCols = '120px 100px 90px 100px 120px 90px 70px 1fr';

  return (
    <main className="mx-auto max-w-6xl px-4 pt-6 pb-10 sm:px-6 lg:px-8 overflow-visible">
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="page-title mb-0">Assets</h1>
          {data && data.items.length > 0 && (
            <p className="mt-1 text-sm text-[var(--muted)]">
              {data.items.length} asset{data.items.length !== 1 ? 's' : ''}
            </p>
          )}
        </div>
        {data && data.items.length > 0 && (
          <div className="w-full sm:w-72">
            <label htmlFor="asset-search" className="sr-only">
              Search assets
            </label>
            <input
              id="asset-search"
              type="search"
              placeholder="Search by asset, name, status, env..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input py-2.5 text-sm"
            />
          </div>
        )}
      </div>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {error}
          <ApiDownHint />
        </div>
      )}
      {data && filteredAndSorted.length > 0 && (
        <div className="card p-0 animate-in overflow-hidden rounded-2xl">
          <div className="overflow-x-auto rounded-b-2xl" style={{ minWidth: 0 }}>
            <div role="table" className="assets-grid-table" style={{ minWidth: 900, gridTemplateColumns: gridCols }}>
              <div role="row" className="assets-grid-header">
                <div role="columnheader" className={headerClass}>
                  <SortBtn label="Asset" sortKey="asset_key" />
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortBtn label="Name" sortKey="name" />
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortBtn label="Status" sortKey="status" />
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortBtn label="Criticality" sortKey="criticality" />
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortBtn label="Score" sortKey="posture_score" />
                </div>
                <div role="columnheader" className={headerClass}>
                  Owner
                </div>
                <div role="columnheader" className={headerClass}>
                  Env
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortBtn label="Last seen" sortKey="last_seen" />
                </div>
              </div>
              {filteredAndSorted.map((a, idx) => (
                <div
                  key={assetKey(a) || idx}
                  role="row"
                  className="assets-grid-row border-b border-[var(--border)] transition-colors hover:bg-[var(--surface-elevated-50)] group"
                >
                  <div role="cell" className="px-5 py-3">
                    <Link
                      href={`/assets/${encodeURIComponent(assetKey(a))}`}
                      className="font-semibold text-[var(--text)] transition hover:text-[var(--green)] inline-flex items-center gap-2"
                    >
                      {assetKey(a) || '–'}
                      <span className="text-[var(--muted)] opacity-0 group-hover:opacity-100 transition-opacity" aria-hidden>
                        →
                      </span>
                    </Link>
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm text-[var(--text-muted)]">
                    {a.name ?? '–'}
                  </div>
                  <div role="cell" className="px-5 py-3">
                    <span className={`badge ${(a.status || 'unknown').toLowerCase()}`}>
                      {a.status || 'unknown'}
                    </span>
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm">
                    <CriticalityCell value={a.criticality ?? undefined} />
                  </div>
                  <div role="cell" className="px-5 py-3">
                    <ScoreBar score={a.posture_score ?? null} />
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm text-[var(--muted)]">
                    {a.owner?.trim() || 'Unassigned'}
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm text-[var(--muted)]">
                    {a.environment ?? '–'}
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm text-[var(--muted)] tabular-nums">
                    {a.last_seen ? formatDateTime(a.last_seen) : '–'}
                  </div>
                </div>
              ))}
            </div>
          </div>
          {search.trim() && data.items.length !== filteredAndSorted.length && (
            <p className="px-5 py-3 text-xs text-[var(--muted)] border-t border-[var(--border)]">
              Showing {filteredAndSorted.length} of {data.items.length} assets
            </p>
          )}
        </div>
      )}
      {data && data.items.length > 0 && filteredAndSorted.length === 0 && (
        <div className="card animate-in py-12 text-center">
          <p className="text-[var(--muted)]">No assets match &quot;{search}&quot;</p>
          <button
            type="button"
            onClick={() => setSearch('')}
            className="mt-3 text-sm font-medium text-[var(--green)] hover:underline"
          >
            Clear search
          </button>
        </div>
      )}
      {data && data.items.length === 0 && (
        <EmptyState
          icon={<span className="text-2xl font-bold text-[var(--muted)]">0</span>}
          title="No assets yet"
          description="Assets appear here once posture data is ingested. Ingestion runs every 60s when the stack is up. Check that the ingestion container is running."
        />
      )}
      {!data && !error && (
        <AssetsTableSkeleton rows={8} />
      )}
    </main>
  );
}
