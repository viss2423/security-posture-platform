'use client';

import { useDeferredValue, useMemo, useState } from 'react';
import Link from 'next/link';
import { formatDateTime } from '@/lib/format';
import { runAttackLabAssetScan, type AssetPosture } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';

type AssetsPageClientProps = {
  items: AssetPosture[];
};

type SortKey =
  | 'asset_key'
  | 'name'
  | 'status'
  | 'criticality'
  | 'posture_score'
  | 'last_seen'
  | null;
type SortDir = 'asc' | 'desc';

function ScoreBar({ score }: { score: number | string | null }) {
  const n = score != null ? Number(score) : Number.NaN;
  const pct = Number.isNaN(n) ? 0 : Math.min(100, Math.max(0, n));
  const color = pct >= 80 ? 'var(--green)' : pct >= 50 ? 'var(--amber)' : 'var(--red)';
  return (
    <div className="flex min-w-[80px] items-center gap-2">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--border)]" role="presentation">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="w-7 text-sm font-semibold tabular-nums">{Number.isNaN(n) ? '-' : n}</span>
    </div>
  );
}

function CriticalityCell({ value }: { value: string | null | undefined }) {
  const v = (value ?? '').toLowerCase();
  const dotColor =
    v === 'high'
      ? 'var(--red)'
      : v === 'medium'
        ? 'var(--amber)'
        : v === 'low'
          ? 'var(--green)'
          : 'var(--muted)';
  return (
    <span className="inline-flex items-center gap-2">
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: dotColor }} aria-hidden />
      <span className="capitalize">{value ?? '-'}</span>
    </span>
  );
}

export default function AssetsPageClient({ items }: AssetsPageClientProps) {
  const { isAdmin } = useAuth();
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>(null);
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [scanBusyByAsset, setScanBusyByAsset] = useState<Record<string, boolean>>({});
  const [scanNotice, setScanNotice] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const deferredSearch = useDeferredValue(search);

  const filteredAndSorted = useMemo(() => {
    let list = items;
    const q = deferredSearch.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (asset) =>
          (asset.asset_key ?? asset.asset_id ?? '').toLowerCase().includes(q) ||
          (asset.name ?? '').toLowerCase().includes(q) ||
          (asset.status ?? '').toLowerCase().includes(q) ||
          (asset.environment ?? '').toLowerCase().includes(q)
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
        if (typeof av === 'number' && typeof bv === 'number') {
          return sortDir === 'asc' ? av - bv : bv - av;
        }
        const cmp = String(av).toLowerCase().localeCompare(String(bv).toLowerCase());
        return sortDir === 'asc' ? cmp : -cmp;
      });
    }
    return list;
  }, [deferredSearch, items, sortDir, sortKey]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((current) => (current === 'asc' ? 'desc' : 'asc'));
      return;
    }
    setSortKey(key);
    setSortDir('asc');
  };

  const headerClass =
    'px-5 py-3 text-left text-xs font-semibold uppercase tracking-widest text-[var(--muted)] whitespace-nowrap';

  const SortButton = ({ label, value }: { label: string; value: SortKey }) => (
    <button
      type="button"
      onClick={() => handleSort(value)}
      className="inline-flex items-center gap-1.5 rounded transition-colors hover:text-[var(--text)] focus:outline-none focus:ring-2 focus:ring-[var(--green)] focus:ring-offset-2 focus:ring-offset-[var(--surface-elevated)]"
    >
      {label}
      {sortKey === value && (
        <span className="shrink-0 text-[var(--green)]" aria-hidden>
          {sortDir === 'asc' ? '\u2191' : '\u2193'}
        </span>
      )}
    </button>
  );

  const gridCols = '120px 100px 90px 100px 120px 90px 70px 1fr';
  const assetKey = (asset: AssetPosture) => asset.asset_key ?? asset.asset_id ?? '';

  const handleScanAsset = async (asset: AssetPosture) => {
    const key = assetKey(asset);
    if (!key || !isAdmin) return;
    setScanError(null);
    setScanNotice(null);
    setScanBusyByAsset((current) => ({ ...current, [key]: true }));
    try {
      const job = await runAttackLabAssetScan({ asset_key: key });
      setScanNotice(`Scan queued for ${key} (job ${job.job_id}). Track progress in Jobs.`);
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Failed to queue scan');
    } finally {
      setScanBusyByAsset((current) => ({ ...current, [key]: false }));
    }
  };

  return (
    <main className="page-shell overflow-visible">
      <div className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="text-sm text-[var(--muted)]">
          {items.length > 0
            ? `${items.length} assets in the current workspace view.`
            : 'Asset inventory, posture status, and ownership in one list.'}
        </div>
        {items.length > 0 && (
          <div className="w-full sm:w-72">
            <label htmlFor="asset-search" className="sr-only">
              Search assets
            </label>
            <input
              id="asset-search"
              type="search"
              placeholder="Search by asset, name, status, env..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              className="input py-2.5 text-sm"
            />
          </div>
        )}
      </div>

      {scanNotice && (
        <div className="mb-4 rounded-xl border border-[var(--green)]/30 bg-[var(--green)]/10 px-4 py-3 text-sm text-[var(--text)]">
          {scanNotice}
        </div>
      )}
      {scanError && (
        <div className="mb-4 rounded-xl border border-[var(--red)]/30 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--text)]">
          {scanError}
        </div>
      )}

      {items.length > 0 && filteredAndSorted.length > 0 && (
        <div className="card animate-in overflow-hidden rounded-2xl p-0">
          <div className="overflow-x-auto rounded-b-2xl" style={{ minWidth: 0 }}>
            <div role="table" className="assets-grid-table" style={{ minWidth: 980, gridTemplateColumns: `${gridCols} 120px` }}>
              <div role="row" className="assets-grid-header">
                <div role="columnheader" className={headerClass}>
                  <SortButton label="Asset" value="asset_key" />
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortButton label="Name" value="name" />
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortButton label="Status" value="status" />
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortButton label="Criticality" value="criticality" />
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortButton label="Score" value="posture_score" />
                </div>
                <div role="columnheader" className={headerClass}>
                  Owner
                </div>
                <div role="columnheader" className={headerClass}>
                  Env
                </div>
                <div role="columnheader" className={headerClass}>
                  <SortButton label="Last seen" value="last_seen" />
                </div>
                <div role="columnheader" className={headerClass}>
                  Action
                </div>
              </div>
              {filteredAndSorted.map((asset, index) => (
                <div
                  key={assetKey(asset) || index}
                  role="row"
                  className="assets-grid-row group border-b border-[var(--border)] transition-colors hover:bg-[var(--surface-elevated-50)]"
                >
                  <div role="cell" className="px-5 py-3">
                    <Link
                      href={`/assets/${encodeURIComponent(assetKey(asset))}`}
                      className="inline-flex items-center gap-2 font-semibold text-[var(--text)] transition hover:text-[var(--green)]"
                    >
                      {assetKey(asset) || '-'}
                      <span className="text-[var(--muted)] opacity-0 transition-opacity group-hover:opacity-100" aria-hidden>
                        {'->'}
                      </span>
                    </Link>
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm text-[var(--text-muted)]">
                    {asset.name ?? '-'}
                  </div>
                  <div role="cell" className="px-5 py-3">
                    <span className={`badge ${(asset.status || 'unknown').toLowerCase()}`}>
                      {asset.status || 'unknown'}
                    </span>
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm">
                    <CriticalityCell value={asset.criticality ?? undefined} />
                  </div>
                  <div role="cell" className="px-5 py-3">
                    <ScoreBar score={asset.posture_score ?? null} />
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm text-[var(--muted)]">
                    {asset.owner?.trim() || 'Unassigned'}
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm text-[var(--muted)]">
                    {asset.environment ?? '-'}
                  </div>
                  <div role="cell" className="px-5 py-3 text-sm tabular-nums text-[var(--muted)]">
                    {asset.last_seen ? formatDateTime(asset.last_seen) : '-'}
                  </div>
                  <div role="cell" className="px-5 py-3">
                    {isAdmin ? (
                      <button
                        type="button"
                        onClick={() => void handleScanAsset(asset)}
                        disabled={Boolean(scanBusyByAsset[assetKey(asset)])}
                        className="btn-secondary px-2 py-1 text-xs"
                      >
                        {scanBusyByAsset[assetKey(asset)] ? 'Queueing...' : 'Scan this asset'}
                      </button>
                    ) : (
                      <span className="text-xs text-[var(--muted)]">Admin only</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
          {search.trim() && items.length !== filteredAndSorted.length && (
            <p className="border-t border-[var(--border)] px-5 py-3 text-xs text-[var(--muted)]">
              Showing {filteredAndSorted.length} of {items.length} assets
            </p>
          )}
        </div>
      )}

      {items.length > 0 && filteredAndSorted.length === 0 && (
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
    </main>
  );
}
