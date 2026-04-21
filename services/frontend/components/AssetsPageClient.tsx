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
type StatusQuick = 'all' | 'up' | 'down' | 'degraded' | 'unknown';
type CriticalityQuick = 'all' | 'high' | 'medium' | 'low';

function normalizeStatusQuick(value: string | null | undefined): Exclude<StatusQuick, 'all'> {
  const normalized = (value ?? '').toLowerCase();
  if (normalized === 'green' || normalized === 'up') return 'up';
  if (normalized === 'amber' || normalized === 'degraded' || normalized === 'stale') {
    return 'degraded';
  }
  if (normalized === 'red' || normalized === 'down') return 'down';
  return 'unknown';
}

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
  const [statusQuick, setStatusQuick] = useState<StatusQuick>('all');
  const [criticalityQuick, setCriticalityQuick] = useState<CriticalityQuick>('all');
  const [sortKey, setSortKey] = useState<SortKey>(null);
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [scanBusyByAsset, setScanBusyByAsset] = useState<Record<string, boolean>>({});
  const [scanNotice, setScanNotice] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const deferredSearch = useDeferredValue(search);

  const filteredAndSorted = useMemo(() => {
    let list = items;
    if (statusQuick !== 'all') {
      list = list.filter((asset) => normalizeStatusQuick(asset.status) === statusQuick);
    }
    if (criticalityQuick !== 'all') {
      list = list.filter((asset) => (asset.criticality || '').toLowerCase() === criticalityQuick);
    }
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
  }, [criticalityQuick, deferredSearch, items, sortDir, sortKey, statusQuick]);

  const statusCounts = useMemo(() => {
    const counts: Record<Exclude<StatusQuick, 'all'>, number> = {
      up: 0,
      down: 0,
      degraded: 0,
      unknown: 0,
    };
    for (const asset of items) {
      const key = normalizeStatusQuick(asset.status);
      if (key in counts) counts[key] += 1;
      else counts.unknown += 1;
    }
    return counts;
  }, [items]);

  const criticalityCounts = useMemo(() => {
    const counts: Record<Exclude<CriticalityQuick, 'all'>, number> = {
      high: 0,
      medium: 0,
      low: 0,
    };
    for (const asset of items) {
      const key = ((asset.criticality || '').toLowerCase() as Exclude<CriticalityQuick, 'all'>);
      if (key in counts) counts[key] += 1;
    }
    return counts;
  }, [items]);

  const topRiskAssets = useMemo(
    () =>
      [...filteredAndSorted]
        .sort(
          (a, b) =>
            Number(a.posture_score ?? 101) - Number(b.posture_score ?? 101) ||
            String(a.asset_key || '').localeCompare(String(b.asset_key || ''))
        )
        .slice(0, 5),
    [filteredAndSorted]
  );

  const unhealthyCount = useMemo(
    () => items.filter((asset) => normalizeStatusQuick(asset.status) !== 'up').length,
    [items]
  );
  const lowPostureCount = useMemo(
    () =>
      items.filter((asset) => {
        const score = asset.posture_score != null ? Number(asset.posture_score) : Number.NaN;
        return !Number.isNaN(score) && score < 50;
      }).length,
    [items]
  );

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((current) => (current === 'asc' ? 'desc' : 'asc'));
      return;
    }
    setSortKey(key);
    setSortDir('asc');
  };

  const assetKey = (asset: AssetPosture) => asset.asset_key ?? asset.asset_id ?? '';

  const sortOptions: Array<{ label: string; value: SortKey }> = [
    { label: 'Asset', value: 'asset_key' },
    { label: 'Name', value: 'name' },
    { label: 'Status', value: 'status' },
    { label: 'Criticality', value: 'criticality' },
    { label: 'Score', value: 'posture_score' },
    { label: 'Last seen', value: 'last_seen' },
  ];

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
    <main className="page-shell view-stack overflow-visible">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <h1 className="hero-title">Asset Inventory</h1>
            <p className="hero-copy">
              See every monitored asset with ownership, posture, health, and direct scan actions
              in one customer-friendly inventory view.
            </p>
            <div className="mt-4 max-w-sm">
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
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Total assets</p>
              <p className="hero-stat-value">{items.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Visible after filter</p>
              <p className="hero-stat-value">{filteredAndSorted.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Status not up</p>
              <p className="hero-stat-value">{unhealthyCount}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Score below 50</p>
              <p className="hero-stat-value">{lowPostureCount}</p>
            </div>
          </div>
        </div>
      </section>

      <section className="command-lane animate-in">
        <div className="command-lane-grid">
          <span className="command-pill-strong">Visible {filteredAndSorted.length}</span>
          <span className="command-pill">Down/degraded {unhealthyCount}</span>
          <span className="command-pill">Low score {lowPostureCount}</span>
        </div>
        <div className="mt-3 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
              Status
            </span>
            {(['all', 'up', 'down', 'degraded', 'unknown'] as const).map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => setStatusQuick(status)}
                className={`rounded-full border px-3 py-1.5 text-xs font-semibold uppercase transition ${
                  statusQuick === status
                    ? 'border-cyan-300/20 bg-cyan-300/08 text-[var(--cyan-strong)]'
                    : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)] hover:border-cyan-300/18 hover:text-[var(--text)]'
                }`}
              >
                {status}
                {status !== 'all' && ` ${statusCounts[status]}`}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
              Criticality
            </span>
            {(['all', 'high', 'medium', 'low'] as const).map((criticality) => (
              <button
                key={criticality}
                type="button"
                onClick={() => setCriticalityQuick(criticality)}
                className={`rounded-full border px-3 py-1.5 text-xs font-semibold uppercase transition ${
                  criticalityQuick === criticality
                    ? 'border-cyan-300/20 bg-cyan-300/08 text-[var(--cyan-strong)]'
                    : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)] hover:border-cyan-300/18 hover:text-[var(--text)]'
                }`}
              >
                {criticality}
                {criticality !== 'all' && ` ${criticalityCounts[criticality]}`}
              </button>
            ))}
            {(statusQuick !== 'all' || criticalityQuick !== 'all') && (
              <button
                type="button"
                onClick={() => {
                  setStatusQuick('all');
                  setCriticalityQuick('all');
                }}
                className="btn-secondary px-3 py-1.5 text-xs"
              >
                Reset slice
              </button>
            )}
          </div>
        </div>
      </section>

      <section className="section-panel-tight animate-in">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="section-title mb-2">Sort the inventory</p>
            <p className="text-sm text-[var(--text-muted)]">
              Switch from alphabetical browsing to risk-first review with one click.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {sortOptions.map((option) => {
              const active = sortKey === option.value;
              return (
                <button
                  key={option.label}
                  type="button"
                  onClick={() => handleSort(option.value)}
                  className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition ${
                    active
                      ? 'border-cyan-300/20 bg-cyan-300/08 text-[var(--cyan-strong)]'
                      : 'border-[var(--border)] bg-white text-[var(--text-muted)] hover:border-cyan-300/20 hover:text-[var(--text)]'
                  }`}
                >
                  {option.label}
                  {active ? ` ${sortDir === 'asc' ? '↑' : '↓'}` : ''}
                </button>
              );
            })}
          </div>
        </div>
      </section>

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
        <section className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <div className="grid gap-4 lg:grid-cols-2">
            {filteredAndSorted.map((asset, index) => (
              <article key={assetKey(asset) || index} className="section-panel animate-in">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
                      {assetKey(asset) || 'Unassigned asset'}
                    </p>
                    <Link
                      href={`/assets/${encodeURIComponent(assetKey(asset))}`}
                      className="mt-2 inline-flex items-center gap-2 text-[1.35rem] font-semibold tracking-[-0.03em] text-[var(--text)] transition hover:text-[var(--green)]"
                    >
                      {asset.name || assetKey(asset) || 'Unnamed asset'}
                      <span aria-hidden>{'->'}</span>
                    </Link>
                  </div>
                  <span className={`badge ${(asset.status || 'unknown').toLowerCase()}`}>
                    {asset.status || 'unknown'}
                  </span>
                </div>

                <div className="mt-5 grid gap-3 sm:grid-cols-2">
                  <div className="signal-card">
                    <p className="text-[10px] uppercase tracking-[0.14em] text-[var(--muted)]">
                      Criticality
                    </p>
                    <div className="mt-2 text-sm text-[var(--text)]">
                      <CriticalityCell value={asset.criticality ?? undefined} />
                    </div>
                  </div>
                  <div className="signal-card">
                    <p className="text-[10px] uppercase tracking-[0.14em] text-[var(--muted)]">
                      Owner
                    </p>
                    <p className="mt-2 text-sm font-medium text-[var(--text)]">
                      {asset.owner?.trim() || 'Unassigned'}
                    </p>
                  </div>
                  <div className="signal-card">
                    <p className="text-[10px] uppercase tracking-[0.14em] text-[var(--muted)]">
                      Environment
                    </p>
                    <p className="mt-2 text-sm font-medium text-[var(--text)]">
                      {asset.environment ?? '-'}
                    </p>
                  </div>
                  <div className="signal-card">
                    <p className="text-[10px] uppercase tracking-[0.14em] text-[var(--muted)]">
                      Last seen
                    </p>
                    <p className="mt-2 text-sm font-medium text-[var(--text)]">
                      {asset.last_seen ? formatDateTime(asset.last_seen) : '-'}
                    </p>
                  </div>
                </div>

                <div className="mt-5 rounded-[1.35rem] border border-[var(--border)] bg-white/84 px-4 py-4">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
                      Posture score
                    </p>
                    <span className="stat-chip">
                      {asset.posture_score != null ? Number(asset.posture_score) : '-'}
                    </span>
                  </div>
                  <div className="mt-3">
                    <ScoreBar score={asset.posture_score ?? null} />
                  </div>
                </div>

                <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
                  <Link
                    href={`/assets/${encodeURIComponent(assetKey(asset))}`}
                    className="btn-secondary"
                  >
                    Open asset
                  </Link>
                  {isAdmin ? (
                    <button
                      type="button"
                      onClick={() => void handleScanAsset(asset)}
                      disabled={Boolean(scanBusyByAsset[assetKey(asset)])}
                      className="btn-primary"
                    >
                      {scanBusyByAsset[assetKey(asset)] ? 'Queueing...' : 'Run verification scan'}
                    </button>
                  ) : (
                    <span className="text-xs text-[var(--muted)]">Verification scans are admin-only</span>
                  )}
                </div>
              </article>
            ))}
          </div>

          <aside className="space-y-4">
            <section className="section-panel animate-in h-fit">
              <h2 className="section-title mb-3">Priority lane</h2>
              <p className="mb-3 text-sm text-[var(--text-muted)]">
                The assets at greatest risk in the current view.
              </p>
              {topRiskAssets.length === 0 ? (
                <p className="text-sm text-[var(--muted)]">No assets in scope.</p>
              ) : (
                <ul className="space-y-2">
                  {topRiskAssets.map((asset) => (
                    <li
                      key={assetKey(asset)}
                      className="rounded-[1.2rem] border border-[var(--border)] bg-white/84 px-3 py-3"
                    >
                      <Link
                        href={`/assets/${encodeURIComponent(assetKey(asset))}`}
                        className="text-sm font-semibold text-[var(--text)] hover:text-[var(--green)]"
                      >
                        {asset.name || assetKey(asset)}
                      </Link>
                      <div className="mt-2 flex items-center justify-between text-xs text-[var(--muted)]">
                        <span>{asset.status || 'unknown'}</span>
                        <span>
                          Score {asset.posture_score != null ? Number(asset.posture_score) : '-'}
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="section-panel-tight animate-in">
              <p className="section-title mb-2">Inventory summary</p>
              <div className="space-y-2">
                <div className="flex items-center justify-between rounded-[1rem] border border-[var(--border)] bg-white/86 px-3 py-2 text-sm">
                  <span className="text-[var(--text-muted)]">Total assets</span>
                  <span className="font-semibold text-[var(--text)]">{items.length}</span>
                </div>
                <div className="flex items-center justify-between rounded-[1rem] border border-[var(--border)] bg-white/86 px-3 py-2 text-sm">
                  <span className="text-[var(--text-muted)]">Visible in slice</span>
                  <span className="font-semibold text-[var(--text)]">{filteredAndSorted.length}</span>
                </div>
                <div className="flex items-center justify-between rounded-[1rem] border border-[var(--border)] bg-white/86 px-3 py-2 text-sm">
                  <span className="text-[var(--text-muted)]">Need attention</span>
                  <span className="font-semibold text-[var(--text)]">{unhealthyCount}</span>
                </div>
              </div>
            </section>
          </aside>
        </section>
      )}

      {items.length > 0 && filteredAndSorted.length === 0 && (
        <div className="card animate-in py-12 text-center">
          <p className="text-[var(--muted)]">
            No assets match the current search and slice filters.
          </p>
          <button
            type="button"
            onClick={() => {
              setSearch('');
              setStatusQuick('all');
              setCriticalityQuick('all');
            }}
            className="mt-3 text-sm font-medium text-[var(--green)] hover:underline"
          >
            Clear filters
          </button>
        </div>
      )}
    </main>
  );
}
