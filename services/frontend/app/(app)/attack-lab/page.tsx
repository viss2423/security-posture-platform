'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  getAssets,
  getAttackLabRuns,
  getAttackLabTasks,
  runAttackLabTask,
  type AssetInventoryItem,
  type AttackLabRun,
  type AttackLabTask,
} from '@/lib/api';
import { friendlyApiMessage } from '@/lib/apiError';
import { ApiDownHint } from '@/components/EmptyState';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

const SCENARIO_META: Record<string, { label: string; icon: string; description: string }> = {
  port_scan: {
    label: 'Port Exposure Check',
    icon: '🔍',
    description: 'Scans open ports on your asset to verify your firewall rules are working.',
  },
  web_scan: {
    label: 'Web Security Scan',
    icon: '🌐',
    description: 'Tests web endpoints for common vulnerabilities like injection and misconfigurations.',
  },
  brute_force_sim: {
    label: 'Login Brute-force Drill',
    icon: '🔒',
    description: 'Simulates a credential-stuffing attack to confirm your lockout policies trigger correctly.',
  },
};

function scenarioLabel(taskType: string): string {
  return SCENARIO_META[taskType]?.label ?? taskType.replace(/_/g, ' ');
}

function runStatusColor(status: AttackLabRun['status']): string {
  switch (status) {
    case 'done': return 'var(--green)';
    case 'running': return 'var(--amber)';
    case 'failed': return 'var(--red)';
    default: return 'var(--text-subtle)';
  }
}

function runStatusLabel(status: AttackLabRun['status']): string {
  switch (status) {
    case 'done': return 'Detected';
    case 'running': return 'Running';
    case 'failed': return 'Failed';
    default: return 'Queued';
  }
}

export default function AttackLabPage() {
  const { isAdmin } = useAuth();
  const [tasks, setTasks] = useState<AttackLabTask[]>([]);
  const [runs, setRuns] = useState<AttackLabRun[]>([]);
  const [assets, setAssets] = useState<AssetInventoryItem[]>([]);
  const [selectedTask, setSelectedTask] = useState('port_scan');
  const [selectedAssetKey, setSelectedAssetKey] = useState('');
  const [launcherOpen, setLauncherOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [taskResult, runResult, assetResult] = await Promise.all([
      getAttackLabTasks(),
      getAttackLabRuns({ limit: 40 }),
      getAssets(),
    ]);
    setTasks(taskResult.items || []);
    setRuns(runResult.items || []);
    setAssets(assetResult || []);
    if (assetResult?.length && !selectedAssetKey) {
      setSelectedAssetKey(assetResult[0].asset_key);
    }
  }, [selectedAssetKey]);

  useEffect(() => {
    void load().catch((loadError) => {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load detection validation');
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submitRun = async () => {
    if (!isAdmin) return;
    const targetAsset = assets.find((a) => a.asset_key === selectedAssetKey);
    if (!selectedAssetKey || !targetAsset) {
      setError('Select an asset to test');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await runAttackLabTask({
        task_type: selectedTask,
        target: targetAsset.address ?? selectedAssetKey,
        asset_key: selectedAssetKey,
      });
      await load();
      setLauncherOpen(false);
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : 'Failed to start simulation');
    } finally {
      setBusy(false);
    }
  };

  const detected = runs.filter((r) => r.status === 'done').length;
  const total = runs.length;
  const detectionPct = total > 0 ? Math.round((detected / total) * 100) : null;

  const scorePctColor =
    detectionPct == null ? 'var(--text-subtle)'
    : detectionPct >= 80 ? 'var(--green)'
    : detectionPct >= 50 ? 'var(--amber)'
    : 'var(--red)';

  const availableTaskTypes = tasks.length > 0
    ? tasks.map((t) => t.task_type)
    : Object.keys(SCENARIO_META);

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <span className="live-pill">
              <span className={runs.some((r) => r.status === 'running') ? 'dot-warning' : 'dot-online'} />
              Detection Validation
            </span>

            <div className="mt-5 flex items-end gap-4">
              <span
                className="text-[5.5rem] font-black leading-none tabular-nums animate-count"
                style={{
                  color: scorePctColor,
                  textShadow: detectionPct != null ? `0 0 40px ${scorePctColor}55, 0 0 80px ${scorePctColor}22` : 'none',
                }}
              >
                {detectionPct != null ? `${detectionPct}%` : '--'}
              </span>
              <div className="mb-4 flex flex-col gap-1">
                <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--text-subtle)]">
                  Detection rate
                </span>
                <span className="text-sm text-[var(--text-muted)]">
                  {detected} of {total} simulations detected
                </span>
              </div>
            </div>

            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
              <div
                className="h-full rounded-full transition-all duration-1000"
                style={{
                  width: `${detectionPct ?? 0}%`,
                  background: scorePctColor,
                  boxShadow: `0 0 8px ${scorePctColor}66`,
                }}
              />
            </div>

            <h1 className="mt-5 text-xl font-bold text-[var(--text-strong)]">Detection Validation</h1>
            <p className="hero-copy">
              Run safe, controlled simulations against your real assets to verify your detections fire correctly — and prove your security controls are actually working.
            </p>

            <div className="mt-4 flex flex-wrap gap-2">
              {isAdmin && (
                <button
                  type="button"
                  onClick={() => setLauncherOpen((v) => !v)}
                  className="btn-primary text-sm"
                >
                  {launcherOpen ? 'Cancel' : 'Run a simulation'}
                </button>
              )}
              <Link href="/findings" className="btn-secondary text-sm">View findings</Link>
              <Link href="/jobs" className="btn-secondary text-sm">All jobs</Link>
            </div>
          </div>

          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Simulations run</p>
              <p className="hero-stat-value">{total}</p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">Total across all scenarios</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Detected</p>
              <p className="hero-stat-value" style={{ color: 'var(--green)' }}>{detected}</p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">Controls triggered correctly</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Currently running</p>
              <p className="hero-stat-value" style={{ color: runs.some((r) => r.status === 'running') ? 'var(--amber)' : 'var(--text-subtle)' }}>
                {runs.filter((r) => r.status === 'running').length}
              </p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">Active simulations</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Assets covered</p>
              <p className="hero-stat-value">{assets.length}</p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">In your inventory</p>
            </div>
          </div>
        </div>
      </section>

      {error && (
        <div className="alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {launcherOpen && isAdmin && (
        <section className="section-panel animate-in">
          <h2 className="section-title mb-1">Run a simulation</h2>
          <p className="mb-5 text-sm text-[var(--text-muted)]">
            Simulations run inside your monitored environment boundary only and generate real telemetry.
          </p>

          <div className="mb-5">
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--text-subtle)]">Choose scenario</p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {availableTaskTypes.map((taskType) => {
                const meta = SCENARIO_META[taskType] ?? { label: scenarioLabel(taskType), icon: '⚡', description: '' };
                const task = tasks.find((t) => t.task_type === taskType);
                return (
                  <button
                    key={taskType}
                    type="button"
                    onClick={() => setSelectedTask(taskType)}
                    className="rounded-xl border p-4 text-left transition"
                    style={{
                      borderColor: selectedTask === taskType ? 'var(--accent)' : 'var(--border)',
                      background: selectedTask === taskType ? 'var(--accent-dim)' : 'var(--surface)',
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-2xl">{meta.icon}</span>
                      <span className="font-semibold text-[var(--text)]">{meta.label}</span>
                    </div>
                    <p className="mt-2 text-xs text-[var(--text-muted)]">
                      {task?.description ?? meta.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="mb-5 max-w-md">
            <label className="block">
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--text-subtle)]">Target asset</p>
              {assets.length > 0 ? (
                <select
                  value={selectedAssetKey}
                  onChange={(e) => setSelectedAssetKey(e.target.value)}
                  className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-3 py-2 text-sm text-[var(--text)]"
                >
                  {assets.map((asset) => (
                    <option key={asset.asset_key} value={asset.asset_key}>
                      {asset.name || asset.asset_key} ({asset.type})
                    </option>
                  ))}
                </select>
              ) : (
                <p className="text-sm text-[var(--text-muted)]">
                  No assets in inventory.{' '}
                  <Link href="/assets" className="text-[var(--accent)] hover:underline">Add assets</Link> first.
                </p>
              )}
            </label>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => void submitRun()}
              disabled={busy || assets.length === 0}
              className="btn-primary"
            >
              {busy ? 'Starting...' : `Run ${SCENARIO_META[selectedTask]?.label ?? scenarioLabel(selectedTask)}`}
            </button>
            <p className="text-xs text-[var(--text-subtle)]">
              Safe simulation · stays within your monitored boundary
            </p>
          </div>
        </section>
      )}

      <section className="section-panel animate-in">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="section-title">Simulation results</h2>
            <p className="mt-1 text-sm text-[var(--text-muted)]">Each run generates real telemetry and alerts in your environment.</p>
          </div>
          <span className="text-xs text-[var(--text-subtle)]">{runs.length} total runs</span>
        </div>

        {runs.length === 0 ? (
          <div className="rounded-xl border border-dashed border-[var(--border)] px-6 py-12 text-center">
            <p className="text-2xl">🎯</p>
            <p className="mt-3 font-semibold text-[var(--text)]">No simulations run yet</p>
            <p className="mt-1 text-sm text-[var(--text-muted)]">
              Run your first simulation above to verify your detections are working.
            </p>
          </div>
        ) : (
          <ul className="space-y-3">
            {runs.map((run) => {
              const color = runStatusColor(run.status);
              const incidentId = run.output_json?.incident_id as number | undefined;
              return (
                <li
                  key={run.run_id}
                  className="rounded-xl border border-[var(--border)] p-4"
                  style={{ borderLeft: `3px solid ${color}` }}
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-[var(--text)]">{scenarioLabel(run.task_type)}</span>
                        <span
                          className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase"
                          style={{ color, background: `${color}18` }}
                        >
                          {run.status === 'running' && <span className="dot-warning" />}
                          {runStatusLabel(run.status)}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-[var(--text-subtle)]">
                        {run.target_asset_key ?? run.target ?? 'Unknown asset'}
                        {run.started_at ? ` · ${formatDateTime(run.started_at)}` : ''}
                        {run.requested_by ? ` · by ${run.requested_by}` : ''}
                      </p>
                      {run.status === 'failed' && run.error && (
                        <p className="mt-2 text-xs text-[var(--red)]">{run.error}</p>
                      )}
                    </div>
                    <div className="text-right">
                      {run.status === 'done' && incidentId ? (
                        <Link
                          href={`/incidents/${incidentId}`}
                          className="text-sm font-semibold text-[var(--green)] hover:underline"
                        >
                          Detected → Incident #{incidentId}
                        </Link>
                      ) : run.status === 'done' ? (
                        <span className="text-sm text-[var(--green)]">Detected</span>
                      ) : null}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="section-panel animate-in">
        <h2 className="section-title mb-4">Available scenarios</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {availableTaskTypes.map((taskType) => {
            const meta = SCENARIO_META[taskType] ?? { label: scenarioLabel(taskType), icon: '⚡', description: '' };
            const task = tasks.find((t) => t.task_type === taskType);
            return (
              <div key={taskType} className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xl">{meta.icon}</span>
                  <span className="font-semibold text-[var(--text)]">{meta.label}</span>
                </div>
                <p className="text-sm text-[var(--text-muted)]">{task?.description ?? meta.description}</p>
              </div>
            );
          })}
        </div>
      </section>
    </main>
  );
}
