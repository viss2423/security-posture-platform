'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  getAttackLabRuns,
  getAttackLabTasks,
  runAttackLabTask,
  type AttackLabRun,
  type AttackLabTask,
} from '@/lib/api';
import { friendlyApiMessage } from '@/lib/apiError';
import { ApiDownHint } from '@/components/EmptyState';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

export default function AttackLabPage() {
  const { isAdmin } = useAuth();
  const [tasks, setTasks] = useState<AttackLabTask[]>([]);
  const [runs, setRuns] = useState<AttackLabRun[]>([]);
  const [taskType, setTaskType] = useState('port_scan');
  const [target, setTarget] = useState('verify-web');
  const [assetKey, setAssetKey] = useState('verify-web');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [taskResult, runResult] = await Promise.all([
      getAttackLabTasks(),
      getAttackLabRuns({ limit: 40 }),
    ]);
    setTasks(taskResult.items || []);
    setRuns(runResult.items || []);
  }, []);

  useEffect(() => {
    void load().catch((loadError) => {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load attack-lab');
    });
  }, [load]);

  const submitRun = async () => {
    if (!isAdmin) return;
    if (!target.trim()) {
      setError('Target is required');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await runAttackLabTask({
        task_type: taskType,
        target: target.trim(),
        asset_key: assetKey.trim() || undefined,
      });
      await load();
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : 'Failed to start attack-lab run');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="page-shell">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="page-title">Attack Lab</h1>
          <p className="mt-2 max-w-3xl text-sm text-[var(--text-muted)]">
            Controlled purple-team simulations that generate telemetry, alerts, and incident
            workflow data inside the lab boundary.
          </p>
        </div>
        <Link href="/jobs" className="btn-secondary text-sm">
          Open jobs
        </Link>
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      <section className="mb-8 grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.9fr)]">
        <div className="section-panel animate-in">
          <h2 className="section-title">Scenarios</h2>
          {tasks.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No attack-lab tasks are available.</p>
          ) : (
            <ul className="space-y-3">
              {tasks.map((task) => (
                <li key={task.task_type} className="rounded-2xl border border-[var(--border)] p-4">
                  <div className="flex items-center justify-between gap-3">
                    <p className="font-medium text-[var(--text)]">{task.label}</p>
                    <span className="stat-chip font-mono">{task.task_type}</span>
                  </div>
                  <p className="mt-2 text-sm text-[var(--text-muted)]">{task.description}</p>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="section-panel animate-in">
          <h2 className="section-title">Run simulation</h2>
          {!isAdmin ? (
            <p className="text-sm text-[var(--muted)]">
              Admin role is required to execute attack-lab tasks.
            </p>
          ) : (
            <div className="grid gap-4">
              <label className="text-sm text-[var(--muted)]">
                Task
                <select
                  value={taskType}
                  onChange={(event) => setTaskType(event.target.value)}
                  className="input mt-1"
                >
                  <option value="port_scan">port_scan</option>
                  <option value="web_scan">web_scan</option>
                  <option value="brute_force_sim">brute_force_sim</option>
                </select>
              </label>
              <label className="text-sm text-[var(--muted)]">
                Target
                <input
                  type="text"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  className="input mt-1"
                  placeholder="verify-web or http://verify-web"
                />
              </label>
              <label className="text-sm text-[var(--muted)]">
                Asset key (optional)
                <input
                  type="text"
                  value={assetKey}
                  onChange={(event) => setAssetKey(event.target.value)}
                  className="input mt-1"
                />
              </label>
              <button
                type="button"
                onClick={() => void submitRun()}
                disabled={busy}
                className="btn-primary"
              >
                {busy ? 'Starting...' : 'Start attack-lab run'}
              </button>
              <p className="text-xs text-[var(--muted)]">
                Targets are restricted to internal lab networks configured in API settings.
              </p>
            </div>
          )}
        </div>
      </section>

      <section className="section-panel animate-in">
        <h2 className="section-title">Recent runs</h2>
        {runs.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No attack-lab runs recorded yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  <th className="px-4 py-3">Run</th>
                  <th className="px-4 py-3">Task</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Requested by</th>
                  <th className="px-4 py-3">Started</th>
                  <th className="px-4 py-3">Result</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.run_id} className="border-b border-[var(--border)]/40">
                    <td className="px-4 py-3">{run.run_id}</td>
                    <td className="px-4 py-3">{run.task_type}</td>
                    <td className="px-4 py-3">{run.target || '-'}</td>
                    <td className="px-4 py-3 uppercase">{run.status}</td>
                    <td className="px-4 py-3">{run.requested_by || '-'}</td>
                    <td className="px-4 py-3">
                      {run.started_at ? formatDateTime(run.started_at) : '-'}
                    </td>
                    <td className="px-4 py-3">
                      {run.status === 'done' ? (
                        <span className="text-[var(--green)]">
                          incident {String(run.output_json?.incident_id || '-')}
                        </span>
                      ) : run.error ? (
                        <span className="text-[var(--red)]">{run.error}</span>
                      ) : (
                        <span className="text-[var(--muted)]">-</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
