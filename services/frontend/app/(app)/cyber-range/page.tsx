'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  getCyberRangeMissions,
  launchCyberRangeMission,
  type CyberRangeMission,
} from '@/lib/api';
import { friendlyApiMessage } from '@/lib/apiError';
import { ApiDownHint } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';
import { formatDateTime } from '@/lib/format';

export default function CyberRangePage() {
  const { isAdmin } = useAuth();
  const [missions, setMissions] = useState<CyberRangeMission[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busyMissionId, setBusyMissionId] = useState<string | null>(null);

  const load = useCallback(async () => {
    const payload = await getCyberRangeMissions();
    setMissions(payload.items || []);
  }, []);

  useEffect(() => {
    void load().catch((loadError) => {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load cyber-range');
    });
  }, [load]);

  const runMission = async (missionId: string) => {
    if (!isAdmin) return;
    setBusyMissionId(missionId);
    setError(null);
    try {
      await launchCyberRangeMission(missionId);
      await load();
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : 'Failed to launch mission');
    } finally {
      setBusyMissionId(null);
    }
  };

  return (
    <main className="page-shell">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="page-title">Cyber Range</h1>
          <p className="mt-2 max-w-3xl text-sm text-[var(--text-muted)]">
            Guided blue-team training missions built on top of Attack Lab telemetry, detections,
            incidents, and findings workflows.
          </p>
        </div>
        <div className="flex gap-2">
          <Link href="/attack-lab" className="btn-secondary text-sm">
            Open attack lab
          </Link>
          <Link href="/jobs" className="btn-secondary text-sm">
            Open jobs
          </Link>
        </div>
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="grid gap-4">
          {missions.length === 0 ? (
            <div className="section-panel animate-in">
              <h2 className="section-title">No missions yet</h2>
              <p className="text-sm text-[var(--muted)]">
                Cyber-range missions are not configured.
              </p>
            </div>
          ) : (
            missions.map((mission) => (
              <article key={mission.mission_id} className="section-panel animate-in">
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <h2 className="section-title">{mission.title}</h2>
                  <div className="flex gap-2">
                    <span className="stat-chip">{mission.difficulty}</span>
                    <span className="stat-chip">{mission.task_type}</span>
                  </div>
                </div>
                <p className="text-sm text-[var(--text-muted)]">{mission.description}</p>

                <div className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
                  <div className="rounded-xl border border-[var(--border)] p-3">
                    <p className="text-xs uppercase tracking-[0.16em] text-[var(--muted)]">Asset</p>
                    <p className="mt-1 font-mono text-[var(--text)]">{mission.asset_key}</p>
                    <p className="mt-1 text-[var(--muted)]">
                      {mission.asset_available
                        ? mission.asset?.name || 'Available'
                        : 'Not present in assets table'}
                    </p>
                  </div>
                  <div className="rounded-xl border border-[var(--border)] p-3">
                    <p className="text-xs uppercase tracking-[0.16em] text-[var(--muted)]">Target</p>
                    <p className="mt-1 font-mono text-[var(--text)]">{mission.target}</p>
                    <p className="mt-1 text-[var(--muted)]">{mission.focus}</p>
                  </div>
                </div>

                <div className="mt-4">
                  <p className="text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                    MITRE ATT&CK
                  </p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {(mission.mitre_techniques || []).map((technique) => (
                      <span key={technique} className="stat-chip">
                        {technique}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                  <p className="text-sm text-[var(--muted)]">
                    Latest job:{' '}
                    {mission.latest_job
                      ? `#${mission.latest_job.job_id} ${mission.latest_job.status}${
                          mission.latest_job.created_at
                            ? ` (${formatDateTime(mission.latest_job.created_at)})`
                            : ''
                        }`
                      : 'none'}
                  </p>
                  {isAdmin ? (
                    <button
                      type="button"
                      className="btn-primary"
                      disabled={busyMissionId === mission.mission_id}
                      onClick={() => void runMission(mission.mission_id)}
                    >
                      {busyMissionId === mission.mission_id ? 'Launching...' : 'Launch mission'}
                    </button>
                  ) : (
                    <span className="text-xs uppercase tracking-[0.14em] text-[var(--muted)]">
                      Admin only launch
                    </span>
                  )}
                </div>
              </article>
            ))
          )}
        </div>

        <aside className="section-panel animate-in h-fit">
          <h2 className="section-title">Training Workflow</h2>
          <ol className="mt-3 space-y-3 text-sm text-[var(--text-muted)]">
            <li>1. Launch a mission and wait for the attack-lab job to complete.</li>
            <li>2. Review generated telemetry and alerts for mission artifacts.</li>
            <li>3. Open the correlated incident and add analyst notes.</li>
            <li>4. Validate detections and promote or tune rules as needed.</li>
            <li>5. Track remediation in findings and close the incident.</li>
          </ol>
        </aside>
      </section>
    </main>
  );
}
