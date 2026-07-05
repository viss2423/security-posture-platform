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

const DIFFICULTY_COLOR: Record<string, string> = {
  beginner: 'var(--green)',
  intermediate: 'var(--amber)',
  advanced: 'var(--red)',
};

const STEP_ICONS = ['🚀', '🔍', '📋', '✅', '🏁'];

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
      setError(loadError instanceof Error ? loadError.message : 'Failed to load security drills');
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
      setError(runError instanceof Error ? runError.message : 'Failed to launch drill');
    } finally {
      setBusyMissionId(null);
    }
  };

  const availableMissions = missions.filter((m) => m.asset_available);
  const totalMissions = missions.length;

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <span className="live-pill">
              <span className={busyMissionId ? 'dot-warning' : 'dot-online'} />
              Security Drills
            </span>

            <div className="mt-5 flex items-end gap-4">
              <span
                className="text-[5.5rem] font-black leading-none tabular-nums animate-count"
                style={{
                  color: availableMissions.length > 0 ? 'var(--green)' : 'var(--text-subtle)',
                  textShadow: availableMissions.length > 0
                    ? '0 0 40px var(--green)55, 0 0 80px var(--green)22'
                    : 'none',
                }}
              >
                {availableMissions.length}
              </span>
              <div className="mb-4 flex flex-col gap-1">
                <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--text-subtle)]">
                  Drills ready
                </span>
                <span className="text-sm text-[var(--text-muted)]">
                  {availableMissions.length} of {totalMissions} available now
                </span>
              </div>
            </div>

            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
              <div
                className="h-full rounded-full transition-all duration-1000"
                style={{
                  width: totalMissions > 0 ? `${Math.round((availableMissions.length / totalMissions) * 100)}%` : '0%',
                  background: 'var(--green)',
                  boxShadow: '0 0 8px var(--green)66',
                }}
              />
            </div>

            <h1 className="mt-5 text-xl font-bold text-[var(--text-strong)]">Security Drills</h1>
            <p className="hero-copy">
              Guided training exercises that simulate real attacks against your environment. Each drill produces live detections, alerts, and incidents — giving your team hands-on experience with real workflows.
            </p>

            <div className="mt-4 flex flex-wrap gap-2">
              <Link href="/attack-lab" className="btn-secondary text-sm">Detection Validation</Link>
              <Link href="/findings" className="btn-secondary text-sm">View findings</Link>
            </div>
          </div>

          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Total drills</p>
              <p className="hero-stat-value">{totalMissions}</p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">In your library</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Ready now</p>
              <p className="hero-stat-value" style={{ color: 'var(--green)' }}>{availableMissions.length}</p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">Assets online</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Difficulties</p>
              <p className="hero-stat-value">{[...new Set(missions.map((m) => m.difficulty))].length}</p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">Skill levels covered</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Active now</p>
              <p className="hero-stat-value" style={{ color: busyMissionId ? 'var(--amber)' : 'var(--text-subtle)' }}>
                {busyMissionId ? '1' : '0'}
              </p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">Drill in progress</p>
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

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
        <div className="space-y-4">
          {missions.length === 0 ? (
            <div className="section-panel animate-in">
              <div className="py-8 text-center">
                <p className="text-4xl">🎯</p>
                <h2 className="mt-4 text-lg font-bold text-[var(--text-strong)]">No drills configured yet</h2>
                <p className="mt-2 text-sm text-[var(--text-muted)]">
                  Security drills are set up by your administrator. Once configured, they appear here ready to launch.
                </p>
                <div className="mt-6 flex justify-center gap-3">
                  <Link href="/attack-lab" className="btn-secondary text-sm">
                    Try Detection Validation
                  </Link>
                  <Link href="/jobs" className="btn-secondary text-sm">
                    Run a scan
                  </Link>
                </div>
              </div>
            </div>
          ) : (
            missions.map((mission) => {
              const diffColor = DIFFICULTY_COLOR[mission.difficulty?.toLowerCase() ?? ''] ?? 'var(--text-subtle)';
              const isAvailable = mission.asset_available;
              return (
                <article
                  key={mission.mission_id}
                  className="section-panel animate-in"
                  style={{ borderLeft: `3px solid ${isAvailable ? diffColor : 'var(--border)'}` }}
                >
                  <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="section-title mb-0">{mission.title}</h2>
                      <span
                        className="inline-block rounded-full px-2 py-0.5 text-[10px] font-bold uppercase"
                        style={{ color: diffColor, background: `${diffColor}18` }}
                      >
                        {mission.difficulty}
                      </span>
                      {!isAvailable && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-[var(--surface-elevated)] px-2 py-0.5 text-[10px] font-semibold uppercase text-[var(--text-subtle)]">
                          <span className="dot-warning" style={{ '--ping-color': 'var(--amber)' } as React.CSSProperties} />
                          Asset offline
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-sm text-[var(--text-muted)]">{mission.description}</p>

                  <div className="mt-4 grid gap-3 sm:grid-cols-2">
                    <div className="rounded-xl border border-[var(--border)] p-3">
                      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--text-subtle)]">Asset</p>
                      <p className="mt-1 font-medium text-[var(--text)]">
                        {mission.asset?.name || mission.asset_key}
                      </p>
                      <p className="mt-0.5 text-xs" style={{ color: isAvailable ? 'var(--green)' : 'var(--amber)' }}>
                        {isAvailable ? 'Online — ready to drill' : 'Not found in inventory'}
                      </p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] p-3">
                      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-[var(--text-subtle)]">Focus area</p>
                      <p className="mt-1 font-medium text-[var(--text)]">{mission.focus}</p>
                      {mission.mitre_techniques?.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {mission.mitre_techniques.slice(0, 4).map((t) => (
                            <span key={t} className="rounded bg-[var(--surface-elevated)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--text-subtle)]">
                              {t}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                    <p className="text-xs text-[var(--text-subtle)]">
                      {mission.latest_job
                        ? `Last run: ${mission.latest_job.status}${mission.latest_job.created_at ? ` · ${formatDateTime(mission.latest_job.created_at)}` : ''}`
                        : 'Never run'}
                    </p>
                    {isAdmin ? (
                      <button
                        type="button"
                        className={isAvailable ? 'btn-primary' : 'btn-secondary'}
                        disabled={busyMissionId === mission.mission_id || !isAvailable}
                        onClick={() => void runMission(mission.mission_id)}
                        title={!isAvailable ? 'Asset not available in inventory' : undefined}
                      >
                        {busyMissionId === mission.mission_id ? 'Launching...' : isAvailable ? 'Launch drill' : 'Unavailable'}
                      </button>
                    ) : (
                      <span className="text-xs text-[var(--text-subtle)]">Admin required to launch</span>
                    )}
                  </div>
                </article>
              );
            })
          )}
        </div>

        <aside className="space-y-4">
          <div className="section-panel animate-in">
            <h2 className="section-title mb-4">How drills work</h2>
            <ol className="space-y-4">
              {[
                'Launch a drill — a safe simulation runs against your asset.',
                'Watch telemetry appear in real-time as the scenario unfolds.',
                'Review the alert that fires and correlate it to the incident.',
                'Add analyst notes and validate your detection rules.',
                'Mark the finding resolved and close the incident.',
              ].map((step, i) => (
                <li key={i} className="flex gap-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-[var(--border)] bg-[var(--surface-elevated)] text-sm">
                    {STEP_ICONS[i]}
                  </span>
                  <p className="pt-0.5 text-sm text-[var(--text-muted)]">{step}</p>
                </li>
              ))}
            </ol>
          </div>

          <div className="section-panel animate-in">
            <h2 className="section-title mb-3">Quick links</h2>
            <div className="space-y-2">
              <Link href="/attack-lab" className="flex items-center gap-2 rounded-lg border border-[var(--border)] px-3 py-2 text-sm text-[var(--text)] transition hover:border-[var(--accent)]/40 hover:bg-[var(--accent-dim)]">
                <span>🔍</span> Detection Validation
              </Link>
              <Link href="/findings" className="flex items-center gap-2 rounded-lg border border-[var(--border)] px-3 py-2 text-sm text-[var(--text)] transition hover:border-[var(--accent)]/40 hover:bg-[var(--accent-dim)]">
                <span>📋</span> View findings
              </Link>
              <Link href="/alerts" className="flex items-center gap-2 rounded-lg border border-[var(--border)] px-3 py-2 text-sm text-[var(--text)] transition hover:border-[var(--accent)]/40 hover:bg-[var(--accent-dim)]">
                <span>🔔</span> Active alerts
              </Link>
              <Link href="/incidents" className="flex items-center gap-2 rounded-lg border border-[var(--border)] px-3 py-2 text-sm text-[var(--text)] transition hover:border-[var(--accent)]/40 hover:bg-[var(--accent-dim)]">
                <span>🚨</span> Incidents
              </Link>
            </div>
          </div>
        </aside>
      </div>
    </main>
  );
}
