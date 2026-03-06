'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  createJob,
  getTelemetryEvents,
  getTelemetrySummary,
  type TelemetryEvent,
  type TelemetrySummary,
} from '@/lib/api';
import { formatDateTime } from '@/lib/format';
import { friendlyApiMessage } from '@/lib/apiError';
import { ApiDownHint } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';

export default function TelemetryPage() {
  const { canMutate } = useAuth();
  const [summary, setSummary] = useState<TelemetrySummary | null>(null);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [sourceFilter, setSourceFilter] = useState('');
  const [tiOnly, setTiOnly] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const [summaryResult, eventsResult] = await Promise.all([
        getTelemetrySummary(),
        getTelemetryEvents({
          source: sourceFilter || undefined,
          ti_match: tiOnly ? true : undefined,
          limit: 150,
        }),
      ]);
      setSummary(summaryResult);
      setEvents(eventsResult.items || []);
      setError(null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load telemetry');
    } finally {
      setRefreshing(false);
    }
  }, [sourceFilter, tiOnly]);

  useEffect(() => {
    void load();
  }, [load]);

  const triggerJob = async (jobType: 'telemetry_import' | 'network_anomaly_score') => {
    try {
      await createJob({
        job_type: jobType,
        job_params_json:
          jobType === 'telemetry_import'
            ? { source: 'suricata', file_path: '/workspace/lab-data/suricata/eve.json' }
            : { lookback_hours: 24, threshold: 2.5 },
      });
      await load();
    } catch (jobError) {
      setError(jobError instanceof Error ? jobError.message : 'Failed to enqueue telemetry job');
    }
  };

  return (
    <main className="page-shell">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="page-title">Telemetry</h1>
          <p className="mt-2 max-w-3xl text-sm text-[var(--text-muted)]">
            Unified event stream from Suricata, Zeek, auditd, and Cowrie with IOC enrichment and
            event-centric alerts.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void load()} className="btn-secondary text-sm">
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
          {canMutate && (
            <>
              <button
                type="button"
                onClick={() => void triggerJob('telemetry_import')}
                className="btn-secondary text-sm"
              >
                Import sample logs
              </button>
              <button
                type="button"
                onClick={() => void triggerJob('network_anomaly_score')}
                className="btn-secondary text-sm"
              >
                Run anomaly scoring
              </button>
            </>
          )}
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

      {summary && (
        <section className="mb-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <div className="metric-card animate-in">
            <div className="text-4xl font-bold text-[var(--text)]">{summary.totals.events}</div>
            <div className="mt-2 text-sm font-medium text-[var(--muted)]">Events</div>
          </div>
          <div className="metric-card red animate-in">
            <div className="text-4xl font-bold text-[var(--red)]">{summary.totals.ti_matches}</div>
            <div className="mt-2 text-sm font-medium text-[var(--muted)]">IOC matches</div>
          </div>
          <div className="metric-card animate-in">
            <div className="text-4xl font-bold text-[var(--amber)]">{summary.totals.assets}</div>
            <div className="mt-2 text-sm font-medium text-[var(--muted)]">Assets observed</div>
          </div>
          <div className="metric-card animate-in">
            <div className="text-4xl font-bold text-[var(--text)]">{summary.totals.sources}</div>
            <div className="mt-2 text-sm font-medium text-[var(--muted)]">Sources</div>
          </div>
        </section>
      )}

      <section className="mb-8 grid gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)]">
        <div className="section-panel animate-in">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <h2 className="section-title">Source health</h2>
            <Link href="/alerts" className="btn-secondary text-sm">
              Open alerts
            </Link>
          </div>
          {!summary || summary.sources.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">
              No telemetry source data yet. Import logs from Jobs or run source collectors.
            </p>
          ) : (
            <ul className="space-y-3">
              {summary.sources.map((item) => (
                <li
                  key={item.source}
                  className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <span className="font-medium text-[var(--text)]">{item.source}</span>
                    <span className="stat-chip-strong">{item.event_count} events</span>
                  </div>
                  <p className="mt-2 text-xs text-[var(--muted)]">
                    IOC matches {item.ti_matches} | assets {item.asset_count}
                  </p>
                  <p className="mt-1 text-xs text-[var(--muted)]">
                    Alerts: firing {item.alerts.firing || 0}, acked {item.alerts.acked || 0},
                    suppressed {item.alerts.suppressed || 0}, resolved {item.alerts.resolved || 0}
                  </p>
                  <p className="mt-1 text-xs text-[var(--muted)]">
                    Last event {item.last_event_at ? formatDateTime(item.last_event_at) : '-'}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="section-panel animate-in">
          <h2 className="section-title">Latest anomaly scores</h2>
          {!summary || summary.latest_anomaly_scores.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">
              No anomaly scores recorded yet. Run `network_anomaly_score` from Jobs.
            </p>
          ) : (
            <ul className="space-y-3">
              {summary.latest_anomaly_scores.map((item) => (
                <li key={`${item.asset_key}-${item.computed_at}`} className="rounded-xl border border-[var(--border)] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <Link
                      href={`/assets/${encodeURIComponent(item.asset_key)}`}
                      className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                    >
                      {item.asset_key}
                    </Link>
                    <span className="stat-chip">{item.anomaly_score.toFixed(2)}</span>
                  </div>
                  <p className="mt-1 text-xs text-[var(--muted)]">
                    Current {item.current_value ?? '-'} | baseline {item.baseline_mean ?? '-'}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="section-panel animate-in">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h2 className="section-title">Recent events</h2>
          <div className="flex flex-wrap gap-2">
            <select
              value={sourceFilter}
              onChange={(event) => setSourceFilter(event.target.value)}
              className="input text-sm"
            >
              <option value="">All sources</option>
              <option value="suricata">suricata</option>
              <option value="zeek">zeek</option>
              <option value="auditd">auditd</option>
              <option value="cowrie">cowrie</option>
              <option value="custom">custom</option>
            </select>
            <label className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] px-3 text-xs text-[var(--text)]">
              <input
                type="checkbox"
                checked={tiOnly}
                onChange={(event) => setTiOnly(event.target.checked)}
              />
              IOC matches only
            </label>
          </div>
        </div>
        {events.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No events found for the current filter.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Asset</th>
                  <th className="px-4 py-3">Flow</th>
                  <th className="px-4 py-3">Domain / URL</th>
                  <th className="px-4 py-3">TI</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.event_id} className="border-b border-[var(--border)]/40">
                    <td className="px-4 py-3">
                      {event.event_time ? formatDateTime(event.event_time) : '-'}
                    </td>
                    <td className="px-4 py-3 uppercase">{event.source}</td>
                    <td className="px-4 py-3">{event.event_type}</td>
                    <td className="px-4 py-3">
                      {event.asset_key ? (
                        <Link
                          href={`/assets/${encodeURIComponent(event.asset_key)}`}
                          className="hover:text-[var(--green)] hover:underline"
                        >
                          {event.asset_key}
                        </Link>
                      ) : (
                        <span className="text-[var(--muted)]">unassigned</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {(event.src_ip || '-') + ':' + (event.src_port ?? '-')}
                      {' → '}
                      {(event.dst_ip || '-') + ':' + (event.dst_port ?? '-')}
                    </td>
                    <td className="px-4 py-3">{event.domain || event.url || '-'}</td>
                    <td className="px-4 py-3">
                      {event.ti_match ? (
                        <span className="rounded bg-[var(--red)]/20 px-2 py-0.5 text-xs text-[var(--red)]">
                          {event.ti_source || 'match'}
                        </span>
                      ) : (
                        <span className="text-xs text-[var(--muted)]">none</span>
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
