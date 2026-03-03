'use client';

import { useState } from 'react';
import {
  detectPostureAnomalies,
  listPostureAnomalies,
  type PostureAnomaly,
} from '@/lib/api';
import { formatDateTime } from '@/lib/format';

type LastDetection = {
  detected_at: string;
  detected: number;
  persisted: number;
} | null;

type OverviewAnomaliesPanelProps = {
  initialAnomalies: PostureAnomaly[];
  canMutate: boolean;
};

export default function OverviewAnomaliesPanel({
  initialAnomalies,
  canMutate,
}: OverviewAnomaliesPanelProps) {
  const [anomalies, setAnomalies] = useState(initialAnomalies);
  const [detecting, setDetecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastDetection, setLastDetection] = useState<LastDetection>(null);

  const handleDetectAnomalies = async () => {
    setDetecting(true);
    setError(null);
    try {
      const result = await detectPostureAnomalies(true);
      setLastDetection({
        detected_at: result.detected_at,
        detected: result.detected,
        persisted: result.persisted,
      });
      if ((result.items ?? []).length > 0) {
        setAnomalies(result.items.slice(0, 5));
      } else {
        const latest = await listPostureAnomalies(5);
        setAnomalies(latest.items ?? []);
      }
    } catch (detectionError) {
      setError(detectionError instanceof Error ? detectionError.message : 'Anomaly detection failed');
    } finally {
      setDetecting(false);
    }
  };

  return (
    <section className="mb-10">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="section-title">AI anomalies</h2>
        {canMutate && (
          <button
            type="button"
            onClick={handleDetectAnomalies}
            disabled={detecting}
            className="btn-secondary text-sm"
          >
            {detecting ? 'Detecting...' : 'Run detection'}
          </button>
        )}
      </div>
      {lastDetection && (
        <p className="mb-3 text-xs text-[var(--muted)]">
          Last run {formatDateTime(lastDetection.detected_at)}: detected {lastDetection.detected},
          persisted {lastDetection.persisted}.
        </p>
      )}
      {error && <p className="mb-3 text-sm text-[var(--red)]">{error}</p>}
      <div className="card">
        {anomalies.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No anomalies detected.</p>
        ) : (
          <ul className="space-y-2">
            {anomalies.map((anomaly, index) => (
              <li key={`${anomaly.metric}-${index}`} className="rounded border border-[var(--border)] p-3">
                <p className="text-sm">
                  <span className="font-semibold">{anomaly.metric}</span>
                  <span className="ml-2 capitalize text-[var(--muted)]">{anomaly.severity}</span>
                </p>
                <p className="mt-1 text-xs text-[var(--muted)]">
                  current {anomaly.current_value ?? '-'} vs baseline{' '}
                  {anomaly.baseline_mean != null ? Number(anomaly.baseline_mean).toFixed(2) : '-'}
                  {anomaly.z_score != null ? ` (z=${Number(anomaly.z_score).toFixed(2)})` : ''}
                </p>
                {anomaly.detected_at && (
                  <p className="mt-1 text-[11px] text-[var(--muted)]">
                    detected {formatDateTime(anomaly.detected_at)}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
