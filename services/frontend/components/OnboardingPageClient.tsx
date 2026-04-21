'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiDownHint } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';
import { friendlyApiMessage } from '@/lib/apiError';
import {
  createAsset,
  createDetectionRule,
  createIncident,
  getAlerts,
  getAssets,
  getDetectionRules,
  getIncidents,
  getPlatformDemoStatus,
  getTelemetrySummary,
  ingestTelemetry,
  resetDemoEnvironment,
  seedDemoEnvironment,
  testDetectionRule,
  type AlertsResponse,
  type AssetInventoryItem,
  type DetectionRule,
  type IncidentsListResponse,
  type PlatformDemoStatus,
  type TelemetrySummary,
} from '@/lib/api';
import {
  countCompletedOnboardingSteps,
  deriveOnboardingSteps,
  type OnboardingStep,
} from '@/lib/onboarding';

const DEFAULT_ASSET_KEY = 'onboarding-edge-gateway';
const BASELINE_RULE_NAME = 'SecPlat onboarding cowrie failed login';
const BASELINE_RULE_KEY = 'secplat-onboarding-cowrie-login';

function stepCardClass(step: OnboardingStep): string {
  return step.complete ? 'step-card complete' : 'step-card';
}

function countAlerts(alerts: AlertsResponse | null): number {
  if (!alerts) return 0;
  return alerts.firing.length + alerts.acked.length + alerts.suppressed.length + alerts.resolved.length;
}

export default function OnboardingPageClient() {
  const { canMutate, isAdmin, user } = useAuth();
  const [authConfigLoaded, setAuthConfigLoaded] = useState(false);
  const [oidcEnabled, setOidcEnabled] = useState(false);
  const [assets, setAssets] = useState<AssetInventoryItem[]>([]);
  const [telemetrySummary, setTelemetrySummary] = useState<TelemetrySummary | null>(null);
  const [detectionRules, setDetectionRules] = useState<DetectionRule[]>([]);
  const [alerts, setAlerts] = useState<AlertsResponse | null>(null);
  const [incidents, setIncidents] = useState<IncidentsListResponse | null>(null);
  const [demoStatus, setDemoStatus] = useState<PlatformDemoStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [assetKey, setAssetKey] = useState(DEFAULT_ASSET_KEY);
  const [assetName, setAssetName] = useState('Edge gateway');
  const [assetAddress, setAssetAddress] = useState('https://gateway.example.test');
  const [assetOwner, setAssetOwner] = useState('platform-security');
  const [selectedAssetKey, setSelectedAssetKey] = useState(DEFAULT_ASSET_KEY);

  const load = useCallback(async () => {
    setLoading(true);
    const [
      authConfigResult,
      assetsResult,
      telemetryResult,
      detectionsResult,
      alertsResult,
      incidentsResult,
      demoStatusResult,
    ] = await Promise.allSettled([
      fetch('/api/auth/config', { cache: 'no-store' }).then(async (response) => {
        if (!response.ok) {
          return { oidc_enabled: false };
        }
        return response.json() as Promise<{ oidc_enabled: boolean }>;
      }),
      getAssets(),
      getTelemetrySummary(),
      getDetectionRules(true),
      getAlerts(),
      getIncidents({ limit: 25 }),
      getPlatformDemoStatus(),
    ]);

    if (authConfigResult.status === 'fulfilled') {
      setOidcEnabled(Boolean(authConfigResult.value.oidc_enabled));
      setAuthConfigLoaded(true);
    } else {
      setOidcEnabled(false);
      setAuthConfigLoaded(false);
    }

    if (assetsResult.status === 'fulfilled') {
      setAssets(assetsResult.value);
      if (assetsResult.value.length > 0) {
        const preferredKey =
          assetsResult.value.find((item) => item.asset_key === selectedAssetKey)?.asset_key ||
          assetsResult.value[0].asset_key;
        setSelectedAssetKey(preferredKey);
      }
    } else {
      setAssets([]);
    }

    setTelemetrySummary(telemetryResult.status === 'fulfilled' ? telemetryResult.value : null);
    setDetectionRules(
      detectionsResult.status === 'fulfilled' ? detectionsResult.value.items || [] : []
    );
    setAlerts(alertsResult.status === 'fulfilled' ? alertsResult.value : null);
    setIncidents(incidentsResult.status === 'fulfilled' ? incidentsResult.value : null);
    setDemoStatus(demoStatusResult.status === 'fulfilled' ? demoStatusResult.value : null);

    const failures = [
      assetsResult,
      telemetryResult,
      detectionsResult,
      alertsResult,
      incidentsResult,
    ].filter((result) => result.status === 'rejected');
    setError(
      failures.length > 0
        ? failures
            .map((result) =>
              result.status === 'rejected' && result.reason instanceof Error
                ? result.reason.message
                : 'Request failed'
            )
            .join(' | ')
        : null
    );
    setLoading(false);
  }, [selectedAssetKey]);

  useEffect(() => {
    void load();
  }, [load]);

  const alertCount = useMemo(() => countAlerts(alerts), [alerts]);

  const steps = useMemo(
    () =>
      deriveOnboardingSteps({
        authenticated: Boolean(user),
        authConfigLoaded,
        oidcEnabled,
        assetCount: assets.length,
        telemetryEventCount: telemetrySummary?.totals.events ?? 0,
        detectionRuleCount: detectionRules.length,
        alertCount,
        incidentCount: incidents?.total ?? 0,
      }),
    [
      alertCount,
      assets.length,
      authConfigLoaded,
      detectionRules.length,
      incidents?.total,
      oidcEnabled,
      telemetrySummary?.totals.events,
      user,
    ]
  );

  const completedSteps = countCompletedOnboardingSteps(steps);
  const progressPct = Math.round((completedSteps / Math.max(steps.length, 1)) * 100);

  const executeAction = async (action: string, run: () => Promise<void>) => {
    setBusyAction(action);
    setMessage(null);
    setError(null);
    try {
      await run();
      await load();
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : 'Action failed');
    } finally {
      setBusyAction(null);
    }
  };

  const handleCreateAsset = async () => {
    const normalizedKey = assetKey.trim();
    if (!normalizedKey) {
      setError('Asset key is required');
      return;
    }
    await executeAction('asset', async () => {
      const existing = assets.find(
        (item) => item.asset_key.toLowerCase() === normalizedKey.toLowerCase()
      );
      if (existing) {
        setSelectedAssetKey(existing.asset_key);
        setMessage(`Asset ${existing.asset_key} is already registered.`);
        return;
      }
      const created = await createAsset({
        asset_key: normalizedKey,
        type: 'external_web',
        name: assetName.trim() || normalizedKey,
        owner: assetOwner.trim() || undefined,
        address: assetAddress.trim() || undefined,
        environment: 'prod',
        criticality: 'high',
        asset_type: 'external_web',
        metadata: { onboarding: true },
      });
      setSelectedAssetKey(created.asset_key);
      setMessage(`Asset ${created.asset_key} created.`);
    });
  };

  const handleSampleTelemetry = async () => {
    const targetAssetKey = selectedAssetKey || assets[0]?.asset_key || assetKey.trim();
    if (!targetAssetKey) {
      setError('Create or select an asset before ingesting telemetry.');
      return;
    }
    await executeAction('telemetry', async () => {
      const response = await ingestTelemetry({
        source: 'cowrie',
        asset_key: targetAssetKey,
        create_alerts: true,
        events: [
          {
            eventid: 'cowrie.login.failed',
            session: `onboarding-${targetAssetKey}`,
            src_ip: '203.0.113.88',
            username: 'root',
            message: 'Failed login attempt from onboarding flow',
            timestamp: new Date().toISOString(),
          },
        ],
      });
      setMessage(
        `Telemetry ingested for ${targetAssetKey}. Processed ${response.processed_events} event(s).`
      );
    });
  };

  const handleBaselineDetection = async () => {
    await executeAction('detections', async () => {
      let rule = detectionRules.find(
        (item) => item.rule_key === BASELINE_RULE_KEY || item.name === BASELINE_RULE_NAME
      );
      if (!rule) {
        rule = await createDetectionRule({
          name: BASELINE_RULE_NAME,
          rule_key: BASELINE_RULE_KEY,
          description: 'Baseline onboarding detector for Cowrie failed login activity.',
          source: 'cowrie',
          stage: 'active',
          severity: 'high',
          enabled: true,
          definition_json: {
            condition_mode: 'all',
            conditions: [{ field: 'event_type', op: 'eq', value: 'cowrie.login.failed' }],
          },
        });
      }
      const result = await testDetectionRule(rule.rule_id, {
        lookback_hours: 168,
        create_alerts: true,
      });
      setMessage(
        `Detection rule ${rule.name} matched ${result.matches} event(s) over ${result.lookback_hours}h.`
      );
    });
  };

  const handleCreateIncident = async () => {
    const targetAssetKey = selectedAssetKey || assets[0]?.asset_key;
    if (!targetAssetKey) {
      setError('No asset available for incident creation.');
      return;
    }
    await executeAction('incident', async () => {
      const currentAlerts = await getAlerts();
      const availableAlerts = [
        ...currentAlerts.firing,
        ...currentAlerts.acked,
        ...currentAlerts.suppressed,
        ...currentAlerts.resolved,
      ];
      const matchedAlert = availableAlerts.find((item) => item.asset_key === targetAssetKey);
      if (!matchedAlert) {
        throw new Error('Create telemetry and run detections before creating the first incident.');
      }
      const incident = await createIncident({
        incident_key: `onboarding:${targetAssetKey}`,
        title: `Onboarding incident for ${targetAssetKey}`,
        severity: 'high',
        asset_keys: [targetAssetKey],
        alert_ids: matchedAlert.alert_id ? [matchedAlert.alert_id] : undefined,
      });
      setMessage(`Incident ${incident.id} is ready for triage.`);
    });
  };

  const handleSeedDemo = async () => {
    await executeAction('demo-seed', async () => {
      const result = await seedDemoEnvironment(true);
      setMessage(`Demo baseline refreshed by ${result.requested_by}.`);
    });
  };

  const handleResetDemo = async () => {
    await executeAction('demo-reset', async () => {
      const result = await resetDemoEnvironment();
      setMessage(`Demo reset completed by ${result.requested_by}.`);
    });
  };

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <span className="stat-chip-strong">Guided launch</span>
            <h1 className="hero-title mt-3">Launch your account in one guided flow</h1>
            <p className="hero-copy">
              Take a new customer account from sign-in to the first monitored asset, first
              signal, and first incident with a clear guided launch sequence.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <button type="button" onClick={() => void load()} className="btn-secondary text-sm">
                {loading ? 'Refreshing...' : 'Refresh status'}
              </button>
              <Link href="/overview" className="btn-secondary text-sm">
                Open overview
              </Link>
              <Link href="/jobs" className="btn-secondary text-sm">
                Open jobs
              </Link>
            </div>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Launch progress</p>
              <p className="hero-stat-value">
                {completedSteps}/{steps.length}
              </p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Completion</p>
              <p className="hero-stat-value">{progressPct}%</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Assets monitored</p>
              <p className="hero-stat-value">{assets.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Alerts / incidents</p>
              <p className="hero-stat-value">
                {alertCount}/{incidents?.total ?? 0}
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="command-lane animate-in">
        <div className="command-lane-grid">
          <span className="command-pill-strong">
            Telemetry events {telemetrySummary?.totals.events ?? 0}
          </span>
          <span className="command-pill">Detection rules {detectionRules.length}</span>
          <span className="command-pill">Firing alerts {alerts?.firing.length ?? 0}</span>
          <span className="command-pill">Incident queue {incidents?.total ?? 0}</span>
          <span className="command-pill">
            {oidcEnabled ? 'OIDC configured' : 'Local auth active'}
          </span>
        </div>
        <div className="step-progress-bar">
          <span style={{ width: `${progressPct}%` }} />
        </div>
      </section>

      {error && (
        <div className="alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}
      {message && (
        <div className="rounded-xl border border-cyan-300/18 bg-cyan-300/08 px-4 py-3 text-sm text-[var(--text)]">
          {message}
        </div>
      )}

      <section className="grid gap-4 xl:grid-cols-2">
        {steps.map((step) => (
          <article key={step.id} className={stepCardClass(step)}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  {step.id}
                </p>
                <h2 className="mt-1 text-xl font-semibold text-[var(--text)]">{step.title}</h2>
              </div>
              <span className={step.complete ? 'stat-chip-strong' : 'stat-chip'}>
                {step.complete ? 'Complete' : 'Pending'}
              </span>
            </div>
            <p className="mt-3 text-sm leading-7 text-[var(--text-muted)]">
              {step.description}
            </p>
            <p className="mt-3 text-sm leading-7 text-[var(--text)]">{step.detail}</p>
            <div className="step-progress-bar">
              <span style={{ width: step.complete ? '100%' : '34%' }} />
            </div>
          </article>
        ))}
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">1. Register the first asset</h2>
              <p className="section-head-copy">
                Start with the first customer-facing service you want SecPlat to monitor and
                explain.
              </p>
            </div>
            <span className="stat-chip">{assets.length} assets</span>
          </div>
          <div className="grid gap-4">
            <label className="text-sm text-[var(--muted)]">
              Asset key
              <input
                value={assetKey}
                onChange={(event) => {
                  setAssetKey(event.target.value);
                  setSelectedAssetKey(event.target.value);
                }}
                className="input mt-1"
                placeholder="edge-gateway"
              />
            </label>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="text-sm text-[var(--muted)]">
                Display name
                <input
                  value={assetName}
                  onChange={(event) => setAssetName(event.target.value)}
                  className="input mt-1"
                />
              </label>
              <label className="text-sm text-[var(--muted)]">
                Owner
                <input
                  value={assetOwner}
                  onChange={(event) => setAssetOwner(event.target.value)}
                  className="input mt-1"
                />
              </label>
            </div>
            <label className="text-sm text-[var(--muted)]">
              Address
              <input
                value={assetAddress}
                onChange={(event) => setAssetAddress(event.target.value)}
                className="input mt-1"
                placeholder="https://service.example.test"
              />
            </label>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => void handleCreateAsset()}
                disabled={!canMutate || busyAction === 'asset'}
                className="btn-primary text-sm"
              >
                {busyAction === 'asset' ? 'Saving...' : 'Create asset'}
              </button>
              <select
                value={selectedAssetKey}
                onChange={(event) => setSelectedAssetKey(event.target.value)}
                className="input max-w-xs text-sm"
              >
                <option value={assetKey || DEFAULT_ASSET_KEY}>Current draft asset</option>
                {assets.map((item) => (
                  <option key={item.asset_key} value={item.asset_key}>
                    {item.asset_key}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">2. Generate the first signal</h2>
              <p className="section-head-copy">
                Drive telemetry into the platform, turn on the starter detection, and create the
                first incident customers can investigate.
              </p>
            </div>
            <span className="stat-chip">{selectedAssetKey || 'No asset selected'}</span>
          </div>
          <div className="grid gap-3">
            <button
              type="button"
              onClick={() => void handleSampleTelemetry()}
              disabled={!canMutate || busyAction === 'telemetry'}
              className="btn-secondary text-sm"
            >
              {busyAction === 'telemetry' ? 'Ingesting...' : 'Ingest sample telemetry'}
            </button>
            <button
              type="button"
              onClick={() => void handleBaselineDetection()}
              disabled={!canMutate || busyAction === 'detections'}
              className="btn-secondary text-sm"
            >
              {busyAction === 'detections' ? 'Running...' : 'Enable baseline detection'}
            </button>
            <button
              type="button"
              onClick={() => void handleCreateIncident()}
              disabled={!canMutate || busyAction === 'incident'}
              className="btn-primary text-sm"
            >
              {busyAction === 'incident' ? 'Creating...' : 'Create first incident'}
            </button>
          </div>
          <div className="mt-5 grid gap-3 md:grid-cols-3">
            <Link
              href="/telemetry"
              className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4 text-sm text-[var(--text)]"
            >
              Telemetry
            </Link>
            <Link
              href="/alerts"
              className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4 text-sm text-[var(--text)]"
            >
              Alerts
            </Link>
            <Link
              href="/incidents"
              className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4 text-sm text-[var(--text)]"
            >
              Incidents
            </Link>
          </div>
        </div>
      </section>

      <section className="section-panel animate-in">
        <div className="section-head">
          <div>
            <h2 className="section-title">Demo baseline</h2>
            <p className="section-head-copy">
              Seed or reset the cyberlab storyline for operator demos. Reset restores the seeded
              baseline before replaying it.
            </p>
          </div>
          <span className="stat-chip">{demoStatus?.seeded ? 'Seeded' : 'Not seeded'}</span>
        </div>
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_auto]">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-[var(--muted)]">
                Demo telemetry
              </p>
              <p className="mt-2 text-2xl font-semibold text-[var(--text)]">
                {demoStatus?.telemetry_events ?? 0}
              </p>
            </div>
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-[var(--muted)]">
                Demo alerts
              </p>
              <p className="mt-2 text-2xl font-semibold text-[var(--text)]">
                {demoStatus?.alerts ?? 0}
              </p>
            </div>
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-[var(--muted)]">
                Repository findings
              </p>
              <p className="mt-2 text-2xl font-semibold text-[var(--text)]">
                {demoStatus?.repository_findings ?? 0}
              </p>
            </div>
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-4">
              <p className="text-xs uppercase tracking-[0.14em] text-[var(--muted)]">
                Attack lab runs
              </p>
              <p className="mt-2 text-2xl font-semibold text-[var(--text)]">
                {demoStatus?.attack_lab_runs ?? 0}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => void handleSeedDemo()}
              disabled={!isAdmin || busyAction === 'demo-seed'}
              className="btn-secondary text-sm"
            >
              {busyAction === 'demo-seed' ? 'Refreshing...' : 'Seed demo'}
            </button>
            <button
              type="button"
              onClick={() => void handleResetDemo()}
              disabled={!isAdmin || busyAction === 'demo-reset'}
              className="btn-primary text-sm"
            >
              {busyAction === 'demo-reset' ? 'Resetting...' : 'Reset demo'}
            </button>
          </div>
        </div>
        {!isAdmin && (
          <p className="mt-4 text-sm text-[var(--muted)]">
            Demo seed and reset controls are admin-only.
          </p>
        )}
      </section>
    </main>
  );
}
