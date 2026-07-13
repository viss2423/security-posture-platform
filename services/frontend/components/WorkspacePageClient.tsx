'use client';

import Link from 'next/link';
import type { FormEvent } from 'react';
import { useCallback, useEffect, useState } from 'react';
import { ApiDownHint } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';
import {
  connectWorkspace,
  getWorkspaceScanHistory,
  setSessionTokens,
  startWorkspaceScan,
  updateWorkspaceConnectorSchedule,
  type WorkspaceConnectorSchedule,
  type WorkspaceProvider,
  type WorkspaceScanHistoryItem,
  type WorkspaceSchedule,
  type WorkspaceScopeType,
} from '@/lib/api';
import { friendlyApiMessage } from '@/lib/apiError';

const fieldClass = 'w-full rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-subtle)] transition focus:outline-none focus:ring-2 focus:ring-[var(--accent-ring)] focus:border-[var(--accent)]';
const scheduleOptions: WorkspaceSchedule[] = ['off', 'hourly', 'daily', 'weekly'];
const connectWorkspaceHistoryMessages = [
  'connect a workspace before viewing scan history',
  'no workspace connected',
];

function isConnectWorkspaceHistoryError(message: string | null): boolean {
  const normalizedMessage = message?.toLowerCase() ?? '';
  return connectWorkspaceHistoryMessages.some((expectedMessage) => (
    normalizedMessage.includes(expectedMessage)
  ));
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function connectorName(
  connector: Pick<WorkspaceConnectorSchedule, 'credential_id' | 'provider'>
): string {
  return `${connector.provider === 'github' ? 'GitHub' : 'AWS'} #${connector.credential_id}`;
}

function historyConnectorName(
  item: WorkspaceScanHistoryItem,
  connectors: WorkspaceConnectorSchedule[]
): string {
  const match = connectors.find((connector) => String(connector.credential_id) === String(item.connector));
  if (match) return connectorName(match);
  const providerLabel = item.provider === 'github' ? 'GitHub' : item.provider === 'aws' ? 'AWS' : item.provider;
  return item.connector ? `${providerLabel} #${item.connector}` : providerLabel;
}

function upsertConnector(
  connectors: WorkspaceConnectorSchedule[],
  next: WorkspaceConnectorSchedule
): WorkspaceConnectorSchedule[] {
  const exists = connectors.some((connector) => connector.credential_id === next.credential_id);
  if (!exists) return [next, ...connectors];
  return connectors.map((connector) => (
    connector.credential_id === next.credential_id ? next : connector
  ));
}

export default function WorkspacePageClient() {
  const { user, refresh, canMutate } = useAuth();
  const [provider, setProvider] = useState<WorkspaceProvider>('github');
  const [token, setToken] = useState('');
  const [scopeType, setScopeType] = useState<WorkspaceScopeType>('user');
  const [scope, setScope] = useState('');
  const [maxRepos, setMaxRepos] = useState('50');
  const [awsAccessKeyId, setAwsAccessKeyId] = useState('');
  const [awsSecretAccessKey, setAwsSecretAccessKey] = useState('');
  const [awsSessionToken, setAwsSessionToken] = useState('');
  const [awsRegion, setAwsRegion] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [connectors, setConnectors] = useState<WorkspaceConnectorSchedule[]>([]);
  const [scanHistory, setScanHistory] = useState<WorkspaceScanHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [scheduleUpdating, setScheduleUpdating] = useState<number | null>(null);

  const loadScanHistory = useCallback(async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const response = await getWorkspaceScanHistory(50);
      setScanHistory(response.history || []);
    } catch (historyLoadError) {
      setScanHistory([]);
      setHistoryError(historyLoadError instanceof Error ? historyLoadError.message : 'Scan history unavailable');
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadScanHistory();
  }, [loadScanHistory]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    let credentialToken = token.trim();
    let credentialLabel = 'GitHub account';
    let scanScope: string | undefined = scope.trim() || undefined;
    let parsedMaxRepos: number | undefined;

    if (provider === 'github') {
      if (!credentialToken) {
        setError('GitHub token is required');
        return;
      }
      if (scopeType === 'org' && !scope.trim()) {
        setError('Organization name is required for org scans');
        return;
      }
      parsedMaxRepos = parseInt(maxRepos, 10);
      if (Number.isNaN(parsedMaxRepos) || parsedMaxRepos < 1 || parsedMaxRepos > 500) {
        setError('Max repositories must be between 1 and 500');
        return;
      }
      credentialLabel = scopeType === 'org' && scope.trim() ? `GitHub org: ${scope.trim()}` : 'GitHub account';
    } else {
      const accessKeyId = awsAccessKeyId.trim();
      const secretAccessKey = awsSecretAccessKey.trim();
      const sessionToken = awsSessionToken.trim();
      if (!accessKeyId) {
        setError('AWS access key ID is required');
        return;
      }
      if (!secretAccessKey) {
        setError('AWS secret access key is required');
        return;
      }
      credentialToken = JSON.stringify({
        access_key_id: accessKeyId,
        secret_access_key: secretAccessKey,
        ...(sessionToken ? { session_token: sessionToken } : {}),
      });
      credentialLabel = 'AWS account';
      scanScope = awsRegion.trim() || undefined;
    }

    setSubmitting(true);
    setError(null);
    setMessage(`Connecting ${provider === 'github' ? 'GitHub' : 'AWS'} workspace...`);
    try {
      const connected = await connectWorkspace({
        provider,
        token: credentialToken,
        ...(provider === 'github' ? { scope_type: scopeType, scope: scanScope } : {}),
        label: credentialLabel,
      });
      setConnectors((current) => upsertConnector(current, {
        credential_id: connected.credential_id,
        provider: connected.provider,
        schedule: connected.schedule ?? 'off',
        last_scanned_at: connected.last_scanned_at ?? null,
        next_scan_at: connected.next_scan_at ?? null,
      }));
      await setSessionTokens({
        access_token: connected.access_token,
        refresh_token: connected.refresh_token,
      });
      await refresh();
      setMessage(`Workspace connected. Starting ${provider === 'github' ? 'GitHub' : 'AWS'} posture scan...`);
      await startWorkspaceScan({
        provider,
        credential_id: connected.credential_id,
        ...(provider === 'github' ? { scope_type: scopeType, max_repos: parsedMaxRepos } : {}),
        scope: scanScope,
      });
      setMessage('Workspace connected and the first posture scan is queued.');
      await loadScanHistory();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Workspace connection failed');
      setMessage(null);
    } finally {
      setSubmitting(false);
    }
  };

  const changeConnectorSchedule = async (
    connector: WorkspaceConnectorSchedule,
    schedule: WorkspaceSchedule
  ) => {
    if (!canMutate) return;
    setScheduleUpdating(connector.credential_id);
    setError(null);
    setMessage(`Updating ${connectorName(connector)} schedule...`);
    try {
      const updated = await updateWorkspaceConnectorSchedule(connector.credential_id, schedule);
      setConnectors((current) => upsertConnector(current, updated));
      setMessage(`${connectorName(updated)} schedule set to ${updated.schedule || 'off'}.`);
    } catch (scheduleError) {
      setError(scheduleError instanceof Error ? scheduleError.message : 'Schedule update failed');
      setMessage(null);
    } finally {
      setScheduleUpdating(null);
    }
  };

  const scanHistoryNeedsWorkspace = isConnectWorkspaceHistoryError(historyError);

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <span className="stat-chip-strong">Self-serve workspace</span>
            <h1 className="hero-title mt-3">Connect a workspace and start a live posture scan</h1>
            <p className="hero-copy">
              Add GitHub or AWS credentials to create your isolated workspace, promote this
              account for live analysis, and queue a posture scan against your own environment.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Link href="/onboarding" className="btn-secondary text-sm">
                Launch checklist
              </Link>
              <Link href="/jobs" className="btn-secondary text-sm">
                Activity center
              </Link>
            </div>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Current role</p>
              <p className="hero-stat-value capitalize">{user?.role ?? 'viewer'}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Provider</p>
              <p className="hero-stat-value">{provider === 'github' ? 'GitHub' : 'AWS'}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">{provider === 'github' ? 'Scope' : 'Region'}</p>
              <p className="hero-stat-value capitalize">
                {provider === 'github' ? scopeType : awsRegion.trim() || 'us-east-1'}
              </p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Next stop</p>
              <p className="hero-stat-value">Jobs</p>
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
      {message && (
        <div className="rounded-xl border border-cyan-300/18 bg-cyan-300/08 px-4 py-3 text-sm text-[var(--text)]">
          {message}
        </div>
      )}

      <section className="section-panel animate-in">
        <div className="section-head">
          <div>
            <h2 className="section-title">{provider === 'github' ? 'GitHub connection' : 'AWS connection'}</h2>
            <p className="section-head-copy">
              The credentials are sent once to the backend credential store. The browser session is then
              replaced with workspace-scoped auth returned by the API.
            </p>
          </div>
          <span className="stat-chip">{provider === 'github' ? 'Read-only PAT' : 'Access key'}</span>
        </div>

        <form onSubmit={submit} className="grid gap-5">
          <fieldset className="space-y-2 text-sm text-[var(--muted)]">
            <legend className="block text-[11px] font-semibold uppercase tracking-widest">
              Provider
            </legend>
            <div className="flex flex-wrap gap-2">
              {(['github', 'aws'] as WorkspaceProvider[]).map((option) => (
                <label
                  key={option}
                  className="flex min-h-10 items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-3 text-sm text-[var(--text)]"
                >
                  <input
                    type="radio"
                    name="provider"
                    value={option}
                    checked={provider === option}
                    onChange={() => setProvider(option)}
                  />
                  <span>{option === 'github' ? 'GitHub' : 'AWS'}</span>
                </label>
              ))}
            </div>
          </fieldset>

          {provider === 'github' ? (
            <label className="space-y-1.5 text-sm text-[var(--muted)]">
              <span className="block text-[11px] font-semibold uppercase tracking-widest">
                GitHub token
              </span>
              <input
                type="password"
                value={token}
                onChange={(event) => setToken(event.target.value)}
                placeholder="github_pat_..."
                autoComplete="off"
                className={fieldClass}
              />
            </label>
          ) : (
            <div className="grid gap-4 lg:grid-cols-3">
              <label className="space-y-1.5 text-sm text-[var(--muted)]">
                <span className="block text-[11px] font-semibold uppercase tracking-widest">
                  Access key ID
                </span>
                <input
                  type="text"
                  value={awsAccessKeyId}
                  onChange={(event) => setAwsAccessKeyId(event.target.value)}
                  placeholder="AKIA..."
                  autoComplete="off"
                  className={fieldClass}
                />
              </label>
              <label className="space-y-1.5 text-sm text-[var(--muted)]">
                <span className="block text-[11px] font-semibold uppercase tracking-widest">
                  Secret access key
                </span>
                <input
                  type="password"
                  value={awsSecretAccessKey}
                  onChange={(event) => setAwsSecretAccessKey(event.target.value)}
                  autoComplete="off"
                  className={fieldClass}
                />
              </label>
              <label className="space-y-1.5 text-sm text-[var(--muted)]">
                <span className="block text-[11px] font-semibold uppercase tracking-widest">
                  Session token (optional)
                </span>
                <input
                  type="password"
                  value={awsSessionToken}
                  onChange={(event) => setAwsSessionToken(event.target.value)}
                  autoComplete="off"
                  className={fieldClass}
                />
              </label>
            </div>
          )}

          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
            {provider === 'github' ? (
              <div className="grid gap-4 lg:grid-cols-3">
                <fieldset className="space-y-2 text-sm text-[var(--muted)]">
                  <legend className="block text-[11px] font-semibold uppercase tracking-widest">
                    Scan scope
                  </legend>
                  <div className="flex flex-wrap gap-2">
                    {(['user', 'org'] as WorkspaceScopeType[]).map((option) => (
                      <label
                        key={option}
                        className="flex min-h-10 items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-3 text-sm text-[var(--text)]"
                      >
                        <input
                          type="radio"
                          name="scope_type"
                          value={option}
                          checked={scopeType === option}
                          onChange={() => setScopeType(option)}
                        />
                        <span>{option === 'user' ? 'User account' : 'Organization'}</span>
                      </label>
                    ))}
                  </div>
                </fieldset>
                <label className="space-y-1.5 text-sm text-[var(--muted)]">
                  <span className="block text-[11px] font-semibold uppercase tracking-widest">
                    {scopeType === 'org' ? 'Organization name' : 'Username (optional)'}
                  </span>
                  <input
                    type="text"
                    value={scope}
                    onChange={(event) => setScope(event.target.value)}
                    placeholder={scopeType === 'org' ? 'my-company' : 'Leave blank to scan the token owner'}
                    className={fieldClass}
                  />
                </label>
                <label className="space-y-1.5 text-sm text-[var(--muted)]">
                  <span className="block text-[11px] font-semibold uppercase tracking-widest">
                    Max repositories
                  </span>
                  <input
                    type="number"
                    min={1}
                    max={500}
                    value={maxRepos}
                    onChange={(event) => setMaxRepos(event.target.value)}
                    className={fieldClass}
                  />
                </label>
              </div>
            ) : (
              <label className="block max-w-md space-y-1.5 text-sm text-[var(--muted)]">
                <span className="block text-[11px] font-semibold uppercase tracking-widest">
                  Region (optional)
                </span>
                <input
                  type="text"
                  value={awsRegion}
                  onChange={(event) => setAwsRegion(event.target.value)}
                  placeholder="us-east-1"
                  className={fieldClass}
                />
              </label>
            )}
            <p className="mt-4 text-xs text-[var(--text-subtle)]">
              {provider === 'github'
                ? 'Checks branch protection, 2FA enforcement, Dependabot alerts, secret scanning, and public repositories, then maps results into findings and compliance evidence.'
                : 'Checks AWS IAM posture for the selected region, then maps results into findings and compliance evidence.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button type="submit" disabled={submitting} className="btn-primary text-sm">
              {submitting ? 'Connecting...' : 'Connect and scan'}
            </button>
            <p className="text-xs text-[var(--text-subtle)]">
              You will land in Activity Center when the scan is queued.
            </p>
          </div>
        </form>
      </section>

      <section className="section-panel animate-in">
        <div className="section-head">
          <div>
            <h2 className="section-title">Scheduled scans</h2>
            <p className="section-head-copy">
              Set connector cadence after connecting a workspace. Viewer accounts can inspect schedules
              but need analyst or admin rights to change them.
            </p>
          </div>
          <span className="stat-chip">{canMutate ? 'Analyst controls' : 'Read only'}</span>
        </div>

        {connectors.length > 0 ? (
          <div className="grid gap-3">
            {connectors.map((connector) => {
              const scheduleValue = connector.schedule ?? 'off';
              const updating = scheduleUpdating === connector.credential_id;
              return (
                <div
                  key={connector.credential_id}
                  className="flex flex-col gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4 md:flex-row md:items-center md:justify-between"
                >
                  <div>
                    <p className="text-sm font-semibold text-[var(--text)]">{connectorName(connector)}</p>
                    <p className="mt-1 text-xs text-[var(--text-subtle)]">
                      Next scan {formatDateTime(connector.next_scan_at)}
                    </p>
                  </div>
                  <label className="min-w-[180px] space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">
                      Cadence
                    </span>
                    <select
                      value={scheduleValue}
                      disabled={!canMutate || updating}
                      onChange={(event) => {
                        void changeConnectorSchedule(connector, event.target.value as WorkspaceSchedule);
                      }}
                      className={fieldClass}
                    >
                      {scheduleOptions.map((option) => (
                        <option key={option} value={option}>
                          {option}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4 text-sm text-[var(--muted)]">
            Connect a GitHub or AWS workspace in this session to manage its schedule here.
          </div>
        )}
      </section>

      <section className="section-panel animate-in">
        <div className="section-head">
          <div>
            <h2 className="section-title">Scan history</h2>
            <p className="section-head-copy">
              Recent workspace scans across manual and scheduled triggers.
            </p>
          </div>
          <button type="button" onClick={loadScanHistory} className="btn-secondary text-sm">
            Refresh
          </button>
        </div>

        {historyError && !scanHistoryNeedsWorkspace && (
          <div className="alert-error mb-4" role="alert">
            {friendlyApiMessage(historyError)}
          </div>
        )}

        {scanHistoryNeedsWorkspace ? (
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4 text-sm text-[var(--muted)]">
            Connect a GitHub or AWS workspace in this session to view scan history here.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] border-collapse text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-[11px] uppercase tracking-widest text-[var(--text-subtle)]">
                  <th className="py-3 pr-4 font-semibold">Started</th>
                  <th className="py-3 pr-4 font-semibold">Finished</th>
                  <th className="py-3 pr-4 font-semibold">Connector</th>
                  <th className="py-3 pr-4 font-semibold">Status</th>
                  <th className="py-3 pr-4 font-semibold">Findings</th>
                  <th className="py-3 font-semibold">Triggered by</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {scanHistory.map((item) => (
                  <tr key={item.scan_history_id}>
                    <td className="py-3 pr-4 text-[var(--muted)]">{formatDateTime(item.started_at)}</td>
                    <td className="py-3 pr-4 text-[var(--muted)]">{formatDateTime(item.finished_at)}</td>
                    <td className="py-3 pr-4 text-[var(--text)]">{historyConnectorName(item, connectors)}</td>
                    <td className="py-3 pr-4">
                      <span className="stat-chip uppercase">{item.status}</span>
                    </td>
                    <td className="py-3 pr-4 text-[var(--text)]">{item.findings_count}</td>
                    <td className="py-3">
                      <span className={item.triggered_by === 'scheduled' ? 'stat-chip-strong' : 'stat-chip'}>
                        {item.triggered_by === 'scheduled' ? 'Scheduled' : 'Manual'}
                      </span>
                    </td>
                  </tr>
                ))}
                {!historyLoading && scanHistory.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-6 text-center text-[var(--muted)]">
                      No scan history yet.
                    </td>
                  </tr>
                )}
                {historyLoading && (
                  <tr>
                    <td colSpan={6} className="py-6 text-center text-[var(--muted)]">
                      Loading scan history...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
