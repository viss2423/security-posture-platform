'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import type { FormEvent } from 'react';
import { useState } from 'react';
import { ApiDownHint } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';
import {
  connectWorkspace,
  setSessionTokens,
  startWorkspaceScan,
  type WorkspaceProvider,
  type WorkspaceScopeType,
} from '@/lib/api';
import { friendlyApiMessage } from '@/lib/apiError';

const fieldClass = 'w-full rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-subtle)] transition focus:outline-none focus:ring-2 focus:ring-[var(--accent-ring)] focus:border-[var(--accent)]';

export default function WorkspacePageClient() {
  const router = useRouter();
  const { user, refresh } = useAuth();
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
      router.push('/jobs');
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Workspace connection failed');
      setMessage(null);
    } finally {
      setSubmitting(false);
    }
  };

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
    </main>
  );
}
