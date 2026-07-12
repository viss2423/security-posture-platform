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
  type WorkspaceScopeType,
} from '@/lib/api';
import { friendlyApiMessage } from '@/lib/apiError';

const fieldClass = 'w-full rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-subtle)] transition focus:outline-none focus:ring-2 focus:ring-[var(--accent-ring)] focus:border-[var(--accent)]';

export default function WorkspacePageClient() {
  const router = useRouter();
  const { user, refresh } = useAuth();
  const [token, setToken] = useState('');
  const [scopeType, setScopeType] = useState<WorkspaceScopeType>('user');
  const [scope, setScope] = useState('');
  const [maxRepos, setMaxRepos] = useState('50');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!token.trim()) {
      setError('GitHub token is required');
      return;
    }
    if (scopeType === 'org' && !scope.trim()) {
      setError('Organization name is required for org scans');
      return;
    }
    const parsedMaxRepos = parseInt(maxRepos, 10);
    if (Number.isNaN(parsedMaxRepos) || parsedMaxRepos < 1 || parsedMaxRepos > 500) {
      setError('Max repositories must be between 1 and 500');
      return;
    }

    setSubmitting(true);
    setError(null);
    setMessage('Connecting GitHub workspace...');
    try {
      const connected = await connectWorkspace({
        provider: 'github',
        token: token.trim(),
        scope_type: scopeType,
        scope: scope.trim() || undefined,
        label: scopeType === 'org' && scope.trim() ? `GitHub org: ${scope.trim()}` : 'GitHub account',
      });
      await setSessionTokens({
        access_token: connected.access_token,
        refresh_token: connected.refresh_token,
      });
      await refresh();
      setMessage('Workspace connected. Starting GitHub posture scan...');
      await startWorkspaceScan({
        provider: 'github',
        credential_id: connected.credential_id,
        scope_type: scopeType,
        scope: scope.trim() || undefined,
        max_repos: parsedMaxRepos,
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
            <h1 className="hero-title mt-3">Connect GitHub and start a live posture scan</h1>
            <p className="hero-copy">
              Paste a read-only GitHub token to create your isolated workspace, promote this
              account for live analysis, and queue a scan against your own repositories.
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
              <p className="hero-stat-value">GitHub</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Scope</p>
              <p className="hero-stat-value capitalize">{scopeType}</p>
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
            <h2 className="section-title">GitHub connection</h2>
            <p className="section-head-copy">
              The token is sent once to the backend credential store. The browser session is then
              replaced with workspace-scoped auth returned by the API.
            </p>
          </div>
          <span className="stat-chip">Read-only PAT</span>
        </div>

        <form onSubmit={submit} className="grid gap-5">
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

          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
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
            <p className="mt-4 text-xs text-[var(--text-subtle)]">
              Checks branch protection, 2FA enforcement, Dependabot alerts, secret scanning, and
              public repositories, then maps results into findings and compliance evidence.
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
