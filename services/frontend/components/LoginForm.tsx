'use client';

import { useEffect, useState } from 'react';
import { KeyRound, ShieldCheck, Sparkles, Workflow } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

type LoginFormProps = {
  oidcEnabled: boolean;
  selfRegistration?: boolean;
};

async function createSession(body: Record<string, string>) {
  const res = await fetch('/api/auth/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    let message = text || 'Login failed';
    try {
      const data = JSON.parse(text);
      if (typeof data?.error === 'string') {
        message = data.error;
      }
    } catch {
      /* keep text */
    }
    throw new Error(message);
  }
}

async function registerAccount(username: string, password: string) {
  const res = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const text = await res.text();
  if (!res.ok) {
    let message = text || 'Signup failed';
    try {
      const data = JSON.parse(text);
      if (typeof data?.detail === 'string') message = data.detail;
      else if (typeof data?.error === 'string') message = data.error;
    } catch {
      /* keep text */
    }
    throw new Error(message);
  }
  const tokens = JSON.parse(text) as { access_token?: string; refresh_token?: string };
  if (!tokens.access_token) {
    throw new Error('Signup succeeded but no session token was returned');
  }
  const payload: Record<string, string> = { access_token: tokens.access_token };
  if (tokens.refresh_token) payload.refresh_token = tokens.refresh_token;
  await createSession(payload);
}

export default function LoginForm({ oidcEnabled, selfRegistration = false }: LoginFormProps) {
  const router = useRouter();
  const [mode, setMode] = useState<'signin' | 'register'>('signin');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [syncingToken, setSyncingToken] = useState(false);
  const registering = mode === 'register';

  useEffect(() => {
    const hash = typeof window !== 'undefined' ? window.location.hash.slice(1) : '';
    if (!hash) return;

    const params = Object.fromEntries(new URLSearchParams(hash));
    if (params.access_token) {
      setSyncingToken(true);
      const payload: Record<string, string> = { access_token: params.access_token };
      if (params.refresh_token) {
        payload.refresh_token = params.refresh_token;
      }
      createSession(payload)
        .then(() => {
          window.history.replaceState(null, '', '/login');
          router.replace('/overview');
          router.refresh();
        })
        .catch((sessionError) => {
          setError(
            sessionError instanceof Error ? sessionError.message : 'SSO sign-in failed'
          );
          window.history.replaceState(null, '', '/login');
        })
        .finally(() => setSyncingToken(false));
      return;
    }

    if (params.error) {
      const msg =
        params.error === 'user_not_found'
          ? 'Your account is not in SecPlat. Ask an admin to add you.'
          : params.error === 'invalid_callback'
            ? 'SSO sign-in was invalid or expired. Try again.'
            : `SSO error: ${params.error}`;
      setError(msg);
      window.history.replaceState(null, '', '/login');
    }
  }, [router]);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError('');
    if (registering) {
      if (password !== confirmPassword) {
        setError('Passwords do not match');
        return;
      }
      if (password.length < 8) {
        setError('Password must be at least 8 characters');
        return;
      }
    }
    setLoading(true);
    try {
      if (registering) {
        await registerAccount(username.trim(), password);
      } else {
        await createSession({ username, password });
      }
      // Brand-new accounts start on the guided checklist; returning users go to the overview.
      router.replace(registering ? '/onboarding' : '/overview');
      router.refresh();
    } catch (submitError) {
      setError(
        submitError instanceof Error
          ? submitError.message
          : registering
            ? 'Signup failed'
            : 'Login failed'
      );
    } finally {
      setLoading(false);
    }
  }

  function toggleMode() {
    setMode((current) => (current === 'signin' ? 'register' : 'signin'));
    setError('');
    setConfirmPassword('');
  }

  return (
    <div className="auth-stage flex items-center justify-center px-4 py-8 sm:px-6 lg:px-10">
      <div className="relative z-[1] grid w-full max-w-6xl items-center gap-6 lg:grid-cols-[minmax(0,1.08fr)_minmax(25rem,0.92fr)]">
        <section className="auth-panel surface-noise data-scan hidden max-w-none p-8 lg:block xl:p-10">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-300/18 bg-cyan-300/08 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--cyan-strong)]">
            <Sparkles size={11} />
            Customer-ready security platform
          </div>

          <div className="mt-7 max-w-2xl">
            <h2 className="text-[2.8rem] leading-[0.98] tracking-[-0.05em] text-[var(--text)] xl:text-[3.5rem]">
              See posture, signals, and response in one place.
            </h2>
            <p className="mt-5 max-w-xl text-[15px] leading-7 text-[var(--text-muted)]">
              SecPlat brings exposure visibility, telemetry, detection workflows, and executive
              reporting into one clear operating view.
            </p>
          </div>

          <div className="mt-7 grid gap-3">
            <article className="card-glass surface-noise flex items-start gap-4 rounded-xl p-4">
              <div className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-cyan-300/18 bg-cyan-300/08 text-[var(--cyan-strong)]">
                <ShieldCheck size={18} />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">Continuous visibility</h3>
                <p className="mt-1 text-[13px] leading-5 text-[var(--text-muted)]">
                  Follow asset health, exposure, and the risks that need action.
                </p>
              </div>
            </article>
            <article className="card-glass surface-noise flex items-start gap-4 rounded-xl p-4">
              <div className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-emerald-300/18 bg-emerald-300/08 text-[var(--green)]">
                <Workflow size={18} />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">Guided response</h3>
                <p className="mt-1 text-[13px] leading-5 text-[var(--text-muted)]">
                  Move from finding to incident to remediation without losing context.
                </p>
              </div>
            </article>
            <article className="card-glass surface-noise flex items-start gap-4 rounded-xl p-4">
              <div className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-amber-300/18 bg-amber-300/08 text-[var(--amber)]">
                <KeyRound size={18} />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">Secure access</h3>
                <p className="mt-1 text-[13px] leading-5 text-[var(--text-muted)]">
                  Use local credentials or configured SSO to reach your workspace.
                </p>
              </div>
            </article>
          </div>

          <div className="mt-7 flex flex-wrap gap-x-6 gap-y-2 border-t border-[var(--border)] pt-5 text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-subtle)]">
            <span>Live asset posture</span>
            <span>Prioritized risk</span>
            <span>Actionable incidents</span>
          </div>
        </section>

        <section className="auth-panel surface-noise max-w-none p-6 sm:p-8 lg:self-center">
          <div className="mx-auto w-full max-w-md">
            <div className="mb-6">
              <Link
                href="/"
                aria-label="Return to the SecPlat product overview"
                className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-[1.1rem] border border-[var(--accent)]/40 bg-[var(--accent)] text-[0.95rem] font-black uppercase tracking-[0.18em] text-[#07090e] shadow-[var(--shadow-glow-accent)] transition-transform hover:-translate-y-0.5"
              >
                SP
              </Link>
              <h1 className="text-[2.15rem] leading-none tracking-[-0.04em] text-[var(--text)] sm:text-[2.4rem]">
                {registering ? 'Create your account' : 'Sign in to SecPlat'}
              </h1>
              <p className="mt-3 text-sm leading-7 text-[var(--text-muted)]">
                {registering
                  ? 'Set up a free account and start exploring the platform right away.'
                  : 'Access your security posture workspace.'}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label
                  htmlFor="username"
                  className="mb-2 block text-sm font-medium text-[var(--text-muted)]"
                >
                  Username
                </label>
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  required
                  autoComplete="username"
                  className="input"
                />
              </div>
              <div>
                <label
                  htmlFor="password"
                  className="mb-2 block text-sm font-medium text-[var(--text-muted)]"
                >
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  minLength={registering ? 8 : undefined}
                  autoComplete={registering ? 'new-password' : 'current-password'}
                  className="input"
                />
              </div>
              {registering && (
                <div>
                  <label
                    htmlFor="confirm-password"
                    className="mb-2 block text-sm font-medium text-[var(--text-muted)]"
                  >
                    Confirm password
                  </label>
                  <input
                    id="confirm-password"
                    type="password"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    required
                    minLength={8}
                    autoComplete="new-password"
                    className="input"
                  />
                </div>
              )}

              {error && (
                <p className="alert-error" role="alert">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={loading || syncingToken}
                className="btn-primary flex w-full items-center justify-center gap-2 py-3.5"
              >
                <KeyRound size={15} />
                {syncingToken
                  ? 'Completing SSO...'
                  : loading
                    ? registering
                      ? 'Creating account...'
                      : 'Signing in...'
                    : registering
                      ? 'Create account'
                      : 'Sign in'}
              </button>

              {selfRegistration && (
                <p className="text-center text-sm text-[var(--text-muted)]">
                  {registering ? 'Already have an account?' : 'New to SecPlat?'}{' '}
                  <button
                    type="button"
                    onClick={toggleMode}
                    className="font-semibold text-[var(--accent)] hover:underline"
                  >
                    {registering ? 'Sign in' : 'Create an account'}
                  </button>
                </p>
              )}

              {oidcEnabled && (
                <div className="relative my-5">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-[var(--border)]" />
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="rounded-full border border-[var(--border)] bg-white px-3 py-1 text-xs text-[var(--muted)]">
                      Or continue with SSO
                    </span>
                  </div>
                </div>
              )}

              {oidcEnabled && (
                <a
                  href="/api/auth/oidc/login"
                  className="btn-secondary flex w-full items-center justify-center gap-2 py-3.5"
                >
                  <ShieldCheck size={15} />
                  Sign in with SSO
                </a>
              )}
            </form>

            <div className="mt-6 border-t border-[var(--border)] pt-5 text-center">
              <Link
                href="/"
                className="text-xs font-medium text-[var(--text-muted)] transition-colors hover:text-[var(--accent)]"
              >
                Learn what SecPlat protects
              </Link>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
