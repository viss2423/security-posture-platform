'use client';

import { useEffect, useState } from 'react';
import { KeyRound, ShieldCheck, Sparkles, Workflow } from 'lucide-react';
import { useRouter } from 'next/navigation';

type LoginFormProps = {
  oidcEnabled: boolean;
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

export default function LoginForm({ oidcEnabled }: LoginFormProps) {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [syncingToken, setSyncingToken] = useState(false);

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
    setLoading(true);
    try {
      await createSession({ username, password });
      router.replace('/overview');
      router.refresh();
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-stage flex items-center justify-center px-4 py-10 sm:px-6 lg:px-10">
      <div className="relative z-[1] grid w-full max-w-7xl gap-6 lg:grid-cols-[minmax(0,1.2fr)_minmax(25rem,0.8fr)]">
        <section className="auth-panel surface-noise data-scan hidden p-8 lg:block xl:p-10">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-300/18 bg-cyan-300/08 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--cyan-strong)]">
            <Sparkles size={11} />
            Customer-ready security platform
          </div>

          <div className="mt-8 max-w-2xl">
            <h1 className="text-[3rem] leading-[0.96] tracking-[-0.05em] text-[var(--text)] xl:text-[4.3rem]">
              See posture, signals, and response in one premium platform.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-8 text-[var(--text-muted)]">
              SecPlat brings exposure visibility, telemetry, detection workflows, and executive
              reporting into a single customer-facing control plane.
            </p>
          </div>

          <div className="mt-8 grid gap-4 sm:grid-cols-3">
            <article className="card-glass surface-noise rounded-[1.5rem] p-4">
              <div className="mb-3 inline-flex h-10 w-10 items-center justify-center rounded-[1rem] border border-cyan-300/18 bg-cyan-300/08 text-[var(--cyan-strong)]">
                <ShieldCheck size={17} />
              </div>
              <h2 className="text-base font-semibold text-[var(--text)]">Continuous visibility</h2>
              <p className="mt-2 text-sm leading-6 text-[var(--text-muted)]">
                One live view of asset health, exposure, and the risks that actually need action.
              </p>
            </article>
            <article className="card-glass surface-noise rounded-[1.5rem] p-4">
              <div className="mb-3 inline-flex h-10 w-10 items-center justify-center rounded-[1rem] border border-emerald-300/18 bg-emerald-300/08 text-[var(--green)]">
                <Workflow size={17} />
              </div>
              <h2 className="text-base font-semibold text-[var(--text)]">Guided workflows</h2>
              <p className="mt-2 text-sm leading-6 text-[var(--text-muted)]">
                Move from finding to incident to remediation without losing the underlying context.
              </p>
            </article>
            <article className="card-glass surface-noise rounded-[1.5rem] p-4">
              <div className="mb-3 inline-flex h-10 w-10 items-center justify-center rounded-[1rem] border border-amber-300/18 bg-amber-300/08 text-[var(--amber)]">
                <KeyRound size={17} />
              </div>
              <h2 className="text-base font-semibold text-[var(--text)]">Fast access</h2>
              <p className="mt-2 text-sm leading-6 text-[var(--text-muted)]">
                Sign in with credentials or SSO and land directly in the operating view that matters.
              </p>
            </article>
          </div>

          <div className="mt-8 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(16rem,0.8fr)]">
            <div className="rounded-[1.6rem] border border-[var(--border)] bg-white/84 p-5">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
                What customers understand instantly
              </p>
              <ul className="mt-4 space-y-3 text-sm leading-6 text-[var(--text-muted)]">
                <li>What assets are being monitored</li>
                <li>What risk is rising right now</li>
                <li>What alerts and incidents need attention</li>
              </ul>
            </div>
            <div className="rounded-[1.6rem] border border-[var(--border)] bg-white/84 p-5">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
                Access model
              </p>
              <p className="mt-4 text-sm leading-7 text-[var(--text-muted)]">
                Secure platform access with local authentication today and SSO when configured.
              </p>
            </div>
          </div>
        </section>

        <section className="auth-panel surface-noise p-6 sm:p-8">
          <div className="mx-auto w-full max-w-md">
            <div className="mb-6">
              <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-[1.1rem] border border-[var(--border)] bg-white text-[0.95rem] font-black uppercase tracking-[0.18em] text-[var(--text)] shadow-[var(--shadow-soft)]">
                SP
              </div>
              <h2 className="text-[2.4rem] leading-none tracking-[-0.04em] text-[var(--text)]">
                Sign in to SecPlat
              </h2>
              <p className="mt-3 text-sm leading-7 text-[var(--text-muted)]">
                Access your customer-facing security posture platform.
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
                  autoComplete="current-password"
                  className="input"
                />
              </div>

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
                {syncingToken ? 'Completing SSO...' : loading ? 'Signing in...' : 'Sign in'}
              </button>

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
          </div>
        </section>
      </div>
    </div>
  );
}
