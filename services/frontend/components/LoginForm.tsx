'use client';

import { useEffect, useState } from 'react';
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
          setError(sessionError instanceof Error ? sessionError.message : 'SSO sign-in failed');
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
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md animate-in">
        <div className="card-glass relative mb-8 overflow-hidden text-center">
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-[var(--green)]/5 to-transparent" />
          <div className="relative">
            <div className="shadow-glow mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-[var(--green)] to-[#16a34a] text-xl font-bold text-white">
              SP
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[var(--text)]">SecPlat</h1>
            <p className="mt-1 text-sm text-[var(--muted)]">Security Posture Platform</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="animate-in animate-in-delay-1 space-y-5">
          <div>
            <label htmlFor="username" className="mb-2 block text-sm font-medium text-[var(--text-muted)]">
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
            <label htmlFor="password" className="mb-2 block text-sm font-medium text-[var(--text-muted)]">
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
          <button type="submit" disabled={loading || syncingToken} className="btn-primary w-full py-3.5">
            {syncingToken ? 'Completing SSO...' : loading ? 'Signing in...' : 'Sign in'}
          </button>
          {oidcEnabled && (
            <div className="relative my-4">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-[var(--border)]" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="bg-[var(--card)] px-2 text-[var(--muted)]">or</span>
              </div>
            </div>
          )}
          {oidcEnabled && (
            <a
              href="/api/auth/oidc/login"
              className="btn-secondary flex w-full items-center justify-center gap-2 py-3.5"
            >
              Sign in with SSO
            </a>
          )}
        </form>
      </div>
    </div>
  );
}
