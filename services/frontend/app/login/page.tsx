'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { login, setToken } from '@/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const { access_token } = await login(username, password);
      setToken(access_token);
      router.replace('/overview');
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-md animate-in">
        <div className="card-glass mb-8 text-center relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-[var(--green)]/5 to-transparent pointer-events-none" />
          <div className="relative">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-[var(--green)] to-[#16a34a] text-xl font-bold text-white shadow-glow">
              SP
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[var(--text)]">SecPlat</h1>
            <p className="mt-1 text-sm text-[var(--muted)]">Security Posture Platform</p>
          </div>
        </div>
        <form onSubmit={handleSubmit} className="space-y-5 animate-in animate-in-delay-1">
          <div>
            <label htmlFor="username" className="mb-2 block text-sm font-medium text-[var(--text-muted)]">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
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
              onChange={(e) => setPassword(e.target.value)}
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
          <button type="submit" disabled={loading} className="btn-primary w-full py-3.5">
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
