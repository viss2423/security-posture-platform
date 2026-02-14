'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { getUsers, type User } from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { useAuth } from '@/contexts/AuthContext';

export default function UsersPage() {
  const router = useRouter();
  const { isAdmin, loading: authLoading } = useAuth();
  const [data, setData] = useState<{ items: User[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !isAdmin) router.replace('/overview');
  }, [authLoading, isAdmin, router]);

  useEffect(() => {
    if (!isAdmin) return;
    getUsers()
      .then(setData)
      .catch((e) => setError(e.message));
  }, [isAdmin]);

  if (!authLoading && !isAdmin) return null;

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-2">Users & Access</h1>
      <p className="mb-8 text-sm text-[var(--muted)]">
        Users with access to SecPlat. Audit log tracks who did what.
      </p>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState
          title="No users"
          description="No users are configured. Check API settings (ADMIN_USERNAME)."
        />
      )}

      {data && data.items.length > 0 && (
        <div className="card overflow-hidden p-0 animate-in">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] bg-[var(--surface-elevated)]">
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Username</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Role</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Source</th>
                  <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Status</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((u) => (
                  <tr key={u.username} className="border-b border-[var(--border)] hover:bg-[var(--border)]/20">
                    <td className="px-4 py-3 font-medium text-[var(--text)]">{u.username}</td>
                    <td className="px-4 py-3 text-[var(--muted)]">{u.role}</td>
                    <td className="px-4 py-3 text-[var(--muted)]">{u.source}</td>
                    <td className="px-4 py-3 text-[var(--muted)]">{u.disabled ? 'Disabled' : 'Active'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="border-t border-[var(--border)] px-4 py-3 text-xs text-[var(--muted)]">
            <Link href="/audit" className="hover:underline">
              View audit log
            </Link>
            {' — who did what and when.'}
          </div>
        </div>
      )}

      {!data && !error && (
        <div className="card overflow-hidden p-0">
          <div className="animate-pulse space-y-3 p-6">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-10 rounded bg-[var(--border)]/50" />
            ))}
          </div>
        </div>
      )}
    </main>
  );
}
