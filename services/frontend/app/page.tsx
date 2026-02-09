'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('secplat_token') : null;
    if (token) router.replace('/overview');
    else router.replace('/login');
  }, [router]);
  return (
    <div className="flex min-h-screen items-center justify-center gap-3 text-[var(--muted)]">
      <span className="h-5 w-5 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--green)]" />
      Loading…
    </div>
  );
}
