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
      <div className="loading-dots">
        <span />
        <span />
        <span />
      </div>
      <span>Loading…</span>
    </div>
  );
}
