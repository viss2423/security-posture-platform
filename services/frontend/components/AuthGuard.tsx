'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('secplat_token');
}

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  useEffect(() => {
    if (!getToken()) router.replace('/login');
  }, [router]);
  return <>{children}</>;
}
