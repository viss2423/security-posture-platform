'use client';

import { useEffect, useState } from 'react';

const HEALTH_URL = '/api/health';

export default function ApiStatusBanner() {
  const [down, setDown] = useState(false);

  useEffect(() => {
    let mounted = true;
    async function check() {
      if (!mounted) return;
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        return;
      }
      try {
        const res = await fetch(HEALTH_URL, { cache: 'no-store' });
        if (mounted) {
          setDown(!res.ok);
        }
      } catch {
        if (mounted) {
          setDown(true);
        }
      }
    }

    const handleVisibility = () => {
      void check();
    };

    void check();
    window.addEventListener('focus', handleVisibility);
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      mounted = false;
      window.removeEventListener('focus', handleVisibility);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, []);

  if (!down) return null;

  return (
    <div
      className="sticky top-0 z-50 border-b border-[var(--red)] bg-[var(--red-bg)] px-4 py-2 text-center text-sm font-medium text-[var(--red)]"
      role="alert"
    >
      API unavailable. Data may be stale or missing. Check the API is running and try again.
    </div>
  );
}
