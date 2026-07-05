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
      className="sticky top-0 z-50 border-b border-rose-500/20 bg-[rgba(20,6,10,0.92)] px-4 py-3 text-center text-sm font-medium text-[var(--red)] backdrop-blur-xl"
      role="alert"
    >
      <span className="inline-flex items-center gap-2 rounded-full border border-rose-500/20 bg-rose-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--red)]">
        API degraded
      </span>{' '}
      Live data is currently unavailable. Some metrics or lists may be stale until the API
      recovers.
    </div>
  );
}
