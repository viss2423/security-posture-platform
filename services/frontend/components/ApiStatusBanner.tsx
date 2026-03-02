'use client';

import { useEffect, useState } from 'react';

const HEALTH_URL = '/api/health';
const POLL_MS = 15000;

export default function ApiStatusBanner() {
  const [down, setDown] = useState(false);

  useEffect(() => {
    let mounted = true;
    function check() {
      fetch(HEALTH_URL, { cache: 'no-store' })
        .then((res) => {
          if (!mounted) return;
          setDown(!res.ok);
        })
        .catch(() => {
          if (mounted) setDown(true);
        });
    }
    check();
    const t = setInterval(check, POLL_MS);
    return () => {
      mounted = false;
      clearInterval(t);
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
