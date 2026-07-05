'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Compass, X } from 'lucide-react';

const STORAGE_KEY = 'secplat-getting-started-dismissed';

/**
 * Compact, dismissible pointer to the Launch Checklist shown at the top of the
 * overview until the user closes it. Keeps first-time users from being dropped
 * into the executive dashboard with no orientation.
 */
export default function GettingStartedBanner() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    try {
      if (window.localStorage.getItem(STORAGE_KEY) !== '1') setVisible(true);
    } catch {
      setVisible(true);
    }
  }, []);

  const dismiss = () => {
    setVisible(false);
    try {
      window.localStorage.setItem(STORAGE_KEY, '1');
    } catch {
      /* storage unavailable */
    }
  };

  if (!visible) return null;

  return (
    <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[var(--accent)]/25 bg-[var(--accent-dim)] px-4 py-3 animate-in">
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--accent)]/15 text-[var(--accent)]">
        <Compass size={16} />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-[var(--text)]">New to SecPlat?</p>
        <p className="text-xs text-[var(--text-muted)]">
          Follow the Launch Checklist to connect your first data source and see real findings in
          minutes.
        </p>
      </div>
      <Link href="/onboarding" className="btn-primary shrink-0 px-3 py-1.5 text-xs">
        Open the checklist
      </Link>
      <button
        type="button"
        aria-label="Dismiss getting started banner"
        onClick={dismiss}
        className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-[var(--text-subtle)] transition-colors hover:bg-white/[0.06] hover:text-[var(--text)]"
      >
        <X size={14} />
      </button>
    </div>
  );
}
