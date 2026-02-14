'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { logout } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';

const links: { href: string; label: string; adminOnly?: boolean }[] = [
  { href: '/overview', label: 'Overview' },
  { href: '/assets', label: 'Assets' },
  { href: '/findings', label: 'Findings' },
  { href: '/alerts', label: 'Alerts' },
  { href: '/incidents', label: 'Incidents' },
  { href: '/reports', label: 'Reports' },
  { href: '/policy', label: 'Policy' },
  { href: '/audit', label: 'Audit' },
  { href: '/users', label: 'Users', adminOnly: true },
  { href: '/jobs', label: 'Jobs' },
  { href: '/dashboards', label: 'Dashboards' },
];

export default function Nav() {
  const pathname = usePathname();
  const { isAdmin } = useAuth();

  const visibleLinks = links.filter((link) => !link.adminOnly || isAdmin);

  return (
    <header className="sticky top-0 z-50 border-b border-[var(--border)] bg-[var(--surface)]/80 backdrop-blur-xl supports-[backdrop-filter]:bg-[var(--surface)]/70">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <nav className="flex items-center gap-1 sm:gap-3">
          <Link
            href="/overview"
            className="flex items-center gap-2.5 rounded-xl px-3 py-2.5 text-base font-bold tracking-tight text-[var(--text)] transition-all hover:bg-[var(--surface-elevated)]"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--green)]/15 text-sm font-bold text-[var(--green)]">
              SP
            </span>
            <span className="hidden sm:inline">SecPlat</span>
          </Link>
          <div className="ml-2 flex items-center gap-0.5 border-l border-[var(--border)] pl-5">
            {visibleLinks.map(({ href, label }) => {
              const isActive = pathname === href || (href !== '/overview' && pathname.startsWith(href));
              return (
                <Link
                  key={href}
                  href={href}
                  className={`relative rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${
                    isActive
                      ? 'text-[var(--text)]'
                      : 'text-[var(--muted)] hover:bg-[var(--surface-elevated)] hover:text-[var(--text)]'
                  }`}
                >
                  {isActive && (
                    <span className="absolute inset-0 rounded-lg bg-[var(--green)]/10 ring-1 ring-[var(--green)]/20" aria-hidden />
                  )}
                  <span className="relative">{label}</span>
                </Link>
              );
            })}
          </div>
        </nav>
        <button
          type="button"
          onClick={() => {
            logout();
            window.location.href = '/login';
          }}
          className="rounded-lg px-4 py-2.5 text-sm font-medium text-[var(--muted)] transition-all hover:bg-[var(--surface-elevated)] hover:text-[var(--text)] focus:outline-none focus:ring-2 focus:ring-[var(--border)] focus:ring-offset-2 focus:ring-offset-[var(--bg)]"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
