'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { logout } from '@/lib/api';

const links = [
  { href: '/overview', label: 'Overview' },
  { href: '/assets', label: 'Assets' },
  { href: '/alerts', label: 'Alerts' },
  { href: '/reports', label: 'Reports' },
  { href: '/dashboards', label: 'Dashboards' },
];

export default function Nav() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-50 border-b border-[var(--border)] bg-[var(--bg)]/95 backdrop-blur supports-[backdrop-filter]:bg-[var(--bg)]/80">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <nav className="flex items-center gap-1 sm:gap-2">
          <Link
            href="/overview"
            className="flex items-center gap-2 rounded-lg px-3 py-2 text-base font-semibold text-[var(--text)] transition hover:bg-[var(--surface)]"
          >
            <span className="hidden sm:inline">SecPlat</span>
            <span className="text-[var(--green)] sm:text-lg">◆</span>
          </Link>
          <div className="ml-2 flex items-center gap-0.5 border-l border-[var(--border)] pl-4">
            {links.map(({ href, label }) => {
              const isActive = pathname === href || (href !== '/overview' && pathname.startsWith(href));
              return (
                <Link
                  key={href}
                  href={href}
                  className={`rounded-md px-3 py-2 text-sm font-medium transition ${
                    isActive
                      ? 'bg-[var(--surface)] text-[var(--text)]'
                      : 'text-[var(--muted)] hover:bg-[var(--surface)] hover:text-[var(--text)]'
                  }`}
                >
                  {label}
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
          className="rounded-md px-3 py-2 text-sm font-medium text-[var(--muted)] transition hover:bg-[var(--surface)] hover:text-[var(--text)] focus:outline-none focus:ring-2 focus:ring-[var(--border)] focus:ring-offset-2 focus:ring-offset-[var(--bg)]"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
