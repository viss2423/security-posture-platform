'use client';

import * as Dialog from '@radix-ui/react-dialog';
import { motion } from 'framer-motion';
import {
  Activity,
  Archive,
  BarChart3,
  Bell,
  BrainCircuit,
  Briefcase,
  Bug,
  ChevronRight,
  FileText,
  LogOut,
  Menu,
  Scale,
  ScrollText,
  Shield,
  ShieldAlert,
  Users,
  X,
  type LucideIcon,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useMemo, useState } from 'react';
import { getPostureSummary, logout, type PostureSummary } from '@/lib/api';
import { cn } from '@/lib/cn';
import {
  getVisibleNavGroups,
  isActivePath,
  type NavGroup,
  type NavIconKey,
} from '@/lib/navigation';
import { useAuth } from '@/contexts/AuthContext';

const ICONS: Record<NavIconKey, LucideIcon> = {
  activity: Activity,
  dashboard: BarChart3,
  assets: Archive,
  findings: Bug,
  alerts: Bell,
  incidents: ShieldAlert,
  suppression: Shield,
  jobs: Briefcase,
  reports: FileText,
  policy: Scale,
  audit: ScrollText,
  users: Users,
  ml: BrainCircuit,
};

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link
      href="/overview"
      className="flex items-center gap-3 rounded-xl px-2 py-1 text-[var(--text)] transition hover:bg-[var(--surface-elevated)]"
    >
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-[var(--green)] via-emerald-300 to-cyan-300 text-sm font-black text-black shadow-[0_0_20px_rgba(52,211,153,0.55)]">
        SP
      </span>
      {!compact && (
        <span className="flex flex-col">
          <span className="[font-family:var(--font-display)] text-sm font-bold uppercase tracking-[0.08em] text-[var(--text)]">SecPlat</span>
          <span className="text-xs text-[var(--muted)]">Enterprise security operations</span>
        </span>
      )}
    </Link>
  );
}

function PulseCard({ summary }: { summary: PostureSummary | null }) {
  const score = summary?.posture_score_avg != null ? Math.round(Number(summary.posture_score_avg)) : null;

  return (
    <div className="rounded-2xl border border-[var(--border)] bg-gradient-to-br from-[var(--surface-elevated)] to-[var(--surface)] p-3.5 shadow-lg shadow-black/25">
      <div className="mb-3 flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--text-muted)]">Operational pulse</p>
        <span className="rounded-full bg-[var(--green)]/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-[var(--green)]">
          Live
        </span>
      </div>
      <div className="mb-3 flex items-end justify-between">
        <div>
          <p className="text-[11px] uppercase tracking-[0.1em] text-[var(--muted)]">Posture score</p>
          <p className="[font-family:var(--font-display)] text-3xl font-bold text-[var(--text)]">{score ?? '--'}</p>
        </div>
        <div className="h-10 w-28 overflow-hidden rounded-full border border-[var(--border)] bg-[var(--surface)] p-1">
          <div
            className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-cyan-300 transition-all"
            style={{ width: `${Math.max(8, Math.min(100, score ?? 8))}%` }}
          />
        </div>
      </div>
      <div className="grid grid-cols-3 gap-2 text-xs">
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-2">
          <p className="text-[var(--muted)]">Green</p>
          <p className="mt-1 font-semibold text-emerald-300">{summary?.green ?? '--'}</p>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-2">
          <p className="text-[var(--muted)]">Amber</p>
          <p className="mt-1 font-semibold text-amber-300">{summary?.amber ?? '--'}</p>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-2">
          <p className="text-[var(--muted)]">Red</p>
          <p className="mt-1 font-semibold text-rose-300">{summary?.red ?? '--'}</p>
        </div>
      </div>
    </div>
  );
}

function SidebarPanel({
  pathname,
  groups,
  username,
  role,
  summary,
  onSignOut,
  onNavigate,
}: {
  pathname: string;
  groups: NavGroup[];
  username?: string;
  role?: string;
  summary: PostureSummary | null;
  onSignOut: () => void;
  onNavigate?: () => void;
}) {
  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-[var(--border)] p-4">
        <Brand />
      </div>
      <div className="space-y-4 border-b border-[var(--border)] px-3 py-4">
        <PulseCard summary={summary} />
      </div>
      <div className="flex-1 space-y-6 overflow-y-auto px-3 py-4">
        {groups.map((group, idx) => (
          <motion.section
            key={group.title}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25, delay: idx * 0.04 }}
          >
            <h2 className="px-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--muted)]">{group.title}</h2>
            <div className="mt-2 space-y-1">
              {group.items.map((item) => {
                const Icon = ICONS[item.icon];
                const active = isActivePath(pathname, item.href);
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={onNavigate}
                    className={cn(
                      'group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition',
                      active
                        ? 'bg-[var(--green)]/16 text-[var(--text)] ring-1 ring-[var(--green)]/30 shadow-[0_0_0_1px_rgba(52,211,153,0.08)]'
                        : 'text-[var(--text-muted)] hover:bg-[var(--surface-elevated)] hover:text-[var(--text)]'
                    )}
                  >
                    <Icon
                      size={16}
                      className={cn(
                        'shrink-0 transition',
                        active ? 'text-[var(--green)]' : 'text-[var(--muted)] group-hover:text-[var(--text)]'
                      )}
                    />
                    <span className="flex-1 truncate">{item.label}</span>
                    <ChevronRight
                      size={14}
                      className={cn('transition', active ? 'text-[var(--green)]' : 'text-[var(--muted)]/70')}
                    />
                  </Link>
                );
              })}
            </div>
          </motion.section>
        ))}
      </div>
      <div className="border-t border-[var(--border)] p-4">
        <div className="mb-3 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/70 px-3 py-2.5">
          <p className="truncate text-sm font-medium text-[var(--text)]">{username || 'Signed in'}</p>
          <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted)]">{role || 'viewer'}</p>
        </div>
        <button
          type="button"
          onClick={onSignOut}
          className="flex w-full items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2.5 text-sm font-medium text-[var(--text-muted)] transition hover:border-[var(--green)]/40 hover:text-[var(--text)]"
        >
          <LogOut size={15} />
          Sign out
        </button>
      </div>
    </div>
  );
}

export default function Nav() {
  const pathname = usePathname();
  const { isAdmin, user } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [summary, setSummary] = useState<PostureSummary | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () => {
      getPostureSummary()
        .then((resp) => {
          if (alive) setSummary(resp);
        })
        .catch(() => {
          if (alive) setSummary(null);
        });
    };

    load();
    const timer = window.setInterval(load, 60000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  const visibleGroups = useMemo(() => getVisibleNavGroups(isAdmin), [isAdmin]);

  const handleSignOut = () => {
    logout();
    window.location.href = '/login';
  };

  return (
    <>
      <div className="sticky top-2 z-40 mb-4 lg:hidden">
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)]/92 shadow-xl shadow-black/25 backdrop-blur-xl">
          <div className="flex items-center justify-between px-3 py-2.5">
            <Brand compact />
            <Dialog.Root open={mobileOpen} onOpenChange={setMobileOpen}>
              <Dialog.Trigger asChild>
                <button
                  type="button"
                  aria-label="Open menu"
                  className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text)] transition hover:border-[var(--green)]/50"
                >
                  <Menu size={18} />
                </button>
              </Dialog.Trigger>
              <Dialog.Portal>
                <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" />
                <Dialog.Content className="fixed inset-y-0 left-0 z-[60] w-[min(88vw,22rem)] border-r border-[var(--border)] bg-[var(--surface)] shadow-2xl shadow-black/60 focus:outline-none">
                  <Dialog.Title className="sr-only">Main navigation</Dialog.Title>
                  <Dialog.Description className="sr-only">Enterprise navigation and workspace controls.</Dialog.Description>
                  <button
                    type="button"
                    aria-label="Close menu"
                    onClick={() => setMobileOpen(false)}
                    className="absolute right-3 top-3 inline-flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text)]"
                  >
                    <X size={16} />
                  </button>
                  <SidebarPanel
                    pathname={pathname}
                    groups={visibleGroups}
                    username={user?.username}
                    role={user?.role}
                    summary={summary}
                    onSignOut={handleSignOut}
                    onNavigate={() => setMobileOpen(false)}
                  />
                </Dialog.Content>
              </Dialog.Portal>
            </Dialog.Root>
          </div>
        </div>
      </div>

      <aside className="hidden lg:block lg:w-[19rem] lg:shrink-0">
        <div className="sticky top-4 h-[calc(100vh-2rem)] overflow-hidden rounded-3xl border border-[var(--border)] bg-[var(--surface)]/92 shadow-2xl shadow-black/30 backdrop-blur-xl">
          <SidebarPanel
            pathname={pathname}
            groups={visibleGroups}
            username={user?.username}
            role={user?.role}
            summary={summary}
            onSignOut={handleSignOut}
          />
        </div>
      </aside>
    </>
  );
}
