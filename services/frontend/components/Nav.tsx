'use client';

import {
  Activity,
  Archive,
  BarChart3,
  Bell,
  BrainCircuit,
  Briefcase,
  Bug,
  Gamepad2,
  LogOut,
  Menu,
  Radar,
  Scale,
  ScrollText,
  Shield,
  ShieldAlert,
  Sparkles,
  Users,
  X,
  type LucideIcon,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useMemo, useState } from 'react';
import CommandPalette from '@/components/CommandPalette';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/cn';
import { logout, type PostureSummary } from '@/lib/api';
import {
  getActiveNavItem,
  getVisibleNavGroups,
  isActivePath,
  type NavGroup,
  type NavIconKey,
  type NavItem,
} from '@/lib/navigation';

const ICONS: Record<NavIconKey, LucideIcon> = {
  activity: Activity,
  dashboard: BarChart3,
  assets: Archive,
  surface: Radar,
  graph: Radar,
  intel: Radar,
  telemetry: Activity,
  detections: ScrollText,
  automation: Briefcase,
  attack: ShieldAlert,
  range: Gamepad2,
  findings: Bug,
  alerts: Bell,
  incidents: ShieldAlert,
  suppression: Shield,
  jobs: Briefcase,
  reports: BarChart3,
  policy: Scale,
  audit: ScrollText,
  users: Users,
  ml: BrainCircuit,
};

function BrandBlock() {
  return (
    <Link href="/overview" className="inline-flex items-center gap-4 rounded-[1.25rem]">
      <span className="inline-flex h-14 w-14 items-center justify-center rounded-[1.25rem] border border-white/15 bg-white/10 text-lg font-black uppercase tracking-[0.18em] text-white shadow-[0_18px_40px_-22px_rgba(0,0,0,0.45)] backdrop-blur-md">
        SP
      </span>
      <span className="min-w-0">
        <span className="block text-lg font-semibold tracking-[-0.03em] text-white">
          SecPlat
        </span>
        <span className="block text-[11px] uppercase tracking-[0.2em] text-white/60">
          Customer Security Platform
        </span>
      </span>
    </Link>
  );
}

function OverviewMetric({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div className="rounded-[1.1rem] border border-white/10 bg-white/7 px-4 py-3 backdrop-blur-md">
      <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-white/58">
        {label}
      </p>
      <p className="mt-2 text-2xl font-semibold leading-none text-white">{value}</p>
    </div>
  );
}

function GroupChips({
  group,
  pathname,
}: {
  group: NavGroup;
  pathname: string;
}) {
  return (
    <section className="rounded-[1.45rem] border border-[var(--border)] bg-[rgba(255,255,255,0.76)] p-3 shadow-[var(--shadow-soft)] backdrop-blur-xl">
      <div className="flex items-center justify-between gap-3">
        <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[var(--muted)]">
          {group.title}
        </p>
        <span className="rounded-full border border-[var(--border)] bg-white/80 px-2 py-0.5 text-[10px] text-[var(--muted)]">
          {group.items.length}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {group.items.map((item) => {
          const Icon = ICONS[item.icon];
          const active = isActivePath(pathname, item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'inline-flex items-center gap-2 rounded-full border px-3 py-2 text-xs transition',
                active
                  ? 'border-cyan-300/24 bg-cyan-300/10 text-[var(--cyan-strong)]'
                  : 'border-[var(--border)] bg-white/88 text-[var(--text-muted)] hover:border-cyan-300/20 hover:text-[var(--text)]'
              )}
            >
              <Icon size={13} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </div>
    </section>
  );
}

function DrawerList({
  items,
  pathname,
  onNavigate,
}: {
  items: NavItem[];
  pathname: string;
  onNavigate: () => void;
}) {
  return (
    <div className="space-y-2">
      {items.map((item) => {
        const Icon = ICONS[item.icon];
        const active = isActivePath(pathname, item.href);
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onNavigate}
            className={cn(
              'flex items-start gap-3 rounded-[1.25rem] border px-3.5 py-3 transition',
              active
                ? 'border-cyan-300/24 bg-cyan-300/10'
                : 'border-[var(--border)] bg-white/86 hover:border-cyan-300/20'
            )}
          >
            <span
              className={cn(
                'mt-0.5 inline-flex h-9 w-9 items-center justify-center rounded-[0.95rem] border',
                active
                  ? 'border-cyan-300/24 bg-cyan-300/10 text-[var(--cyan-strong)]'
                  : 'border-[var(--border)] bg-[var(--surface-soft)] text-[var(--muted)]'
              )}
            >
              <Icon size={16} />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-semibold text-[var(--text)]">{item.label}</span>
              <span className="mt-1 block text-xs leading-5 text-[var(--text-muted)]">
                {item.description}
              </span>
            </span>
          </Link>
        );
      })}
    </div>
  );
}

export default function Nav({ initialSummary }: { initialSummary: PostureSummary | null }) {
  const pathname = usePathname();
  const { isAdmin, user } = useAuth();
  const [open, setOpen] = useState(false);
  const visibleGroups = useMemo(() => getVisibleNavGroups(isAdmin), [isAdmin]);
  const active = useMemo(() => getActiveNavItem(pathname, isAdmin), [pathname, isAdmin]);

  const score =
    initialSummary?.posture_score_avg != null
      ? Math.round(Number(initialSummary.posture_score_avg))
      : '--';
  const alertPressure = initialSummary?.red ?? 0;
  const attentionItems = (initialSummary?.red ?? 0) + (initialSummary?.amber ?? 0);

  const handleSignOut = async () => {
    try {
      await logout();
    } finally {
      window.location.href = '/login';
    }
  };

  return (
    <>
      <header className="relative z-20">
        <div className="relative overflow-hidden rounded-[2.3rem] border border-[var(--border)] bg-[rgba(255,255,255,0.78)] p-4 shadow-[var(--shadow-heavy)] backdrop-blur-2xl sm:p-5">
          <div className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-cyan-200/55 to-transparent" />
          <div className="pointer-events-none absolute -left-16 top-16 h-44 w-44 rounded-full bg-cyan-300/10 blur-3xl" />
          <div className="pointer-events-none absolute right-[-2rem] top-[-1rem] h-44 w-44 rounded-full bg-emerald-300/10 blur-3xl" />

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(22rem,0.8fr)]">
            <section className="relative overflow-hidden rounded-[1.9rem] bg-[linear-gradient(135deg,#08111c_0%,#12233c_36%,#0d5f8f_100%)] px-5 py-5 text-white sm:px-6 sm:py-6">
              <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(255,255,255,0.16),transparent_34%),radial-gradient(circle_at_bottom_left,rgba(31,183,166,0.18),transparent_32%)]" />
              <div className="relative">
                <div className="flex items-start justify-between gap-4">
                  <BrandBlock />
                  <button
                    type="button"
                    onClick={() => setOpen(true)}
                    className="inline-flex h-11 w-11 items-center justify-center rounded-[1rem] border border-white/12 bg-white/10 text-white transition hover:bg-white/16 lg:hidden"
                    aria-label="Open navigation"
                  >
                    <Menu size={18} />
                  </button>
                </div>

                <div className="mt-6 flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-white/12 bg-white/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-white/78">
                    <Sparkles size={10} />
                    New customer portal
                  </span>
                  <span className="inline-flex rounded-full border border-white/12 bg-white/8 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-white/58">
                    Component-gallery inspired
                  </span>
                </div>

                <div className="mt-5 max-w-3xl">
                  <p className="text-[2.45rem] leading-[0.92] tracking-[-0.06em] text-white sm:text-[3.1rem]">
                    A clearer product story for customers.
                  </p>
                  <p className="mt-4 max-w-2xl text-sm leading-7 text-white/74 sm:text-base">
                    {active?.description ??
                      'See coverage, priorities, and proof of progress without decoding an internal operations console.'}
                  </p>
                </div>

                <div className="mt-5 grid gap-3 sm:grid-cols-3">
                  <OverviewMetric label="Security Score" value={score} />
                  <OverviewMetric label="Needs Attention" value={attentionItems} />
                  <OverviewMetric label="Live Pressure" value={alertPressure} />
                </div>
              </div>
            </section>

            <section className="grid gap-3">
              <div className="rounded-[1.65rem] border border-[var(--border)] bg-[rgba(255,255,255,0.9)] p-4 shadow-[var(--shadow-soft)]">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[var(--muted)]">
                      Current page
                    </p>
                    <p className="mt-2 text-[1.65rem] leading-none tracking-[-0.05em] text-[var(--text)]">
                      {active?.label ?? 'Executive Overview'}
                    </p>
                    <p className="mt-3 max-w-xl text-sm leading-6 text-[var(--text-muted)]">
                      Jump anywhere, then use the page itself to explain risk, progress, and next
                      steps.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setOpen(true)}
                    className="hidden h-11 w-11 items-center justify-center rounded-[1rem] border border-[var(--border)] bg-[var(--surface-soft)] text-[var(--text)] transition hover:border-cyan-300/20 hover:text-[var(--cyan-strong)] lg:inline-flex"
                    aria-label="Open navigation"
                  >
                    <Menu size={18} />
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-2">
                  <CommandPalette isAdmin={isAdmin} />
                  <Link href="/reports" className="btn-secondary">
                    Share reporting
                  </Link>
                  <Link href="/incidents" className="btn-secondary">
                    Review response
                  </Link>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-[1.4rem] border border-[var(--border)] bg-[rgba(255,255,255,0.9)] p-4 shadow-[var(--shadow-soft)]">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
                    Customer focus
                  </p>
                  <p className="mt-2 text-sm font-medium leading-6 text-[var(--text)]">
                    Coverage, risk, and proof of progress.
                  </p>
                </div>
                <div className="rounded-[1.4rem] border border-[var(--border)] bg-[rgba(255,255,255,0.9)] p-4 shadow-[var(--shadow-soft)]">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
                    Signed in as
                  </p>
                  <p className="mt-2 truncate text-sm font-medium text-[var(--text)]">
                    {user?.username || 'operator'}
                  </p>
                  <p className="mt-1 text-xs uppercase tracking-[0.18em] text-[var(--muted)]">
                    {user?.role || 'viewer'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleSignOut}
                  className="flex items-center justify-between rounded-[1.4rem] border border-[var(--border)] bg-[rgba(255,255,255,0.9)] p-4 text-left shadow-[var(--shadow-soft)] transition hover:border-cyan-300/20 hover:text-[var(--text)]"
                >
                  <span>
                    <span className="block text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
                      Session
                    </span>
                    <span className="mt-2 block text-sm font-medium text-[var(--text)]">
                      Sign out
                    </span>
                  </span>
                  <LogOut size={16} className="text-[var(--muted)]" />
                </button>
              </div>
            </section>
          </div>

          <div className="mt-4 hidden gap-3 lg:grid xl:grid-cols-4">
            {visibleGroups.map((group) => (
              <GroupChips key={group.title} group={group} pathname={pathname} />
            ))}
          </div>
        </div>
      </header>

      {open && (
        <>
          <button
            type="button"
            className="fixed inset-0 z-[70] bg-[rgba(14,18,28,0.22)] backdrop-blur-md"
            onClick={() => setOpen(false)}
            aria-label="Close navigation"
          />
          <aside className="fixed inset-y-0 right-0 z-[80] flex w-[min(94vw,34rem)] flex-col border-l border-[var(--border)] bg-[rgba(248,244,237,0.98)] shadow-[0_36px_90px_-28px_rgba(14,18,28,0.24)]">
            <div className="flex items-center justify-between border-b border-[var(--border)] px-5 py-4">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
                  Browse product
                </p>
                <p className="mt-2 text-3xl leading-none tracking-[-0.05em] text-[var(--text)]">
                  All pages
                </p>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="inline-flex h-10 w-10 items-center justify-center rounded-[1rem] border border-[var(--border)] bg-white text-[var(--text)] transition hover:border-cyan-300/22"
                aria-label="Close navigation"
              >
                <X size={16} />
              </button>
            </div>

            <div className="min-h-0 flex-1 space-y-6 overflow-y-auto px-5 py-5">
              {visibleGroups.map((group) => (
                <section key={group.title}>
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[var(--muted)]">
                      {group.title}
                    </p>
                    <span className="rounded-full border border-[var(--border)] bg-white/86 px-2 py-0.5 text-[10px] text-[var(--muted)]">
                      {group.items.length}
                    </span>
                  </div>
                  <DrawerList
                    items={group.items}
                    pathname={pathname}
                    onNavigate={() => setOpen(false)}
                  />
                </section>
              ))}
            </div>

            <div className="border-t border-[var(--border)] px-5 py-4">
              <button
                type="button"
                onClick={handleSignOut}
                className="flex w-full items-center justify-center gap-2 rounded-[1rem] border border-[var(--border)] bg-white px-3 py-2.5 text-sm text-[var(--text-muted)] transition hover:border-cyan-300/20 hover:text-[var(--text)]"
              >
                <LogOut size={14} />
                Sign out
              </button>
            </div>
          </aside>
        </>
      )}
    </>
  );
}
