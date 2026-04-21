import Nav from '@/components/Nav';
import ApiStatusBanner from '@/components/ApiStatusBanner';
import FilterBar from '@/components/FilterBar';
import { AuthProvider } from '@/contexts/AuthContext';
import type { PostureSummary } from '@/lib/api';
import { requireServerSession, withServerSession } from '@/lib/session';

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const user = await requireServerSession();
  let summary: PostureSummary | null = null;

  try {
    summary = await withServerSession<PostureSummary>('/posture/summary', {
      cache: 'no-store',
    });
  } catch {
    summary = null;
  }

  return (
    <AuthProvider initialUser={user}>
      <ApiStatusBanner />
      <div className="relative min-h-screen w-full overflow-x-clip px-3 py-4 sm:px-5 lg:px-6 xl:px-8 2xl:px-10">
        <div className="pointer-events-none absolute inset-x-0 top-0 h-[24rem] bg-[radial-gradient(circle_at_top_left,rgba(22,142,196,0.14),transparent_42%),radial-gradient(circle_at_top_right,rgba(31,183,166,0.12),transparent_38%)]" />
        <div className="pointer-events-none absolute left-[-6rem] top-24 h-[26rem] w-[26rem] rounded-full bg-cyan-300/12 blur-3xl" />
        <div className="pointer-events-none absolute right-[-5rem] top-10 h-[28rem] w-[28rem] rounded-full bg-emerald-300/10 blur-3xl" />
        <div className="pointer-events-none absolute bottom-[-6rem] left-[22%] h-[24rem] w-[24rem] rounded-full bg-orange-300/10 blur-3xl" />
        <div className="pointer-events-none absolute inset-x-[8%] top-[14rem] h-px bg-gradient-to-r from-transparent via-cyan-200/50 to-transparent" />

        <div className="relative mx-auto max-w-[1880px] space-y-5 pb-10">
          <Nav initialSummary={summary} />
          <div className="space-y-5">
            <FilterBar />
            <div className="rounded-[2.2rem] border border-[var(--border)] bg-[rgba(255,255,255,0.72)] p-2 shadow-[var(--shadow-heavy)] backdrop-blur-2xl sm:p-3">
              <div className="rounded-[1.7rem] border border-white/55 bg-[linear-gradient(180deg,rgba(255,255,255,0.92),rgba(247,243,237,0.82))] px-1 py-2 sm:px-2 sm:py-3">
                <div className="relative pb-8">{children}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AuthProvider>
  );
}
