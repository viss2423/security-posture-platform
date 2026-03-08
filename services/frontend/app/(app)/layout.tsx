import Nav from '@/components/Nav';
import ApiStatusBanner from '@/components/ApiStatusBanner';
import FilterBar from '@/components/FilterBar';
import AppTopBar from '@/components/AppTopBar';
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
      <div className="relative min-h-screen w-full overflow-x-clip px-2 py-3 sm:px-4 lg:px-6 xl:px-8 2xl:px-10">
        <div className="pointer-events-none absolute -left-20 top-0 h-80 w-80 rounded-full bg-cyan-400/12 blur-3xl" />
        <div className="pointer-events-none absolute -right-20 top-8 h-96 w-96 rounded-full bg-emerald-400/10 blur-3xl" />
        <div className="pointer-events-none absolute bottom-10 left-1/2 h-64 w-64 -translate-x-1/2 rounded-full bg-orange-400/8 blur-3xl" />
        <div className="pointer-events-none absolute inset-x-20 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/60 to-transparent" />
        <div className="relative mx-auto max-w-[1760px] lg:flex lg:gap-6 xl:gap-8">
          <Nav initialSummary={summary} />
          <div className="min-w-0 flex-1">
            <AppTopBar />
            <FilterBar />
            <div className="pb-14">{children}</div>
          </div>
        </div>
      </div>
    </AuthProvider>
  );
}
