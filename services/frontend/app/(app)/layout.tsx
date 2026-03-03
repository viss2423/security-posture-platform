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
      <div className="mx-auto min-h-screen w-full max-w-[1560px] px-3 py-3 sm:px-4 lg:px-5">
        <div className="lg:flex lg:gap-5">
          <Nav initialSummary={summary} />
          <div className="min-w-0 flex-1">
            <AppTopBar />
            <FilterBar />
            <div className="pb-10">{children}</div>
          </div>
        </div>
      </div>
    </AuthProvider>
  );
}
