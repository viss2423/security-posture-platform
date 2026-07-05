import Nav from '@/components/Nav';
import ApiStatusBanner from '@/components/ApiStatusBanner';
import FilterBar from '@/components/FilterBar';
import ViewerPreviewGate from '@/components/ViewerPreviewGate';
import WorkspaceRail from '@/components/WorkspaceRail';
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

  const scoreNum = summary?.posture_score_avg != null ? Math.round(Number(summary.posture_score_avg)) : null;
  const stripColor =
    scoreNum == null ? 'var(--surface-elevated)' :
    scoreNum >= 75   ? 'var(--green)' :
    scoreNum >= 50   ? 'var(--amber)' :
    'var(--red)';

  return (
    <AuthProvider initialUser={user}>
      {/* Nav renders fixed elements (icon rail + secondary panel + mobile bar) */}
      <Nav initialSummary={summary} />

      {/* Content area — pl-12 leaves room for the fixed 48px icon rail on desktop */}
      <div className="min-h-screen pl-0 pt-12 lg:pl-12 lg:pt-0">
        {/* 3px posture status strip — pulses when score is critical */}
        <div
          className={`h-[3px] w-full transition-colors duration-700${scoreNum != null && scoreNum < 50 ? ' animate-pulse' : ''}`}
          style={{ background: stripColor }}
        />
        <ApiStatusBanner />
        <div className="mx-auto max-w-[1600px] p-4 sm:p-6 lg:p-8">
          <FilterBar />
          <div className="mt-5 flex gap-6 xl:items-start">
            <div className="min-w-0 flex-1 space-y-5">
              <ViewerPreviewGate>{children}</ViewerPreviewGate>
            </div>
            <WorkspaceRail summary={summary} />
          </div>
        </div>
      </div>
    </AuthProvider>
  );
}
