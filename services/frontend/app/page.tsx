import { redirect } from 'next/navigation';
import type { OverviewResponse } from '@/lib/api';
import { getServerSession } from '@/lib/session';
import { withServerSession } from '@/lib/session';

export default async function Home() {
  const user = await getServerSession();
  if (!user) {
    redirect('/login');
  }

  try {
    const overview = await withServerSession<OverviewResponse>('/posture/overview', {
      cache: 'no-store',
    });
    if ((overview.executive_strip?.total_assets ?? 0) === 0) {
      redirect('/onboarding');
    }
  } catch {
    // Fall back to overview when the bootstrap probe cannot complete.
  }

  redirect('/overview');
}
