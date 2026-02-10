'use client';

import AuthGuard from '@/components/AuthGuard';
import Nav from '@/components/Nav';
import ApiStatusBanner from '@/components/ApiStatusBanner';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <ApiStatusBanner />
      <Nav />
      <div className="min-h-[calc(100vh-4rem)]">
        {children}
      </div>
    </AuthGuard>
  );
}
