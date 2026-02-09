'use client';

import AuthGuard from '@/components/AuthGuard';
import Nav from '@/components/Nav';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <Nav />
      <div className="min-h-[calc(100vh-3.5rem)]">
        {children}
      </div>
    </AuthGuard>
  );
}
