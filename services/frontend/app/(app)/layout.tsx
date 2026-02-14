'use client';

import AuthGuard from '@/components/AuthGuard';
import Nav from '@/components/Nav';
import ApiStatusBanner from '@/components/ApiStatusBanner';
import FilterBar from '@/components/FilterBar';
import { AuthProvider } from '@/contexts/AuthContext';
import { FilterProvider } from '@/contexts/FilterContext';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <AuthProvider>
        <FilterProvider>
          <ApiStatusBanner />
          <Nav />
          <FilterBar />
          <div className="min-h-[calc(100vh-4rem)]">
            {children}
          </div>
        </FilterProvider>
      </AuthProvider>
    </AuthGuard>
  );
}
