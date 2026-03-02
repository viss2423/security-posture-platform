'use client';

import AuthGuard from '@/components/AuthGuard';
import Nav from '@/components/Nav';
import ApiStatusBanner from '@/components/ApiStatusBanner';
import FilterBar from '@/components/FilterBar';
import AppTopBar from '@/components/AppTopBar';
import PageTransition from '@/components/PageTransition';
import { AuthProvider } from '@/contexts/AuthContext';
import { FilterProvider } from '@/contexts/FilterContext';

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <AuthProvider>
        <FilterProvider>
          <ApiStatusBanner />
          <div className="mx-auto min-h-screen w-full max-w-[1640px] px-3 py-3 sm:px-4 lg:px-6">
            <div className="lg:flex lg:gap-4">
              <Nav />
              <div className="min-w-0 flex-1">
                <AppTopBar />
                <FilterBar />
                <div className="pb-10">
                  <PageTransition>{children}</PageTransition>
                </div>
              </div>
            </div>
          </div>
        </FilterProvider>
      </AuthProvider>
    </AuthGuard>
  );
}
