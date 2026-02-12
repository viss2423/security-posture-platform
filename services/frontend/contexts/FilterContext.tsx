'use client';

import { createContext, useCallback, useContext, useState } from 'react';
import type { PostureFilters } from '@/lib/api';

type FilterState = PostureFilters & {
  setFilters: (f: PostureFilters) => void;
  clearFilters: () => void;
};

const defaultFilters: PostureFilters = {};

const FilterContext = createContext<FilterState>({
  ...defaultFilters,
  setFilters: () => {},
  clearFilters: () => {},
});

export function FilterProvider({ children }: { children: React.ReactNode }) {
  const [filters, setFiltersState] = useState<PostureFilters>(defaultFilters);

  const setFilters = useCallback((f: PostureFilters) => {
    setFiltersState((prev) => ({ ...prev, ...f }));
  }, []);

  const clearFilters = useCallback(() => {
    setFiltersState(defaultFilters);
  }, []);

  const value: FilterState = {
    ...filters,
    setFilters,
    clearFilters,
  };

  return <FilterContext.Provider value={value}>{children}</FilterContext.Provider>;
}

export function useFilters(): FilterState {
  const ctx = useContext(FilterContext);
  if (!ctx) throw new Error('useFilters must be used within FilterProvider');
  return ctx;
}
