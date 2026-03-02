'use client';

import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { getMe, getToken, type Me } from '@/lib/api';

type AuthState = {
  user: Me | null;
  loading: boolean;
  canMutate: boolean;
  isAdmin: boolean;
  refresh: () => void;
};

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  canMutate: false,
  isAdmin: false,
  refresh: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchUser = useCallback(() => {
    if (!getToken()) {
      setUser(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    getMe()
      .then((me) => setUser(me))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const role = user?.role?.toLowerCase() ?? '';
  const canMutate = role === 'admin' || role === 'analyst';
  const isAdmin = role === 'admin';

  return (
    <AuthContext.Provider value={{ user, loading, canMutate, isAdmin, refresh: fetchUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
