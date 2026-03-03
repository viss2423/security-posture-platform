'use client';

import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { getMe, type Me } from '@/lib/api';

type AuthUser = Me & {
  canMutate: boolean;
  isAdmin: boolean;
};

type AuthState = {
  user: AuthUser | null;
  loading: boolean;
  canMutate: boolean;
  isAdmin: boolean;
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthState>({
  user: null,
  loading: false,
  canMutate: false,
  isAdmin: false,
  refresh: async () => {},
});

function withCapabilities(user: Me | null): AuthUser | null {
  if (!user) return null;
  const role = user.role?.toLowerCase() ?? '';
  return {
    ...user,
    canMutate: role === 'admin' || role === 'analyst',
    isAdmin: role === 'admin',
  };
}

export function AuthProvider({
  children,
  initialUser = null,
}: {
  children: React.ReactNode;
  initialUser?: AuthUser | null;
}) {
  const [user, setUser] = useState<AuthUser | null>(initialUser);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setUser(initialUser);
    setLoading(false);
  }, [initialUser]);

  const fetchUser = useCallback(async () => {
    setLoading(true);
    try {
      const me = await getMe();
      setUser(withCapabilities(me));
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const canMutate = user?.canMutate ?? false;
  const isAdmin = user?.isAdmin ?? false;

  return (
    <AuthContext.Provider value={{ user, loading, canMutate, isAdmin, refresh: fetchUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
