// ── Auth Context: JWT token management, login/logout ─────────────────────

import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';

const TOKEN_KEY = 'dashboard_token';

interface AuthCtx {
  token: string | null;
  isAuthenticated: boolean;
  authEnabled: boolean | null; // null = checking
  login: (token: string) => void;
  logout: () => void;
}

// eslint-disable-next-line @typescript-eslint/no-empty-function
const noop = () => {};

const AuthContext = createContext<AuthCtx>({
  token: null,
  isAuthenticated: false,
  authEnabled: null,
  login: noop,
  logout: noop,
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY));
  const [authEnabled, setAuthEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    // Check if auth endpoint exists — 405 = exists (wrong method), 404 = not configured
    fetch('/api/auth/login', { method: 'GET' })
      .then((r) => {
        setAuthEnabled(r.status !== 404);
      })
      .catch(() => {
        setAuthEnabled(false);
      });
  }, []);

  const login = useCallback((t: string) => {
    localStorage.setItem(TOKEN_KEY, t);
    setToken(t);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
  }, []);

  const isAuthenticated = authEnabled === false || !!token; // no auth → always authenticated

  return (
    <AuthContext.Provider value={{ token, isAuthenticated, authEnabled, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthCtx {
  return useContext(AuthContext);
}
