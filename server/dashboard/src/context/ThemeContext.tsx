// ── Theme Context: light/dark/auto with prefers-color-scheme listener ───

import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react';

export type ThemeMode = 'auto' | 'light' | 'dark';

const STORAGE_KEY = 'dashboard_theme';

function resolve(mode: ThemeMode): 'light' | 'dark' {
  if (mode === 'auto') return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  return mode;
}

interface ThemeCtx {
  mode: ThemeMode;
  setMode: (m: ThemeMode) => void;
  resolved: 'light' | 'dark';
}

// eslint-disable-next-line @typescript-eslint/no-empty-function
const noopTheme = () => {};
const ThemeContext = createContext<ThemeCtx>({ mode: 'auto', setMode: noopTheme, resolved: 'dark' });

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    return (localStorage.getItem(STORAGE_KEY) as ThemeMode | null) ?? 'auto';
  });

  const setMode = useCallback((m: ThemeMode) => {
    localStorage.setItem(STORAGE_KEY, m);
    setModeState(m);
  }, []);

  const resolved = resolve(mode);

  useEffect(() => {
    document.documentElement.dataset.theme = resolved;
  }, [resolved]);

  useEffect(() => {
    if (mode !== 'auto') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => {
      document.documentElement.dataset.theme = e.matches ? 'dark' : 'light';
    };
    mq.addEventListener('change', handler);
    return () => {
      mq.removeEventListener('change', handler);
    };
  }, [mode]);

  return <ThemeContext.Provider value={{ mode, setMode, resolved }}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeCtx {
  return useContext(ThemeContext);
}
