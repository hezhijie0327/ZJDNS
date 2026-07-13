// ── Theme: light/dark/auto with prefers-color-scheme listener ────────────

export type ThemeMode = 'auto' | 'light' | 'dark';

const STORAGE_KEY = 'dashboard_theme';

let mediaQueryList: MediaQueryList | null = null;

function resolveTheme(mode: ThemeMode): 'light' | 'dark' {
  if (mode === 'auto') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return mode;
}

/** Apply a theme mode. Persists to localStorage and updates DOM. */
export function applyTheme(mode: ThemeMode): void {
  const resolved = resolveTheme(mode);
  document.documentElement.dataset.theme = resolved;
  localStorage.setItem(STORAGE_KEY, mode);

  // Highlight the active toggle button
  document.querySelectorAll<HTMLButtonElement>('.theme-toggle button').forEach((btn) => {
    btn.classList.toggle('active', btn.getAttribute('data-theme') === mode);
  });
}

function onMediaChange(e: MediaQueryListEvent): void {
  const mode = (localStorage.getItem(STORAGE_KEY) ?? 'dark') as ThemeMode;
  if (mode === 'auto') {
    document.documentElement.dataset.theme = e.matches ? 'dark' : 'light';
  }
}

function attachMediaListener(): void {
  if (!mediaQueryList) {
    mediaQueryList = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQueryList.addEventListener('change', onMediaChange);
  }
}

function detachMediaListener(): void {
  if (mediaQueryList) {
    mediaQueryList.removeEventListener('change', onMediaChange);
    mediaQueryList = null;
  }
}

/** Initialize theme: read stored preference, apply, bind toggle buttons. */
export function initTheme(): void {
  const stored = (localStorage.getItem(STORAGE_KEY) ?? 'dark') as ThemeMode;
  applyTheme(stored);
  if (stored === 'auto') attachMediaListener();

  // Bind theme toggle buttons
  document.querySelectorAll<HTMLButtonElement>('.theme-toggle button').forEach((btn) => {
    btn.addEventListener('click', () => {
      const mode = btn.getAttribute('data-theme') as ThemeMode;
      applyTheme(mode);
      if (mode === 'auto') {
        attachMediaListener();
      } else {
        detachMediaListener();
      }
    });
  });
}
