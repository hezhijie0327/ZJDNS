// ── I18n Context: locale loading, t(), language switching ────────────────

import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';

type LocaleMap = Record<string, string>;

interface I18nCtx {
  t: (key: string) => string;
  lang: string;
  setLang: (l: string) => void;
}

// eslint-disable-next-line @typescript-eslint/no-empty-function
const noopI18n = () => {};
const I18nContext = createContext<I18nCtx>({ t: (k) => k, lang: 'en', setLang: noopI18n });

function detectLanguage(): string {
  const stored = localStorage.getItem('dashboard_lang');
  if (stored) return stored;
  const nav = navigator.language || '';
  if (nav.startsWith('zh')) return 'zh-CN';
  return 'en';
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<LocaleMap>({});
  const [lang, setLangState] = useState<string>(detectLanguage);

  const t = useCallback((key: string) => locale[key] || key, [locale]);

  const setLang = useCallback((l: string) => {
    localStorage.setItem('dashboard_lang', l);
    setLangState(l);
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetch('/locales/' + lang + '.json')
      .then((r) => r.json())
      .then((data: unknown) => {
        if (!cancelled) setLocale(data as LocaleMap);
      })
      .catch(() => {
        if (!cancelled && lang !== 'en') setLang('en');
      });
    document.documentElement.lang = lang;
    return () => {
      cancelled = true;
    };
  }, [lang, setLang]);

  useEffect(() => {
    document.title = locale.title || 'ZJDNS Dashboard';
  }, [locale]);

  return <I18nContext.Provider value={{ t, lang, setLang }}>{children}</I18nContext.Provider>;
}

export function useT(): I18nCtx {
  return useContext(I18nContext);
}
