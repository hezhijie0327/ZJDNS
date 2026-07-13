// ── i18n: locale loading, translation, language switching ────────────────

import { $ } from './helpers';

let currentLocale: Record<string, string> = {};
let currentLang = 'en';

/** Lookup a translation key. Returns the key itself if not found. */
export function t(key: string): string {
  return currentLocale[key] || key;
}

export function getCurrentLang(): string {
  return currentLang;
}

/** Detect preferred language: localStorage → navigator → 'en'. */
function detectLanguage(): string {
  const stored = localStorage.getItem('dashboard_lang');
  if (stored) return stored;
  const nav = navigator.language || '';
  if (nav.startsWith('zh')) return 'zh-CN';
  return 'en';
}

/** Fetch and activate a locale JSON file. Falls back to English on error. */
async function loadLocale(lang: string): Promise<boolean> {
  try {
    const resp = await fetch('/locales/' + lang + '.json');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    currentLocale = (await resp.json()) as Record<string, string>;
    currentLang = lang;
    localStorage.setItem('dashboard_lang', lang);
    document.documentElement.lang = lang;
    return true;
  } catch {
    if (lang !== 'en') return loadLocale('en');
    currentLocale = {};
    return false;
  }
}

/** Walk all [data-i18n] elements and update their text/placeholder. */
function applyTranslations(): void {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n')!;
    const translated = t(key);
    if (el instanceof HTMLInputElement && el.type === 'search') {
      el.placeholder = translated;
    } else {
      el.textContent = translated;
    }
  });
  document.title = t('title');
}

/** Switch to a new language and refresh the UI. */
export async function switchLanguage(lang: string): Promise<void> {
  if (lang === currentLang) return;
  await loadLocale(lang);
  applyTranslations();
}

/** Initialize i18n: detect language, load locale, apply translations. */
export async function initI18n(): Promise<void> {
  const lang = detectLanguage();
  await loadLocale(lang);
  applyTranslations();

  // Bind language switcher
  $('lang-select').addEventListener('change', function (this: HTMLSelectElement) {
    void switchLanguage(this.value);
  });
  const sel = $('lang-select') as HTMLSelectElement;
  sel.value = currentLang;
}
