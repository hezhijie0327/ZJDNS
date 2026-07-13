// ── Layout: Header with theme toggle, language switcher ──────────────────

import { useTheme } from '../context/ThemeContext';
import { useT } from '../context/I18nContext';
import { useAuth } from '../context/AuthContext';
import { Sun, Moon, Monitor, Globe, LogOut } from 'lucide-react';
import type { ThemeMode } from '../context/ThemeContext';

const themes: { mode: ThemeMode; icon: typeof Sun; labelKey: string }[] = [
  { mode: 'auto', icon: Monitor, labelKey: 'themeAuto' },
  { mode: 'light', icon: Sun, labelKey: 'themeLight' },
  { mode: 'dark', icon: Moon, labelKey: 'themeDark' },
];

export default function Layout({ refreshStatus, children }: { refreshStatus: string; children: React.ReactNode }) {
  const { mode, setMode } = useTheme();
  const { t, lang, setLang } = useT();
  const { logout } = useAuth();

  return (
    <>
      <div className="header">
        <div className="header-left">
          <h1>{t('title')}</h1>
        </div>
        <div className="header-right">
          <span id="refresh-status">{refreshStatus}</span>
          <button
            className="lang-select"
            onClick={() => {
              setLang(lang === 'en' ? 'zh-CN' : 'en');
            }}
            title={t('themeAuto')}
          >
            <Globe size={14} />
            <span style={{ marginLeft: 4 }}>{lang === 'en' ? 'EN' : '中文'}</span>
          </button>
          <div className="theme-toggle">
            {themes.map(({ mode: m, icon: Icon, labelKey }) => (
              <button
                key={m}
                className={mode === m ? 'active' : ''}
                onClick={() => {
                  setMode(m);
                }}
                title={t(labelKey)}
              >
                <Icon size={14} />
              </button>
            ))}
          </div>
          <button className="lang-select" onClick={logout} title="Logout">
            <LogOut size={14} />
          </button>
        </div>
      </div>
      {children}
    </>
  );
}
