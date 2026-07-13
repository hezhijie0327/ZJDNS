// ── LoginPage: JWT authentication form ────────────────────────────────────

import { useState, type SyntheticEvent } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useT } from '../context/I18nContext';
import { useTheme } from '../context/ThemeContext';
import { Sun, Moon, Monitor, Globe, LogIn } from 'lucide-react';
import type { ThemeMode } from '../context/ThemeContext';

const themes: { mode: ThemeMode; icon: typeof Sun; labelKey: string }[] = [
  { mode: 'auto', icon: Monitor, labelKey: 'themeAuto' },
  { mode: 'light', icon: Sun, labelKey: 'themeLight' },
  { mode: 'dark', icon: Moon, labelKey: 'themeDark' },
];

export default function LoginPage() {
  const { t, lang, setLang } = useT();
  const { mode, setMode } = useTheme();
  const { login, authEnabled } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Auth disabled → skip login
  if (authEnabled === false) return <Navigate to="/" replace />;

  // Still checking
  if (authEnabled === null) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          height: '100vh',
          color: 'var(--dim)',
        }}
      >
        …
      </div>
    );
  }

  function handleSubmit(e: SyntheticEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
      .then(async (r) => {
        if (!r.ok) {
          setError(t('loginError'));
          return;
        }
        const data = (await r.json()) as { token: string };
        login(data.token);
        void navigate('/', { replace: true });
      })
      .catch(() => {
        setError(t('loginNetworkError'));
      })
      .finally(() => {
        setLoading(false);
      });
  }

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
      <div className="card" style={{ width: 360, maxWidth: '90vw' }}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, marginBottom: 20 }}>
          <button
            className="lang-select"
            onClick={() => {
              setLang(lang === 'en' ? 'zh-CN' : 'en');
            }}
            title="Language"
          >
            <Globe size={14} />
            <span style={{ marginLeft: 4, fontSize: 12 }}>{lang === 'en' ? 'EN' : '中文'}</span>
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
        </div>

        <h1 style={{ textAlign: 'center', marginBottom: 24 }}>{t('title')}</h1>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 12 }}>
            <input
              className="search-input"
              style={{ width: '100%' }}
              type="text"
              placeholder={t('loginUsername')}
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
              }}
              autoFocus
            />
          </div>
          <div style={{ marginBottom: 16 }}>
            <input
              className="search-input"
              style={{ width: '100%' }}
              type="password"
              placeholder={t('loginPassword')}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />
          </div>
          {error && (
            <div className="error" style={{ marginBottom: 12 }}>
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading || !username || !password}
            style={{
              width: '100%',
              padding: '8px 16px',
              background: 'var(--blue)',
              color: '#fff',
              border: 'none',
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 14,
              fontWeight: 600,
              opacity: loading ? 0.6 : 1,
            }}
          >
            <LogIn size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
            {loading ? '…' : t('loginButton')}
          </button>
        </form>
      </div>
    </div>
  );
}
