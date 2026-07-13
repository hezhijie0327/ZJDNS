// ── ZJDNS Dashboard Entry Point ──────────────────────────────────────────

import './style.css';
import { initI18n } from './i18n';
import { initTheme } from './theme';
import { initSearch } from './search';
import { refreshAll } from './api';

async function init(): Promise<void> {
  initTheme();
  await initI18n();
  initSearch();

  // Listen for custom refresh events (triggered by search/pagination)
  document.addEventListener('dashboard:refresh', () => {
    void refreshAll();
  });

  // Initial load + auto-refresh every 30s
  await refreshAll();
  setInterval(refreshAll, 30000);
}

document.addEventListener('DOMContentLoaded', () => {
  void init();
});
