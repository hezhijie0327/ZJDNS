// ── SearchBar: search input + result filter ──────────────────────────────

import { Search } from 'lucide-react';
import { useT } from '../context/I18nContext';

interface Props {
  searchTerm: string;
  resultFilter: string;
  onSearchChange: (v: string) => void;
  onFilterChange: (v: string) => void;
}

export default function SearchBar({ searchTerm, resultFilter, onSearchChange, onFilterChange }: Props) {
  const { t } = useT();

  return (
    <div className="log-toolbar">
      <div style={{ position: 'relative', flex: 1, minWidth: 180 }}>
        <Search size={14} style={{ position: 'absolute', left: 8, top: 7, color: 'var(--dim)' }} />
        <input
          type="search"
          className="search-input"
          placeholder={t('searchPlaceholder')}
          value={searchTerm}
          onChange={(e) => {
            onSearchChange(e.target.value);
          }}
          style={{ paddingLeft: 28 }}
        />
      </div>
      <select
        className="filter-select"
        value={resultFilter}
        onChange={(e) => {
          onFilterChange(e.target.value);
        }}
      >
        <option value="">{t('allResults')}</option>
        <option value="miss">miss</option>
        <option value="hit">hit</option>
        <option value="stale">stale</option>
        <option value="zone">zone</option>
        <option value="error">error</option>
        <option value="blocked">blocked</option>
        <option value="badcookie">badcookie</option>
      </select>
    </div>
  );
}
