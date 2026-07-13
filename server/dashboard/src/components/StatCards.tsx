// ── StatCards: 4 overview stat cards ──────────────────────────────────────

import { useT } from '../context/I18nContext';
import { Database, Zap, Clock, Activity } from 'lucide-react';
import { fmt, fmtPct, fmtMs } from '../helpers';
import type { OverviewResponse } from '../types';

const cards = [
  { key: 'totalQueries', icon: Zap, color: 'var(--blue)', field: 'total_queries' as const },
  { key: 'hitRate', icon: Activity, color: 'var(--green)', field: 'hit_rate' as const, fmt: (v: number) => fmtPct(v) },
  {
    key: 'avgResponse',
    icon: Clock,
    color: 'var(--purple)',
    field: 'avg_response_ms' as const,
    fmt: (v: number) => fmtMs(v),
  },
  { key: 'cacheEntries', icon: Database, color: 'var(--orange)', field: 'entries' as const },
];

export default function StatCards({ data }: { data: OverviewResponse | null }) {
  const { t } = useT();

  return (
    <div className="grid">
      {cards.map(({ key, icon: Icon, color, field, fmt: fmtFn }) => (
        <div className="card" key={key}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <Icon size={18} color={color} />
            <div className="stat-val" style={{ color }}>
              {data ? (fmtFn ? fmtFn(data[field]) : fmt(data[field])) : '--'}
            </div>
          </div>
          <div className="stat-label">{t(key)}</div>
        </div>
      ))}
    </div>
  );
}
