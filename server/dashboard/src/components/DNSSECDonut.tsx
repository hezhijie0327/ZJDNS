// ── DNSSECDonut: Recharts PieChart ───────────────────────────────────────

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { useT } from '../context/I18nContext';
import { fmt } from '../helpers';
import type { DNSSECResponse } from '../types';

const ITEMS = [
  { key: 'secure' as const, label: 'Secure', color: 'var(--green)' },
  { key: 'insecure' as const, label: 'Insecure', color: 'var(--yellow)' },
  { key: 'bogus' as const, label: 'Bogus', color: 'var(--red)' },
];

export default function DNSSECDonut({ data }: { data: DNSSECResponse | null }) {
  const { t } = useT();

  const items = data ? ITEMS.map((d) => ({ ...d, value: data[d.key] })).filter((d) => d.value > 0) : [];

  if (!items.length) {
    return (
      <div className="card">
        <h2>{t('dnssecStatus')}</h2>
        <div className="loading">{t('noData')}</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>{t('dnssecStatus')}</h2>
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={items}
            dataKey="value"
            nameKey="label"
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={80}
            paddingAngle={2}
          >
            {items.map((d, i) => (
              <Cell key={i} fill={d.color} />
            ))}
          </Pie>
          <Tooltip
            formatter={(v: number) => fmt(v)}
            contentStyle={{
              background: 'var(--card)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              fontSize: 12,
              color: 'var(--text)',
            }}
          />
          <Legend wrapperStyle={{ fontSize: 11, color: 'var(--dim)' }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
