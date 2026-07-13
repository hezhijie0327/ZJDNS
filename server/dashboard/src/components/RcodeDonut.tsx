// ── RcodeDonut: Recharts PieChart ────────────────────────────────────────

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { useT } from '../context/I18nContext';
import { fmt } from '../helpers';
import type { RcodesResponse } from '../types';

const COLORS = [
  'var(--blue)',
  'var(--red)',
  'var(--yellow)',
  'var(--orange)',
  'var(--purple)',
  'var(--gray)',
  'var(--cyan)',
];

const KEYS: { key: keyof RcodesResponse; label: string }[] = [
  { key: 'noerror', label: 'NOERROR' },
  { key: 'nxdomain', label: 'NXDOMAIN' },
  { key: 'servfail', label: 'SERVFAIL' },
  { key: 'refused', label: 'REFUSED' },
  { key: 'formerr', label: 'FORMERR' },
  { key: 'notimp', label: 'NOTIMP' },
  { key: 'other', label: 'Other' },
];

export default function RcodeDonut({ data }: { data: RcodesResponse | null }) {
  const { t } = useT();

  const items = data
    ? KEYS.map(({ key, label }, i) => ({ name: label, value: data[key], color: COLORS[i] })).filter((d) => d.value > 0)
    : [];

  if (!items.length) {
    return (
      <div className="card">
        <h2>{t('rcodeDistribution')}</h2>
        <div className="loading">{t('noData')}</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>{t('rcodeDistribution')}</h2>
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={items}
            dataKey="value"
            nameKey="name"
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
