// ── ProtocolBars: Recharts BarChart ──────────────────────────────────────

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { useT } from '../context/I18nContext';
import { fmt } from '../helpers';
import type { ProtocolsResponse } from '../types';

const BARS = [
  { key: 'udp' as const, label: 'UDP', color: 'var(--blue)' },
  { key: 'tcp' as const, label: 'TCP', color: 'var(--cyan)' },
  { key: 'doh' as const, label: 'DoH', color: 'var(--green)' },
  { key: 'doh3' as const, label: 'DoH3', color: 'var(--purple)' },
  { key: 'dot' as const, label: 'DoT', color: 'var(--yellow)' },
  { key: 'doq' as const, label: 'DoQ', color: 'var(--orange)' },
  { key: 'dnscrypt' as const, label: 'DNSCrypt', color: 'var(--red)' },
  { key: 'dnscrypt_tcp' as const, label: 'DNSCrypt-TCP', color: 'var(--gray)' },
];

export default function ProtocolBars({ data }: { data: ProtocolsResponse | null }) {
  const { t } = useT();

  const items = data ? BARS.map((d) => ({ ...d, value: data[d.key] })).filter((d) => d.value > 0) : [];

  if (!items.length) {
    return (
      <div className="card">
        <h2>{t('protocolBreakdown')}</h2>
        <div className="loading">{t('noData')}</div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>{t('protocolBreakdown')}</h2>
      <ResponsiveContainer width="100%" height={Math.max(60, items.length * 30 + 20)}>
        <BarChart data={items} layout="vertical" margin={{ top: 0, right: 10, left: 80, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
          <XAxis type="number" tick={{ fontSize: 11, fill: 'var(--dim)' }} />
          <YAxis type="category" dataKey="label" tick={{ fontSize: 11, fill: 'var(--dim)' }} width={75} />
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
          <Bar dataKey="value" radius={[0, 4, 4, 0]}>
            {items.map((d, i) => (
              <Cell key={i} fill={d.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
