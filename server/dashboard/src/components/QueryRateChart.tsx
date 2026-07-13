// ── QueryRateChart: Recharts AreaChart ────────────────────────────────────

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useT } from '../context/I18nContext';
import { ts2str } from '../helpers';
import type { TimeseriesBucket } from '../types';

export default function QueryRateChart({ data }: { data: TimeseriesBucket[] | null }) {
  const { t } = useT();

  if (!data?.length) {
    return (
      <div className="card" style={{ marginBottom: 12 }}>
        <h2>{t('queryRate')}</h2>
        <div className="loading">{t('noData')}</div>
      </div>
    );
  }

  const chartData = data.map((d) => ({ ...d, time: ts2str(d.ts) }));

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h2>{t('queryRate')}</h2>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
          <defs>
            <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--blue)" stopOpacity={0.3} />
              <stop offset="95%" stopColor="var(--blue)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="time" tick={{ fontSize: 11, fill: 'var(--dim)' }} interval="preserveStartEnd" />
          <YAxis tick={{ fontSize: 11, fill: 'var(--dim)' }} width={40} />
          <Tooltip
            contentStyle={{
              background: 'var(--card)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              fontSize: 12,
              color: 'var(--text)',
            }}
          />
          <Area type="monotone" dataKey="count" stroke="var(--blue)" fill="url(#colorCount)" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
      <div className="stat-sub">{t('noteTimeseries')}</div>
    </div>
  );
}
