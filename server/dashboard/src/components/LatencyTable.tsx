// ── LatencyTable: IP latency list ────────────────────────────────────────

import { useT } from '../context/I18nContext';
import type { LatencyEntry } from '../types';

export default function LatencyTable({ data }: { data: LatencyEntry[] | null }) {
  const { t } = useT();

  return (
    <div className="card">
      <h2>{t('latencyIP')}</h2>
      <div style={{ maxHeight: 260, overflowY: 'auto' }}>
        <table>
          <thead>
            <tr>
              <th>{t('latencyIP')}</th>
              <th style={{ textAlign: 'right' }}>{t('colRT')}</th>
            </tr>
          </thead>
          <tbody>
            {!data?.length ? (
              <tr>
                <td className="loading" colSpan={2}>
                  {t('noData')}
                </td>
              </tr>
            ) : (
              data.map((ip) => (
                <tr key={ip.ip}>
                  <td>{ip.ip}</td>
                  <td style={{ textAlign: 'right' }}>{ip.latency_ms}ms</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
