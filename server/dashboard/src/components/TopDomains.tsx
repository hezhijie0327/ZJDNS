// ── TopDomains: sorted domain table ──────────────────────────────────────

import { useT } from '../context/I18nContext';
import { fmt } from '../helpers';
import type { TopDomainEntry } from '../types';

export default function TopDomains({ data }: { data: TopDomainEntry[] | null }) {
  const { t } = useT();

  return (
    <div className="card">
      <h2>{t('topDomains')}</h2>
      <div style={{ maxHeight: 260, overflowY: 'auto' }}>
        <table>
          <thead>
            <tr>
              <th>{t('colDomain')}</th>
              <th style={{ textAlign: 'right' }}>{t('totalQueries')}</th>
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
              data.map((d) => (
                <tr key={d.qname}>
                  <td className="domain" title={d.qname}>
                    {d.qname}
                  </td>
                  <td style={{ textAlign: 'right' }}>{fmt(d.count)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
