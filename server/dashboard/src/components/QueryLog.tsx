// ── QueryLog: paginated query log table ──────────────────────────────────

import { useT } from '../context/I18nContext';
import { ts2str, qtypeStr } from '../helpers';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import type { QueryLogEntry } from '../types';

const PAGE_SIZE = 50;

interface Props {
  data: QueryLogEntry[] | null;
  page: number;
  onPrev: () => void;
  onNext: () => void;
}

export default function QueryLog({ data, page, onPrev, onNext }: Props) {
  const { t } = useT();

  return (
    <div className="card">
      <h2>{t('queryLog')}</h2>
      <div style={{ maxHeight: 400, overflowY: 'auto' }}>
        <table>
          <thead>
            <tr>
              <th>{t('colTime')}</th>
              <th>{t('colDomain')}</th>
              <th>{t('colType')}</th>
              <th>{t('colResult')}</th>
              <th>{t('colRT')}</th>
              <th>{t('colProto')}</th>
              <th>{t('colServer')}</th>
              <th>{t('colDNSSEC')}</th>
            </tr>
          </thead>
          <tbody>
            {!data?.length ? (
              <tr>
                <td className="loading" colSpan={8}>
                  {t('noEntries')}
                </td>
              </tr>
            ) : (
              data.map((e) => (
                <tr key={e.id}>
                  <td>{ts2str(e.timestamp)}</td>
                  <td className="domain" title={e.qname}>
                    {e.qname}
                  </td>
                  <td>{qtypeStr(e.qtype)}</td>
                  <td>
                    <span className={'badge badge-' + e.result}>{e.result}</span>
                  </td>
                  <td>{e.response_time_ms}ms</td>
                  <td>{e.protocol}</td>
                  <td style={{ maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }} title={e.server}>
                    {e.server}
                  </td>
                  <td>{e.dnssec_status}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      <div className="pagination">
        <button disabled={page <= 1} onClick={onPrev}>
          <ChevronLeft size={14} /> {t('prev')}
        </button>
        <span className="page-info">
          {t('page')} {page}
        </span>
        <button disabled={!data || data.length < PAGE_SIZE} onClick={onNext}>
          {t('next')} <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}
