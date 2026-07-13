// ── DashboardPage: Main dashboard layout ──────────────────────────────────

import { useState, useCallback, useRef } from 'react';
import { useDashboardData } from '../hooks/useApi';
import { useInterval } from '../hooks/useInterval';
import { useT } from '../context/I18nContext';
import Layout from '../components/Layout';
import StatCards from '../components/StatCards';
import QueryRateChart from '../components/QueryRateChart';
import RcodeDonut from '../components/RcodeDonut';
import DNSSECDonut from '../components/DNSSECDonut';
import ProtocolBars from '../components/ProtocolBars';
import TopDomains from '../components/TopDomains';
import LatencyTable from '../components/LatencyTable';
import SearchBar from '../components/SearchBar';
import QueryLog from '../components/QueryLog';

export default function DashboardPage() {
  const { t } = useT();
  const [refreshTime, setRefreshTime] = useState('');
  const [page, setPage] = useState(1);
  const [searchTerm, setSearchTerm] = useState('');
  const [resultFilter, setResultFilter] = useState('');
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Debounced search
  const onSearchChange = useCallback((v: string) => {
    setSearchTerm(v);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setPage(1);
    }, 300);
  }, []);

  const onFilterChange = useCallback((v: string) => {
    setResultFilter(v);
    setPage(1);
  }, []);

  // Use the debounced page: if search just changed, page resets after debounce
  const effectivePage = page;

  const { data, refresh } = useDashboardData(effectivePage, searchTerm, resultFilter);

  // Auto-refresh every 30s
  useInterval(() => {
    setRefreshTime(new Date().toLocaleTimeString());
    void refresh();
  }, 30000);

  // Initial refresh time
  if (!refreshTime) setRefreshTime(new Date().toLocaleTimeString());

  return (
    <Layout refreshStatus={t('updated') + ' ' + refreshTime}>
      <StatCards data={data.overview} />

      <QueryRateChart data={data.timeseries} />

      <div className="row2">
        <TopDomains data={data.topDomains} />
        <RcodeDonut data={data.rcodes} />
        <DNSSECDonut data={data.dnssec} />
      </div>

      <div className="row3">
        <ProtocolBars data={data.protocols} />
        <LatencyTable data={data.latency} />
      </div>

      <div className="card">
        <SearchBar
          searchTerm={searchTerm}
          resultFilter={resultFilter}
          onSearchChange={onSearchChange}
          onFilterChange={onFilterChange}
        />
      </div>
      <QueryLog
        data={data.queryLog}
        page={page}
        onPrev={() => {
          setPage((p) => Math.max(1, p - 1));
        }}
        onNext={() => {
          setPage((p) => p + 1);
        }}
      />
    </Layout>
  );
}
