// ── useApi: data fetching with auth headers ──────────────────────────────

import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import type {
  OverviewResponse,
  RcodesResponse,
  ProtocolsResponse,
  DNSSECResponse,
  TopDomainEntry,
  QueryLogEntry,
  LatencyEntry,
  TimeseriesBucket,
} from '../types';

const PAGE_SIZE = 50;

async function fetchJSON<T>(path: string, token: string | null): Promise<T | null> {
  try {
    const headers: HeadersInit = token ? { Authorization: 'Bearer ' + token } : {};
    const r = await fetch(path, { headers });
    if (!r.ok) return null;
    return r.json() as T;
  } catch {
    return null;
  }
}

export interface DashboardData {
  overview: OverviewResponse | null;
  rcodes: RcodesResponse | null;
  protocols: ProtocolsResponse | null;
  dnssec: DNSSECResponse | null;
  topDomains: TopDomainEntry[] | null;
  latency: LatencyEntry[] | null;
  timeseries: TimeseriesBucket[] | null;
  queryLog: QueryLogEntry[] | null;
}

export function useDashboardData(page: number, searchTerm: string, resultFilter: string) {
  const { token } = useAuth();
  const [data, setData] = useState<DashboardData>({
    overview: null,
    rcodes: null,
    protocols: null,
    dnssec: null,
    topDomains: null,
    latency: null,
    timeseries: null,
    queryLog: null,
  });
  const [loading, setLoading] = useState(true);

  const buildQueryLogURL = useCallback(() => {
    let url = '/api/query-log?limit=' + PAGE_SIZE + '&offset=' + (page - 1) * PAGE_SIZE;
    if (searchTerm) url += '&search=' + encodeURIComponent(searchTerm);
    if (resultFilter) url += '&result=' + encodeURIComponent(resultFilter);
    return url;
  }, [page, searchTerm, resultFilter]);

  const refresh = useCallback(async () => {
    setLoading(true);
    const [overview, rcodes, protocols, dnssec, topDomains, latency, timeseries, queryLog] = await Promise.all([
      fetchJSON<OverviewResponse>('/api/overview', token),
      fetchJSON<RcodesResponse>('/api/rcodes', token),
      fetchJSON<ProtocolsResponse>('/api/protocols', token),
      fetchJSON<DNSSECResponse>('/api/dnssec', token),
      fetchJSON<TopDomainEntry[]>('/api/top-domains?limit=20', token),
      fetchJSON<LatencyEntry[]>('/api/latency?limit=10', token),
      fetchJSON<TimeseriesBucket[]>('/api/timeseries?minutes=60', token),
      fetchJSON<QueryLogEntry[]>(buildQueryLogURL(), token),
    ]);
    setData({ overview, rcodes, protocols, dnssec, topDomains, latency, timeseries, queryLog });
    setLoading(false);
  }, [token, buildQueryLogURL]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { data, loading, refresh };
}
