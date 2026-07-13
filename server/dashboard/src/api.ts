// ── API fetching & DOM rendering ─────────────────────────────────────────

import { $, fmt, fmtMs, fmtPct, ts2str, qtypeStr } from './helpers';
import { t } from './i18n';
import { drawLineChart, drawDonut, drawHBar, type DonutItem, type BarItem } from './charts';
import { page, PAGE_SIZE, buildQueryLogURL } from './search';
import type {
  OverviewResponse,
  RcodesResponse,
  ProtocolsResponse,
  DNSSECResponse,
  TopDomainEntry,
  QueryLogEntry,
  LatencyEntry,
  TimeseriesBucket,
} from './types';

// ── Fetch ────────────────────────────────────────────────────────────────

async function fetchJSON<T>(path: string): Promise<T | null> {
  try {
    const r = await fetch(path);
    if (!r.ok) return null;
    return r.json() as T;
  } catch {
    return null;
  }
}

// ── Render Cards ─────────────────────────────────────────────────────────

function renderCards(o: OverviewResponse): void {
  $('st-queries').textContent = fmt(o.total_queries);
  $('st-hitrate').textContent = fmtPct(o.hit_rate);
  $('st-avgms').textContent = fmtMs(o.avg_response_ms);
  $('st-entries').textContent = fmt(o.entries);
}

// ── Main Refresh ─────────────────────────────────────────────────────────

export async function refreshAll(): Promise<void> {
  const [overview, rcodes, protocols, dnssec, topDomains, latency, timeseries, queryLog] = await Promise.all([
    fetchJSON<OverviewResponse>('/api/overview'),
    fetchJSON<RcodesResponse>('/api/rcodes'),
    fetchJSON<ProtocolsResponse>('/api/protocols'),
    fetchJSON<DNSSECResponse>('/api/dnssec'),
    fetchJSON<TopDomainEntry[]>('/api/top-domains?limit=20'),
    fetchJSON<LatencyEntry[]>('/api/latency?limit=10'),
    fetchJSON<TimeseriesBucket[]>('/api/timeseries?minutes=60'),
    fetchJSON<QueryLogEntry[]>(buildQueryLogURL()),
  ]);

  if (overview) renderCards(overview);

  // RCODE donut
  const rcItems: DonutItem[] = rcodes
    ? [
        { l: 'NOERROR', v: rcodes.noerror },
        { l: 'NXDOMAIN', v: rcodes.nxdomain },
        { l: 'SERVFAIL', v: rcodes.servfail },
        { l: 'REFUSED', v: rcodes.refused },
        { l: 'FORMERR', v: rcodes.formerr },
        { l: 'NOTIMP', v: rcodes.notimp },
        { l: 'Other', v: rcodes.other },
      ].filter((x) => x.v > 0)
    : [];
  drawDonut('chart-rcodes', rcItems, 100, 100, 70);

  // DNSSEC donut — short English labels for chart readability
  const dsItems: DonutItem[] = dnssec
    ? [
        { l: 'Secure', v: dnssec.secure },
        { l: 'Insecure', v: dnssec.insecure },
        { l: 'Bogus', v: dnssec.bogus },
      ].filter((x) => x.v > 0)
    : [];
  drawDonut('chart-dnssec', dsItems, 100, 100, 70);

  // Protocols horizontal bar
  const pItems: BarItem[] = protocols
    ? [
        { l: 'UDP', v: protocols.udp, c: 'var(--blue)' },
        { l: 'TCP', v: protocols.tcp, c: 'var(--cyan)' },
        { l: 'DoH', v: protocols.doh, c: 'var(--green)' },
        { l: 'DoH3', v: protocols.doh3, c: 'var(--purple)' },
        { l: 'DoT', v: protocols.dot, c: 'var(--yellow)' },
        { l: 'DoQ', v: protocols.doq, c: 'var(--orange)' },
        { l: 'DNSCrypt', v: protocols.dnscrypt, c: 'var(--red)' },
        { l: 'DNSCrypt-TCP', v: protocols.dnscrypt_tcp, c: 'var(--gray)' },
      ].filter((x) => x.v > 0)
    : [];
  drawHBar('chart-protocols', pItems, 420, Math.max(60, pItems.length * 28 + 10));

  // Timeseries
  if (timeseries) {
    drawLineChart('chart-timeseries', timeseries, 900, 200);
  }
  $('ts-note').textContent = t('noteTimeseries');

  // Top Domains table
  if (topDomains) {
    let h = '<tr><th>' + t('colDomain') + '</th><th style="text-align:right">' + t('totalQueries') + '</th></tr>';
    for (const d of topDomains) {
      h +=
        '<tr><td class="domain" title="' +
        d.qname +
        '">' +
        d.qname +
        '</td><td style="text-align:right">' +
        fmt(d.count) +
        '</td></tr>';
    }
    if (!topDomains.length) h = '<tr><td class="loading">' + t('noData') + '</td></tr>';
    $('tbl-topdomains').innerHTML = h;
  }

  // Latency table
  if (latency) {
    let h = '<tr><th>' + t('latencyIP') + '</th><th style="text-align:right">' + t('colRT') + '</th></tr>';
    for (const ip of latency) {
      h += '<tr><td>' + ip.ip + '</td><td style="text-align:right">' + ip.latency_ms + 'ms</td></tr>';
    }
    if (!latency.length) h = '<tr><td class="loading">' + t('noData') + '</td></tr>';
    $('tbl-latency').innerHTML = h;
  }

  // Query Log table
  if (queryLog) {
    let h = '';
    for (const e of queryLog) {
      h +=
        '<tr>' +
        '<td>' +
        ts2str(e.timestamp) +
        '</td>' +
        '<td class="domain" title="' +
        e.qname +
        '">' +
        e.qname +
        '</td>' +
        '<td>' +
        qtypeStr(e.qtype) +
        '</td>' +
        '<td><span class="badge badge-' +
        e.result +
        '">' +
        e.result +
        '</span></td>' +
        '<td>' +
        e.response_time_ms +
        'ms</td>' +
        '<td>' +
        e.protocol +
        '</td>' +
        '<td style="max-width:120px;overflow:hidden;text-overflow:ellipsis" title="' +
        e.server +
        '">' +
        e.server +
        '</td>' +
        '<td>' +
        e.dnssec_status +
        '</td></tr>';
    }
    if (!queryLog.length) h = '<tr><td colspan="8" class="loading">' + t('noEntries') + '</td></tr>';
    $('tbl-log').innerHTML = h;
    $('page-info').textContent = t('page') + ' ' + page;
    ($('btn-prev') as HTMLButtonElement).disabled = page <= 1;
    ($('btn-next') as HTMLButtonElement).disabled = queryLog.length < PAGE_SIZE;
  }

  $('refresh-status').textContent = t('updated') + ' ' + new Date().toLocaleTimeString();
}
