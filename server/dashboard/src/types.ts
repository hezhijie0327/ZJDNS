// ── API response types ───────────────────────────────────────────────────

export interface OverviewResponse {
  entries: number;
  total_queries: number;
  hits: number;
  misses: number;
  stales: number;
  zones: number;
  errors: number;
  blocked: number;
  badcookie: number;
  avg_response_ms: number;
  hit_rate: number;
  hijack: number;
  fallback: number;
}

export interface RcodesResponse {
  noerror: number;
  formerr: number;
  servfail: number;
  nxdomain: number;
  notimp: number;
  refused: number;
  other: number;
}

export interface ProtocolsResponse {
  udp: number;
  tcp: number;
  dot: number;
  doq: number;
  doh: number;
  doh3: number;
  dnscrypt: number;
  dnscrypt_tcp: number;
}

export interface DNSSECResponse {
  secure: number;
  insecure: number;
  bogus: number;
}

export interface TopDomainEntry {
  qname: string;
  count: number;
}

export interface QueryLogEntry {
  id: number;
  timestamp: number;
  qname: string;
  qtype: number;
  protocol: string;
  result: string;
  response_time_ms: number;
  rcode: number;
  server: string;
  hijack: boolean;
  fallback: boolean;
  dnssec_status: string;
}

export interface LatencyEntry {
  ip: string;
  qtype: number;
  latency_ms: number;
  last_probe_time: number;
}

export interface TimeseriesBucket {
  ts: number;
  count: number;
  avg_ms: number;
}
