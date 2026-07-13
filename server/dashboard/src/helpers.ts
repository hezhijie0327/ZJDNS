// ── DOM helper ───────────────────────────────────────────────────────────
export function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

// ── Formatting ───────────────────────────────────────────────────────────
export function fmt(n: number): string {
  return n.toLocaleString();
}

export function fmtPct(n: number): string {
  return (n * 100).toFixed(1) + '%';
}

export function fmtMs(n: number): string {
  return (n || 0).toFixed(1) + 'ms';
}

export function ts2str(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toISOString().slice(11, 19);
}

// ── DNS QTYPE lookup ─────────────────────────────────────────────────────
const QTYPES: Record<number, string> = {
  1: 'A',
  28: 'AAAA',
  15: 'MX',
  2: 'NS',
  5: 'CNAME',
  16: 'TXT',
  6: 'SOA',
  33: 'SRV',
  12: 'PTR',
  48: 'DNSKEY',
  43: 'DS',
  255: 'ANY',
};

export function qtypeStr(t: number): string {
  return QTYPES[t] || 'T' + t;
}
