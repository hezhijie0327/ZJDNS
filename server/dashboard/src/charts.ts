// ── SVG Charts: pure renderers, zero dependencies ────────────────────────

import { $, fmt, fmtPct, ts2str } from './helpers';
import { t } from './i18n';

// ── Types ────────────────────────────────────────────────────────────────

export interface LineChartData {
  ts: number;
  count: number;
}

export interface DonutItem {
  l: string; // label
  v: number; // value
}

export interface BarItem {
  l: string; // label
  v: number; // value
  c?: string; // optional CSS color variable
}

// ── Line Chart ───────────────────────────────────────────────────────────

export function drawLineChart(svgId: string, data: LineChartData[], w: number, h: number): void {
  const svg = $(svgId);
  svg.innerHTML = '';
  if (!data.length) {
    svg.innerHTML = '<text x="' + w / 2 + '" y="' + h / 2 + '" text-anchor="middle">' + t('noData') + '</text>';
    return;
  }

  const pad = { top: 20, right: 20, bottom: 30, left: 50 };
  const pw = w - pad.left - pad.right;
  const ph = h - pad.top - pad.bottom;
  const maxCnt = Math.max(...data.map((d) => d.count), 1);
  const pts = data.map((d, i) => [
    pad.left + (i / (data.length - 1 || 1)) * pw,
    pad.top + ph - (d.count / maxCnt) * ph,
  ]);

  let html = '';

  // Grid lines
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (ph / 4) * i;
    html +=
      '<line x1="' +
      pad.left +
      '" y1="' +
      y +
      '" x2="' +
      (w - pad.right) +
      '" y2="' +
      y +
      '" stroke="var(--border)" stroke-dasharray="4,3"/>';
  }

  // Y-axis labels
  for (let i = 0; i <= 4; i++) {
    const v = Math.round(maxCnt * (1 - i / 4));
    const y = pad.top + (ph / 4) * i;
    html += '<text x="' + (pad.left - 6) + '" y="' + (y + 4) + '" text-anchor="end">' + v + '</text>';
  }

  // X-axis labels
  const step = Math.max(1, Math.floor(data.length / 6));
  for (let i = 0; i < data.length; i += step) {
    const x = pts[i][0];
    html +=
      '<text x="' + x + '" y="' + (h - pad.bottom + 16) + '" text-anchor="middle">' + ts2str(data[i].ts) + '</text>';
  }

  // Line path
  if (pts.length > 1) {
    const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ',' + p[1].toFixed(1)).join('');
    html += '<path d="' + d + '" fill="none" stroke="var(--blue)" stroke-width="2"/>';
  }

  // Data points
  for (const p of pts) {
    html += '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="2" fill="var(--blue)"/>';
  }

  svg.innerHTML = html;
}

// ── Donut Chart ──────────────────────────────────────────────────────────

const DONUT_COLORS = [
  'var(--blue)',
  'var(--green)',
  'var(--red)',
  'var(--yellow)',
  'var(--purple)',
  'var(--orange)',
  'var(--gray)',
  'var(--cyan)',
];

export function drawDonut(svgId: string, items: DonutItem[], cx: number, cy: number, r: number): void {
  const svg = $(svgId);
  svg.innerHTML = '';
  if (!items.length) {
    svg.innerHTML =
      '<text x="' + cx + '" y="' + cy + '" text-anchor="middle" font-size="12">' + t('noData') + '</text>';
    return;
  }

  const total = items.reduce((s, i) => s + i.v, 0);
  if (!total) {
    svg.innerHTML =
      '<text x="' + cx + '" y="' + cy + '" text-anchor="middle" font-size="12">' + t('noData') + '</text>';
    return;
  }

  const circum = 2 * Math.PI * r;
  let offset = 0;
  const legendX = cx + r + 20;
  const legendY = cy - items.length * 10;

  let html = '';
  for (let i = 0; i < items.length; i++) {
    const frac = items[i].v / total;
    const dash = circum * frac;
    const rot = (offset / circum) * 360;
    html +=
      '<circle cx="' +
      cx +
      '" cy="' +
      cy +
      '" r="' +
      r +
      '" fill="none" stroke="' +
      DONUT_COLORS[i] +
      '" stroke-width="16"' +
      ' stroke-dasharray="' +
      dash +
      ' ' +
      (circum - dash) +
      '" transform="rotate(' +
      (rot - 90) +
      ',' +
      cx +
      ',' +
      cy +
      ')"/>';
    html +=
      '<rect x="' +
      legendX +
      '" y="' +
      (legendY + i * 18) +
      '" width="10" height="10" fill="' +
      DONUT_COLORS[i] +
      '" rx="2"/>';
    html +=
      '<text x="' +
      (legendX + 14) +
      '" y="' +
      (legendY + i * 18 + 9) +
      '" font-size="11">' +
      items[i].l +
      ': ' +
      fmt(items[i].v) +
      ' (' +
      fmtPct(frac) +
      ')</text>';
    offset += dash;
  }
  svg.innerHTML = html;
}

// ── Horizontal Bar Chart ─────────────────────────────────────────────────

export function drawHBar(svgId: string, items: BarItem[], w: number, h: number): void {
  const svg = $(svgId);
  svg.innerHTML = '';
  if (!items.length) {
    svg.innerHTML = '<text x="' + w / 2 + '" y="' + h / 2 + '" text-anchor="middle">' + t('noData') + '</text>';
    return;
  }

  const maxV = Math.max(...items.map((i) => i.v), 1);
  const barH = 22;
  const gap = 6;
  const padL = 80;
  const padR = 60;

  let html = '';
  for (let i = 0; i < items.length; i++) {
    const bw = Math.max(2, (items[i].v / maxV) * (w - padL - padR));
    const y = 10 + i * (barH + gap);
    html +=
      '<text x="' +
      (padL - 6) +
      '" y="' +
      (y + barH - 6) +
      '" text-anchor="end" font-size="11">' +
      items[i].l +
      '</text>';
    html +=
      '<rect x="' +
      padL +
      '" y="' +
      y +
      '" width="' +
      bw.toFixed(1) +
      '" height="' +
      barH +
      '" rx="3" fill="' +
      (items[i].c ?? 'var(--blue)') +
      '"/>';
    html +=
      '<text x="' +
      (padL + bw + 6) +
      '" y="' +
      (y + barH - 6) +
      '" font-size="11" fill="var(--dim)">' +
      fmt(items[i].v) +
      '</text>';
  }
  svg.innerHTML = html;
}
