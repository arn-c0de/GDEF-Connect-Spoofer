// static/globe/charts.js
//
// Self-contained SVG/HTML chart builders. Inline SVG avoids a charting-CDN
// dependency (which the page CSP would block). Pure string builders.

import { escapeHTML } from './format.js';

export function countBy(arr, keyFn) {
    const m = {};
    arr.forEach(x => { const k = keyFn(x) || 'Unknown'; m[k] = (m[k] || 0) + 1; });
    return m;
}

export function svgDonut(segments, size) {
    const total = segments.reduce((s, x) => s + x.value, 0);
    const r = size / 2 - 6, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
    if (total === 0) {
        return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">` +
            `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#333" stroke-width="12"/>` +
            `<text x="${cx}" y="${cy}" fill="#888" font-size="11" text-anchor="middle" dy="4">no data</text></svg>`;
    }
    let off = 0;
    const rings = segments.filter(s => s.value > 0).map(s => {
        const len = C * (s.value / total);
        const el = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${s.color}" ` +
            `stroke-width="12" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" ` +
            `transform="rotate(-90 ${cx} ${cy})"/>`;
        off += len;
        return el;
    }).join('');
    return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${rings}` +
        `<text x="${cx}" y="${cy}" fill="#ddd" font-size="15" text-anchor="middle" dy="5">${total}</text></svg>`;
}

export function legendHtml(segments) {
    return '<div class="chart-legend">' + segments.filter(s => s.value > 0).map(s =>
        `<span><i style="background:${s.color}"></i>${escapeHTML(s.label)} ${s.value}</span>`).join('') + '</div>';
}

export function svgBars(items, color) {
    const max = items.reduce((m, x) => Math.max(m, x.value), 0) || 1;
    return '<div class="bar-chart">' + items.map(it => {
        const w = Math.round((it.value / max) * 100);
        return `<div class="bar-row"><span class="bar-label">${escapeHTML(it.label)}</span>` +
            `<span class="bar-track"><span class="bar-fill" style="width:${w}%;background:${color}"></span></span>` +
            `<span class="bar-val">${it.value}</span></div>`;
    }).join('') + '</div>';
}
