// static/globe/stats.js
//
// The Statistics + Connections pages of the overlay: the KPI widget grid, the
// distribution charts, the switchable "live lists" (top by rate/talkers/newest/
// unknown/suspicious), and the sortable connections table. All driven by the
// current point/arc state plus the latest server stats push.

import { isValidCoord, isLocalNetwork, recentPacketCount, RATE_WINDOW_SECONDS } from './net.js';
import { getCircleColor } from './classify.js';
import { formatNum, formatBytes, timeAgo, truncate, escapeHTML } from './format.js';
import { countBy, svgDonut, legendHtml, svgBars } from './charts.js';

// The KPI widgets the user can show/hide on the Statistics page.
export const STAT_WIDGETS = [
    { id: 'tcp',    label: 'TCP Pkts', get: s => formatNum(s.tcp || 0) },
    { id: 'udp',    label: 'UDP Pkts', get: s => formatNum(s.udp || 0) },
    { id: 'icmp',   label: 'ICMP',     get: s => formatNum(s.icmp || 0) },
    { id: 'bytes',  label: 'Bytes',    get: s => formatBytes(s.bytes || 0) },
    { id: 'active', label: 'Active',   get: s => formatNum(s.active || 0) },
    { id: 'high',   label: 'HIGH',     cls: 'threat-high',   get: s => `${s.threatHigh || 0}` },
    { id: 'med',    label: 'MED',      cls: 'threat-medium', get: s => `${s.threatMed || 0}` },
    { id: 'low',    label: 'LOW',      cls: 'threat-low',    get: s => `${s.threatLow || 0}` },
];
const DEFAULT_WIDGETS = ['tcp', 'udp', 'bytes', 'active', 'high', 'med', 'low'];

const SEV_RANK = { High: 3, Medium: 2, Low: 1 };

// The switchable lists shown under the charts. Each returns [{p, metric, cls}].
const STAT_LIST_MODES = [
    ['rate', 'Top by rate'], ['talkers', 'Top talkers'], ['newest', 'Newest'],
    ['unknown', 'Unknown'], ['suspicious', 'Suspicious'],
];
const STAT_LIST_METRIC_LABEL = {
    rate: 'Rate', talkers: 'Packets', newest: 'First seen', unknown: 'First seen', suspicious: 'Threat',
};

export function setupStats(app) {
    app.enabledWidgets = (() => {
        try {
            const p = JSON.parse(localStorage.getItem('statWidgets'));
            if (Array.isArray(p) && p.length) return p.filter(id => STAT_WIDGETS.some(w => w.id === id));
        } catch (_) { /* fall through */ }
        return DEFAULT_WIDGETS.slice();
    })();
    app.saveStatPrefs = () => localStorage.setItem('statWidgets', JSON.stringify(app.enabledWidgets));

    function threatCountsFor(deviceSel) {
        const c = { threatHigh: 0, threatMed: 0, threatLow: 0 };
        const bump = t => { if (t === 'High') c.threatHigh++; else if (t === 'Medium') c.threatMed++; else if (t === 'Low') c.threatLow++; };
        if (deviceSel === 'all') {
            for (const ip in app.points) if (!app.points[ip].expired && app.pointDeviceVisible(app.points[ip])) bump(app.points[ip].threat_level);
        } else {
            for (const k in app.arcs) {
                const a = app.arcs[k];
                if (!a.expired && a.device_id === deviceSel && app.isDeviceVisible(deviceSel)) bump(app.points[a.ip]?.threat_level);
            }
        }
        return c;
    }

    function statsFor(deviceSel) {
        const base = deviceSel === 'all'
            ? (app.lastStats.all || {})
            : ((app.lastStats.by_device && app.lastStats.by_device[deviceSel]) || {});
        return Object.assign({}, base, threatCountsFor(deviceSel));
    }

    app.renderStats = () => {
        const grid = document.getElementById('modStatGrid');
        if (!grid) return;
        const s = statsFor(app.statsDevice);
        const frag = document.createDocumentFragment();
        app.enabledWidgets.forEach(id => {
            const w = STAT_WIDGETS.find(x => x.id === id);
            if (!w) return;
            const card = document.createElement('div');
            card.className = 'stat-card';
            const val = document.createElement('span');
            if (w.cls) val.className = `threat-badge ${w.cls}`;
            val.textContent = w.get(s);
            const lbl = document.createElement('small');
            lbl.textContent = w.label;
            card.append(val, lbl);
            frag.appendChild(card);
        });
        grid.replaceChildren(frag);
        // Refresh the device selector's options/value too.
        const sel = document.getElementById('ovDeviceSel');
        if (sel) app.syncDeviceSelect(sel);
        // Keep the live charts/table fresh while the overlay is open. Rendered
        // inline (no call back into renderActivePage) to avoid recursion.
        if (app.statsOverlayOpen) {
            if (app.currentPage === 'stats') {
                const charts = document.getElementById('ovStatsCharts');
                if (charts) renderStatsTab(charts);
            } else if (app.currentPage === 'conn') {
                const body = document.getElementById('ovConnBody');
                if (body) renderConnTab(body);
            }
        }
    };

    app.syncDeviceSelect = sel => {
        const want = ['all', ...Object.keys(app.origins)];
        const have = Array.from(sel.options || []).map(o => o.value);
        if (want.join() !== have.join()) {
            const mkOpt = (text, value) => {
                const o = document.createElement('option');
                o.textContent = text; o.value = value;
                return o;
            };
            sel.replaceChildren();
            sel.appendChild(mkOpt('All devices', 'all'));
            for (const id in app.origins) sel.appendChild(mkOpt(app.deviceName(id), id));
        }
        sel.value = (app.statsDevice === 'all' || app.origins[app.statsDevice]) ? app.statsDevice : 'all';
    };

    // The connections shown for a device: 'all' uses the merged point set; a
    // specific device uses the destinations of that device's arcs.
    function connectionsFor(deviceSel) {
        if (deviceSel === 'all') return Object.values(app.points).filter(p => !p.expired && p.ip && app.pointDeviceVisible(p));
        if (!app.isDeviceVisible(deviceSel)) return [];
        const seen = new Set(); const out = [];
        for (const k in app.arcs) {
            const a = app.arcs[k];
            if (a.expired || a.device_id !== deviceSel) continue;
            const p = app.points[a.ip];
            if (p && !p.expired && !seen.has(a.ip)) { seen.add(a.ip); out.push(p); }
        }
        return out;
    }

    function ovDevice() { return document.getElementById('ovDeviceSel')?.value || 'all'; }

    // Packets/second over the trailing rate window (same data the globe sizes by).
    function pointRate(p) {
        return recentPacketCount(p, Date.now() / 1000) / RATE_WINDOW_SECONDS;
    }
    // An external IP we couldn't attribute to an org or a hostname.
    function isUnknownIp(p) {
        if (isLocalNetwork(p.ip, p.org)) return false;
        const org = (p.org || '').trim();
        const host = (p.hostname || '').trim();
        const noOrg = !org || ['Unknown', 'Not available', 'N/A'].includes(org);
        const noHost = !host || host === 'Unknown';
        return noOrg && noHost;
    }

    function statListRows(mode, cs) {
        const top = (arr) => arr.slice(0, 50);
        if (mode === 'rate') {
            return top(cs.map(p => [p, pointRate(p)]).filter(x => x[1] > 0).sort((a, b) => b[1] - a[1]))
                .map(([p, v]) => ({ p, metric: `${v.toFixed(1)}/s`, cls: 'm-rate' }));
        }
        if (mode === 'talkers') {
            return top(cs.map(p => [p, (p.incoming_count || 0) + (p.outgoing_count || 0)]).sort((a, b) => b[1] - a[1]))
                .map(([p, v]) => ({ p, metric: formatNum(v), cls: 'm-num' }));
        }
        if (mode === 'newest') {
            return top(cs.slice().sort((a, b) => (b._firstSeen || 0) - (a._firstSeen || 0)))
                .map(p => ({ p, metric: p._firstSeen ? timeAgo(p._firstSeen) : '—', cls: 'm-time' }));
        }
        if (mode === 'unknown') {
            return top(cs.filter(isUnknownIp).sort((a, b) => (b._firstSeen || 0) - (a._firstSeen || 0)))
                .map(p => ({ p, metric: p._firstSeen ? timeAgo(p._firstSeen) : '—', cls: 'm-time' }));
        }
        if (mode === 'suspicious') {
            return top(cs.filter(p => SEV_RANK[p.threat_level])
                .sort((a, b) => (SEV_RANK[b.threat_level] - SEV_RANK[a.threat_level]) || (pointRate(b) - pointRate(a))))
                .map(p => ({ p, metric: p.threat_level, cls: 'm-threat ' + (p.threat_level || '').toLowerCase() }));
        }
        return [];
    }

    function renderStatList(container, cs) {
        const rows = statListRows(app.statsListMode, cs);
        const suspCount = cs.filter(p => SEV_RANK[p.threat_level]).length;
        const unkCount = cs.filter(isUnknownIp).length;
        const badge = id =>
            id === 'suspicious' && suspCount ? ` <i class="seg-count">${suspCount}</i>` :
            id === 'unknown' && unkCount ? ` <i class="seg-count">${unkCount}</i>` : '';
        const seg = STAT_LIST_MODES.map(([id, label]) =>
            `<button class="seg${id === app.statsListMode ? ' active' : ''}" data-list="${id}">${label}${badge(id)}</button>`).join('');
        const tbody = rows.length ? rows.map((r, i) => {
            const p = r.p;
            const host = (p.hostname && p.hostname !== 'Unknown') ? p.hostname
                : (p.org && p.org !== 'Not available' ? p.org : '');
            const metric = r.cls.startsWith('m-threat')
                ? `<span class="threat-badge threat-${(p.threat_level || '').toLowerCase()}">${escapeHTML(p.threat_level || '')}</span>`
                : escapeHTML(r.metric || '');
            return `<tr class="sl-row" data-ip="${escapeHTML(p.ip)}">` +
                `<td class="sl-rank">${i + 1}</td>` +
                `<td><span class="sl-dot" style="background:${getCircleColor(p.threat_level, p.org)}"></span>` +
                `<span class="sl-ip">${escapeHTML(p.ip)}</span>` +
                (host ? `<span class="sl-host">${escapeHTML(truncate(host, 36))}</span>` : '') + `</td>` +
                `<td class="ell sl-lan">${escapeHTML(app.localPeersText(p) || '—')}</td>` +
                `<td>${escapeHTML(p.country || '')}</td>` +
                `<td class="sl-metric ${r.cls}">${metric}</td></tr>`;
        }).join('') : '<tr><td colspan="5" class="sl-empty muted">no data</td></tr>';
        container.innerHTML =
            `<div class="seg-ctrl">${seg}</div>` +
            '<div class="conn-table-wrap"><table class="conn-table sl-table"><thead><tr>' +
            `<th class="sl-rank">#</th><th>IP / host</th><th>LAN device(s)</th><th>Country</th>` +
            `<th class="sl-metric-h">${STAT_LIST_METRIC_LABEL[app.statsListMode] || ''}</th>` +
            `</tr></thead><tbody>${tbody}</tbody></table></div>`;
        container.querySelectorAll('.seg').forEach(b => b.addEventListener('click', () => {
            app.statsListMode = b.dataset.list;
            localStorage.setItem('statsListMode', app.statsListMode);
            renderStatList(container, cs);
        }));
        container.querySelectorAll('.sl-row').forEach(tr => tr.addEventListener('click', () => {
            const p = app.points[tr.dataset.ip];
            if (!p) return;
            app.showDataList(p);
            if (isValidCoord(p.lat, p.lng)) app.globe.pointOfView({ lat: p.lat, lng: p.lng, altitude: 2.5 }, 1000);
        }));
    }

    function renderStatsTab(body) {
        const dev = ovDevice();
        const conns = connectionsFor(dev);
        const s = statsFor(dev);
        const totalRate = conns.reduce((sum, p) => sum + pointRate(p), 0);
        const suspicious = conns.filter(p => SEV_RANK[p.threat_level]).length;
        const kpis = [
            ['Connections', formatNum(conns.length), ''],
            ['Active', formatNum(s.active || 0), ''],
            ['Pkts/s', totalRate.toFixed(1), 'accent'],
            ['TCP', formatNum(s.tcp || 0), ''],
            ['UDP', formatNum(s.udp || 0), ''],
            ['Bytes', formatBytes(s.bytes || 0), ''],
            ['Suspicious', formatNum(suspicious), suspicious ? 'warn' : ''],
            ['High', formatNum(s.threatHigh || 0), (s.threatHigh ? 'danger' : '')],
        ];
        const proto = countBy(conns, p => p.protocol);
        const protoSeg = [
            { label: 'TCP', value: proto.TCP || 0, color: '#4FC3F7' },
            { label: 'UDP', value: proto.UDP || 0, color: '#FFD54F' },
            { label: 'ICMP', value: proto.ICMP || 0, color: '#BA68C8' },
        ];
        const cnt = lvl => conns.filter(p => p.threat_level === lvl).length;
        const threatSeg = [
            { label: 'High', value: cnt('High'), color: '#d11' },
            { label: 'Medium', value: cnt('Medium'), color: '#e80' },
            { label: 'Low', value: cnt('Low'), color: '#cc0' },
            { label: 'None', value: conns.filter(p => !['High', 'Medium', 'Low'].includes(p.threat_level)).length, color: '#393' },
        ];
        const countries = Object.entries(countBy(conns, p => p.country))
            .filter(([k]) => k && k !== 'Unknown').sort((a, b) => b[1] - a[1]).slice(0, 10)
            .map(([label, value]) => ({ label, value }));
        body.innerHTML =
            '<div class="stat-section">' +
                '<div class="kpi-row">' + kpis.map(([l, v, c]) =>
                    `<div class="kpi ${c}"><span class="kpi-val">${v}</span><small>${escapeHTML(l)}</small></div>`).join('') + '</div>' +
            '</div>' +
            '<div class="stat-section"><h4 class="stat-section-title">Distribution</h4>' +
                '<div class="chart-grid">' +
                    `<div class="chart-card"><h5>Protocols</h5>${svgDonut(protoSeg, 140)}${legendHtml(protoSeg)}</div>` +
                    `<div class="chart-card"><h5>Threats</h5>${svgDonut(threatSeg, 140)}${legendHtml(threatSeg)}</div>` +
                    `<div class="chart-card wide"><h5>Top countries</h5>${countries.length ? svgBars(countries, '#3b82f6') : '<p class="muted">no data</p>'}</div>` +
                '</div>' +
            '</div>' +
            '<div class="stat-section"><h4 class="stat-section-title">Live lists</h4>' +
                '<div id="statListHost"></div>' +
            '</div>';
        renderStatList(body.querySelector('#statListHost'), conns);
    }

    function renderConnTab(body) {
        const dev = ovDevice();
        const { key, dir } = app.connSort;
        const numeric = k => k === 'incoming_count' || k === 'outgoing_count' || k === 'last_seen';
        const rows = connectionsFor(dev).slice().sort((a, b) => {
            if (numeric(key)) return ((a[key] || 0) - (b[key] || 0)) * dir;
            return String(a[key] || '').localeCompare(String(b[key] || '')) * dir;
        });
        const cols = [['ip', 'IP'], ['local_ip', 'LAN device(s)'], ['country', 'Country'], ['org', 'Org'], ['protocol', 'Proto'],
                      ['incoming_count', 'In'], ['outgoing_count', 'Out'], ['threat_level', 'Threat'], ['last_seen', 'Last seen']];
        const head = cols.map(([k, l]) =>
            `<th data-k="${k}">${l}${key === k ? (dir < 0 ? ' ▼' : ' ▲') : ''}</th>`).join('');
        const trs = rows.slice(0, 500).map(p =>
            `<tr><td>${escapeHTML(p.ip)}</td><td class="ell">${escapeHTML(app.localPeersText(p) || '—')}</td><td>${escapeHTML(p.country || '')}</td>` +
            `<td class="ell">${escapeHTML(p.org || '')}</td><td>${escapeHTML(p.protocol || '')}</td>` +
            `<td>${formatNum(p.incoming_count || 0)}</td><td>${formatNum(p.outgoing_count || 0)}</td>` +
            `<td>${escapeHTML(p.threat_level || 'No Threat')}</td>` +
            `<td>${p.last_seen ? new Date(p.last_seen * 1000).toLocaleTimeString() : ''}</td></tr>`).join('');
        body.innerHTML = `<div class="conn-count">${rows.length} connections</div>` +
            `<div class="conn-table-wrap"><table class="conn-table"><thead><tr>${head}</tr></thead><tbody>${trs}</tbody></table></div>`;
        body.querySelectorAll('th[data-k]').forEach(th => th.addEventListener('click', () => {
            const k = th.dataset.k;
            if (app.connSort.key === k) app.connSort.dir *= -1; else { app.connSort.key = k; app.connSort.dir = -1; }
            renderConnTab(body);
        }));
    }

    // Render whichever page is currently shown. Stats/Connections are live;
    // Devices/Settings are built once and updated through their own paths.
    app.renderActivePage = () => {
        if (!app.statsOverlayOpen) return;
        if (app.currentPage === 'stats') {
            app.renderStats();                             // fills grid + charts
        } else if (app.currentPage === 'conn') {
            const body = document.getElementById('ovConnBody');
            if (body) renderConnTab(body);
        }
    };
}
