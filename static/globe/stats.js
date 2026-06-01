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

    // ── Search / filter predicate (Live mode) ─────────────
    // Applies the overlay search box + country/threat/protocol filters to a live
    // point. History mode pushes the same query to the DB instead (fetchHistory).
    app.matchesOvFilter = p => {
        const f = app.ovFilters;
        if (f.country && (p.country || '') !== f.country) return false;
        if (f.protocol && (p.protocol || '') !== f.protocol) return false;
        if (f.threat && (p.threat_level || 'No Threat') !== f.threat) return false;
        const q = app.ovQuery;
        if (!q) return true;
        return (p.ip || '').toLowerCase().includes(q) ||
            (app.ipLabel(p.ip) || '').toLowerCase().includes(q) ||
            (p.hostname || '').toLowerCase().includes(q) ||
            (p.org || '').toLowerCase().includes(q) ||
            (p.country || '').toLowerCase().includes(q) ||
            (p.city || '').toLowerCase().includes(q) ||
            (app.localPeersText(p) || '').toLowerCase().includes(q) ||
            (p.mac || '').toLowerCase().includes(q) ||
            (p.vendor || '').toLowerCase().includes(q);
    };

    function updateHistStatus() {
        const el = document.getElementById('ovHistStatus');
        if (!el) return;
        if (app.histMode !== 'history') { el.textContent = ''; return; }
        if (app.histLoading) { el.textContent = 'Loading…'; return; }
        const total = (app.histData && app.histData.total) || 0;
        el.textContent = `${total} match${total === 1 ? '' : 'es'} · ~30d`;
    }

    // ── History fetch (DB query for the current scope/search/filters) ─────
    // Queries /api/connections so Statistics + Connections can show the full
    // retained history, not just the live points. Latest-wins via _histToken so a
    // slow response can't overwrite a newer one.
    app.fetchHistory = async () => {
        if (!app.statsOverlayOpen || app.histMode !== 'history') return;
        const token = ++app._histToken;
        app.histLoading = true;
        updateHistStatus();
        const params = new URLSearchParams();
        params.set('device', app.statsDevice || 'all');
        if (app.ovQuery) params.set('q', app.ovQuery);
        if (app.ovFilters.country) params.set('country', app.ovFilters.country);
        if (app.ovFilters.threat) params.set('threat', app.ovFilters.threat);
        if (app.ovFilters.protocol) params.set('protocol', app.ovFilters.protocol);
        params.set('sort', app.connSort.key);
        params.set('dir', app.connSort.dir < 0 ? 'desc' : 'asc');
        params.set('limit', '500');
        const empty = { rows: [], total: 0, summary: {}, facets: { countries: [] } };
        try {
            const res = await fetch('/api/connections?' + params.toString(), { credentials: 'same-origin' });
            if (token !== app._histToken) return;   // a newer fetch superseded us
            app.histData = res.ok ? await res.json() : empty;
        } catch (_) {
            if (token !== app._histToken) return;
            app.histData = empty;
        }
        if (token !== app._histToken) return;
        app.histLoading = false;
        app.syncCountryFilter?.();
        updateHistStatus();
        app.renderActivePage();
    };

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
        // The "At a glance" widget grid is a live-only surface (it reads the 5s
        // stats push). In History mode the page renders its KPIs from the DB
        // aggregate instead, so hide the live grid + its widget chooser.
        const hist = app.histMode === 'history';
        const head = document.querySelector('#appOverlay .stat-head');
        const cfg = document.getElementById('statCfg');
        if (head) head.style.display = hist ? 'none' : '';
        grid.style.display = hist ? 'none' : '';
        if (hist && cfg) cfg.style.display = 'none';
        if (!hist) {
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
        }
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
        if (deviceSel === 'all') {
            return Object.values(app.points).filter(p =>
                !p.expired && p.ip && app.pointDeviceVisible(p) && app.matchesOvFilter(p));
        }
        if (!app.isDeviceVisible(deviceSel)) return [];
        const seen = new Set(); const out = [];
        for (const k in app.arcs) {
            const a = app.arcs[k];
            if (a.expired || a.device_id !== deviceSel) continue;
            const p = app.points[a.ip];
            if (p && !p.expired && !seen.has(a.ip) && app.matchesOvFilter(p)) { seen.add(a.ip); out.push(p); }
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

    // ── Per-LAN-device aggregation ────────────────────────
    // Flip the usual "external IP -> which LAN hosts" view around: group the
    // visible connections by local (LAN) device so the operator can see which
    // host on their own network is busiest — its combined packet rate, how many
    // distinct external endpoints it talks to, total packets and threat mix.
    // An external IP reached by several LAN hosts contributes to each of them
    // (we have no per-host packet split), so rates are an upper-bound attribution;
    // the distinct-connection count is exact.
    function lanAggregate(cs) {
        const map = new Map();
        for (const p of cs) {
            const peers = app.localPeers(p);
            if (!peers.length) continue;
            const rate = pointRate(p);
            const pkts = (p.incoming_count || 0) + (p.outgoing_count || 0);
            for (const lip of peers) {
                let e = map.get(lip);
                if (!e) { e = { ip: lip, rate: 0, packets: 0, conns: new Set(), high: 0, med: 0, low: 0, last: 0 }; map.set(lip, e); }
                e.rate += rate;
                e.packets += pkts;
                e.conns.add(p.ip);
                if (p.threat_level === 'High') e.high++;
                else if (p.threat_level === 'Medium') e.med++;
                else if (p.threat_level === 'Low') e.low++;
                if ((p.last_seen || 0) > e.last) e.last = p.last_seen || 0;
            }
        }
        return Array.from(map.values());
    }

    const LAN_SORT_MODES = [['rate', 'Top by rate'], ['conns', 'Most connections'], ['packets', 'Most packets']];
    const lanSortKey = { rate: e => e.rate, conns: e => e.conns.size, packets: e => e.packets };

    function renderLanList(container, cs) {
        const mode = app.lanSortMode;
        const keyFn = lanSortKey[mode] || lanSortKey.rate;
        const rows = lanAggregate(cs).sort((a, b) => keyFn(b) - keyFn(a)).slice(0, 50);
        const seg = LAN_SORT_MODES.map(([id, label]) =>
            `<button class="seg${id === mode ? ' active' : ''}" data-lan="${id}">${label}</button>`).join('');
        const threatCell = e => {
            const parts = [];
            if (e.high) parts.push(`<span class="threat-badge threat-high">${e.high}</span>`);
            if (e.med) parts.push(`<span class="threat-badge threat-medium">${e.med}</span>`);
            if (e.low) parts.push(`<span class="threat-badge threat-low">${e.low}</span>`);
            return parts.join(' ') || '<span class="muted">—</span>';
        };
        const tbody = rows.length ? rows.map((e, i) =>
            `<tr class="sl-row lan-row" data-lan-ip="${escapeHTML(e.ip)}">` +
                `<td class="sl-rank">${i + 1}</td>` +
                `<td><span class="sl-ip">${escapeHTML(app.ipDisplay(e.ip))}</span></td>` +
                `<td class="sl-metric ${mode === 'conns' ? 'm-num' : ''}">${formatNum(e.conns.size)}</td>` +
                `<td class="sl-metric ${mode === 'rate' ? 'm-rate' : ''}">${e.rate.toFixed(1)}/s</td>` +
                `<td class="sl-metric ${mode === 'packets' ? 'm-num' : ''}">${formatNum(e.packets)}</td>` +
                `<td>${threatCell(e)}</td></tr>`).join('')
            : '<tr><td colspan="6" class="sl-empty muted">no LAN data</td></tr>';
        container.innerHTML =
            `<div class="seg-ctrl">${seg}</div>` +
            '<div class="conn-table-wrap"><table class="conn-table sl-table"><thead><tr>' +
            `<th class="sl-rank">#</th><th>LAN device</th><th>Connections</th>` +
            `<th>Pkts/s</th><th>Packets</th><th>Threats</th>` +
            `</tr></thead><tbody>${tbody}</tbody></table></div>`;
        container.querySelectorAll('.seg').forEach(b => b.addEventListener('click', () => {
            app.lanSortMode = b.dataset.lan;
            localStorage.setItem('lanSortMode', app.lanSortMode);
            renderLanList(container, cs);
        }));
        // Clicking a LAN row filters the live lists / globe focus to that host's
        // busiest external endpoint so the two views stay connected.
        container.querySelectorAll('.lan-row').forEach(tr => tr.addEventListener('click', () => {
            const lip = tr.dataset.lanIp;
            const peerPoints = cs.filter(p => app.localPeers(p).includes(lip));
            if (!peerPoints.length) return;
            const top = peerPoints.sort((a, b) => pointRate(b) - pointRate(a))[0];
            app.showDataList(top);
            if (isValidCoord(top.lat, top.lng)) app.globe.pointOfView({ lat: top.lat, lng: top.lng, altitude: 2.5 }, 1000);
        }));
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
        if (app.histMode === 'history') return renderStatsHistory(body);
        const dev = ovDevice();
        const conns = connectionsFor(dev);
        const s = statsFor(dev);
        const totalRate = conns.reduce((sum, p) => sum + pointRate(p), 0);
        const suspicious = conns.filter(p => SEV_RANK[p.threat_level]).length;
        const lanRows = lanAggregate(conns);
        const kpis = [
            ['Connections', formatNum(conns.length), ''],
            ['LAN devices', formatNum(lanRows.length), ''],
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
                    `<div class="chart-card wide"><h5>Top countries (IPs)</h5>${countries.length ? svgBars(countries, '#3b82f6') : '<p class="muted">no data</p>'}</div>` +
                '</div>' +
            '</div>' +
            '<div class="stat-section"><h4 class="stat-section-title">LAN devices</h4>' +
                '<div id="lanListHost"></div>' +
            '</div>' +
            '<div class="stat-section"><h4 class="stat-section-title">Live lists</h4>' +
                '<div id="statListHost"></div>' +
            '</div>';
        renderLanList(body.querySelector('#lanListHost'), conns);
        renderStatList(body.querySelector('#statListHost'), conns);
    }

    function renderConnTab(body) {
        if (app.histMode === 'history') return renderConnHistory(body);
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

    // ── History renderers (DB-backed; see app.fetchHistory) ───────────────
    // The Connections table over the full retained history. Rows are already
    // sorted + capped server-side, so a header click re-queries rather than
    // re-sorting the page.
    function renderConnHistory(body) {
        const data = app.histData;
        if (app.histLoading && !data) { body.innerHTML = '<div class="conn-count muted">Loading history…</div>'; return; }
        const rows = (data && data.rows) || [];
        const total = (data && data.total) || 0;
        const { key, dir } = app.connSort;
        const cols = [['ip', 'IP'], ['local_ip', 'LAN device(s)'], ['country', 'Country'], ['org', 'Org'], ['protocol', 'Proto'],
                      ['incoming_count', 'In'], ['outgoing_count', 'Out'], ['threat_level', 'Threat'], ['last_seen', 'Last seen']];
        const head = cols.map(([k, l]) =>
            `<th data-k="${k}">${l}${key === k ? (dir < 0 ? ' ▼' : ' ▲') : ''}</th>`).join('');
        const trs = rows.map(p =>
            `<tr><td>${escapeHTML(p.ip)}</td><td class="ell">${escapeHTML(p.local_ip || '—')}</td><td>${escapeHTML(p.country || '')}</td>` +
            `<td class="ell">${escapeHTML(p.org || '')}</td><td>${escapeHTML(p.protocol || '')}</td>` +
            `<td>${formatNum(p.incoming_count || 0)}</td><td>${formatNum(p.outgoing_count || 0)}</td>` +
            `<td>${escapeHTML(p.threat_level || 'No Threat')}</td>` +
            `<td>${p.last_seen ? new Date(p.last_seen * 1000).toLocaleString() : ''}</td></tr>`).join('');
        const note = total > rows.length ? ` (showing ${rows.length} of ${total})` : '';
        body.innerHTML = `<div class="conn-count">${formatNum(total)} connections${note} · history ~30 days</div>` +
            `<div class="conn-table-wrap"><table class="conn-table"><thead><tr>${head}</tr></thead><tbody>${trs}</tbody></table></div>`;
        body.querySelectorAll('th[data-k]').forEach(th => th.addEventListener('click', () => {
            const k = th.dataset.k;
            if (app.connSort.key === k) app.connSort.dir *= -1; else { app.connSort.key = k; app.connSort.dir = -1; }
            app.fetchHistory();
        }));
        const rowEls = body.querySelectorAll('tbody tr');
        rows.forEach((p, i) => rowEls[i] && rowEls[i].addEventListener('click', () => {
            app.showDataList(p);
            if (isValidCoord(p.lat, p.lng)) app.globe.pointOfView({ lat: p.lat, lng: p.lng, altitude: 2.5 }, 1000);
        }));
    }

    // The Statistics page over the full retained history: KPIs/charts from the
    // server-side aggregate (whole match set), plus a top-by-packets list built
    // from the returned rows.
    function renderStatsHistory(body) {
        const data = app.histData;
        if (app.histLoading && !data) { body.innerHTML = '<div class="stat-section muted">Loading history…</div>'; return; }
        const sum = (data && data.summary) || {};
        const proto = sum.protocol || {};
        const threat = sum.threat || {};
        const total = (data && data.total) || 0;
        const suspicious = (threat.High || 0) + (threat.Medium || 0) + (threat.Low || 0);
        const kpis = [
            ['Connections', formatNum(total), ''],
            ['LAN devices', formatNum(sum.lan_devices || 0), ''],
            ['Packets', formatNum(sum.packets || 0), 'accent'],
            ['TCP', formatNum(proto.TCP || 0), ''],
            ['UDP', formatNum(proto.UDP || 0), ''],
            ['ICMP', formatNum(proto.ICMP || 0), ''],
            ['Suspicious', formatNum(suspicious), suspicious ? 'warn' : ''],
            ['High', formatNum(threat.High || 0), (threat.High ? 'danger' : '')],
        ];
        const protoSeg = [
            { label: 'TCP', value: proto.TCP || 0, color: '#4FC3F7' },
            { label: 'UDP', value: proto.UDP || 0, color: '#FFD54F' },
            { label: 'ICMP', value: proto.ICMP || 0, color: '#BA68C8' },
        ];
        const threatSeg = [
            { label: 'High', value: threat.High || 0, color: '#d11' },
            { label: 'Medium', value: threat.Medium || 0, color: '#e80' },
            { label: 'Low', value: threat.Low || 0, color: '#cc0' },
            { label: 'None', value: threat['No Threat'] || 0, color: '#393' },
        ];
        const countries = (sum.countries || []).map(([label, value]) => ({ label, value }));
        body.innerHTML =
            '<div class="stat-section">' +
                '<div class="kpi-row">' + kpis.map(([l, v, c]) =>
                    `<div class="kpi ${c}"><span class="kpi-val">${v}</span><small>${escapeHTML(l)}</small></div>`).join('') + '</div>' +
            '</div>' +
            '<div class="stat-section"><h4 class="stat-section-title">Distribution</h4>' +
                '<div class="chart-grid">' +
                    `<div class="chart-card"><h5>Protocols</h5>${svgDonut(protoSeg, 140)}${legendHtml(protoSeg)}</div>` +
                    `<div class="chart-card"><h5>Threats</h5>${svgDonut(threatSeg, 140)}${legendHtml(threatSeg)}</div>` +
                    `<div class="chart-card wide"><h5>Top countries (IPs)</h5>${countries.length ? svgBars(countries, '#3b82f6') : '<p class="muted">no data</p>'}</div>` +
                '</div>' +
            '</div>' +
            '<div class="stat-section"><h4 class="stat-section-title">Top connections by packets</h4>' +
                '<div id="histListHost"></div>' +
            '</div>';
        renderHistList(body.querySelector('#histListHost'), (data && data.rows) || []);
    }

    function renderHistList(container, rows) {
        const top = rows.slice().sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0)).slice(0, 50);
        const tbody = top.length ? top.map((p, i) => {
            const host = (p.hostname && p.hostname !== 'Unknown') ? p.hostname
                : (p.org && p.org !== 'Not available' ? p.org : '');
            return `<tr class="sl-row" data-i="${i}">` +
                `<td class="sl-rank">${i + 1}</td>` +
                `<td><span class="sl-dot" style="background:${getCircleColor(p.threat_level, p.org)}"></span>` +
                `<span class="sl-ip">${escapeHTML(p.ip)}</span>` +
                (host ? `<span class="sl-host">${escapeHTML(truncate(host, 36))}</span>` : '') + `</td>` +
                `<td class="ell sl-lan">${escapeHTML(p.local_ip || '—')}</td>` +
                `<td>${escapeHTML(p.country || '')}</td>` +
                `<td class="sl-metric m-num">${formatNum(p.packet_count || 0)}</td></tr>`;
        }).join('') : '<tr><td colspan="5" class="sl-empty muted">no data</td></tr>';
        container.innerHTML =
            '<div class="conn-table-wrap"><table class="conn-table sl-table"><thead><tr>' +
            '<th class="sl-rank">#</th><th>IP / host</th><th>LAN device(s)</th><th>Country</th><th class="sl-metric-h">Packets</th>' +
            '</tr></thead><tbody>' + tbody + '</tbody></table></div>';
        container.querySelectorAll('.sl-row').forEach(tr => tr.addEventListener('click', () => {
            const p = top[+tr.dataset.i];
            if (!p) return;
            app.showDataList(p);
            if (isValidCoord(p.lat, p.lng)) app.globe.pointOfView({ lat: p.lat, lng: p.lng, altitude: 2.5 }, 1000);
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
