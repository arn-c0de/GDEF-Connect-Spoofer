// static/globe/threats.js
//
// Top-bar threat ticker: two rows (suspicious/dangerous IPs, and the newest
// connections) shown either as a scrolling marquee or — when scrolling is off —
// as a step display that cycles one IP at a time on a fixed interval. Clicking
// the ticker expands a panel with a mini settings menu (scroll on/off, scroll
// speed, step interval) plus the full threat list and newest connections.
//
// Reads straight from app.points, re-rendered off the throttled refreshViews
// path. Brand-new IPs (server flag is_new, from the permanent ip_seen ledger)
// are tagged "NEW" so genuinely-new connections stand out.

import { timeAgo, escapeHTML, makeThreatBadge, loadJSON, saveJSON } from './format.js';
import { getCircleColor } from './classify.js';

const THREAT_RANK = { High: 3, Medium: 2, Low: 1 };
const NEWEST_PANEL_LIMIT  = 12;   // detail panel
const NEWEST_TICKER_LIMIT = 20;   // scrolling/step row

// Persisted ticker settings (localStorage).
const settings = {
    scroll: loadJSON('tickerScroll', true),         // true = marquee, false = step
    speed:  loadJSON('tickerSpeed', 60),            // px/sec for the marquee
    stepSec: loadJSON('tickerStepSec', 5),          // seconds between step swaps
};
function saveSettings() {
    saveJSON('tickerScroll', settings.scroll);
    saveJSON('tickerSpeed', settings.speed);
    saveJSON('tickerStepSec', settings.stepSec);
}

export function setupThreatTicker(app) {
    const ticker      = document.getElementById('threatTicker');
    const caret       = document.getElementById('threatTickerCaret');
    const panel       = document.getElementById('threatPanel');
    const threatList  = document.getElementById('threatPanelList');
    const newestList  = document.getElementById('newestPanelList');
    const threatTrack = document.getElementById('threatTickerTrack');
    const newestTrack = document.getElementById('newestTickerTrack');
    if (!ticker || !panel || !threatList || !newestList || !threatTrack || !newestTrack) return;

    // Recent rows from the permanent ip_seen ledger (fetched from /api/recent),
    // so the tickers show history that has aged out of the live points too.
    let serverNewest = [], serverThreats = [];

    // ── data selectors (live app.points MERGED with the DB ledger) ─────────
    function visiblePoints() {
        const out = [];
        for (const ip in app.points) {
            const p = app.points[ip];
            if (!p || p.expired || p.isOrigin) continue;
            out.push(p);
        }
        return out;
    }
    // When this IP was EVER first observed (server-backed, survives restarts);
    // falls back to the session-local first sight, then last activity.
    function firstSeenEver(p) {
        return p.first_seen_ever || p._firstSeen || p.last_seen || 0;
    }
    // A ledger row dressed up as a point so the renderers/panel treat it uniformly.
    function ledgerToPoint(r) {
        return {
            ip: r.ip, org: r.org, country: r.country,
            hostname: r.hostname || 'Unknown',
            threat_level: r.threat_level || 'No Threat',
            last_seen: r.last_seen,
            _firstSeen: r.first_seen, first_seen_ever: r.first_seen,
            is_new: false, incoming_count: 0, outgoing_count: 0, packet_count: 0,
            _fromDB: true,
        };
    }
    // Merge DB rows with live points, keyed by IP — the live object wins (it is
    // richer and clickable), the DB fills in everything that has expired.
    function merged(serverRows, livePoints) {
        const map = new Map();
        for (const r of serverRows) map.set(r.ip, ledgerToPoint(r));
        for (const p of livePoints) map.set(p.ip, p);
        return [...map.values()];
    }
    function threatPoints() {
        const live = visiblePoints().filter(p => THREAT_RANK[p.threat_level]);
        return merged(serverThreats, live).sort((a, b) =>
            (THREAT_RANK[b.threat_level] - THREAT_RANK[a.threat_level]) ||
            ((b.last_seen || 0) - (a.last_seen || 0)));
    }
    function newestPoints(limit) {
        // Most-recently FIRST-seen across all history → genuinely new connections
        // bubble to the top; long-known IPs sink even while live.
        return merged(serverNewest, visiblePoints())
            .sort((a, b) => firstSeenEver(b) - firstSeenEver(a))
            .slice(0, limit);
    }
    // Resolved hostname, else org (the meaningful name for an external IP), else IP.
    function nameOf(p) {
        if (p.hostname && p.hostname !== 'Unknown' && p.hostname !== p.ip) return p.hostname;
        if (p.org && p.org !== 'Unknown' && p.org !== 'N/A') return p.org;
        return p.ip;
    }
    // Membership signature: rebuild a row only when its IP set (or new-flag)
    // changes — never on mere reordering — so the marquee scroll isn't restarted.
    function sigOf(points) {
        return points.map(p => p.ip + (p.is_new ? '!' : '')).slice().sort().join('|');
    }

    // ── one item's markup ──────────────────────────────────
    function itemHTML(p, stamp) {
        const color = getCircleColor(p.threat_level, p.org);
        return '<span class="ticker-item">' +
               `<span class="ticker-dot" style="background:${color}"></span>` +
               (p.is_new ? '<span class="ticker-new">NEW</span>' : '') +
               `<span class="ticker-ip">${escapeHTML(p.ip)}</span>` +
               `<span class="ticker-name">${escapeHTML(nameOf(p))}</span>` +
               `<span class="ticker-time">${escapeHTML(timeAgo(stamp))}</span>` +
               '</span>';
    }

    // ── per-row controller (scroll OR step) ────────────────
    function makeRow(trackEl, stampFn, emptyMsg) {
        let points = [], sig = null, stepIdx = 0, stepTimer = null;

        function clearStep() { if (stepTimer) { clearInterval(stepTimer); stepTimer = null; } }

        function renderScroll() {
            clearStep();
            if (!points.length) {
                trackEl.style.animation = 'none';
                trackEl.style.transform = 'none';
                trackEl.className = 'ticker-track';
                trackEl.innerHTML = `<span class="ticker-item ticker-none">${escapeHTML(emptyMsg)}</span>`;
                return;
            }
            const sep = '<span class="ticker-sep">•</span>';
            const seq = points.map(p => itemHTML(p, stampFn(p))).join(sep);
            // Duplicate the sequence so a -50% shift loops seamlessly (pixel-exact:
            // both halves are identical, so the wrap point has no jump).
            trackEl.className = 'ticker-track';
            trackEl.innerHTML = seq + sep + seq + sep;
            trackEl.style.transform = '';
            applyScrollSpeed();
        }

        // Constant linear speed: duration = half the track width / px-per-second,
        // so BOTH rows move at exactly settings.speed px/s regardless of how many
        // items each holds (identical visual speed — no length-based scaling, no
        // floor that would slow a short row down).
        function applyScrollSpeed() {
            const half = trackEl.scrollWidth / 2;
            if (half < 1) { trackEl.style.animation = 'none'; return; }
            const dur = half / Math.max(10, settings.speed);
            trackEl.style.animation = `tickerScroll ${dur}s linear infinite`;
        }

        // Update only the "x ago" text in place — no innerHTML rebuild, so the
        // scroll animation never restarts (a prime source of the brief stutter).
        function refreshTimes() {
            const items = trackEl.querySelectorAll('.ticker-item');
            if (!items.length || !points.length) return;
            items.forEach((el, i) => {
                const p = points[i % points.length];
                const t = el.querySelector('.ticker-time');
                if (p && t) t.textContent = timeAgo(stampFn(p));
            });
        }

        function renderStepFrame() {
            if (!points.length) {
                trackEl.className = 'ticker-track ticker-step';
                trackEl.innerHTML = `<span class="ticker-item ticker-none">${escapeHTML(emptyMsg)}</span>`;
                return;
            }
            if (stepIdx >= points.length) stepIdx = 0;
            const p = points[stepIdx];
            trackEl.className = 'ticker-track ticker-step';
            trackEl.style.animation = 'none';
            trackEl.style.transform = 'none';
            // Re-trigger the fade-in by reflowing the single child.
            trackEl.innerHTML = itemHTML(p, stampFn(p));
            const child = trackEl.firstElementChild;
            if (child) { child.classList.add('ticker-fade'); }
        }

        function renderStep() {
            clearStep();
            renderStepFrame();
            if (points.length > 1) {
                stepTimer = setInterval(() => {
                    stepIdx = (stepIdx + 1) % points.length;
                    renderStepFrame();
                }, Math.max(1000, settings.stepSec * 1000));
            }
        }

        return {
            // Feed fresh data; rebuild only on membership change, else just refresh
            // the visible times (scroll) — keeps the animation uninterrupted.
            update(newPoints) {
                points = newPoints;
                const newSig = sigOf(points);
                const changed = newSig !== sig;
                sig = newSig;
                if (settings.scroll) {
                    if (changed) renderScroll();
                    else refreshTimes();
                } else {
                    if (changed) renderStep();
                    else renderStepFrame();
                }
            },
            // Re-apply after a settings change (mode/speed/interval).
            relayout() {
                sig = sigOf(points);   // force the next update to refresh, not rebuild
                if (settings.scroll) renderScroll();
                else renderStep();
            },
            tickTimes() { if (settings.scroll) refreshTimes(); },
            destroy() { clearStep(); },
        };
    }

    const rowThreat = makeRow(threatTrack, p => p.last_seen,   'No threats detected');
    const rowNewest = makeRow(newestTrack, p => firstSeenEver(p), 'No connections yet');

    // ── detail panel rows ──────────────────────────────────
    function panelRow(p, withBadge) {
        const li = document.createElement('li');
        li.className = 'tp-row';

        const dot = document.createElement('span');
        dot.className = 'tp-dot';
        dot.style.background = getCircleColor(p.threat_level, p.org);
        li.appendChild(dot);

        const main = document.createElement('div');
        main.className = 'tp-main';
        const ipLine = document.createElement('span');
        ipLine.className = 'tp-ip';
        ipLine.textContent = p.ip;
        if (p.is_new) {
            const nb = document.createElement('span');
            nb.className = 'tp-new';
            nb.textContent = 'NEW';
            ipLine.appendChild(nb);
        }
        const metaEl = document.createElement('span');
        metaEl.className = 'tp-meta';
        const country = (p.country && p.country !== 'N/A') ? ` · ${p.country}` : '';
        metaEl.textContent = nameOf(p) + country;
        main.appendChild(ipLine);
        main.appendChild(metaEl);
        li.appendChild(main);

        const right = document.createElement('div');
        right.className = 'tp-right';
        if (withBadge) right.appendChild(makeThreatBadge(p.threat_level));
        const t = document.createElement('span');
        t.className = 'tp-time';
        const stamp = withBadge ? p.last_seen : (p._firstSeen || p.last_seen);
        t.textContent = timeAgo(stamp);
        if (stamp) t.title = new Date(stamp * 1000).toLocaleString();
        right.appendChild(t);
        li.appendChild(right);

        li.addEventListener('click', (e) => {
            e.stopPropagation();
            if (app.showDataList) app.showDataList(p);
            closePanel();
        });
        return li;
    }
    function fill(listEl, points, withBadge, emptyMsg) {
        listEl.innerHTML = '';
        if (!points.length) {
            const li = document.createElement('li');
            li.className = 'tp-none';
            li.textContent = emptyMsg;
            listEl.appendChild(li);
            return;
        }
        for (const p of points) listEl.appendChild(panelRow(p, withBadge));
    }

    // ── settings menu ──────────────────────────────────────
    const scrollToggle = document.getElementById('tickerScrollToggle');
    const speedInput   = document.getElementById('tickerSpeed');
    const stepInput    = document.getElementById('tickerStepSec');
    const stepVal      = document.getElementById('tickerStepVal');
    const speedRow     = document.getElementById('tickerSpeedRow');
    const stepRow      = document.getElementById('tickerStepRow');

    function syncSettingsUI() {
        if (scrollToggle) scrollToggle.checked = settings.scroll;
        if (speedInput)   speedInput.value = settings.speed;
        if (stepInput)    stepInput.value = settings.stepSec;
        if (stepVal)      stepVal.textContent = `${settings.stepSec}s`;
        if (speedRow)     speedRow.style.display = settings.scroll ? '' : 'none';
        if (stepRow)      stepRow.style.display = settings.scroll ? 'none' : '';
    }
    if (scrollToggle) scrollToggle.addEventListener('change', () => {
        settings.scroll = scrollToggle.checked; saveSettings(); syncSettingsUI();
        rowThreat.relayout(); rowNewest.relayout();
    });
    if (speedInput) speedInput.addEventListener('input', () => {
        settings.speed = Number(speedInput.value) || 60; saveSettings();
        if (settings.scroll) { rowThreat.relayout(); rowNewest.relayout(); }
    });
    if (stepInput) stepInput.addEventListener('input', () => {
        settings.stepSec = Number(stepInput.value) || 5; saveSettings();
        if (stepVal) stepVal.textContent = `${settings.stepSec}s`;
        if (!settings.scroll) { rowThreat.relayout(); rowNewest.relayout(); }
    });
    // Don't let clicks inside the settings menu bubble up and toggle the panel.
    const settingsBox = panel.querySelector('.tp-settings');
    if (settingsBox) settingsBox.addEventListener('click', e => e.stopPropagation());

    // ── open / close panel ─────────────────────────────────
    let open = false;
    function openPanel() {
        open = true;
        panel.classList.remove('hidden');
        if (caret) caret.textContent = '▴';
        ticker.classList.add('ticker-open');
        renderPanelLists();
    }
    function closePanel() {
        open = false;
        panel.classList.add('hidden');
        if (caret) caret.textContent = '▾';
        ticker.classList.remove('ticker-open');
    }
    ticker.addEventListener('click', () => open ? closePanel() : openPanel());
    document.addEventListener('click', (e) => {
        if (open && !panel.contains(e.target) && !ticker.contains(e.target)) closePanel();
    });

    // ── render entry point ─────────────────────────────────
    function renderPanelLists() {
        fill(threatList, threatPoints(),                  true,  'No threats detected');
        fill(newestList, newestPoints(NEWEST_PANEL_LIMIT), false, 'No connections yet');
    }
    function render() {
        rowThreat.update(threatPoints());
        rowNewest.update(newestPoints(NEWEST_TICKER_LIMIT));
        if (open) renderPanelLists();
    }
    app.renderThreatTicker = render;

    // Pull the permanent ledger so the rows include IPs that have aged out of the
    // live points (history). Refreshed periodically; merged in by the selectors.
    async function fetchRecent() {
        try {
            const res = await fetch('/api/recent', { credentials: 'same-origin' });
            if (!res.ok) return;
            const d = await res.json();
            serverNewest  = Array.isArray(d.newest)  ? d.newest  : [];
            serverThreats = Array.isArray(d.threats) ? d.threats : [];
            render();
        } catch (_) { /* transient / offline — keep last data */ }
    }

    syncSettingsUI();
    render();
    fetchRecent();
    setInterval(fetchRecent, 30000);
    // Keep the "x ago" stamps fresh without rebuilding/restarting the marquee.
    setInterval(() => { rowThreat.tickTimes(); rowNewest.tickTimes(); }, 15000);
}
