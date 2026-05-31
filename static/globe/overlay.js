// static/globe/overlay.js
//
// The unified modal overlay (Statistics · Connections · Devices · Settings)
// with its left tab rail, plus the ⚙ menu button entry point and the
// organisation-list editor. The settings controls from the old sidebar are
// relocated here so the whole app config lives on one modern surface.

import { loadTrustedOrgs } from './classify.js';
import { showToast, icon } from './format.js';
import { STAT_WIDGETS } from './stats.js';

export function setupOverlay(app) {
    // ── Settings entry point ──────────────────────────────
    // Settings live as a page inside the unified overlay (see buildOverlay).
    // The ⚙ top-bar button opens that overlay straight to the Settings page.
    const menuButton = document.getElementById('menuButton');
    let orgsLoaded   = false;

    menuButton.addEventListener('click', () => {
        if (!orgsLoaded) { loadOrgEditor(); orgsLoaded = true; }
        app.openOverlay();   // opens on the last-viewed page (Statistics by default)
    });

    async function loadOrgEditor() {
        try {
            const res  = await fetch('/api/organisations');
            if (!res.ok) throw new Error('Failed to load');
            const data = await res.json();
            const el   = id => document.getElementById(id);
            if (el('orgTrusted'))    el('orgTrusted').value    = (data.trusted_organisations   || []).join('\n');
            if (el('orgSuspicious')) el('orgSuspicious').value = (data.suspicious_organisations || []).join('\n');
            if (el('orgDangerous'))  el('orgDangerous').value  = (data.dangerous_organisations  || []).join('\n');
        } catch (err) {
            console.error('Error loading organisations:', err);
        }
    }

    document.getElementById('saveOrgs')?.addEventListener('click', async () => {
        const lines = id => (document.getElementById(id)?.value || '')
            .split('\n').map(s => s.trim()).filter(Boolean);
        const payload = {
            trusted_organisations:    lines('orgTrusted'),
            suspicious_organisations: lines('orgSuspicious'),
            dangerous_organisations:  lines('orgDangerous'),
        };
        try {
            const res = await fetch('/api/organisations', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (res.ok) {
                showToast('Organisation lists saved.', 'ok');
                await loadTrustedOrgs();
                app.refreshViews();
            } else {
                showToast('Failed to save organisation lists.', 'error');
            }
        } catch (_) {
            showToast('Network error saving organisation lists.', 'error');
        }
    });

    // ── Tabbed Statistics / Connections / Devices / Settings overlay ──
    // One modal with a left tab rail. The ⚙ top-bar button opens it on Settings,
    // the floating 📊 button on Statistics. The settings controls from the old
    // sidebar (Display, Org lists, IP labels, Export) are relocated here so the
    // whole app config lives in a single modern surface.
    function buildOverlay() {
        if (document.getElementById('appOverlay')) return;

        const ov = document.createElement('div');
        ov.id = 'appOverlay'; ov.style.display = 'none';
        ov.innerHTML =
            '<div class="ov-panel">' +
              '<nav class="ov-nav">' +
                '<div class="ov-brand">GDEF<span>-L1NK</span></div>' +
                '<button class="ov-nav-item active" data-page="stats"><span class="ov-ico">' + icon('stats') + '</span>Statistics</button>' +
                '<button class="ov-nav-item" data-page="conn"><span class="ov-ico">' + icon('conn') + '</span>Connections</button>' +
                '<button class="ov-nav-item" data-page="devices"><span class="ov-ico">' + icon('monitor') + '</span>Devices</button>' +
                '<button class="ov-nav-item" data-page="settings"><span class="ov-ico">' + icon('gear') + '</span>Settings</button>' +
                '<div class="ov-nav-spacer"></div>' +
                '<a class="ov-nav-item ov-logout" id="ovLogout"><span class="ov-ico">↩</span>Logout</a>' +
              '</nav>' +
              '<section class="ov-main">' +
                '<header class="ov-pagehead">' +
                  '<h2 id="ovTitle">Statistics</h2>' +
                  '<div class="ov-head-tools">' +
                    '<label class="ov-scope" id="ovScope">Device&nbsp;' +
                      '<select id="ovDeviceSel" class="stat-device-sel"></select></label>' +
                    '<button id="ovClose" class="ov-close" title="Close (Esc)">' + icon('close') + '</button>' +
                  '</div>' +
                '</header>' +
                '<div class="ov-scroll">' +
                  '<div class="ov-page active" data-page="stats">' +
                    '<div class="stat-head"><h4>At a glance</h4>' +
                      '<button id="statCfgBtn" class="device-btn" title="Choose widgets">' + icon('widgets') + ' Widgets</button></div>' +
                    '<div id="statCfg" class="stat-cfg" style="display:none"></div>' +
                    '<div id="modStatGrid" class="stat-grid"></div>' +
                    '<div id="ovStatsCharts"></div>' +
                  '</div>' +
                  '<div class="ov-page" data-page="conn"><div id="ovConnBody"></div></div>' +
                  '<div class="ov-page" data-page="devices">' +
                    '<div class="color-mode-row">Colour globe by:' +
                      ' <button id="cmThreat" class="toggle-button">Threat</button>' +
                      ' <button id="cmDevice" class="toggle-button">Device</button></div>' +
                    '<div id="deviceLegendList" class="device-legend"></div>' +
                    '<button id="addDeviceBtn" class="toggle-button">+ Add device</button>' +
                  '</div>' +
                  '<div class="ov-page" data-page="settings"><div id="ovSettingsHost"></div></div>' +
                '</div>' +
              '</section>' +
            '</div>';
        document.body.appendChild(ov);

        // Relocate the template settings sections (Display, Org lists, IP labels,
        // Export) into the Settings page — moving the nodes keeps their existing
        // IDs and event wiring intact.
        const host = document.getElementById('ovSettingsHost');
        const sb = document.getElementById('sidebar');
        if (sb) {
            sb.querySelectorAll('.sidebar-section').forEach(sec => host.appendChild(sec));
            const lo = sb.querySelector('.logout-link');
            if (lo) document.getElementById('ovLogout').href = lo.getAttribute('href');
            sb.remove();
        }

        // ── Page switching ──
        const titles = { stats: 'Statistics', conn: 'Connections', devices: 'Devices', settings: 'Settings' };
        const showPage = page => {
            app.currentPage = page;
            ov.querySelectorAll('.ov-nav-item[data-page]').forEach(b =>
                b.classList.toggle('active', b.dataset.page === page));
            ov.querySelectorAll('.ov-page').forEach(p =>
                p.classList.toggle('active', p.dataset.page === page));
            document.getElementById('ovTitle').textContent = titles[page] || '';
            // The device scope selector only applies to Statistics + Connections.
            document.getElementById('ovScope').style.display =
                (page === 'stats' || page === 'conn') ? '' : 'none';
            app.renderActivePage();
        };

        // ── Open / close ──
        app.openOverlay = page => {
            app.statsOverlayOpen = true;
            ov.style.display = 'flex';
            app.syncDeviceSelect(document.getElementById('ovDeviceSel'));
            app.syncNetworkFilterButtons?.();
            app.syncGlobeDisplayToggles?.();
            app.buildDeviceLegend();
            showPage(page || app.currentPage || 'stats');
        };
        const close = () => { app.statsOverlayOpen = false; ov.style.display = 'none'; };
        document.getElementById('ovClose').addEventListener('click', close);
        ov.addEventListener('click', e => { if (e.target === ov) close(); });
        document.addEventListener('keydown', e => { if (e.key === 'Escape' && app.statsOverlayOpen) close(); });
        ov.querySelectorAll('.ov-nav-item[data-page]').forEach(b =>
            b.addEventListener('click', () => showPage(b.dataset.page)));

        // ── Device scope selector ──
        const sel = document.getElementById('ovDeviceSel');
        app.syncDeviceSelect(sel);
        sel.addEventListener('change', () => {
            app.statsDevice = sel.value;
            localStorage.setItem('statsDevice', app.statsDevice);
            app.renderActivePage();
        });

        // ── Colour-mode toggle (Devices page) ──
        const cmThreat = document.getElementById('cmThreat');
        const cmDevice = document.getElementById('cmDevice');
        const syncCm = () => {
            cmThreat.classList.toggle('active', app.colorMode === 'threat');
            cmDevice.classList.toggle('active', app.colorMode === 'device');
        };
        const setMode = m => { app.colorMode = m; localStorage.setItem('colorMode', m); syncCm(); app.updateGlobeData(); };
        cmThreat.addEventListener('click', () => setMode('threat'));
        cmDevice.addEventListener('click', () => setMode('device'));
        syncCm();
        document.getElementById('addDeviceBtn').addEventListener('click', app.addDevice);

        // ── Globe filter toggles (Settings page) ──
        [
            ['ovToggleLocalNetwork', 'local', () => !app.showLocalNetwork],
            ['ovToggleExternalNetwork', 'external', () => !app.showExternalNetwork],
            ['ovToggleTCPOnly', 'tcp', () => !app.showTCPOnly],
            ['ovToggleAllUDPPackets', 'udp', () => !app.showAllUDPPackets],
        ].forEach(([id, key, next]) => {
            document.getElementById(id)?.addEventListener('click', () => app.setNetworkFilter(key, next()));
        });
        app.syncNetworkFilterButtons?.();

        // ── Widget chooser (Statistics page) ──
        const cfg = document.getElementById('statCfg');
        document.getElementById('statCfgBtn').addEventListener('click', () => {
            cfg.style.display = cfg.style.display === 'none' ? 'block' : 'none';
            buildStatCfg();
        });
        function buildStatCfg() {
            const frag = document.createDocumentFragment();
            const ordered = [...app.enabledWidgets, ...STAT_WIDGETS.map(w => w.id).filter(id => !app.enabledWidgets.includes(id))];
            ordered.forEach(id => {
                const w = STAT_WIDGETS.find(x => x.id === id);
                const on = app.enabledWidgets.includes(id);
                const r = document.createElement('div');
                r.className = 'stat-cfg-row';
                const cb = document.createElement('input');
                cb.type = 'checkbox'; cb.checked = on;
                cb.addEventListener('change', () => {
                    if (cb.checked) { if (!app.enabledWidgets.includes(id)) app.enabledWidgets.push(id); }
                    else app.enabledWidgets = app.enabledWidgets.filter(x => x !== id);
                    app.saveStatPrefs(); app.renderStats(); buildStatCfg();
                });
                const lbl = document.createElement('span'); lbl.textContent = w.label;
                const up = document.createElement('button'); up.className = 'device-btn'; up.textContent = '↑';
                const dn = document.createElement('button'); dn.className = 'device-btn'; dn.textContent = '↓';
                const move = dir => {
                    const i = app.enabledWidgets.indexOf(id);
                    if (i < 0) return;
                    const j = i + dir;
                    if (j < 0 || j >= app.enabledWidgets.length) return;
                    [app.enabledWidgets[i], app.enabledWidgets[j]] = [app.enabledWidgets[j], app.enabledWidgets[i]];
                    app.saveStatPrefs(); app.renderStats(); buildStatCfg();
                };
                up.addEventListener('click', () => move(-1));
                dn.addEventListener('click', () => move(1));
                r.append(cb, lbl);
                if (on) r.append(up, dn);
                frag.appendChild(r);
            });
            cfg.replaceChildren(frag);
        }

        app.buildDeviceLegend();
        app.renderStats();
        app.wireIpLabelsEditor();
    }
    buildOverlay();
}
