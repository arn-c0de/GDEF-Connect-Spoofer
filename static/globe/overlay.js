// static/globe/overlay.js
//
// The unified modal overlay (Statistics · Connections · Devices · Settings)
// with its left tab rail, plus the gear menu button entry point and the
// organisation-list editor. The settings controls from the old sidebar are
// relocated here so the whole app config lives on one modern surface.

import { loadTrustedOrgs } from './classify.js';
import { showToast, icon } from './format.js';
import { STAT_WIDGETS } from './stats.js';

export function setupOverlay(app) {
    // ── Settings entry point ──────────────────────────────
    // Settings live as a page inside the unified overlay (see buildOverlay).
    // The gear top-bar button opens that overlay straight to the Settings page.
    const menuButton = document.getElementById('menuButton');
    let orgsLoaded   = false;

    menuButton.addEventListener('click', () => {
        if (!orgsLoaded) { loadOrgEditor(); orgsLoaded = true; }
        app.openOverlay();   // opens on the last-viewed page (Statistics by default)
    });

    const globeQuickMenu = document.getElementById('globeQuickMenu');
    const globeQuickButton = document.getElementById('globeQuickButton');
    globeQuickButton?.addEventListener('click', e => {
        e.stopPropagation();
        const open = !globeQuickMenu.classList.contains('open');
        globeQuickMenu.classList.toggle('open', open);
        app.syncNetworkFilterButtons?.();
        app.syncGlobeDisplayToggles?.();
    });
    document.addEventListener('click', e => {
        if (!globeQuickMenu?.classList.contains('open')) return;
        if (globeQuickMenu.contains(e.target)) return;
        globeQuickMenu.classList.remove('open');
    });
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') globeQuickMenu?.classList.remove('open');
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
    // One modal with a left tab rail. The gear top-bar button opens it on Settings,
    // the floating stats button on Statistics. The settings controls from the old
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
                  '<div class="ov-head-top">' +
                    '<h2 id="ovTitle">Statistics</h2>' +
                    '<div class="ov-head-tools">' +
                      '<div class="ov-mode seg-ctrl" id="ovMode">' +
                        '<button class="seg active" data-mode="live" title="Real-time view (last hour)">Live</button>' +
                        '<button class="seg" data-mode="history" title="Full retained history (~30 days)">History</button>' +
                      '</div>' +
                      '<label class="ov-scope" id="ovScope">Device&nbsp;' +
                        '<select id="ovDeviceSel" class="stat-device-sel"></select></label>' +
                      '<button id="ovClose" class="ov-close" title="Close (Esc)">' + icon('close') + '</button>' +
                    '</div>' +
                  '</div>' +
                  '<div class="ov-head-search" id="ovSearchBar">' +
                    '<input type="text" id="ovSearch" class="search-input" autocomplete="off"' +
                      ' placeholder="Search IP, host, org, country, MAC…">' +
                    '<div class="ov-filters" id="ovFilters">' +
                      '<label class="ov-filter">Country' +
                        '<select id="ovFilterCountry"><option value="">All</option></select></label>' +
                      '<label class="ov-filter">Threat' +
                        '<select id="ovFilterThreat"><option value="">All</option>' +
                          '<option value="High">High</option><option value="Medium">Medium</option>' +
                          '<option value="Low">Low</option><option value="No Threat">No Threat</option>' +
                        '</select></label>' +
                      '<label class="ov-filter">Proto' +
                        '<select id="ovFilterProto"><option value="">All</option>' +
                          '<option value="TCP">TCP</option><option value="UDP">UDP</option>' +
                          '<option value="ICMP">ICMP</option></select></label>' +
                      '<button id="ovClearFilters" class="device-btn" title="Clear search & filters">Clear</button>' +
                      '<span class="ov-hist-status" id="ovHistStatus"></span>' +
                    '</div>' +
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
            const isData = page === 'stats' || page === 'conn';
            // The device scope selector and Live/History toggle apply only to the
            // data pages (Statistics + Connections).
            document.getElementById('ovScope').style.display = isData ? '' : 'none';
            document.getElementById('ovMode').style.display = isData ? '' : 'none';
            // The search box is shown on every page except Settings; the
            // country/threat/proto filters only make sense on the data pages
            // (on Devices the box just filters the legend).
            document.getElementById('ovSearchBar').style.display = page === 'settings' ? 'none' : '';
            document.getElementById('ovFilters').style.display = isData ? '' : 'none';
            syncSearchUi(page);
            // Entering History on a data page (re)loads from the DB.
            if (isData && app.histMode === 'history') app.fetchHistory();
            // The Devices tab pulls fresh per-device history totals on open.
            if (page === 'devices') app.fetchDeviceStats?.();
            app.renderActivePage();
        };

        // Reflect the current query/filters in the controls and adapt the search
        // box to whichever page is active (data search vs device-legend filter).
        const searchInput = document.getElementById('ovSearch');
        function syncSearchUi(page) {
            if (page === 'devices') {
                searchInput.placeholder = 'Search devices…';
                searchInput.value = app.deviceQuery;
            } else {
                searchInput.placeholder = 'Search IP, host, org, country, MAC…';
                searchInput.value = app.ovQuery;
            }
            const mode = document.getElementById('ovMode');
            mode.querySelectorAll('.seg').forEach(b =>
                b.classList.toggle('active', b.dataset.mode === app.histMode));
            document.getElementById('ovFilterThreat').value = app.ovFilters.threat;
            document.getElementById('ovFilterProto').value = app.ovFilters.protocol;
            app.syncCountryFilter();
        }
        app.syncSearchUi = () => syncSearchUi(app.currentPage);

        // Country options come from the history facets when available, otherwise
        // from the live points, so the dropdown is useful in both modes.
        app.syncCountryFilter = () => {
            const sel = document.getElementById('ovFilterCountry');
            if (!sel) return;
            let pairs;  // [[country, ipCount], …], most IPs first
            if (app.histMode === 'history' && app.histData && app.histData.facets) {
                pairs = (app.histData.facets.countries || []).filter(p => p && p[0]);
            } else {
                const counts = {};
                for (const ip in app.points) {
                    const p = app.points[ip];
                    if (p.expired || !p.country || p.country === 'Unknown') continue;
                    counts[p.country] = (counts[p.country] || 0) + 1;
                }
                pairs = Object.entries(counts).sort((a, b) => b[1] - a[1]);
            }
            // Rebuild only when the option set actually changed (cheap signature).
            const sig = pairs.map(p => p[0] + ':' + p[1]).join('|');
            if (sel.dataset.sig !== sig) {
                sel.dataset.sig = sig;
                const frag = document.createDocumentFragment();
                const mk = (text, value) => { const o = document.createElement('option'); o.textContent = text; o.value = value; return o; };
                frag.appendChild(mk('All countries', ''));
                pairs.forEach(([cn, n]) => frag.appendChild(mk(`${cn} (${Number(n).toLocaleString()})`, cn)));
                sel.replaceChildren(frag);
            }
            sel.value = app.ovFilters.country;
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
            if (app.histMode === 'history') app.fetchHistory();
            app.renderActivePage();
        });

        // ── Live / History mode toggle ──
        document.getElementById('ovMode').querySelectorAll('.seg').forEach(b =>
            b.addEventListener('click', () => {
                if (app.histMode === b.dataset.mode) return;
                app.histMode = b.dataset.mode;
                localStorage.setItem('histMode', app.histMode);
                app.syncSearchUi();
                if (app.histMode === 'history') app.fetchHistory();
                app.renderActivePage();
            }));

        // ── Search box (debounced). On the data pages it drives the query (live
        // filter or DB fetch); on the Devices page it filters the legend. ──
        let searchDebounce;
        searchInput.addEventListener('input', e => {
            const v = e.target.value.trim();
            clearTimeout(searchDebounce);
            searchDebounce = setTimeout(() => {
                if (app.currentPage === 'devices') {
                    app.deviceQuery = v.toLowerCase();
                    app.buildDeviceLegend();
                    return;
                }
                app.ovQuery = v.toLowerCase();
                if (app.histMode === 'history') app.fetchHistory();
                else app.renderActivePage();
            }, 220);
        });

        // ── Country / Threat / Protocol filters ──
        const onFilterChange = (key, value) => {
            app.ovFilters[key] = value;
            if (app.histMode === 'history') app.fetchHistory();
            else app.renderActivePage();
        };
        document.getElementById('ovFilterCountry').addEventListener('change', e => onFilterChange('country', e.target.value));
        document.getElementById('ovFilterThreat').addEventListener('change', e => onFilterChange('threat', e.target.value));
        document.getElementById('ovFilterProto').addEventListener('change', e => onFilterChange('protocol', e.target.value));
        document.getElementById('ovClearFilters').addEventListener('click', () => {
            app.ovQuery = ''; app.deviceQuery = '';
            app.ovFilters = { country: '', threat: '', protocol: '' };
            app.syncSearchUi();
            if (app.currentPage === 'devices') app.buildDeviceLegend();
            else if (app.histMode === 'history') app.fetchHistory();
            else app.renderActivePage();
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
