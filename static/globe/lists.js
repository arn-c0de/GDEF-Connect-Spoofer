// static/globe/lists.js
//
// The live sidebar: the active-connections list, the internal-network list,
// the per-IP detail panel, the throttled view refresh that coalesces socket
// bursts, the filter toggle buttons + search inputs, and the IP-label editor.

import { isValidCoord, isLocalNetwork } from './net.js';
import { getCircleColor } from './classify.js';
import {
    PORT_SERVICES, timeAgo, formatNum, truncate,
    makeThreatBadge, showToast, escapeHTML,
} from './format.js';

export function setupLists(app) {
    const activeConnectionsList = document.getElementById('activeConnectionsList');
    const internalNetworkList   = document.getElementById('internalNetworkList');
    app.activeConnectionsList = activeConnectionsList;
    app.internalNetworkList   = internalNetworkList;

    if (app.isInternalNetworkCollapsed)  internalNetworkList.classList.add('collapsed');
    if (app.isActiveConnectionsCollapsed) activeConnectionsList.classList.add('collapsed');

    // ── Throttled view refresh ────────────────────────────
    // Coalesces rapid socket bursts to at most one DOM rebuild per
    // REFRESH_MIN_MS, with a trailing update so nothing gets dropped.
    function _refreshViewsNow() {
        app.updateConnectionsList();
        app.updateInternalNetworkList();
        app.updateGlobeData();
        app.renderStats();
        if (app.renderThreatTicker) app.renderThreatTicker();
    }

    app.refreshViews = () => {
        const now     = Date.now();
        const elapsed = now - app._lastRefresh;
        if (elapsed >= app.REFRESH_MIN_MS) {
            app._lastRefresh = now;
            if (app._refreshTimer) { clearTimeout(app._refreshTimer); app._refreshTimer = null; }
            _refreshViewsNow();
        } else if (!app._refreshTimer) {
            app._refreshTimer = setTimeout(() => {
                app._refreshTimer = null;
                app._lastRefresh  = Date.now();
                _refreshViewsNow();
            }, app.REFRESH_MIN_MS - elapsed);
        }
    };

    // ── Toggle buttons ────────────────────────────────────
    const toggleInternalNetworkButton = document.getElementById('toggleInternalNetwork');
    toggleInternalNetworkButton.textContent = app.isInternalNetworkCollapsed ? '▼' : '▲';
    toggleInternalNetworkButton.addEventListener('click', () => {
        app.isInternalNetworkCollapsed = !app.isInternalNetworkCollapsed;
        localStorage.setItem('isInternalNetworkCollapsed', JSON.stringify(app.isInternalNetworkCollapsed));
        toggleInternalNetworkButton.textContent = app.isInternalNetworkCollapsed ? '▼' : '▲';
        internalNetworkList.classList.toggle('collapsed', app.isInternalNetworkCollapsed);
    });

    // Clone to remove the stale listener that the HTML template attached.
    const origToggleActive = document.getElementById('toggleActiveConnections');
    const toggleActiveConnectionsButton = origToggleActive.cloneNode(true);
    origToggleActive.replaceWith(toggleActiveConnectionsButton);
    toggleActiveConnectionsButton.textContent = app.isActiveConnectionsCollapsed ? '▼' : '▲';
    toggleActiveConnectionsButton.addEventListener('click', () => {
        app.isActiveConnectionsCollapsed = !app.isActiveConnectionsCollapsed;
        localStorage.setItem('isActiveConnectionsCollapsed', JSON.stringify(app.isActiveConnectionsCollapsed));
        toggleActiveConnectionsButton.textContent = app.isActiveConnectionsCollapsed ? '▼' : '▲';
        activeConnectionsList.classList.toggle('collapsed', app.isActiveConnectionsCollapsed);
        activeConnectionsList.style.height = app.isActiveConnectionsCollapsed ? '42px' : '';
    });

    const toggleLocalNetworkButton = document.getElementById('toggleLocalNetwork');
    app.toggleLocalNetworkButton = toggleLocalNetworkButton;
    toggleLocalNetworkButton.classList.toggle('active', app.showLocalNetwork);
    let _localDebounce;
    toggleLocalNetworkButton.addEventListener('click', () => {
        clearTimeout(_localDebounce);
        _localDebounce = setTimeout(() => {
            app.showLocalNetwork = !app.showLocalNetwork;
            toggleLocalNetworkButton.classList.toggle('active', app.showLocalNetwork);
            app.syncNetworkFilterButtons?.();
            app.socket.emit('set_local_network', { showLocalNetwork: app.showLocalNetwork });
            app.refreshViews();
        }, 300);
    });

    const toggleExternalNetworkButton = document.getElementById('toggleExternalNetwork');
    app.toggleExternalNetworkButton = toggleExternalNetworkButton;
    toggleExternalNetworkButton.classList.toggle('active', app.showExternalNetwork);
    toggleExternalNetworkButton.addEventListener('click', () => {
        app.showExternalNetwork = !app.showExternalNetwork;
        toggleExternalNetworkButton.classList.toggle('active', app.showExternalNetwork);
        app.syncNetworkFilterButtons?.();
        app.socket.emit('set_external_network', { showExternalNetwork: app.showExternalNetwork });
        app.refreshViews();
    });

    const toggleTCPOnlyButton = document.getElementById('toggleTCPOnly');
    app.toggleTCPOnlyButton = toggleTCPOnlyButton;
    toggleTCPOnlyButton.classList.toggle('active', app.showTCPOnly);
    toggleTCPOnlyButton.addEventListener('click', () => {
        app.showTCPOnly = !app.showTCPOnly;
        toggleTCPOnlyButton.classList.toggle('active', app.showTCPOnly);
        app.syncNetworkFilterButtons?.();
        app.socket.emit('set_tcp_only', { showTCPOnly: app.showTCPOnly });
        app.refreshViews();
    });

    const toggleAllUDPPacketsButton = document.getElementById('toggleAllUDPPackets');
    app.toggleAllUDPPacketsButton = toggleAllUDPPacketsButton;
    toggleAllUDPPacketsButton.classList.toggle('active', app.showAllUDPPackets);
    toggleAllUDPPacketsButton.addEventListener('click', () => {
        app.showAllUDPPackets = !app.showAllUDPPackets;
        toggleAllUDPPacketsButton.classList.toggle('active', app.showAllUDPPackets);
        app.syncNetworkFilterButtons?.();
        app.socket.emit('set_udp_filter', { showAllUDPPackets: app.showAllUDPPackets });
        app.refreshViews();
    });

    app.syncNetworkFilterButtons = () => {
        [
            ['toggleLocalNetwork', 'ovToggleLocalNetwork', app.showLocalNetwork],
            ['toggleExternalNetwork', 'ovToggleExternalNetwork', app.showExternalNetwork],
            ['toggleTCPOnly', 'ovToggleTCPOnly', app.showTCPOnly],
            ['toggleAllUDPPackets', 'ovToggleAllUDPPackets', app.showAllUDPPackets],
        ].forEach(([mainId, overlayId, active]) => {
            document.getElementById(mainId)?.classList.toggle('active', active);
            document.getElementById(overlayId)?.classList.toggle('active', active);
        });
    };

    app.setNetworkFilter = (key, value) => {
        if (key === 'local') {
            app.showLocalNetwork = value;
            app.socket.emit('set_local_network', { showLocalNetwork: app.showLocalNetwork });
        } else if (key === 'external') {
            app.showExternalNetwork = value;
            app.socket.emit('set_external_network', { showExternalNetwork: app.showExternalNetwork });
        } else if (key === 'tcp') {
            app.showTCPOnly = value;
            app.socket.emit('set_tcp_only', { showTCPOnly: app.showTCPOnly });
        } else if (key === 'udp') {
            app.showAllUDPPackets = value;
            app.socket.emit('set_udp_filter', { showAllUDPPackets: app.showAllUDPPackets });
        }
        app.syncNetworkFilterButtons();
        app.refreshViews();
    };
    app.syncNetworkFilterButtons();

    // ── Search inputs ─────────────────────────────────────
    document.getElementById('connectionSearch')?.addEventListener('input', e => {
        app.filterText = e.target.value.toLowerCase().trim();
        app.refreshViews();
    });

    document.getElementById('internalSearch')?.addEventListener('input', e => {
        app.filterTextInternal = e.target.value.toLowerCase().trim();
        app.refreshViews();
    });

    // ── Internal-search checkbox ──────────────────────────
    const searchInternalPacketsCheckbox = document.getElementById('searchInternalPackets');
    app.searchInternalPacketsCheckbox = searchInternalPacketsCheckbox;
    if (searchInternalPacketsCheckbox) {
        searchInternalPacketsCheckbox.checked = app.isInternalSearchActive;
        searchInternalPacketsCheckbox.addEventListener('change', () => {
            app.isInternalSearchActive = searchInternalPacketsCheckbox.checked;
            app.socket.emit('set_internal_search', { isInternalSearchActive: app.isInternalSearchActive });
            app.refreshViews();
        });
    }

    // ── IP labels ─────────────────────────────────────────
    function fillIpLabelsTextarea() {
        const ta = document.getElementById('ipLabels');
        if (ta) ta.value = Object.entries(app.ipLabels).map(([ip, name]) => `${ip} ${name}`).join('\n');
    }

    async function loadIpLabels() {
        try {
            const res = await fetch('/api/ip-labels', { credentials: 'same-origin' });
            if (!res.ok) return;
            const data = await res.json();
            if (data && typeof data === 'object') app.ipLabels = data;
            fillIpLabelsTextarea();
            app.refreshViews();
        } catch (err) { console.error('Error loading IP labels:', err); }
    }

    // Parse the textarea ("192.168.178.100 PC-E1" per line) into a {ip: name}
    // map, PUT it, and re-render so the new names show everywhere immediately.
    app.wireIpLabelsEditor = () => {
        const ta  = document.getElementById('ipLabels');
        const btn = document.getElementById('saveIpLabels');
        if (!ta || !btn || btn.dataset.wired) return;
        btn.dataset.wired = '1';
        // Pre-fill from whatever we already loaded.
        fillIpLabelsTextarea();
        btn.addEventListener('click', async () => {
            const map = {};
            (ta.value || '').split('\n').forEach(line => {
                const s = line.trim();
                if (!s) return;
                // First whitespace splits IP from the (possibly spaced) name.
                const m = s.match(/^(\S+)\s+(.+)$/);
                if (m) map[m[1]] = m[2].trim();
            });
            try {
                const res = await fetch('/api/ip-labels', {
                    method: 'PUT',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(map),
                });
                if (res.ok) {
                    app.ipLabels = map;
                    app.refreshViews();
                    showToast(`Saved ${Object.keys(map).length} IP label(s)`, 'low');
                } else {
                    showToast('Could not save IP labels', 'high');
                }
            } catch (err) { showToast('Could not save IP labels', 'high'); }
        });
    };

    // ── Connection list item ──────────────────────────────
    function createPacketListItem(packet, onReset) {
        const li = document.createElement('li');
        li.className = 'conn-row';

        // Threat colour dot
        const dot = document.createElement('div');
        dot.className = 'conn-dot';
        dot.style.background = getCircleColor(packet.threat_level, packet.org);

        // Pin checkbox
        const checkbox = document.createElement('input');
        checkbox.type      = 'checkbox';
        checkbox.className = 'pin-checkbox';
        checkbox.checked   = !!app.pinnedIPs[packet.ip];
        checkbox.title     = 'Pin this IP';
        checkbox.addEventListener('change', () => {
            app.socket.emit('pin_ip', { ip: packet.ip, isPinned: checkbox.checked });
        });

        // Main column: IP address + hostname / org
        const main  = document.createElement('div');
        main.className = 'conn-main';
        const ipEl  = document.createElement('div');
        ipEl.className   = 'conn-ip';
        ipEl.textContent = packet.ip || 'N/A';
        main.appendChild(ipEl);
        const hostText = (packet.hostname && packet.hostname !== 'Unknown')
            ? packet.hostname
            : (packet.org && packet.org !== 'Not available' ? packet.org : '');
        if (hostText) {
            const hostEl     = document.createElement('div');
            hostEl.className = 'conn-host';
            hostEl.textContent = truncate(hostText, 32);
            hostEl.title       = hostText;
            main.appendChild(hostEl);
        }

        // Which LAN device(s) this external IP is talking to — same info as the
        // statistics/connections tab, now inline in the live list.
        const peersText = app.localPeersText(packet);
        if (peersText) {
            const lanEl     = document.createElement('div');
            lanEl.className = 'conn-lan';
            lanEl.textContent = '→ ' + peersText;
            lanEl.title       = 'LAN device(s): ' + peersText;
            main.appendChild(lanEl);
        }

        // Protocol badge
        const proto       = document.createElement('span');
        proto.className   = 'conn-proto';
        proto.textContent = packet.protocol || '?';

        // Packet counts + optional service name for the destination port
        const pkts     = document.createElement('span');
        pkts.className = 'conn-packets';
        const svc      = PORT_SERVICES[packet.dst_port] || '';
        const svcHtml  = svc ? ` <span class="service-tag">${escapeHTML(svc)}</span>` : '';
        pkts.innerHTML = `↓${formatNum(packet.incoming_count)} ↑${formatNum(packet.outgoing_count)}${svcHtml}`;

        // Threat badge (HIGH / MED / LOW / OK)
        const badge = makeThreatBadge(packet.threat_level);

        // Relative timestamp with absolute time in tooltip
        const timeEl       = document.createElement('span');
        timeEl.className   = 'conn-time';
        if (packet.last_seen) {
            timeEl.textContent = timeAgo(packet.last_seen);
            timeEl.title       = new Date(packet.last_seen * 1000).toLocaleString();
        }

        // Reset packet counter
        const resetBtn       = document.createElement('button');
        resetBtn.className   = 'reset-btn';
        resetBtn.textContent = '↺';
        resetBtn.title       = 'Reset packet count';
        resetBtn.addEventListener('click', e => {
            e.stopPropagation();
            app.socket.emit('reset_packet_count', { ip: packet.ip });
            packet.incoming_count = 0;
            packet.outgoing_count = 0;
            packet.packet_count   = 0;
            onReset();
        });

        // Click row → show detail panel and centre globe on this IP
        li.addEventListener('click', e => {
            if (e.target === checkbox || e.target === resetBtn) return;
            app.showDataList(packet);
            if (isValidCoord(packet.lat, packet.lng)) {
                app.globe.pointOfView({ lat: packet.lat, lng: packet.lng, altitude: 2.5 }, 1000);
            }
        });

        li.appendChild(dot);
        li.appendChild(checkbox);
        li.appendChild(main);
        li.appendChild(proto);
        li.appendChild(pkts);
        li.appendChild(badge);
        li.appendChild(timeEl);
        li.appendChild(resetBtn);
        return li;
    }

    // ── Active connection list ────────────────────────────
    app.updateConnectionsList = () => {
        const listEl  = document.getElementById('connectionsList');
        const countEl = document.getElementById('connectionCount');
        if (!listEl) return;

        const matchesSearch = p =>
            !app.filterText ||
            p.ip.includes(app.filterText) ||
            (p.hostname || '').toLowerCase().includes(app.filterText) ||
            (p.org      || '').toLowerCase().includes(app.filterText) ||
            (p.country  || '').toLowerCase().includes(app.filterText);

        const filtered = Object.values(app.points).filter(p =>
            !p.expired && app.pointDeviceVisible(p) &&
            (app.showTCPOnly ? p.protocol === 'TCP' : true) &&
            ((app.showLocalNetwork    && isLocalNetwork(p.ip, p.org)) ||
             (app.showExternalNetwork && !isLocalNetwork(p.ip, p.org))) &&
            matchesSearch(p)
        );

        const tcpCount  = filtered.filter(p => p.protocol === 'TCP').length;
        const udpCount  = filtered.filter(p => p.protocol === 'UDP').length;
        if (countEl) countEl.textContent = `${filtered.length} connections  (TCP: ${tcpCount}  UDP: ${udpCount})`;

        // Update threat counts in sidebar
        const setEl = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
        setEl('statThreatHigh', `${filtered.filter(p => p.threat_level === 'High').length} HIGH`);
        setEl('statThreatMed',  `${filtered.filter(p => p.threat_level === 'Medium').length} MED`);
        setEl('statThreatLow',  `${filtered.filter(p => p.threat_level === 'Low').length} LOW`);

        const fragment = document.createDocumentFragment();
        filtered
            .sort((a, b) => {
                // Pinned IPs always first, then most recently seen.
                if (!!app.pinnedIPs[a.ip] !== !!app.pinnedIPs[b.ip]) return app.pinnedIPs[b.ip] ? 1 : -1;
                return b.last_seen - a.last_seen;
            })
            .forEach(p => fragment.appendChild(createPacketListItem(p, app.updateConnectionsList)));

        listEl.replaceChildren(fragment);
    };

    // ── Internal network list ─────────────────────────────
    app.updateInternalNetworkList = () => {
        const listEl  = document.getElementById('internalPacketsList');
        const countEl = document.getElementById('internalConnectionCount');
        if (!listEl) return;

        const matchesSearch = p =>
            !app.filterTextInternal ||
            p.ip.includes(app.filterTextInternal) ||
            (p.hostname || '').toLowerCase().includes(app.filterTextInternal) ||
            (p.org      || '').toLowerCase().includes(app.filterTextInternal);

        const filtered = Object.values(app.internalPackets).filter(p =>
            !p.expired &&
            isLocalNetwork(p.ip, p.org) &&
            (app.showTCPOnly ? p.protocol === 'TCP' : true) &&
            (app.isInternalSearchActive || app.pinnedIPs[p.ip]) &&
            matchesSearch(p)
        );

        const tcpCount = filtered.filter(p => p.protocol === 'TCP').length;
        const udpCount = filtered.filter(p => p.protocol === 'UDP').length;
        if (countEl) countEl.textContent = `${filtered.length} connections  (TCP: ${tcpCount}  UDP: ${udpCount})`;

        const fragment = document.createDocumentFragment();
        filtered
            .sort((a, b) => b.incoming_count - a.incoming_count || b.outgoing_count - a.outgoing_count)
            .forEach(p => fragment.appendChild(createPacketListItem(p, app.updateInternalNetworkList)));

        listEl.replaceChildren(fragment);
    };

    // ── Detail panel ──────────────────────────────────────
    function appendDetailItem(ul, label, value, valueClass) {
        const li   = document.createElement('li');
        const name = document.createElement('strong');
        name.textContent = label;
        li.appendChild(name);
        if (valueClass) {
            const span = document.createElement('span');
            span.className = valueClass;
            span.textContent = String(value);
            li.appendChild(span);
        } else {
            li.appendChild(document.createTextNode(String(value)));
        }
        ul.appendChild(li);
    }

    // The <ul> of one IP's details — reused for both the single-IP popup and each
    // tab of the cluster popup.
    function buildDetailBody(packet) {
        const svc = PORT_SERVICES[packet.dst_port];
        const dstPortLabel = packet.dst_port
            ? `${packet.dst_port}${svc ? ' (' + svc + ')' : ''}` : 'N/A';
        const details = [
            // Which device(s) in the local network this external IP is talking to
            // (the LAN-side endpoint). Surfaced first + highlighted so the popup
            // shows the same "→ LAN host" info the live lists do, at a glance.
            ['LAN device(s)',    app.localPeersText(packet) || '—', 'detail-lan'],
            ['Hostname',         packet.hostname    || 'Unknown'],
            ['OS',               packet.os          || 'Unknown'],
            ['MAC Address',      packet.mac         || 'N/A'],
            ['Vendor',           packet.vendor      || 'Unknown'],
            ['City',             packet.city        || 'N/A'],
            ['Country',         packet.country      || 'N/A'],
            ['Region',           packet.region      || 'N/A'],
            ['Organization',     packet.org         || 'N/A'],
            ['Protocol',         packet.protocol    || 'N/A'],
            ['Source Port',      packet.src_port    || 'N/A'],
            ['Dest Port',        dstPortLabel],
            ['Last Seen',        packet.last_seen   ? new Date(packet.last_seen * 1000).toLocaleString() : 'N/A'],
            // Permanent ledger: when this IP was EVER first seen (survives retention
            // & restarts). "NEW" means the server had never recorded it before now.
            ['First Seen',       packet.first_seen_ever
                                    ? new Date(packet.first_seen_ever * 1000).toLocaleString() + (packet.is_new ? '  — NEW' : '')
                                    : (packet.is_new ? 'NEW' : 'N/A')],
            ['Packets In',       formatNum(packet.incoming_count)],
            ['Packets Out',      formatNum(packet.outgoing_count)],
            ['Total Packets',    formatNum(packet.packet_count)],
            ['Threat Level',     packet.threat_level || 'No Threat'],
        ];
        const ul = document.createElement('ul');
        details.forEach(([label, value, cls]) => appendDetailItem(ul, label, value, cls));
        return ul;
    }

    // Render the detail panel for one of `members`, with a tab strip across the
    // top when there's more than one (a clicked cluster) so the operator can
    // switch between every IP in the pile, each with its full details.
    function renderDetailPanel(members, activeIdx, onClose) {
        const dataList = app.dataList;
        const packet   = members[activeIdx];

        const header = document.createElement('div');
        header.className = 'detail-header';
        const title = document.createElement('h3');
        title.textContent = `IP: ${packet.ip || 'N/A'}`;
        const closeBtn = document.createElement('button');
        closeBtn.id    = 'closeDataList';
        closeBtn.title = 'Close';
        closeBtn.textContent = '✕';
        closeBtn.addEventListener('click', () => {
            dataList.style.display = 'none';
            if (onClose) onClose();
        });
        header.appendChild(title);
        header.appendChild(closeBtn);

        const children = [header];
        if (members.length > 1) {
            // The pile's shared location (its IPs geolocate to the same spot), so
            // show city/country once above the tabs rather than per tab.
            const loc = [packet.city, packet.country]
                .filter(x => x && x !== 'N/A' && x !== 'Unknown').join(', ');
            if (loc) {
                const locEl = document.createElement('div');
                locEl.className = 'detail-cluster-loc';
                locEl.textContent = loc;
                children.push(locEl);
            }

            const tabs = document.createElement('div');
            tabs.className = 'detail-tabs';
            members.forEach((m, i) => {
                const tab = document.createElement('button');
                tab.className = 'detail-tab' + (i === activeIdx ? ' active' : '');
                // Tint the tab by its IP's threat colour (red/orange/yellow/green),
                // matching the dot/arc, so a suspicious IP's tab is obviously
                // orange at a glance. White (no-threat) keeps the neutral default.
                const threatColor = getCircleColor(m.threat_level, m.org);
                if (threatColor !== 'white') {
                    tab.style.borderColor = threatColor;
                    tab.style.borderLeftWidth = '3px';
                }
                // Two lines per tab: the IP (or its label) and, beneath it, the
                // vendor (falling back to org when no MAC vendor is known).
                const ipEl = document.createElement('span');
                ipEl.className = 'detail-tab-ip';
                if (threatColor !== 'white') ipEl.style.color = threatColor;
                ipEl.textContent = app.ipLabel(m.ip) || m.ip;
                const venEl = document.createElement('span');
                venEl.className = 'detail-tab-vendor';
                venEl.textContent = (m.vendor && m.vendor !== 'Unknown') ? m.vendor : (m.org || 'Unknown');
                tab.append(ipEl, venEl);
                tab.title = m.org || '';
                // Switch tab in place. stopPropagation is essential: the re-render
                // below detaches this very button, so without it the document-level
                // outside-click handler would see the click target as "outside"
                // #dataList and close the popup.
                tab.addEventListener('click', e => {
                    e.stopPropagation();
                    renderDetailPanel(members, i, onClose);
                });
                tabs.appendChild(tab);
            });
            children.push(tabs);
        }
        children.push(buildDetailBody(packet));
        dataList.replaceChildren(...children);
        dataList.style.display = 'block';
    }

    // Arm the "just opened" guard so the very click that opens the panel doesn't
    // immediately close it via the document-level outside-click handler. The guard
    // must only be live for that one opening click: a globe-point click doesn't
    // reliably bubble to document, so relying on that handler to clear the guard
    // left it armed and eating the user's first genuine outside click. Clearing it
    // on the next tick guarantees it's only set during the opening click itself.
    function armDetailGuard() {
        app._detailJustOpened = true;
        setTimeout(() => { app._detailJustOpened = false; }, 0);
    }

    app.showDataList = (packet, onClose = null) => {
        armDetailGuard();
        renderDetailPanel([packet], 0, onClose);
    };

    // A clicked cluster: one popup, newest IP first, every member on its own tab.
    app.showClusterDetail = (cluster, onClose = null) => {
        armDetailGuard();
        const members = cluster.members.slice()
            .sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
        renderDetailPanel(members, 0, onClose);
    };

    loadIpLabels();
}
