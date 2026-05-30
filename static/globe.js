// static/globe.js

// ============================================================
// Utility helpers
// ============================================================

// Map of common destination ports to human-readable service names.
const PORT_SERVICES = {
    20: 'FTP-DATA', 21: 'FTP',     22: 'SSH',      23: 'Telnet',
    25: 'SMTP',     53: 'DNS',     67: 'DHCP',     68: 'DHCP',
    80: 'HTTP',    110: 'POP3',   143: 'IMAP',    161: 'SNMP',
   443: 'HTTPS',  445: 'SMB',    587: 'SMTPTLS', 993: 'IMAPS',
   995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',  3389: 'RDP',
  5432: 'PG',    5900: 'VNC',   6379: 'Redis',  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt', 27017: 'MongoDB',
};

function timeAgo(unixTs) {
    const secs = Math.floor(Date.now() / 1000 - unixTs);
    if (secs < 5)    return 'just now';
    if (secs < 60)   return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
}

function formatNum(n) {
    return (n || 0).toLocaleString();
}

function formatBytes(bytes) {
    if (bytes < 1024)       return `${bytes} B`;
    if (bytes < 1048576)    return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
    return `${(bytes / 1073741824).toFixed(1)} GB`;
}

function truncate(str, max) {
    if (!str || str.length <= max) return str || '';
    return str.slice(0, max) + '…';
}

function makeThreatBadge(threatLevel) {
    const raw   = (threatLevel || 'no threat').toLowerCase().trim();
    const key   = raw.replace(' ', '-');
    const labels = { 'high': 'HIGH', 'medium': 'MED', 'low': 'LOW', 'no-threat': 'OK', 'no threat': 'OK' };
    const span  = document.createElement('span');
    span.className = `threat-badge threat-${key}`;
    span.textContent = labels[raw] || labels[key] || 'OK';
    return span;
}

function showToast(message, level = 'info', durationMs = 6000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${level}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), durationMs);
}

function notifyHighThreat(ip, org, country) {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    new Notification('⚠ High Threat Detected', {
        body: `${ip} — ${org || 'Unknown'} (${country || 'Unknown'})`,
        tag: `threat-${ip}`,  // prevents duplicate OS notifications for the same IP
    });
}

// Persists across Socket.IO reconnects so we don't re-alert for already-known IPs.
const notifiedHighThreatIPs = new Set();

// ============================================================
// Organisation classification (loaded from backend)
// ============================================================

let trustedOrgs    = [];
let suspiciousOrgs = [];
let dangerousOrgs  = [];

async function loadTrustedOrgs() {
    try {
        const res = await fetch('/trusted_organisations');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        trustedOrgs    = data.trusted_organisations    || [];
        suspiciousOrgs = data.suspicious_organisations || [];
        dangerousOrgs  = data.dangerous_organisations  || [];
    } catch (err) {
        console.error('Could not load trusted_organisations:', err);
        // Sensible fallbacks so the globe colours still work offline.
        trustedOrgs    = ['Google LLC', 'Amazon.com, Inc.', 'Microsoft Corporation',
                          'Cloudflare, Inc.', 'Apple Inc.', 'Meta Platforms, Inc.',
                          'Akamai Technologies, Inc.'];
        suspiciousOrgs = ['Unknown ISP', 'Generic Hosting', 'Suspected Proxy Service'];
        dangerousOrgs  = ['Malware Host', 'Known Botnet', 'Dark Web Service'];
    }
}

// ============================================================
// Pure helpers (no DOM, no side effects)
// ============================================================

function isValidCoord(lat, lng) {
    return typeof lat === 'number' && typeof lng === 'number' &&
           !isNaN(lat) && !isNaN(lng) &&
           lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
}

function isLocalNetwork(ip, org) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    const [a, b] = parts.map(Number);
    return (a === 192 && b === 168) ||
           (a === 10) ||
           (a === 172 && b >= 16 && b <= 31) ||
           org === 'Local Network';
}

function getCircleColor(threatLevel, org) {
    if (org && trustedOrgs.includes(org)) return 'green';
    if (threatLevel === 'High')   return 'red';
    if (threatLevel === 'Medium') return 'orange';
    if (threatLevel === 'Low')    return 'yellow';
    return 'white';
}

function escapeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#039;');
}

// ============================================================
// Main initialisation
// ============================================================

async function initializeGlobe(myIpCoords) {
    await loadTrustedOrgs();

    // Ask for browser notification permission once on load.
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }

    // ── Globe point radius ────────────────────────────────
    function getMarkerRadius(point) {
        const total = (point.incoming_count || 0) + (point.outgoing_count || 0);
        if (total === 0) return 0.3;
        return Math.min(0.3 + Math.log10(total + 1) * 0.2, 2.0);
    }

    // ── Socket.IO ─────────────────────────────────────────
    let socketUrl;
    try {
        const port = location.port ? `:${location.port}` : '';
        socketUrl = `${window.location.protocol}//${document.domain}${port}`;
    } catch (_) {
        socketUrl = `${window.location.protocol}//${document.domain}:8000`;
    }
    const socket = io.connect(socketUrl, {
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000,
    });

    if (!isValidCoord(myIpCoords.lat, myIpCoords.lng)) {
        console.error('Invalid own coordinates:', myIpCoords);
        document.body.innerHTML = '<h1 style="color:red;padding:2rem">Error: could not load globe. Check the console (F12).</h1>';
        return;
    }

    const connectionStatus = document.getElementById('connectionStatus');

    // Detail panel is created dynamically so it stays on top of the globe canvas.
    const dataList = document.createElement('div');
    dataList.id = 'dataList';
    document.body.appendChild(dataList);

    const activeConnectionsList = document.getElementById('activeConnectionsList');

    // ── Globe ─────────────────────────────────────────────
    const globe = Globe()
        .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
        .pointOfView({ lat: myIpCoords.lat, lng: myIpCoords.lng, altitude: 2.5 }, 0)
        .pointRadius(getMarkerRadius)
        .pointColor(point => point.ip === 'Your IP'
            ? '#FFFF00' : getCircleColor(point.threat_level, point.org))
        .pointLabel(point =>
            `<div>${escapeHTML(point.ip) || 'N/A'} — ${escapeHTML(point.org) || 'N/A'}</div>`)
        .pointLat('lat')
        .pointLng('lng')
        .pointAltitude(0.1)
        .arcColor(arc => {
            if (arc.city === 'Unknown' || arc.country === 'Unknown' || arc.org === 'Not available') {
                return '#FFFFFF';
            }
            const pt = points[arc.ip];
            return pt ? getCircleColor(pt.threat_level, pt.org) : '#FFFFFF';
        })
        .arcStroke(0.5)
        .arcDashLength(0.8)
        .arcDashGap(0.5)
        .arcDashAnimateTime(1000)
        .labelSize(0.5)
        .labelDotRadius(0.3)
        .labelColor(() => 'white')
        .labelLabel('label')
        .onPointClick(point => {
            showDataList(point, () => {
                globe.pointRadius(getMarkerRadius);
                globe.labelSize(0.5);
            });
            globe.pointRadius(d => d === point ? getMarkerRadius(d) * 1.5 : getMarkerRadius(d));
            globe.labelSize(d => d === point ? 0.8 : 0.5);
        })
        .onGlobeClick(() => {
            dataList.style.display = 'none';
            globe.pointRadius(getMarkerRadius);
            globe.labelSize(0.5);
        })
        (document.getElementById('globeViz'));

    const ownIpPoint = {
        lat: myIpCoords.lat, lng: myIpCoords.lng,
        label: 'Your IP', ip: 'Your IP', color: '#FFFF00',
        city: 'N/A', country: 'N/A', org: 'N/A',
        incoming_count: 0, outgoing_count: 0,
        last_seen: Date.now() / 1000, expired: false,
    };
    globe.pointsData([ownIpPoint]);

    // ── Country borders checkbox ──────────────────────────
    const showArcsCheckbox = document.getElementById('showArcs');
    let showArcs = JSON.parse(localStorage.getItem('showArcs') ?? 'true');
    if (showArcsCheckbox) {
        showArcsCheckbox.checked = showArcs;
        showArcsCheckbox.addEventListener('change', () => {
            showArcs = showArcsCheckbox.checked;
            localStorage.setItem('showArcs', JSON.stringify(showArcs));
            updateGlobeData();
        });
    }

    let countriesData = [];
    const showBordersCheckbox = document.getElementById('showBorders');
    let showBorders = JSON.parse(localStorage.getItem('showBorders') ?? 'true');
    if (showBordersCheckbox) showBordersCheckbox.checked = showBorders;

    fetch('https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson')
        .then(r => r.json())
        .then(data => {
            countriesData = data.features;
            if (showBorders) {
                globe.polygonsData(countriesData)
                     .polygonCapColor(() => 'rgba(255,255,255,0.1)')
                     .polygonSideColor(() => 'rgba(255,255,255,0.1)')
                     .polygonStrokeColor(() => '#006100');
            }
        })
        .catch(err => console.error('Error loading country borders:', err));

    if (showBordersCheckbox) {
        showBordersCheckbox.addEventListener('change', () => {
            showBorders = showBordersCheckbox.checked;
            localStorage.setItem('showBorders', JSON.stringify(showBorders));
            globe.polygonsData(showBorders ? countriesData : []);
        });
    }

    // ── Sidebar / settings panel ──────────────────────────
    const menuButton = document.getElementById('menuButton');
    const sidebar    = document.getElementById('sidebar');
    let orgsLoaded   = false;

    menuButton.addEventListener('click', () => {
        const isOpen = sidebar.classList.toggle('open');
        if (isOpen && !orgsLoaded) {
            loadOrgEditor();
            orgsLoaded = true;
        }
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
                refreshViews();
            } else {
                showToast('Failed to save organisation lists.', 'error');
            }
        } catch (_) {
            showToast('Network error saving organisation lists.', 'error');
        }
    });

    // ── Collapse state ────────────────────────────────────
    const internalNetworkList = document.getElementById('internalNetworkList');
    let isInternalNetworkCollapsed =
        JSON.parse(localStorage.getItem('isInternalNetworkCollapsed') ?? 'false');
    let isActiveConnectionsCollapsed =
        JSON.parse(localStorage.getItem('isActiveConnectionsCollapsed') ?? 'false');

    if (isInternalNetworkCollapsed)  internalNetworkList.classList.add('collapsed');
    if (isActiveConnectionsCollapsed) activeConnectionsList.classList.add('collapsed');

    // ── Filter / view state ───────────────────────────────
    let showLocalNetwork    = true;
    let showExternalNetwork = true;
    let showTCPOnly         = false;
    let showAllUDPPackets   = false;
    let isInternalSearchActive = true;
    let filterText         = '';
    let filterTextInternal = '';
    let initialLoadDone    = false;

    // ── Throttled view refresh ────────────────────────────
    // Coalesces rapid socket bursts to at most one DOM rebuild per REFRESH_MIN_MS,
    // with a trailing update so nothing gets dropped.
    const REFRESH_MIN_MS = 400;
    let _lastRefresh = 0;
    let _refreshTimer = null;

    function _refreshViewsNow() {
        updateConnectionsList();
        updateInternalNetworkList();
        updateGlobeData();
    }

    function refreshViews() {
        const now     = Date.now();
        const elapsed = now - _lastRefresh;
        if (elapsed >= REFRESH_MIN_MS) {
            _lastRefresh = now;
            if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
            _refreshViewsNow();
        } else if (!_refreshTimer) {
            _refreshTimer = setTimeout(() => {
                _refreshTimer  = null;
                _lastRefresh   = Date.now();
                _refreshViewsNow();
            }, REFRESH_MIN_MS - elapsed);
        }
    }

    // ── Toggle buttons ────────────────────────────────────
    const toggleInternalNetworkButton = document.getElementById('toggleInternalNetwork');
    toggleInternalNetworkButton.textContent = isInternalNetworkCollapsed ? '▼' : '▲';
    toggleInternalNetworkButton.addEventListener('click', () => {
        isInternalNetworkCollapsed = !isInternalNetworkCollapsed;
        localStorage.setItem('isInternalNetworkCollapsed', JSON.stringify(isInternalNetworkCollapsed));
        toggleInternalNetworkButton.textContent = isInternalNetworkCollapsed ? '▼' : '▲';
        internalNetworkList.classList.toggle('collapsed', isInternalNetworkCollapsed);
    });

    // Clone to remove the stale listener that the HTML template attached.
    const origToggleActive = document.getElementById('toggleActiveConnections');
    const toggleActiveConnectionsButton = origToggleActive.cloneNode(true);
    origToggleActive.replaceWith(toggleActiveConnectionsButton);
    toggleActiveConnectionsButton.textContent = isActiveConnectionsCollapsed ? '▼' : '▲';
    toggleActiveConnectionsButton.addEventListener('click', () => {
        isActiveConnectionsCollapsed = !isActiveConnectionsCollapsed;
        localStorage.setItem('isActiveConnectionsCollapsed', JSON.stringify(isActiveConnectionsCollapsed));
        toggleActiveConnectionsButton.textContent = isActiveConnectionsCollapsed ? '▼' : '▲';
        activeConnectionsList.classList.toggle('collapsed', isActiveConnectionsCollapsed);
        activeConnectionsList.style.height = isActiveConnectionsCollapsed ? '42px' : '';
    });

    const toggleLocalNetworkButton = document.getElementById('toggleLocalNetwork');
    toggleLocalNetworkButton.classList.toggle('active', showLocalNetwork);
    let _localDebounce;
    toggleLocalNetworkButton.addEventListener('click', () => {
        clearTimeout(_localDebounce);
        _localDebounce = setTimeout(() => {
            showLocalNetwork = !showLocalNetwork;
            toggleLocalNetworkButton.classList.toggle('active', showLocalNetwork);
            socket.emit('set_local_network', { showLocalNetwork });
            refreshViews();
        }, 300);
    });

    const toggleExternalNetworkButton = document.getElementById('toggleExternalNetwork');
    toggleExternalNetworkButton.classList.toggle('active', showExternalNetwork);
    toggleExternalNetworkButton.addEventListener('click', () => {
        showExternalNetwork = !showExternalNetwork;
        toggleExternalNetworkButton.classList.toggle('active', showExternalNetwork);
        socket.emit('set_external_network', { showExternalNetwork });
        refreshViews();
    });

    const toggleTCPOnlyButton = document.getElementById('toggleTCPOnly');
    toggleTCPOnlyButton.classList.toggle('active', showTCPOnly);
    toggleTCPOnlyButton.addEventListener('click', () => {
        showTCPOnly = !showTCPOnly;
        toggleTCPOnlyButton.classList.toggle('active', showTCPOnly);
        socket.emit('set_tcp_only', { showTCPOnly });
        refreshViews();
    });

    const toggleAllUDPPacketsButton = document.getElementById('toggleAllUDPPackets');
    toggleAllUDPPacketsButton.classList.toggle('active', showAllUDPPackets);
    toggleAllUDPPacketsButton.addEventListener('click', () => {
        showAllUDPPackets = !showAllUDPPackets;
        toggleAllUDPPacketsButton.classList.toggle('active', showAllUDPPackets);
        socket.emit('set_udp_filter', { showAllUDPPackets });
        refreshViews();
    });

    document.getElementById('centerOwnLocation')?.addEventListener('click', () => {
        globe.pointOfView({ lat: myIpCoords.lat, lng: myIpCoords.lng, altitude: 2.5 }, 1000);
    });

    // ── Search inputs ─────────────────────────────────────
    document.getElementById('connectionSearch')?.addEventListener('input', e => {
        filterText = e.target.value.toLowerCase().trim();
        refreshViews();
    });

    document.getElementById('internalSearch')?.addEventListener('input', e => {
        filterTextInternal = e.target.value.toLowerCase().trim();
        refreshViews();
    });

    // ── Internal-search checkbox ──────────────────────────
    const searchInternalPacketsCheckbox = document.getElementById('searchInternalPackets');
    if (searchInternalPacketsCheckbox) {
        searchInternalPacketsCheckbox.checked = isInternalSearchActive;
        searchInternalPacketsCheckbox.addEventListener('change', () => {
            isInternalSearchActive = searchInternalPacketsCheckbox.checked;
            socket.emit('set_internal_search', { isInternalSearchActive });
            refreshViews();
        });
    }

    // ── Data stores ───────────────────────────────────────
    const points           = {};
    const arcs             = {};
    const internalPackets  = {};
    const pinnedIPs        = {};
    const EXPIRATION_SECONDS           = 60;
    const INTERNAL_EXPIRATION_SECONDS  = 600;
    const MAX_POINTS           = 1000;
    const MAX_INTERNAL_PACKETS = 500;

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
        checkbox.checked   = !!pinnedIPs[packet.ip];
        checkbox.title     = 'Pin this IP';
        checkbox.addEventListener('change', () => {
            socket.emit('pin_ip', { ip: packet.ip, isPinned: checkbox.checked });
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
            socket.emit('reset_packet_count', { ip: packet.ip });
            packet.incoming_count = 0;
            packet.outgoing_count = 0;
            packet.packet_count   = 0;
            onReset();
        });

        // Click row → show detail panel and centre globe on this IP
        li.addEventListener('click', e => {
            if (e.target === checkbox || e.target === resetBtn) return;
            showDataList(packet);
            if (isValidCoord(packet.lat, packet.lng)) {
                globe.pointOfView({ lat: packet.lat, lng: packet.lng, altitude: 2.5 }, 1000);
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
    function updateConnectionsList() {
        const listEl  = document.getElementById('connectionsList');
        const countEl = document.getElementById('connectionCount');
        if (!listEl) return;

        const matchesSearch = p =>
            !filterText ||
            p.ip.includes(filterText) ||
            (p.hostname || '').toLowerCase().includes(filterText) ||
            (p.org      || '').toLowerCase().includes(filterText) ||
            (p.country  || '').toLowerCase().includes(filterText);

        const filtered = Object.values(points).filter(p =>
            !p.expired &&
            (showTCPOnly ? p.protocol === 'TCP' : true) &&
            ((showLocalNetwork    && isLocalNetwork(p.ip, p.org)) ||
             (showExternalNetwork && !isLocalNetwork(p.ip, p.org))) &&
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
                if (!!pinnedIPs[a.ip] !== !!pinnedIPs[b.ip]) return pinnedIPs[b.ip] ? 1 : -1;
                return b.last_seen - a.last_seen;
            })
            .forEach(p => fragment.appendChild(createPacketListItem(p, updateConnectionsList)));

        listEl.replaceChildren(fragment);
    }

    // ── Internal network list ─────────────────────────────
    function updateInternalNetworkList() {
        const listEl  = document.getElementById('internalPacketsList');
        const countEl = document.getElementById('internalConnectionCount');
        if (!listEl) return;

        const matchesSearch = p =>
            !filterTextInternal ||
            p.ip.includes(filterTextInternal) ||
            (p.hostname || '').toLowerCase().includes(filterTextInternal) ||
            (p.org      || '').toLowerCase().includes(filterTextInternal);

        const filtered = Object.values(internalPackets).filter(p =>
            !p.expired &&
            isLocalNetwork(p.ip, p.org) &&
            (showTCPOnly ? p.protocol === 'TCP' : true) &&
            (isInternalSearchActive || pinnedIPs[p.ip]) &&
            matchesSearch(p)
        );

        const tcpCount = filtered.filter(p => p.protocol === 'TCP').length;
        const udpCount = filtered.filter(p => p.protocol === 'UDP').length;
        if (countEl) countEl.textContent = `${filtered.length} connections  (TCP: ${tcpCount}  UDP: ${udpCount})`;

        const fragment = document.createDocumentFragment();
        filtered
            .sort((a, b) => b.incoming_count - a.incoming_count || b.outgoing_count - a.outgoing_count)
            .forEach(p => fragment.appendChild(createPacketListItem(p, updateInternalNetworkList)));

        listEl.replaceChildren(fragment);
    }

    // ── Detail panel ──────────────────────────────────────
    function appendDetailItem(ul, label, value) {
        const li   = document.createElement('li');
        const name = document.createElement('strong');
        name.textContent = label;
        li.appendChild(name);
        li.appendChild(document.createTextNode(String(value)));
        ul.appendChild(li);
    }

    function showDataList(packet, onClose = null) {
        const svc = PORT_SERVICES[packet.dst_port];
        const dstPortLabel = packet.dst_port
            ? `${packet.dst_port}${svc ? ' (' + svc + ')' : ''}` : 'N/A';

        const details = [
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
            ['Packets In',       formatNum(packet.incoming_count)],
            ['Packets Out',      formatNum(packet.outgoing_count)],
            ['Total Packets',    formatNum(packet.packet_count)],
            ['Threat Level',     packet.threat_level || 'No Threat'],
        ];

        const header  = document.createElement('div');
        header.className = 'detail-header';

        const title   = document.createElement('h3');
        title.textContent = `IP: ${packet.ip || 'N/A'}`;

        const closeBtn = document.createElement('button');
        closeBtn.id    = 'closeDataList';
        closeBtn.title = 'Close';
        closeBtn.textContent = '✕';
        closeBtn.addEventListener('click', () => {
            dataList.style.display = 'none';
            if (onClose) onClose();
        });

        const ul = document.createElement('ul');
        details.forEach(([label, value]) => appendDetailItem(ul, label, value));

        header.appendChild(title);
        header.appendChild(closeBtn);
        dataList.replaceChildren(header, ul);
        dataList.style.display = 'block';
    }

    // ── Globe data ────────────────────────────────────────
    function updateGlobeData() {
        const visiblePoints = Object.values(points).filter(p =>
            !p.expired &&
            (showTCPOnly ? p.protocol === 'TCP' : true) &&
            ((showLocalNetwork    && isLocalNetwork(p.ip, p.org)) ||
             (showExternalNetwork && !isLocalNetwork(p.ip, p.org)))
        );
        if (isValidCoord(myIpCoords.lat, myIpCoords.lng)) visiblePoints.push(ownIpPoint);
        globe.pointsData(visiblePoints);

        globe.arcsData(showArcs ? Object.values(arcs).filter(a =>
            !a.expired &&
            (showTCPOnly ? a.protocol === 'TCP' : true) &&
            ((showLocalNetwork    && isLocalNetwork(a.ip, a.org)) ||
             (showExternalNetwork && !isLocalNetwork(a.ip, a.org)))
        ) : []);
    }

    // ── Socket.IO handlers ────────────────────────────────
    socket.on('connect', () => {
        console.log('Socket.IO connected, SID:', socket.id);
        if (connectionStatus) connectionStatus.textContent = 'Connected';
        initialLoadDone = false;
        socket.emit('set_internal_search', { isInternalSearchActive });
        socket.emit('request_initial_data');
    });

    socket.on('disconnect', () => {
        console.warn('Socket.IO disconnected');
        if (connectionStatus) connectionStatus.textContent = 'Connection lost';
    });

    socket.on('connect_error', err => {
        console.error('Socket.IO error:', err);
        if (connectionStatus) connectionStatus.textContent = 'Connection error';
    });

    socket.on('reconnect', attempts => {
        console.log(`Socket.IO reconnected after ${attempts} attempts`);
        if (connectionStatus) connectionStatus.textContent = 'Connected';
        socket.emit('request_initial_data');
    });

    socket.on('heartbeat', data => {
        console.debug('Heartbeat — active clients:', data.active_clients);
    });

    // Update the sidebar stats panel every 5 seconds (server push).
    socket.on('network_stats', data => {
        const setEl = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
        setEl('statTCP',    formatNum(data.tcp_packets));
        setEl('statUDP',    formatNum(data.udp_packets));
        setEl('statBytes',  formatBytes(data.total_bytes || 0));
        setEl('statActive', formatNum(data.active_connections));
    });

    // ── IP data processing ────────────────────────────────
    function applyIpUpdate(data) {
        if (!data.ip) { console.warn('ip_update without IP field:', data); return; }
        try {
            if (!isValidCoord(data.lat, data.lon)) return;
            if (data.lat === 0 && data.lon === 0 && data.org !== 'Local Network') return;

            const ip      = data.ip;
            const isNewIP = !points[ip];

            points[ip] = {
                ip:             data.ip,
                lat:            data.lat,
                lng:            data.lon,
                label:          `${data.hostname || data.ip} (${data.os || 'Unknown'})`,
                city:           data.city,
                country:        data.country,
                region:         data.region,
                org:            data.org,
                protocol:       data.protocol,
                src_port:       data.src_port,
                dst_port:       data.dst_port,
                incoming_count: data.incoming_count  || 0,
                outgoing_count: data.outgoing_count  || 0,
                color:          getCircleColor(data.threat_level, data.org),
                last_seen:      data.last_seen,
                mac:            data.mac,
                vendor:         data.vendor,
                packet_count:   data.packet_count    || 0,
                hostname:       data.hostname        || 'Unknown',
                os:             data.os              || 'Unknown',
                threat_level:   data.threat_level    || 'No Threat',
                expired:        false,
            };

            arcs[ip] = {
                startLat:       data.lat,
                startLng:       data.lon,
                endLat:         myIpCoords.lat,
                endLng:         myIpCoords.lng,
                ip:             data.ip,
                city:           data.city,
                country:        data.country,
                org:            data.org,
                protocol:       data.protocol,
                incoming_count: data.incoming_count || 0,
                outgoing_count: data.outgoing_count || 0,
                color:          (data.city === 'Unknown' || data.country === 'Unknown' ||
                                 data.org === 'Not available') ? '#FFFFFF' : '#FF0000',
                last_seen:      data.last_seen,
                packet_count:   data.packet_count || 0,
                hostname:       data.hostname || 'Unknown',
                os:             data.os       || 'Unknown',
                expired:        false,
            };

            if (isLocalNetwork(data.ip, data.org) && (isInternalSearchActive || pinnedIPs[ip])) {
                internalPackets[ip] = {
                    ip:             data.ip,
                    lat:            data.lat,
                    lng:            data.lon,
                    city:           data.city,
                    country:        data.country,
                    region:         data.region,
                    org:            data.org,
                    protocol:       data.protocol,
                    src_port:       data.src_port,
                    dst_port:       data.dst_port,
                    incoming_count: data.incoming_count || 0,
                    outgoing_count: data.outgoing_count || 0,
                    last_seen:      data.last_seen,
                    mac:            data.mac,
                    vendor:         data.vendor,
                    packet_count:   data.packet_count   || 0,
                    hostname:       data.hostname       || 'Unknown',
                    os:             data.os             || 'Unknown',
                    threat_level:   data.threat_level   || 'No Threat',
                    expired:        false,
                };
            }

            // Evict oldest non-pinned entries when limits are exceeded.
            if (Object.keys(points).length > MAX_POINTS) {
                const oldest = Object.keys(points)
                    .filter(k => !pinnedIPs[k] && k !== 'Your IP')
                    .sort((a, b) => points[a].last_seen - points[b].last_seen)[0];
                if (oldest) { delete points[oldest]; delete arcs[oldest]; }
            }
            if (Object.keys(internalPackets).length > MAX_INTERNAL_PACKETS) {
                const oldest = Object.keys(internalPackets)
                    .filter(k => !pinnedIPs[k])
                    .sort((a, b) => internalPackets[a].last_seen - internalPackets[b].last_seen)[0];
                if (oldest) delete internalPackets[oldest];
            }

            // Alert on new high-threat IPs — only after the initial bulk load is done
            // so we don't spam the user with notifications on every page reload.
            if (initialLoadDone && isNewIP &&
                data.threat_level === 'High' && !notifiedHighThreatIPs.has(ip)) {
                notifiedHighThreatIPs.add(ip);
                showToast(
                    `⚠ High Threat: ${ip} — ${data.org || 'Unknown'} (${data.country || ''})`,
                    'high'
                );
                notifyHighThreat(ip, data.org, data.country);
            }

        } catch (err) {
            console.error('Error processing ip_update:', err);
        }
    }

    socket.on('ip_update', data => { applyIpUpdate(data); refreshViews(); });

    socket.on('ip_update_batch', list => {
        if (!Array.isArray(list)) return;
        list.forEach(applyIpUpdate);
        initialLoadDone = true;
        refreshViews();
    });

    socket.on('mac_vendor_update', data => {
        if (!data?.mac || !data?.vendor) return;
        let changed = false;
        for (const ip in points) {
            if (points[ip].mac === data.mac && points[ip].vendor !== data.vendor) {
                points[ip].vendor = data.vendor; changed = true;
            }
        }
        for (const ip in internalPackets) {
            if (internalPackets[ip].mac === data.mac && internalPackets[ip].vendor !== data.vendor) {
                internalPackets[ip].vendor = data.vendor; changed = true;
            }
        }
        if (changed) refreshViews();
    });

    socket.on('ip_pinned_update', data => {
        const { ip, isPinned, packet_count } = data;
        pinnedIPs[ip] = isPinned;
        if (points[ip])          points[ip].packet_count          = packet_count;
        if (arcs[ip])            arcs[ip].packet_count            = packet_count;
        if (internalPackets[ip]) internalPackets[ip].packet_count = packet_count;
        refreshViews();
    });

    socket.on('settings_update', data => {
        if (data.is_internal_search_active !== undefined) {
            isInternalSearchActive = data.is_internal_search_active;
            if (searchInternalPacketsCheckbox)
                searchInternalPacketsCheckbox.checked = isInternalSearchActive;
        }
        if (data.show_all_udp_packets !== undefined) {
            showAllUDPPackets = data.show_all_udp_packets;
            toggleAllUDPPacketsButton.classList.toggle('active', showAllUDPPackets);
        }
        if (data.show_local_network !== undefined) {
            showLocalNetwork = data.show_local_network;
            toggleLocalNetworkButton.classList.toggle('active', showLocalNetwork);
        }
        if (data.show_external_network !== undefined) {
            showExternalNetwork = data.show_external_network;
            toggleExternalNetworkButton.classList.toggle('active', showExternalNetwork);
        }
        if (data.show_tcp_only !== undefined) {
            showTCPOnly = data.show_tcp_only;
            toggleTCPOnlyButton.classList.toggle('active', showTCPOnly);
        }
        refreshViews();
    });

    socket.on('packet_count_reset', data => {
        const pt = points[data.ip];
        if (pt) { pt.incoming_count = 0; pt.outgoing_count = 0; pt.packet_count = 0; refreshViews(); }
    });

    socket.on('pinned_ips_update', data => {
        for (const ip in data) {
            pinnedIPs[ip] = data[ip].isPinned;
            if (points[ip])          points[ip].packet_count          = data[ip].packet_count;
            if (arcs[ip])            arcs[ip].packet_count            = data[ip].packet_count;
            if (internalPackets[ip]) internalPackets[ip].packet_count = data[ip].packet_count;
        }
        refreshViews();
    });

    // ── Expiration timer ──────────────────────────────────
    setInterval(() => {
        const now = Date.now() / 1000;
        for (const ip in points) {
            if (!pinnedIPs[ip] && ip !== 'Your IP' &&
                now - points[ip].last_seen > EXPIRATION_SECONDS) {
                points[ip].expired = true;
                if (arcs[ip]) arcs[ip].expired = true;
            }
        }
        let changed = false;
        for (const ip in internalPackets) {
            if (!pinnedIPs[ip] && now - internalPackets[ip].last_seen > INTERNAL_EXPIRATION_SECONDS) {
                internalPackets[ip].expired = true;
                changed = true;
            }
        }
        if (changed) refreshViews();
    }, 1000);
}
