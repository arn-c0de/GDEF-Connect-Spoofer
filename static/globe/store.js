// static/globe/store.js
//
// The shared application context. createApp() returns one mutable `app` object
// that every setup module reads, writes, and hangs its cross-cutting functions
// off of (app.refreshViews, app.updateGlobeData, app.globe, app.socket, ...).
// Centralising the state here is what lets the old 1700-line closure split into
// focused modules without a web of cross-imports.
//
// This module also owns the small derived helpers that depend purely on app
// state (device visibility, IP labels, LAN peers, origin fan-out), so they are
// available everywhere the moment the app object exists.

import { isValidCoord } from './net.js';
import { loadJSON, saveJSON } from './format.js';

// Each captured connection carries a device_id. The built-in local capture is
// 'local'; remote sensors register their own. Points stay keyed by IP (one
// marker per external IP), but ARCS are keyed per (device, ip) so each device
// draws its own line from its own origin.
const LOCAL_ID = 'local';
const NUL = ' ';

export function createApp(myIpCoords) {
    const app = {
        // ── Own location ──────────────────────────────────────
        myIpCoords,

        // ── Multi-device identity ─────────────────────────────
        LOCAL_ID,
        NUL,
        ckey: (deviceId, ip) => `${deviceId}${NUL}${ip}`,
        colorMode: localStorage.getItem('colorMode') === 'device' ? 'device' : 'threat',
        devices: {},        // device_id -> metadata from the hub
        origins: {},        // device_id -> origin point object (rendered)
        deviceVisible: loadJSON('deviceVisible', {}),  // device_id -> bool

        // ── Tabbed overlay state ──────────────────────────────
        // Declared early to avoid TDZ when renderStats() references
        // statsOverlayOpen on first run.
        statsOverlayOpen: false,
        currentPage: 'stats',
        // Assigned by buildOverlay(); lets the top-bar buttons open the overlay
        // on a specific page (⚙ → Settings, 📊 → Statistics).
        openOverlay: () => {},
        connSort: { key: 'last_seen', dir: -1 },

        // ── Rendering handles (assigned during setup) ─────────
        globe: null,
        globeContainer: null,
        socket: null,
        connectionStatus: null,
        dataList: null,
        activeConnectionsList: null,
        internalNetworkList: null,
        // Toggle buttons the socket 'settings_update' handler also needs to sync.
        toggleLocalNetworkButton: null,
        toggleExternalNetworkButton: null,
        toggleTCPOnlyButton: null,
        toggleAllUDPPacketsButton: null,
        searchInternalPacketsCheckbox: null,

        // ── Globe layers ──────────────────────────────────────
        showArcs: JSON.parse(localStorage.getItem('showArcs') ?? 'true'),
        showBorders: JSON.parse(localStorage.getItem('showBorders') ?? 'true'),
        showLabels: JSON.parse(localStorage.getItem('showLabels') ?? 'true'),
        showLabelsThroughGlobe: JSON.parse(localStorage.getItem('showLabelsThroughGlobe') ?? 'false'),
        countriesData: [],

        // ── Collapse state ────────────────────────────────────
        isInternalNetworkCollapsed:
            JSON.parse(localStorage.getItem('isInternalNetworkCollapsed') ?? 'false'),
        isActiveConnectionsCollapsed:
            JSON.parse(localStorage.getItem('isActiveConnectionsCollapsed') ?? 'false'),

        // ── Filter / view state ───────────────────────────────
        showLocalNetwork: true,
        showExternalNetwork: true,
        showTCPOnly: false,
        showAllUDPPackets: false,
        isInternalSearchActive: true,
        filterText: '',
        filterTextInternal: '',
        initialLoadDone: false,

        // ── Throttled view refresh ────────────────────────────
        REFRESH_MIN_MS: 400,
        _lastRefresh: 0,
        _refreshTimer: null,

        // ── Data stores ───────────────────────────────────────
        points: {},
        arcs: {},
        internalPackets: {},
        pinnedIPs: {},
        // Co-located external/LAN IPs (one city, a shared datacenter, a CDN) merge
        // into ONE cluster marker with a count badge instead of stacking on the
        // exact same spot and burying each other as they swell with traffic. The
        // grid cell size tracks the camera altitude so piles split as you zoom in;
        // clicking a cluster fans its members out (expandedClusters). Cluster
        // render objects are cached by cell key so their refs stay stable across
        // refreshes (no marker re-add flash). See buildRenderPoints in
        // globe-view.js.
        expandedClusters: new Set(),
        _clusterCache: {},
        EXPIRATION_SECONDS: 300,
        // Arcs are a *live* indicator: each arriving packet sweeps a gap along the
        // route from origin to destination over ARC_ANIM_MS, then the line lingers
        // (drawn) for ARC_LINGER_MS and fades out — leaving just the dot (which
        // lingers and fades until EXPIRATION_SECONDS). No traffic means no arc, so
        // a fresh arc always means "a packet flowed just now". See triggerArc/
        // tickArcs in globe-view.js.
        ARC_ANIM_MS: 1000,
        ARC_LINGER_MS: 5000,
        INTERNAL_EXPIRATION_SECONDS: 600,
        MAX_POINTS: 1000,
        MAX_INTERNAL_PACKETS: 500,

        // Operator-defined friendly names for LAN IPs (loaded from /api/ip-labels).
        ipLabels: {},

        // Latest server stats push (every 5s). The modular panel renders from this.
        lastStats: { all: {}, by_device: {} },

        // ── Statistics preferences ────────────────────────────
        statsDevice: localStorage.getItem('statsDevice') || 'all',
        statsListMode: localStorage.getItem('statsListMode') || 'rate',
        lanSortMode: localStorage.getItem('lanSortMode') || 'rate',
        enabledWidgets: [],  // populated by setupStats()
    };

    // ── Derived helpers (depend only on app state) ────────────
    app.saveDeviceVisible = () => saveJSON('deviceVisible', app.deviceVisible);
    app.deviceColor = id => (app.origins[id]?.color) || (app.devices[id]?.color) || '#FFFFFF';
    app.deviceName  = id => (app.devices[id]?.name) || (id === LOCAL_ID ? 'This host' : id);
    // A device is shown only when its checkbox is on AND it is started (enabled).
    // Stopping a device therefore removes it from the globe and every list.
    app.deviceStarted = id => app.devices[id] ? app.devices[id].enabled !== false : true;
    app.isDeviceVisible = id => app.deviceVisible[id] !== false && app.deviceStarted(id);
    // A per-IP point is shown if any device that reported it is currently visible
    // (legacy points with no recorded device fall back to visible).
    app.pointDeviceVisible = p =>
        !p.devices || p.devices.size === 0 || [...p.devices].some(app.isDeviceVisible);

    app.ipLabel = ip => (app.ipLabels && app.ipLabels[ip]) || '';
    app.ipDisplay = ip => { const n = app.ipLabel(ip); return n ? `${n} (${ip})` : ip; };
    // The LAN host(s) talking to an external IP. An external server is often
    // reached by several local devices at once, so we keep a set and show them
    // all (sorted naturally: .44 before .90 before .100), each labelled if named.
    app.localPeers = p => {
        if (p.local_ips && p.local_ips.size) {
            return Array.from(p.local_ips).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
        }
        return p.local_ip ? [p.local_ip] : [];
    };
    app.localPeersText = p => {
        const a = app.localPeers(p);
        return a.length ? a.map(app.ipDisplay).join(', ') : '';
    };

    // Fan out origins that share (almost) the same coordinates so several sensors
    // in one network don't render on top of each other.
    app.rebuildOrigins = () => {
        const groups = {};
        for (const id in app.origins) {
            const o = app.origins[id];
            if (!isValidCoord(o.baseLat, o.baseLng)) continue;
            const k = `${o.baseLat.toFixed(1)}|${o.baseLng.toFixed(1)}`;
            (groups[k] = groups[k] || []).push(o);
        }
        for (const k in groups) {
            const g = groups[k];
            if (g.length === 1) {
                g[0].lat = g[0].baseLat; g[0].lng = g[0].baseLng;
            } else {
                const R = 2.2;  // degrees of fan-out radius
                g.forEach((o, i) => {
                    const ang = (2 * Math.PI * i) / g.length;
                    o.lat = o.baseLat + R * Math.sin(ang);
                    o.lng = o.baseLng + R * Math.cos(ang);
                });
            }
        }
    };

    // Seed the built-in local origin from our own browser-derived coordinates.
    app.origins[LOCAL_ID] = {
        isOrigin: true, device_id: LOCAL_ID, ip: '__origin__' + LOCAL_ID,
        baseLat: myIpCoords.lat, baseLng: myIpCoords.lng,
        lat: myIpCoords.lat, lng: myIpCoords.lng,
        color: '#FFFF00', label: 'This host',
        incoming_count: 0, outgoing_count: 0, last_seen: Date.now() / 1000, expired: false,
    };
    app.rebuildOrigins();

    return app;
}
