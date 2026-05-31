// static/globe/socket.js
//
// The live data link: the Socket.IO connection and every server→client event
// handler, plus applyIpUpdate() which folds an incoming IP record into the
// point/arc/internal-packet stores. `io` is a global from the socket.io client
// loaded via <script> in the page.

import { isValidCoord, isLocalNetwork, recordPacketRate } from './net.js';
import { getCircleColor } from './classify.js';
import { showToast, notifyHighThreat } from './format.js';

export function setupSocket(app) {
    const LOCAL_ID = app.LOCAL_ID;
    // Persists across Socket.IO reconnects so we don't re-alert for known IPs.
    const notifiedHighThreatIPs = new Set();

    const connectionStatus = document.getElementById('connectionStatus');
    app.connectionStatus = connectionStatus;

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
    app.socket = socket;

    // ── Connection lifecycle ──────────────────────────────
    socket.on('connect', () => {
        console.log('Socket.IO connected, SID:', socket.id);
        if (connectionStatus) connectionStatus.textContent = 'Connected';
        app.initialLoadDone = false;
        socket.emit('set_internal_search', { isInternalSearchActive: app.isInternalSearchActive });
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

    // Latest server stats push (every 5s). The modular panel renders from this.
    socket.on('network_stats', data => {
        app.lastStats = data || app.lastStats;
        app.renderStats();
    });

    // ── Device registry ───────────────────────────────────
    // Pushed by the hub (initial + on any change).
    socket.on('devices_update', list => {
        if (!Array.isArray(list)) return;
        const seen = new Set();
        let anyStarted = false;     // a device flipped Stop -> Start: refetch its data
        list.forEach(d => {
            seen.add(d.device_id);
            const wasStarted = app.devices[d.device_id] ? app.devices[d.device_id].enabled !== false : null;
            const nowStarted = d.enabled !== false;
            app.devices[d.device_id] = d;
            if (!(d.device_id in app.deviceVisible)) app.deviceVisible[d.device_id] = true;
            let o = app.origins[d.device_id];
            if (!o) {
                o = app.origins[d.device_id] = {
                    isOrigin: true, device_id: d.device_id, ip: '__origin__' + d.device_id,
                    incoming_count: 0, outgoing_count: 0, last_seen: Date.now() / 1000, expired: false,
                };
            }
            o.color = d.color || o.color || '#FFFFFF';
            o.label = d.name || d.device_id;
            // The local device keeps our precise browser coordinates; devices with
            // a resolved public-IP location use that; coord-less devices (e.g. the
            // FritzDump module) fall back to the hub's own location so their arcs
            // still render.
            if (d.device_id !== LOCAL_ID) {
                o.baseLat = isValidCoord(d.lat, d.lon) ? d.lat : app.origins[LOCAL_ID].baseLat;
                o.baseLng = isValidCoord(d.lat, d.lon) ? d.lon : app.origins[LOCAL_ID].baseLng;
            }
            if (wasStarted === true && !nowStarted) app.removeDeviceData(d.device_id);
            if (wasStarted === false && nowStarted) anyStarted = true;
        });
        // Drop origins whose device was removed (never the local one).
        for (const id in app.origins) {
            if (id !== LOCAL_ID && !seen.has(id)) delete app.origins[id];
        }
        app.rebuildOrigins();
        app.buildDeviceLegend();
        app.renderStats();
        app.refreshViews();
        app.updateGlobeData();
        // A (re)started device: pull the full IP set so its points/arcs reappear
        // immediately (the hub also rebroadcasts, this covers the toggling client).
        if (anyStarted) socket.emit('request_initial_data');
    });

    // ── IP data processing ────────────────────────────────
    function applyIpUpdate(data) {
        if (!data.ip) { console.warn('ip_update without IP field:', data); return; }
        try {
            if (!isValidCoord(data.lat, data.lon)) return;
            if (data.lat === 0 && data.lon === 0 && data.org !== 'Local Network') return;

            const ip      = data.ip;
            const isNewIP = !app.points[ip];
            const total   = (data.incoming_count || 0) + (data.outgoing_count || 0);
            const nowSec  = Date.now() / 1000;

            // Mutate the existing point object in place (instead of replacing it with
            // a fresh object) so the globe keeps the same reference and does NOT
            // remove + re-add the marker on every packet — that re-add was the
            // visible "flash" on busy connections.
            const pt = app.points[ip] || (app.points[ip] = {});
            pt.ip             = data.ip;
            pt.lat            = data.lat;
            pt.lng            = data.lon;
            pt.label          = `${data.hostname || data.ip} (${data.os || 'Unknown'})`;
            pt.city           = data.city;
            pt.country        = data.country;
            pt.region         = data.region;
            pt.org            = data.org;
            pt.protocol       = data.protocol;
            pt.src_port       = data.src_port;
            pt.dst_port       = data.dst_port;
            pt.incoming_count = data.incoming_count || 0;
            pt.outgoing_count = data.outgoing_count || 0;
            pt.color          = getCircleColor(data.threat_level, data.org);
            pt.last_seen      = data.last_seen;
            pt.mac            = data.mac;
            pt.vendor         = data.vendor;
            pt.packet_count   = data.packet_count || 0;
            pt.hostname       = data.hostname     || 'Unknown';
            pt.local_ip       = data.local_ip     || pt.local_ip || null;
            // Several LAN hosts often hit the SAME external server (e.g. .100,
            // .90, .44 all reaching one CDN), so collect every LAN peer we see
            // for this external IP rather than only the latest one.
            if (data.local_ip) (pt.local_ips || (pt.local_ips = new Set())).add(data.local_ip);
            pt.os             = data.os           || 'Unknown';
            pt.threat_level   = data.threat_level || 'No Threat';
            pt.expired        = false;
            // When this client first laid eyes on the IP — drives the "Newest" list.
            if (pt._firstSeen === undefined) pt._firstSeen = nowSec;
            recordPacketRate(pt, total, nowSec);

            // One arc per (device, ip): each device draws its own line from its
            // own origin to this IP. In-place mutation keeps the dash animation
            // from restarting on every packet.
            const deviceId = data.device_id || LOCAL_ID;
            // Track which devices reported this IP so the lists/globe can hide a
            // point the moment its only device is stopped.
            (pt.devices || (pt.devices = new Set())).add(deviceId);
            const origin   = app.origins[deviceId] || app.origins[LOCAL_ID];
            // Coord-less origins (e.g. the FritzDump module, which has no public
            // IP) anchor their arcs at the hub's own location.
            const endLat = isValidCoord(origin.lat, origin.lng) ? origin.lat : app.origins[LOCAL_ID].lat;
            const endLng = isValidCoord(origin.lat, origin.lng) ? origin.lng : app.origins[LOCAL_ID].lng;
            const ack      = app.ckey(deviceId, ip);
            const arc = app.arcs[ack] || (app.arcs[ack] = {});
            arc.startLat       = data.lat;
            arc.startLng       = data.lon;
            arc.endLat         = endLat;
            arc.endLng         = endLng;
            arc.ip             = data.ip;
            arc.device_id      = deviceId;
            arc.city           = data.city;
            arc.country        = data.country;
            arc.org            = data.org;
            arc.protocol       = data.protocol;
            arc.incoming_count = data.incoming_count || 0;
            arc.outgoing_count = data.outgoing_count || 0;
            arc.last_seen      = data.last_seen;
            // Mark the arc "live" whenever fresh packets actually arrive (its
            // count grew) or on first sighting. updateGlobeData only draws an arc
            // while this stamp is recent, so the line is a true live indicator.
            const arcTotal = data.packet_count || ((data.incoming_count || 0) + (data.outgoing_count || 0));
            if (arc.packet_count === undefined || arcTotal > arc.packet_count) arc._lastActive = nowSec;
            arc.packet_count   = arcTotal;
            arc.hostname       = data.hostname || 'Unknown';
            arc.os             = data.os       || 'Unknown';
            arc.expired        = false;

            if (isLocalNetwork(data.ip, data.org) && (app.isInternalSearchActive || app.pinnedIPs[ip])) {
                const ipkt = app.internalPackets[ip] || (app.internalPackets[ip] = {});
                ipkt.ip             = data.ip;
                ipkt.lat            = data.lat;
                ipkt.lng            = data.lon;
                ipkt.city           = data.city;
                ipkt.country        = data.country;
                ipkt.region         = data.region;
                ipkt.org            = data.org;
                ipkt.protocol       = data.protocol;
                ipkt.src_port       = data.src_port;
                ipkt.dst_port       = data.dst_port;
                ipkt.incoming_count = data.incoming_count || 0;
                ipkt.outgoing_count = data.outgoing_count || 0;
                ipkt.last_seen      = data.last_seen;
                ipkt.mac            = data.mac;
                ipkt.vendor         = data.vendor;
                ipkt.packet_count   = data.packet_count   || 0;
                ipkt.hostname       = data.hostname       || 'Unknown';
                ipkt.os             = data.os             || 'Unknown';
                ipkt.threat_level   = data.threat_level   || 'No Threat';
                ipkt.expired        = false;
            }

            // Evict oldest non-pinned entries when limits are exceeded.
            if (Object.keys(app.points).length > app.MAX_POINTS) {
                const oldest = Object.keys(app.points)
                    .filter(k => !app.pinnedIPs[k] && k !== 'Your IP')
                    .sort((a, b) => app.points[a].last_seen - app.points[b].last_seen)[0];
                if (oldest) { delete app.points[oldest]; app.deleteArcsOfIp(oldest); }
            }
            if (Object.keys(app.internalPackets).length > app.MAX_INTERNAL_PACKETS) {
                const oldest = Object.keys(app.internalPackets)
                    .filter(k => !app.pinnedIPs[k])
                    .sort((a, b) => app.internalPackets[a].last_seen - app.internalPackets[b].last_seen)[0];
                if (oldest) delete app.internalPackets[oldest];
            }

            // Alert on new high-threat IPs — only after the initial bulk load is done
            // so we don't spam the user with notifications on every page reload.
            if (app.initialLoadDone && isNewIP &&
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

    socket.on('ip_update', data => { applyIpUpdate(data); app.refreshViews(); });

    socket.on('ip_update_batch', list => {
        if (!Array.isArray(list)) return;
        list.forEach(applyIpUpdate);
        app.initialLoadDone = true;
        app.refreshViews();
    });

    socket.on('mac_vendor_update', data => {
        if (!data?.mac || !data?.vendor) return;
        let changed = false;
        for (const ip in app.points) {
            if (app.points[ip].mac === data.mac && app.points[ip].vendor !== data.vendor) {
                app.points[ip].vendor = data.vendor; changed = true;
            }
        }
        for (const ip in app.internalPackets) {
            if (app.internalPackets[ip].mac === data.mac && app.internalPackets[ip].vendor !== data.vendor) {
                app.internalPackets[ip].vendor = data.vendor; changed = true;
            }
        }
        if (changed) app.refreshViews();
    });

    socket.on('ip_pinned_update', data => {
        const { ip, isPinned, packet_count } = data;
        app.pinnedIPs[ip] = isPinned;
        if (app.points[ip])          app.points[ip].packet_count          = packet_count;
        if (app.arcs[ip])            app.arcs[ip].packet_count            = packet_count;
        if (app.internalPackets[ip]) app.internalPackets[ip].packet_count = packet_count;
        app.refreshViews();
    });

    socket.on('settings_update', data => {
        if (data.is_internal_search_active !== undefined) {
            app.isInternalSearchActive = data.is_internal_search_active;
            if (app.searchInternalPacketsCheckbox)
                app.searchInternalPacketsCheckbox.checked = app.isInternalSearchActive;
        }
        if (data.show_all_udp_packets !== undefined) {
            app.showAllUDPPackets = data.show_all_udp_packets;
            app.toggleAllUDPPacketsButton.classList.toggle('active', app.showAllUDPPackets);
        }
        if (data.show_local_network !== undefined) {
            app.showLocalNetwork = data.show_local_network;
            app.toggleLocalNetworkButton.classList.toggle('active', app.showLocalNetwork);
        }
        if (data.show_external_network !== undefined) {
            app.showExternalNetwork = data.show_external_network;
            app.toggleExternalNetworkButton.classList.toggle('active', app.showExternalNetwork);
        }
        if (data.show_tcp_only !== undefined) {
            app.showTCPOnly = data.show_tcp_only;
            app.toggleTCPOnlyButton.classList.toggle('active', app.showTCPOnly);
        }
        app.refreshViews();
    });

    socket.on('packet_count_reset', data => {
        const pt = app.points[data.ip];
        if (pt) { pt.incoming_count = 0; pt.outgoing_count = 0; pt.packet_count = 0; app.refreshViews(); }
    });

    socket.on('pinned_ips_update', data => {
        for (const ip in data) {
            app.pinnedIPs[ip] = data[ip].isPinned;
            if (app.points[ip])          app.points[ip].packet_count          = data[ip].packet_count;
            if (app.arcs[ip])            app.arcs[ip].packet_count            = data[ip].packet_count;
            if (app.internalPackets[ip]) app.internalPackets[ip].packet_count = data[ip].packet_count;
        }
        app.refreshViews();
    });
}
