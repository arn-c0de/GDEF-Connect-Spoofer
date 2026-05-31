// static/globe/main.js
//
// Entry point + orchestrator. Builds the shared app context, then wires each
// concern (globe, lists, stats, devices, socket, overlay) onto it in an order
// that guarantees every cross-cutting function a setup step calls synchronously
// already exists. The DOMContentLoaded bootstrap (formerly init-globe.js) lives
// here too.

import { createApp } from './store.js';
import { isValidCoord } from './net.js';
import { loadTrustedOrgs } from './classify.js';
import { setupGlobe } from './globe-view.js';
import { setupLists } from './lists.js';
import { setupStats } from './stats.js';
import { setupDevices } from './devices.js';
import { setupSocket } from './socket.js';
import { setupOverlay } from './overlay.js';
import { setupThreatTicker } from './threats.js';

async function initializeGlobe(myIpCoords) {
    // Threat→colour classification first, so the very first render is correct.
    await loadTrustedOrgs();

    if (!isValidCoord(myIpCoords.lat, myIpCoords.lng)) {
        console.error('Invalid own coordinates:', myIpCoords);
        document.body.innerHTML = '<h1 style="color:red;padding:2rem">Error: could not load globe. Check the console (F12).</h1>';
        return;
    }

    const app = createApp(myIpCoords);

    // Ask for browser notification permission once on load.
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }

    // Order matters: a setup step may call cross-cutting functions another step
    // installs. setupOverlay() runs last because buildOverlay() synchronously
    // calls renderStats / buildDeviceLegend / syncDeviceSelect / wireIpLabelsEditor.
    setupGlobe(app);
    setupLists(app);
    setupStats(app);
    setupDevices(app);
    setupSocket(app);
    // After setupLists (so app.showDataList exists for the panel rows); harmless
    // if a socket refresh fires first — app.renderThreatTicker is guarded.
    setupThreatTicker(app);
    setupOverlay(app);

    // ── Expiration timer ──────────────────────────────────
    setInterval(() => {
        const now = Date.now() / 1000;
        for (const ip in app.points) {
            const p = app.points[ip];
            // Threat-flagged IPs (High/Medium/Low) are kept visible like pinned
            // ones — never expired client-side — so a suspicious/dangerous host
            // stays on the globe and under "threats" instead of fading out after
            // EXPIRATION_SECONDS of quiet (and vanishing entirely on reload).
            const isThreat = p.threat_level === 'High' || p.threat_level === 'Medium' || p.threat_level === 'Low';
            if (!app.pinnedIPs[ip] && !isThreat && ip !== 'Your IP' &&
                now - p.last_seen > app.EXPIRATION_SECONDS) {
                p.expired = true;
                app.expireArcsOfIp(ip);
            }
        }
        let changed = false;
        for (const ip in app.internalPackets) {
            if (!app.pinnedIPs[ip] && now - app.internalPackets[ip].last_seen > app.INTERNAL_EXPIRATION_SECONDS) {
                app.internalPackets[ip].expired = true;
                changed = true;
            }
        }
        if (changed) app.refreshViews();

        // Re-render the globe each tick so point sizes decay as their packet-rate
        // window empties (and expired points drop off promptly), even when no new
        // packets are arriving to trigger refreshViews().
        app.updateGlobeData();
    }, 1000);
}

// Bootstrap once the DOM is ready, using the coordinates the server stamped on
// document.body (formerly static/init-globe.js).
document.addEventListener('DOMContentLoaded', () => {
    const body = document.body;
    const lat = parseFloat(body.dataset.lat);
    const lng = parseFloat(body.dataset.lng);

    if (!isNaN(lat) && !isNaN(lng)) {
        initializeGlobe({ lat, lng });
    } else {
        console.error('Coordinates not found on document.body.dataset');
    }
});
