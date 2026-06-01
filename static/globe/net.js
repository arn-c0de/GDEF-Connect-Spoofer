// static/globe/net.js
//
// Pure network/geo helpers and the packet-rate tracking that drives globe
// point size. No DOM, no app state.

export function isValidCoord(lat, lng) {
    return typeof lat === 'number' && typeof lng === 'number' &&
           !isNaN(lat) && !isNaN(lng) &&
           lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
}

// ── Packet-rate tracking (drives globe point size) ─────────
// A point grows with how many packets arrived in the last RATE_WINDOW_SECONDS,
// not with its cumulative total — so a momentarily busy connection swells and
// then shrinks again once the burst passes.
export const RATE_WINDOW_SECONDS = 12;

// Record the packet delta since the last update on a point's rolling sample list.
export function recordPacketRate(pt, total, nowSec) {
    if (pt._lastTotal === undefined) {
        // First sighting: establish a baseline so we only count traffic from here on.
        pt._lastTotal   = total;
        pt._rateSamples = [];
        return;
    }
    const delta = total - pt._lastTotal;
    pt._lastTotal = total;
    if (delta > 0) pt._rateSamples.push([nowSec, delta]);
    const cutoff = nowSec - RATE_WINDOW_SECONDS;
    pt._rateSamples = pt._rateSamples.filter(s => s[0] >= cutoff);
}

// Sum of packets seen on a point within the trailing rate window.
export function recentPacketCount(pt, nowSec) {
    if (!pt._rateSamples || !pt._rateSamples.length) return 0;
    const cutoff = nowSec - RATE_WINDOW_SECONDS;
    let sum = 0;
    for (const [t, d] of pt._rateSamples) if (t >= cutoff) sum += d;
    return sum;
}

export function isLocalNetwork(ip, org) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    const [a, b] = parts.map(Number);
    return (a === 192 && b === 168) ||
           (a === 10) ||
           (a === 172 && b >= 16 && b <= 31) ||
           org === 'Local Network';
}

// The shared network/protocol visibility gate: TCP-only filter plus the
// local/external network toggles. Applied wherever points or arcs are filtered
// for display (sidebar list, globe points, arc comets) so the toggles behave
// identically everywhere. Device visibility and search are checked separately
// by each caller since they differ per view.
export function passesNetworkFilters(app, item) {
    return (app.showTCPOnly ? item.protocol === 'TCP' : true) &&
        ((app.showLocalNetwork    && isLocalNetwork(item.ip, item.org)) ||
         (app.showExternalNetwork && !isLocalNetwork(item.ip, item.org)));
}
