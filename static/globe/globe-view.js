// static/globe/globe-view.js
//
// The 3D globe itself: marker sizing, the globe.gl instance + its
// point/arc/label styling and click handlers, camera persistence, the
// borders/arcs layer toggles, and updateGlobeData() which re-derives what the
// globe shows from the current point/arc/filter state.
//
// `Globe` is provided as a global by globe.gl (loaded via <script> in the page).

import { isValidCoord, recentPacketCount, isLocalNetwork } from './net.js';
import { getCircleColor } from './classify.js';
import { escapeHTML, showToast, toRGBA } from './format.js';

export function setupGlobe(app) {
    const myIpCoords = app.myIpCoords;

    // The arc is drawn almost in full (so you can see the whole route, hence
    // where the traffic goes); the animation is a single short GAP of this width
    // (fraction of the arc) sweeping along it. After the sweep the line lingers
    // for ARC_LINGER_MS, then fades over the last ARC_FADE_MS so it bows out
    // cleanly instead of popping.
    const ARC_GAP_LEN = 0.2;
    const ARC_FADE_MS = 1200;

    // ── Globe point radius ────────────────────────────────
    // Size reflects the *recent* packet rate (packets in the last
    // RATE_WINDOW_SECONDS), so a connection pushing lots of data swells up and
    // shrinks back down once the traffic dies off.
    function getMarkerRadius(point) {
        const recent = recentPacketCount(point, Date.now() / 1000);
        if (recent <= 0) return 0.3;
        return Math.min(0.3 + Math.log10(recent + 1) * 0.6, 3.0);
    }

    // ── Age-based dot fade ────────────────────────────────
    // The longer no fresh packet has arrived, the more transparent the dot is
    // drawn, so a point gently dims over its lifetime until it expires and is
    // filtered out entirely. Origins and pinned IPs never fade. A floor keeps the
    // dimmed dot clearly visible (a "slight" fade) rather than fading to nothing.
    function freshnessAlpha(obj, lifetimeSeconds) {
        if (obj.isOrigin || app.pinnedIPs[obj.ip]) return 1;
        const age = Date.now() / 1000 - (obj.last_seen || 0);
        const t = Math.max(0, Math.min(1, age / lifetimeSeconds));
        return Math.max(0.25, 1 - t);
    }

    // Detail panel is created dynamically so it stays on top of the globe canvas.
    const dataList = document.createElement('div');
    dataList.id = 'dataList';
    document.body.appendChild(dataList);
    app.dataList = dataList;

    // Close the detail panel on any click outside it — including the empty globe
    // canvas ("space" around the sphere), which onGlobeClick does NOT catch.
    // onPointClick fires on the canvas first and bubbles here, so it sets
    // _detailJustOpened to let that one opening click through; every other
    // outside click (background, sidebar, sphere) closes the panel.
    document.addEventListener('click', e => {
        if (dataList.style.display !== 'block') return;
        if (dataList.contains(e.target)) return;
        if (app._detailJustOpened) { app._detailJustOpened = false; return; }
        dataList.style.display = 'none';
    });

    // ── Globe ─────────────────────────────────────────────
    const globe = Globe()
        .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
        .pointOfView({ lat: myIpCoords.lat, lng: myIpCoords.lng, altitude: 2.5 }, 0)
        .pointRadius(getMarkerRadius)
        .pointColor(point => {
            const base = point.isOrigin
                ? (point.color || '#FFFF00')
                : getCircleColor(point.threat_level, point.org);
            // Dots linger and fade over EXPIRATION_SECONDS (origins stay solid).
            return toRGBA(base, freshnessAlpha(point, app.EXPIRATION_SECONDS));
        })
        .pointLabel(point => point.isOrigin
            ? `<div>${escapeHTML(point.label || 'Device')}</div>`
            : `<div>${escapeHTML(point.ip) || 'N/A'} — ${escapeHTML(point.org) || 'N/A'}</div>`)
        .pointLat('lat')
        .pointLng('lng')
        .pointAltitude(0.1)
        .arcColor(arc => {
            // "Colour by device" makes each device's arcs its own colour; "by
            // threat" falls back to the destination IP's threat colour.
            let base;
            if (app.colorMode === 'device') {
                base = app.deviceColor(arc.device_id);
            } else if (arc.city === 'Unknown' || arc.country === 'Unknown' || arc.org === 'Not available') {
                base = '#FFFFFF';
            } else {
                const pt = app.points[arc.ip];
                base = pt ? getCircleColor(pt.threat_level, pt.org) : '#FFFFFF';
            }
            // Each arc is one packet's flight (see tickArcs): _alpha fades it out
            // at the very end so it bows out cleanly, never pops.
            return toRGBA(base, arc._alpha ?? 1);
        })
        .arcStroke(0.5)
        // One packet = the whole route drawn with a single gap sweeping along it,
        // driven manually: with arcDashAnimateTime(0) three-globe leaves
        // dashTranslate at 0, so a fragment is drawn iff
        // mod(d - dashOffset, dashLength+dashGap) <= dashLength. With dashLength=1
        // (full arc) and a short dashGap, the only UNdrawn stretch is one gap of
        // width dashGap; tickArcs ramps each arc's own dashOffset
        // (arcDashInitialGap) so that gap walks from the home origin to the
        // external target — per arc, no shared clock (which is why arcs used to
        // start mid-route).
        .arcDashLength(1)
        .arcDashGap(ARC_GAP_LEN)
        .arcDashInitialGap(arc => arc._dashGap ?? 0)
        .arcDashAnimateTime(0)
        // No built-in grow-in tween — our dashOffset ramp is the whole animation.
        .arcsTransitionDuration(0)
        .labelSize(0.5)
        .labelDotRadius(0.3)
        .labelColor(() => 'white')
        .labelLabel('label')
        .onPointClick(point => {
            // Origin markers are devices, not connections — don't open the IP
            // detail panel full of N/A; just show a small device tooltip.
            if (point.isOrigin) {
                showToast(`${app.deviceName(point.device_id)} — capture origin`, 'low');
                return;
            }
            app.showDataList(point, () => {
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
    app.globe = globe;

    // ── Remember the last camera centre + zoom across reloads ─────────────
    // Without a saved view the globe stays centred on the user's own location
    // (the .pointOfView above). A saved view overrides that on load.
    const SAVED_POV_KEY = 'globePOV';
    try {
        const saved = JSON.parse(localStorage.getItem(SAVED_POV_KEY) || 'null');
        if (saved && isValidCoord(saved.lat, saved.lng) && saved.altitude > 0) {
            globe.pointOfView(saved, 0);
        }
    } catch (_) { /* corrupt value — fall back to own location */ }

    let _povSaveTimer = null;
    globe.onZoom(pov => {
        // Debounced so a drag/zoom gesture writes once it settles, not every frame.
        if (_povSaveTimer) clearTimeout(_povSaveTimer);
        _povSaveTimer = setTimeout(() => {
            try { localStorage.setItem(SAVED_POV_KEY, JSON.stringify(pov)); } catch (_) { /* quota */ }
        }, 400);
    });

    // Origins (one home point per device) are rendered by updateGlobeData; seed
    // the globe with the local origin so it shows immediately on load.
    globe.pointsData([app.origins[app.LOCAL_ID]]);

    // Resize the globe canvas whenever the container changes size.
    const globeContainer = document.getElementById('globeViz');
    app.globeContainer = globeContainer;
    const resizeObserver = new ResizeObserver(() => {
        globe.width(globeContainer.clientWidth)
             .height(globeContainer.clientHeight);
    });
    resizeObserver.observe(globeContainer);

    // ── Arcs checkbox ─────────────────────────────────────
    const showArcsCheckbox = document.getElementById('showArcs');
    if (showArcsCheckbox) {
        showArcsCheckbox.checked = app.showArcs;
        showArcsCheckbox.addEventListener('change', () => {
            app.showArcs = showArcsCheckbox.checked;
            localStorage.setItem('showArcs', JSON.stringify(app.showArcs));
            app.updateGlobeData();
        });
    }

    // ── Country borders checkbox ──────────────────────────
    const showBordersCheckbox = document.getElementById('showBorders');
    if (showBordersCheckbox) showBordersCheckbox.checked = app.showBorders;

    fetch('https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson')
        .then(r => r.json())
        .then(data => {
            app.countriesData = data.features;
            if (app.showBorders) {
                globe.polygonsData(app.countriesData)
                     .polygonCapColor(() => 'rgba(255,255,255,0.1)')
                     .polygonSideColor(() => 'rgba(255,255,255,0.1)')
                     .polygonStrokeColor(() => '#006100');
            }
        })
        .catch(err => console.error('Error loading country borders:', err));

    if (showBordersCheckbox) {
        showBordersCheckbox.addEventListener('change', () => {
            app.showBorders = showBordersCheckbox.checked;
            localStorage.setItem('showBorders', JSON.stringify(app.showBorders));
            globe.polygonsData(app.showBorders ? app.countriesData : []);
        });
    }

    document.getElementById('centerOwnLocation')?.addEventListener('click', () => {
        globe.pointOfView({ lat: myIpCoords.lat, lng: myIpCoords.lng, altitude: 2.5 }, 1000);
    });

    // ── Arc bookkeeping ───────────────────────────────────
    app.deleteArcsOfIp = ip => { for (const k in app.arcs) if (app.arcs[k].ip === ip) delete app.arcs[k]; };
    app.expireArcsOfIp = ip => { for (const k in app.arcs) if (app.arcs[k].ip === ip) app.arcs[k].expired = true; };

    // ── Live arc animation (one comet per packet) ─────────
    // Arcs are no longer a time-windowed line: each arriving packet plays exactly
    // one comet that flies from the origin to the destination, then fades out. No
    // traffic means no arc at all — only the (fading) dot remains. So a moving
    // arc always means "a packet flowed just now".
    function arcPassesFilters(a) {
        return !a.expired && app.isDeviceVisible(a.device_id) &&
            (app.showTCPOnly ? a.protocol === 'TCP' : true) &&
            ((app.showLocalNetwork    && isLocalNetwork(a.ip, a.org)) ||
             (app.showExternalNetwork && !isLocalNetwork(a.ip, a.org)));
    }

    // Called on every fresh packet for an arc. If no comet is in flight, start
    // one now; if one is already flying, remember at most ONE replay so a burst
    // can't build an ever-growing backlog — the held packet flies once the
    // current comet finishes (the user "waits until the current one is over").
    app.triggerArc = arc => {
        const now = Date.now();
        if (arc._t0 !== undefined && (now - arc._t0) < app.ARC_ANIM_MS) {
            arc._pending = true;
        } else {
            arc._t0 = now;
            arc._pending = false;
            ensureArcLoop();
        }
    };

    // One animation frame: advance every arc through its sweep -> linger -> fade
    // lifecycle, hand the globe the currently-visible arcs, and keep the rAF alive
    // only while at least one arc is still alive (so an idle globe does no work).
    // We only re-push to the globe when membership or a drawn value actually
    // changes, so the multi-second linger hold costs nothing.
    function tickArcs() {
        app._arcRAF = null;
        const now = Date.now();
        const SWEEP = app.ARC_ANIM_MS, LINGER = app.ARC_LINGER_MS;
        let anyAlive = false, changed = false;
        const live = [];
        for (const k in app.arcs) {
            const a = app.arcs[k];
            if (a._t0 === undefined) continue;
            let e = now - a._t0;
            // A packet held during the sweep starts a fresh sweep once it ends.
            if (e >= SWEEP && a._pending) { a._t0 = now; a._pending = false; e = 0; }
            if (e >= SWEEP + LINGER) { a._t0 = undefined; changed = true; continue; }  // life over
            anyAlive = true;
            if (!app.showArcs || !arcPassesFilters(a)) continue;  // age out but don't draw
            let gap, alpha;
            if (e < SWEEP) {
                // Sweeping: a single gap walks home -> external. The arc's start is
                // the external IP and its end the home origin (see socket.js), so
                // dashOffset 0 -> -(1+gap) moves the gap from the home origin (the
                // sender) out to the target; the rest of the route stays drawn so
                // its source is always visible.
                gap = -(e / SWEEP) * (1 + ARC_GAP_LEN);
                alpha = 1;
            } else {
                // Lingering: whole route drawn (gap parked just off the external
                // end), then fades over the last ARC_FADE_MS before removal.
                gap = -(1 + ARC_GAP_LEN);
                const held = e - SWEEP;
                alpha = held < LINGER - ARC_FADE_MS
                    ? 1 : Math.max(0, (LINGER - held) / ARC_FADE_MS);
            }
            if (gap !== a._dashGap || alpha !== a._alpha) { a._dashGap = gap; a._alpha = alpha; changed = true; }
            live.push(a);
        }
        // Membership change (an arc dropped or newly drawn) also needs a re-push.
        if (live.length !== app._arcShownCount) { changed = true; app._arcShownCount = live.length; }
        if (changed) globe.arcsData(live);
        if (anyAlive) app._arcRAF = requestAnimationFrame(tickArcs);
    }
    function ensureArcLoop() { if (!app._arcRAF) app._arcRAF = requestAnimationFrame(tickArcs); }

    // ── Globe data (points only; arcs are driven by tickArcs) ──
    app.updateGlobeData = () => {
        const visiblePoints = Object.values(app.points).filter(p =>
            !p.expired && app.pointDeviceVisible(p) &&
            (app.showTCPOnly ? p.protocol === 'TCP' : true) &&
            ((app.showLocalNetwork    && isLocalNetwork(p.ip, p.org)) ||
             (app.showExternalNetwork && !isLocalNetwork(p.ip, p.org)))
        );
        // One home point per visible device.
        for (const id in app.origins) {
            const o = app.origins[id];
            if (app.isDeviceVisible(id) && isValidCoord(o.lat, o.lng)) visiblePoints.push(o);
        }
        globe.pointsData(visiblePoints);
    };
}
