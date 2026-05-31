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

    // ── Co-located point clustering ───────────────────────
    // External/LAN IPs frequently geolocate to identical coordinates (one city, a
    // shared datacenter, a CDN). Drawn raw they stack on the exact same spot and —
    // once they swell with traffic — bury each other. We merge each such pile into
    // ONE cluster marker carrying a count badge. The grid cell size scales with the
    // camera altitude so piles split as you zoom in; clicking a cluster fans its
    // members out (app.expandedClusters). Cluster objects are cached by cell key so
    // their refs stay stable across refreshes (no marker re-add flash).
    const CLUSTER_CELL_BASE = 0.5;   // grid cell size (deg) per unit camera altitude
    const CLUSTER_CELL_MIN  = 0.15;  // finest grid (zoomed all the way in)
    const CLUSTER_CELL_MAX  = 6;     // coarsest grid (zoomed all the way out)
    const CLUSTER_MIN_SIZE  = 2;     // a "pile" worth merging into one marker

    const THREAT_RANK = { High: 3, Medium: 2, Low: 1 };
    const threatRank  = t => THREAT_RANK[t] || 0;

    // Grid cell size in degrees for the current zoom: coarse when far out (more
    // merging), fine when zoomed in (piles split into individual dots).
    function clusterCellDeg() {
        const alt = globe.pointOfView().altitude || 2.5;
        return Math.max(CLUSTER_CELL_MIN, Math.min(CLUSTER_CELL_MAX, alt * CLUSTER_CELL_BASE));
    }

    // ── Globe point radius ────────────────────────────────
    // Size reflects the *recent* packet rate (packets in the last
    // RATE_WINDOW_SECONDS), so a connection pushing lots of data swells up and
    // shrinks back down once the traffic dies off. A cluster is bigger still,
    // growing with how many IPs it hides and their combined live rate.
    function getMarkerRadius(point) {
        if (point.isCluster) {
            // Only modestly bigger than a single dot — the count badge conveys the
            // size, the radius shouldn't dominate the globe.
            return Math.min(0.45 + Math.log10(point.count + 1) * 0.4
                                 + Math.log10((point._recent || 0) + 1) * 0.2, 1.5);
        }
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
            // A cluster takes the colour of its highest-threat member (so a single
            // High in a pile still reads red); otherwise origin colour / threat.
            const base = point.isOrigin
                ? (point.color || '#FFFF00')
                : getCircleColor(point.threat_level, point.org);
            // Dots/clusters linger and fade over EXPIRATION_SECONDS (origins solid).
            return toRGBA(base, freshnessAlpha(point, app.EXPIRATION_SECONDS));
        })
        .pointLabel(point => {
            if (point.isCluster) {
                const names = point.members.slice()
                    .sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0))
                    .slice(0, 6)
                    .map(m => `${escapeHTML(m.ip)} — ${escapeHTML(m.org || 'N/A')}`)
                    .join('<br>');
                const more = point.count > 6 ? `<br>…+${point.count - 6} more` : '';
                return `<div><b>${point.count} connections here</b><br>${names}${more}` +
                       `<br><i>click to expand</i></div>`;
            }
            return point.isOrigin
                ? `<div>${escapeHTML(point.label || 'Device')}</div>`
                : `<div>${escapeHTML(point.ip) || 'N/A'} — ${escapeHTML(point.org) || 'N/A'}</div>`;
        })
        // Members of an opened cluster carry a fan-out offset (_dispLat/_dispLng);
        // everything else renders at its true coordinate.
        .pointLat(d => d._dispLat ?? d.lat)
        .pointLng(d => d._dispLng ?? d.lng)
        // Lift threatening points (Low/Medium/High) off the surface, higher the
        // more severe, so suspicious/dangerous dots stand proud of the plain ones
        // instead of being buried among them. No-threat dots and origins stay flat.
        // Clusters lift by their worst member's threat (carried on threat_level).
        .pointAltitude(d => 0.1 + threatRank(d.threat_level) * 0.06)
        .arcColor(arc => {
            // "Colour by device" makes each device's arcs its own colour.
            let base;
            if (app.colorMode === 'device') {
                base = app.deviceColor(arc.device_id);
            } else {
                // Threat mode: the arc takes the SAME colour as its destination dot
                // — a suspicious IP (orange/Medium) or dangerous one (red/High)
                // draws a matching arc, even when several IPs share one spot (each
                // arc still resolves its own IP's threat). We deliberately do NOT
                // override geographic-unknowns to white here: that used to mask the
                // threat colour, so an orange dot got a white arc. getCircleColor
                // already yields white for no-threat/unclassified. Falls back to the
                // threat recorded on the arc itself if the point was evicted.
                const pt = app.points[arc.ip];
                base = getCircleColor(pt ? pt.threat_level : arc.threat_level,
                                      pt ? pt.org : arc.org);
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
        // The labels layer is fed ONLY the cluster render objects (see
        // updateGlobeData): each shows how many IPs the pile hides, floated just
        // above the marker so the count reads clearly.
        .labelLat(d => d.lat)
        .labelLng(d => d.lng)
        .labelText(d => String(d.count))
        .labelSize(1.0)
        // The badge dims in lock-step with its cluster dot (same freshness fade,
        // same 0.25 floor) so the number never bows out while the pile is still
        // drawn — and the layer's default fade-in/out transition is off so a badge
        // appears/vanishes exactly with its cluster, not a beat behind it.
        .labelColor(d => toRGBA('#FFFFFF', freshnessAlpha(d, app.EXPIRATION_SECONDS)))
        .labelsTransitionDuration(0)
        .labelResolution(2)
        .labelAltitude(0.13)
        .labelIncludeDot(false)
        .onPointClick(point => {
            // A cluster isn't a single connection — open the detail popup with one
            // tab per IP in the pile, so each member's full info is switchable.
            if (point.isCluster) {
                app.showClusterDetail(point);
                return;
            }
            // Origin markers are devices, not connections — don't open the IP
            // detail panel full of N/A; just show a small device tooltip.
            if (point.isOrigin) {
                showToast(`${app.deviceName(point.device_id)} — capture origin`, 'low');
                return;
            }
            app.showDataList(point, () => {
                globe.pointRadius(getMarkerRadius);
            });
            globe.pointRadius(d => d === point ? getMarkerRadius(d) * 1.5 : getMarkerRadius(d));
        })
        .onGlobeClick(() => {
            dataList.style.display = 'none';
            globe.pointRadius(getMarkerRadius);
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
            // Pile sizes track the zoom level, so re-cluster once the view settles.
            // A fresh view also drops any hand-expanded piles (they re-form for the
            // new altitude). Skipped while nothing is on the globe yet.
            if (app.updateGlobeData) {
                if (app.expandedClusters.size) app.expandedClusters.clear();
                app.updateGlobeData();
            }
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

    // Fan members of an opened pile that sit on (almost) the same coordinate out
    // into a small ring so each is separately visible and clickable; members at
    // genuinely distinct coords keep their true position.
    function spreadColocated(members) {
        const sub = new Map();
        for (const p of members) {
            const k = `${p.lat.toFixed(2)}|${p.lng.toFixed(2)}`;
            (sub.get(k) || sub.set(k, []).get(k)).push(p);
        }
        for (const g of sub.values()) {
            if (g.length === 1) continue;
            const R = Math.min(0.6 + g.length * 0.25, 5);   // ring radius (degrees)
            g.forEach((p, i) => {
                const ang = (2 * Math.PI * i) / g.length;
                p._dispLat = p.lat + R * Math.sin(ang);
                p._dispLng = p.lng + R * Math.cos(ang);
            });
        }
    }

    // Build (or reuse) the cached cluster marker for one grid cell. Reusing the
    // object across refreshes keeps its globe reference stable, so a busy pile
    // doesn't flicker (re-add) every update.
    function makeCluster(key, members, nowSec) {
        let lat = 0, lng = 0, lastSeen = 0, recent = 0, top = members[0];
        for (const m of members) {
            lat += m.lat; lng += m.lng;
            if ((m.last_seen || 0) > lastSeen) lastSeen = m.last_seen || 0;
            recent += recentPacketCount(m, nowSec);
            if (threatRank(m.threat_level) > threatRank(top.threat_level)) top = m;
        }
        const c = app._clusterCache[key] || (app._clusterCache[key] = { isCluster: true, cellKey: key });
        c.lat = lat / members.length;
        c.lng = lng / members.length;
        c.last_seen    = lastSeen;
        c.count        = members.length;
        c.members      = members;
        c._recent      = recent;
        c.threat_level = top.threat_level;   // highest-threat member drives the colour
        c.org          = top.org;
        c.ip           = top.ip;             // representative (for trusted-org colour)
        return c;
    }

    // ── Globe data (points + cluster badges; arcs are driven by tickArcs) ──
    app.updateGlobeData = () => {
        const nowSec = Date.now() / 1000;
        const visiblePoints = Object.values(app.points).filter(p =>
            !p.expired && app.pointDeviceVisible(p) &&
            (app.showTCPOnly ? p.protocol === 'TCP' : true) &&
            ((app.showLocalNetwork    && isLocalNetwork(p.ip, p.org)) ||
             (app.showExternalNetwork && !isLocalNetwork(p.ip, p.org)))
        );
        // Clear any fan-out offset from a previous expand; re-applied below only
        // for members of a pile the user has opened.
        for (const p of visiblePoints) { p._dispLat = undefined; p._dispLng = undefined; }

        // Bucket points into a lat/lng grid whose cell size tracks the zoom level.
        const cellDeg = clusterCellDeg();
        const cells = new Map();   // cellKey -> point[]
        for (const p of visiblePoints) {
            if (!isValidCoord(p.lat, p.lng)) continue;
            const key = `${Math.round(p.lat / cellDeg)}|${Math.round(p.lng / cellDeg)}`;
            (cells.get(key) || cells.set(key, []).get(key)).push(p);
        }

        const render = [];
        const liveClusterKeys = new Set();
        for (const [key, members] of cells) {
            if (members.length < CLUSTER_MIN_SIZE || app.expandedClusters.has(key)) {
                spreadColocated(members);            // draw the pile's members individually
                for (const p of members) render.push(p);
            } else {
                liveClusterKeys.add(key);            // merge the pile into one badge
                render.push(makeCluster(key, members, nowSec));
            }
        }
        // Forget cached clusters whose cell no longer exists, so the cache can't
        // grow unbounded as IPs come and go.
        for (const k in app._clusterCache) if (!liveClusterKeys.has(k)) delete app._clusterCache[k];

        // One home point per visible device (origins are never clustered).
        for (const id in app.origins) {
            const o = app.origins[id];
            if (app.isDeviceVisible(id) && isValidCoord(o.lat, o.lng)) render.push(o);
        }

        globe.pointsData(render);
        // The count badge layer carries only the clusters.
        globe.labelsData(render.filter(d => d.isCluster));
    };
}
