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
import { escapeHTML, showToast } from './format.js';

export function setupGlobe(app) {
    const myIpCoords = app.myIpCoords;

    // ── Globe point radius ────────────────────────────────
    // Size reflects the *recent* packet rate (packets in the last
    // RATE_WINDOW_SECONDS), so a connection pushing lots of data swells up and
    // shrinks back down once the traffic dies off.
    function getMarkerRadius(point) {
        const recent = recentPacketCount(point, Date.now() / 1000);
        if (recent <= 0) return 0.3;
        return Math.min(0.3 + Math.log10(recent + 1) * 0.6, 3.0);
    }

    // Detail panel is created dynamically so it stays on top of the globe canvas.
    const dataList = document.createElement('div');
    dataList.id = 'dataList';
    document.body.appendChild(dataList);
    app.dataList = dataList;

    // Close the detail panel when clicking anywhere outside it.
    // Globe-canvas clicks are excluded here — onGlobeClick handles those.
    document.addEventListener('click', e => {
        if (dataList.style.display !== 'block') return;
        if (dataList.contains(e.target)) return;
        if (document.getElementById('globeViz').contains(e.target)) return;
        dataList.style.display = 'none';
    });

    // ── Globe ─────────────────────────────────────────────
    const globe = Globe()
        .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
        .pointOfView({ lat: myIpCoords.lat, lng: myIpCoords.lng, altitude: 2.5 }, 0)
        .pointRadius(getMarkerRadius)
        .pointColor(point => point.isOrigin
            ? (point.color || '#FFFF00')
            : getCircleColor(point.threat_level, point.org))
        .pointLabel(point => point.isOrigin
            ? `<div>${escapeHTML(point.label || 'Device')}</div>`
            : `<div>${escapeHTML(point.ip) || 'N/A'} — ${escapeHTML(point.org) || 'N/A'}</div>`)
        .pointLat('lat')
        .pointLng('lng')
        .pointAltitude(0.1)
        .arcColor(arc => {
            // "Colour by device" makes each device's arcs its own colour; "by
            // threat" falls back to the destination IP's threat colour.
            if (app.colorMode === 'device') return app.deviceColor(arc.device_id);
            if (arc.city === 'Unknown' || arc.country === 'Unknown' || arc.org === 'Not available') {
                return '#FFFFFF';
            }
            const pt = app.points[arc.ip];
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

    // ── Globe data ────────────────────────────────────────
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

        globe.arcsData(app.showArcs ? Object.values(app.arcs).filter(a =>
            !a.expired && app.isDeviceVisible(a.device_id) &&
            (app.showTCPOnly ? a.protocol === 'TCP' : true) &&
            ((app.showLocalNetwork    && isLocalNetwork(a.ip, a.org)) ||
             (app.showExternalNetwork && !isLocalNetwork(a.ip, a.org)))
        ) : []);
    };
}
