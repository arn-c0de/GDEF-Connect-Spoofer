// static/globe/devices.js
//
// The device legend (one row per capture origin) with its per-device controls:
// globe-visibility, colour, start/stop, rename, key-rotation, delete — plus
// adding a new remote sensor. Built dynamically so it tracks the live device
// list pushed by the hub.

import { showToast } from './format.js';

export function setupDevices(app) {
    const LOCAL_ID = app.LOCAL_ID;

    async function apiJson(url, opts) {
        const r = await fetch(url, Object.assign(
            { credentials: 'same-origin', headers: { 'Content-Type': 'application/json' } }, opts || {}));
        let body = null;
        try { body = await r.json(); } catch (_) { /* no body */ }
        return { ok: r.ok, status: r.status, body };
    }
    app.apiJson = apiJson;

    function revealKey(name, deviceId, key) {
        // The key is shown exactly once. window.prompt lets the operator copy it.
        window.prompt(
            `Device "${name}" — copy these into the sensor's environment now ` +
            `(the key is shown only once):`,
            `DEVICE_ID=${deviceId}\nDEVICE_KEY=${key}`);
    }

    app.addDevice = async () => {
        const name = (window.prompt('New device name (e.g. server1):') || '').trim();
        if (!name) return;
        const { ok, body } = await apiJson('/api/devices', { method: 'POST', body: JSON.stringify({ name }) });
        if (ok && body && body.key) {
            revealKey(body.name, body.device_id, body.key);
            showToast(`Device "${body.name}" registered`, 'low');
        } else {
            showToast(`Could not create device${body && body.error ? ': ' + body.error : ''}`, 'high');
        }
    };

    // Stop: purge a device's arcs and drop it from every point's device set so the
    // globe and lists stop showing its connections at once.
    app.removeDeviceData = id => {
        for (const k in app.arcs) if (app.arcs[k].device_id === id) delete app.arcs[k];
        for (const ip in app.points) app.points[ip].devices?.delete(id);
    };

    app.buildDeviceLegend = () => {
        const list = document.getElementById('deviceLegendList');
        if (!list) return;
        const frag = document.createDocumentFragment();
        const ids = Object.keys(app.origins).sort((a, b) =>
            a === LOCAL_ID ? -1 : b === LOCAL_ID ? 1 : app.deviceName(a).localeCompare(app.deviceName(b)));
        ids.forEach(id => {
            const d = app.devices[id] || {};
            const row = document.createElement('div');
            row.className = 'device-row';

            const vis = document.createElement('input');
            vis.type = 'checkbox'; vis.checked = app.deviceVisible[id] !== false; vis.title = 'Show on globe';
            vis.addEventListener('change', () => {
                app.deviceVisible[id] = vis.checked; app.saveDeviceVisible();
                app.refreshViews(); app.updateGlobeData();
            });

            const swatch = document.createElement('input');
            swatch.type = 'color'; swatch.className = 'device-swatch';
            swatch.value = (app.origins[id]?.color) || '#888888';
            swatch.title = 'Device colour';
            swatch.addEventListener('change', async () => {
                if (id === LOCAL_ID) { app.origins[id].color = swatch.value; app.rebuildOrigins(); app.updateGlobeData(); return; }
                const { ok } = await apiJson(`/api/devices/${id}`, { method: 'PATCH', body: JSON.stringify({ color: swatch.value }) });
                if (!ok) showToast('Could not update colour', 'high');
            });

            const nameEl = document.createElement('span');
            nameEl.className = 'device-name';
            nameEl.textContent = app.deviceName(id);
            const live = d.last_seen && (Date.now() / 1000 - d.last_seen) < 30;
            if (id !== LOCAL_ID) {
                nameEl.title = live ? 'online' : 'offline';
                nameEl.classList.toggle('device-online', !!live);
                nameEl.classList.toggle('device-offline', !live);
            }

            const dkind = (app.devices[id]?.kind) || (id === LOCAL_ID ? 'local' : 'remote');
            const kind = document.createElement('small');
            kind.className = 'device-kind';
            kind.textContent = dkind === 'local' ? 'local' : dkind === 'pcap' ? 'module' : 'sensor';

            row.append(vis, swatch, nameEl, kind);

            // Start/Stop — every device. Stopping it halts all processing of its
            // traffic on the hub and clears it from the globe and lists.
            const started = d.enabled !== false;
            const ss = document.createElement('button');
            ss.className = 'device-btn device-startstop' + (started ? ' running' : '');
            ss.textContent = started ? '■ Stop' : '▶ Start';
            ss.title = started ? 'Stop this device (no traffic processed)' : 'Start this device';
            ss.addEventListener('click', async () => {
                const { ok } = await apiJson(`/api/devices/${id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !started }) });
                if (!ok) showToast(`Could not ${started ? 'stop' : 'start'} device`, 'high');
            });
            row.append(ss);

            const ren = document.createElement('button');
            ren.className = 'device-btn'; ren.textContent = '✎'; ren.title = 'Rename';
            ren.addEventListener('click', async () => {
                const nn = (window.prompt('Rename device:', app.deviceName(id)) || '').trim();
                if (!nn) return;
                const { ok } = await apiJson(`/api/devices/${id}`, { method: 'PATCH', body: JSON.stringify({ name: nn }) });
                if (!ok) showToast('Could not rename', 'high');
            });
            // Built-in devices (local, FritzDump module) can be renamed but not
            // key-rotated or deleted; remote sensors get the full set.
            if (id !== LOCAL_ID) row.append(ren);
            if (id !== LOCAL_ID && dkind !== 'pcap') {
                const rot = document.createElement('button');
                rot.className = 'device-btn'; rot.textContent = '⟳'; rot.title = 'Rotate key';
                rot.addEventListener('click', async () => {
                    if (!window.confirm(`Rotate the key for "${app.deviceName(id)}"? The old key stops working.`)) return;
                    const { ok, body } = await apiJson(`/api/devices/${id}/rotate-key`, { method: 'POST' });
                    if (ok && body && body.key) revealKey(app.deviceName(id), id, body.key);
                    else showToast('Could not rotate key', 'high');
                });
                const del = document.createElement('button');
                del.className = 'device-btn'; del.textContent = '🗑'; del.title = 'Delete';
                del.addEventListener('click', async () => {
                    if (!window.confirm(`Delete device "${app.deviceName(id)}" and its data?`)) return;
                    const { ok } = await apiJson(`/api/devices/${id}`, { method: 'DELETE' });
                    if (!ok) showToast('Could not delete', 'high');
                });
                row.append(rot, del);
            }
            frag.appendChild(row);
        });
        list.replaceChildren(frag);
    };
}
