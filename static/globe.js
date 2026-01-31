// static/globe.js

let trustedOrgs = [];
let suspiciousOrgs = [];
let dangerousOrgs = [];

async function loadTrustedOrgs() {
    try {
        const response = await fetch('/trusted_organisations');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}, URL: ${response.url}`);
        }
        const data = await response.json();
        trustedOrgs = data.trusted_organisations || [];
        suspiciousOrgs = data.suspicious_organisations || [];
        dangerousOrgs = data.dangerous_organisations || [];
        console.log("Trusted organisations loaded:", trustedOrgs);
        console.log("Suspicious organisations loaded:", suspiciousOrgs);
        console.log("Dangerous organisations loaded:", dangerousOrgs);
    } catch (error) {
        console.error("Error loading trusted_organisations:", error);
        trustedOrgs = [
            'Google LLC',
            'Amazon.com, Inc.',
            'Microsoft Corporation',
            'Cloudflare, Inc.',
            'Apple Inc.',
            'Meta Platforms, Inc.',
            'Akamai Technologies, Inc.'
        ];
        suspiciousOrgs = [
            'Unknown ISP',
            'Generic Hosting',
            'Suspected Proxy Service'
        ];
        dangerousOrgs = [
            'Malware Host',
            'Known Botnet',
            'Dark Web Service'
        ];
    }
}

function isValidCoord(lat, lng) {
    return typeof lat === 'number' && typeof lng === 'number' && !isNaN(lat) && !isNaN(lng) &&
           lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
}

function isLocalNetwork(ip, org) {
    const ipParts = ip.split('.');
    if (ipParts.length !== 4) return false;
    const [first, second] = ipParts.map(Number);
    return (
        (first === 192 && second === 168) ||
        (first === 10) ||
        (first === 172 && second >= 16 && second <= 31) ||
        org === 'Local Network'
    );
}

function getCircleColor(threat_level, org) {
    if (org && trustedOrgs.includes(org)) {
        return 'green';
    }
    if (threat_level === "High") return 'red';
    if (threat_level === "Medium") return 'orange';
    if (threat_level === "Low") return 'yellow';
    return 'white';
}

async function initializeGlobe(myIpCoords) {
    await loadTrustedOrgs();

    function getMarkerRadius(point) {
        const totalPackets = (point.incoming_count || 0) + (point.outgoing_count || 0);
        if (totalPackets === 0) return 0.3;
        const baseRadius = 0.3;
        const maxRadius = 2.0;
        const scalingFactor = 0.2;
        const radius = baseRadius + Math.log10(totalPackets + 1) * scalingFactor;
        return Math.min(radius, maxRadius);
    }

    let socketUrl;
    try {
        const port = location.port ? `:${location.port}` : '';
        socketUrl = `${window.location.protocol}//${document.domain}${port}`;
    } catch (e) {
        console.error('Error determining socket URL:', e);
        socketUrl = `${window.location.protocol}//${document.domain}:8000`;
    }
    const socket = io.connect(socketUrl, {
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000
    });

    if (!isValidCoord(myIpCoords.lat, myIpCoords.lng)) {
        console.error("Invalid own coordinates:", myIpCoords);
        document.body.innerHTML = '<h1>Error loading globe</h1><p>Please check the console (F12) for details.</p>';
        return;
    }

    const connectionStatusElement = document.getElementById('connectionStatus');
    connectionStatusElement.style.marginLeft = 'auto';
    connectionStatusElement.style.background = 'rgba(0, 128, 0, 0.8)';

    const dataList = document.createElement('div');
    dataList.id = 'dataList';
    dataList.style.position = 'absolute';
    dataList.style.top = '10px';
    dataList.style.left = '10px';
    dataList.style.background = 'rgba(0, 0, 0, 0.8)';
    dataList.style.color = 'white';
    dataList.style.padding = '10px';
    dataList.style.borderRadius = '5px';
    dataList.style.maxWidth = '300px';
    dataList.style.zIndex = '1000';
    dataList.style.display = 'none';
    dataList.style.fontSize = '12px';
    dataList.style.lineHeight = '1.4';
    document.body.appendChild(dataList);

    const activeConnectionsList = document.getElementById('activeConnectionsList');
    activeConnectionsList.style.bottom = '1px';
    activeConnectionsList.style.left = '1px';
    activeConnectionsList.style.background = 'rgba(0, 0, 0, 0.8)';
    activeConnectionsList.style.color = 'white';
    activeConnectionsList.style.padding = '10px';
    activeConnectionsList.style.borderRadius = '15px';
    activeConnectionsList.style.maxWidth = '400px';
    activeConnectionsList.style.maxHeight = '500px';
    activeConnectionsList.style.overflowY = 'auto';
    const UPPER_LIMIT = 100;
    activeConnectionsList.style.zIndex = '1000';
    activeConnectionsList.innerHTML = `
        <div style="display: flex; align-items: center;">
            <button id="toggleActiveConnections" title="Show/hide active connections">▲</button>
            <span id="connectionCount" style="margin-right: 10px;"></span>
            <h3 style="margin: 0; flex-grow: 1;">Active Connections</h3>
            <button id="toggleLocalNetwork" title="Show/hide local network">🌐</button>
            <button id="toggleExternalNetwork" title="Show/hide external network">🔗</button>
            <button id="toggleTCPOnly" title="Show TCP connections only">📡</button>
            <button id="toggleAllUDPPackets" title="Show all UDP packets">📶</button>
            <button id="centerOwnLocation" title="Center on own location">📍</button>
        </div>
        <ul id="connectionsList"></ul>
    `;
    document.body.appendChild(activeConnectionsList);

    const globe = Globe()
        .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
        .pointOfView({ lat: myIpCoords.lat, lng: myIpCoords.lng, altitude: 2.5 }, 0)
        .pointRadius(getMarkerRadius)
        .pointColor(point => point.ip === 'Your IP' ? '#FFFF00' : getCircleColor(point.threat_level))
        .pointLabel(point => `
            <div>
                ${point.ip || 'N/A'} - ${point.org || 'N/A'}
            </div>
        `)
        .pointLat('lat')
        .pointLng('lng')
        .pointAltitude(0.1)
        .arcColor(arc => {
            if (arc.city === 'Unknown' || arc.country === 'Unknown' || arc.org === 'Not available') {
                return '#FFFFFF';
            }
            const point = points[arc.ip];
            return point ? getCircleColor(point.threat_level) : '#FFFFFF';
        })
        .arcStroke(0.5)
        .arcDashLength(0.8)
        .arcDashGap(0.5)
        .arcDashAnimateTime(1000)
        .labelSize(0.5)
        .labelDotRadius(0.3)
        .labelColor(() => 'white')
        .labelLabel('label')
        .onPointClick((point) => {
            dataList.style.display = 'block';
            dataList.innerHTML = `
                <div style="display: flex; align-items: center;">
                    <h3>IP: ${point.ip || 'N/A'}</h3>
                    <button id="closeDataList" style="margin-left: 10px; background: #555; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer;">✖</button>
                </div>
                <ul>
                    <li><strong>Hostname:</strong> ${point.hostname || 'Unknown'}</li>
                    <li><strong>OS:</strong> ${point.os || 'Unknown'}</li>
                    <li><strong>MAC Address:</strong> ${point.mac || 'N/A'}</li>
                    <li><strong>Vendor:</strong> ${point.vendor || 'Unknown'}</li>
                    <li><strong>City:</strong> ${point.city || 'N/A'}</li>
                    <li><strong>Country:</strong> ${point.country || 'N/A'}</li>
                    <li><strong>Region:</strong> ${point.region || 'N/A'}</li>
                    <li><strong>Organization:</strong> ${point.org || 'N/A'}</li>
                    <li><strong>Protocol:</strong> ${point.protocol || 'N/A'}</li>
                    <li><strong>Source Port:</strong> ${point.src_port || 'N/A'}</li>
                    <li><strong>Dest Port:</strong> ${point.dst_port || 'N/A'}</li>
                    <li><strong>Last Seen:</strong> ${point.last_seen ? new Date(point.last_seen * 1000).toLocaleString() : 'N/A'}</li>
                    <li><strong>Incoming Packets:</strong> ${point.incoming_count || 0}</li>
                    <li><strong>Outgoing Packets:</strong> ${point.outgoing_count || 0}</li>
                    <li><strong>Total Packets:</strong> ${point.packet_count || 0}</li>
                    <li><strong>Threat Level:</strong> ${point.threat_level || 'No Threat'}</li>
                </ul>
            `;
            document.getElementById('closeDataList').addEventListener('click', () => {
                dataList.style.display = 'none';
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

    console.log("Globe.GL initialized");

    const ownIpPoint = {
        lat: myIpCoords.lat,
        lng: myIpCoords.lng,
        label: 'Your IP',
        ip: 'Your IP',
        color: '#FFFF00',
        city: 'N/A',
        country: 'N/A',
        org: 'N/A',
        incoming_count: 0,
        outgoing_count: 0,
        last_seen: Date.now() / 1000,
        expired: false
    };

    globe.pointsData([ownIpPoint]);
    console.log("Own IP point added:", myIpCoords);

    const showArcsCheckbox = document.getElementById('showArcs');
    let showArcs = JSON.parse(localStorage.getItem('showArcs')) ?? true;

    if (showArcsCheckbox) {
        showArcsCheckbox.checked = showArcs;
        showArcsCheckbox.addEventListener('change', () => {
            showArcs = showArcsCheckbox.checked;
            localStorage.setItem('showArcs', JSON.stringify(showArcs));
            updateGlobeData();
            console.log(`Lines ${showArcs ? 'shown' : 'hidden'}`);
        });
    } else {
        console.warn('Checkbox with ID "showArcs" not found.');
    }

    let countriesData = [];
    const showBordersCheckbox = document.getElementById('showBorders');
    let showBorders = JSON.parse(localStorage.getItem('showBorders')) ?? true;

    if (showBordersCheckbox) {
        showBordersCheckbox.checked = showBorders;
    } else {
        console.warn('Checkbox with ID "showBorders" not found.');
    }

    fetch('https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson')
        .then(res => res.json())
        .then(countries => {
            countriesData = countries.features;
            if (showBorders) {
                globe.polygonsData(countriesData)
                    .polygonCapColor(() => 'rgba(255, 255, 255, 0.1)')
                    .polygonSideColor(() => 'rgba(255, 255, 255, 0.1)')
                    .polygonStrokeColor(() => '#006100');
            }
            console.log("Country borders loaded");
        })
        .catch(err => console.error('Error loading country borders:', err));

    const menuButton = document.getElementById('menuButton');
    const sidebar = document.getElementById('sidebar');

    menuButton.addEventListener('click', () => {
        const isSidebarOpen = sidebar.classList.contains('open');
        if (isSidebarOpen) {
            sidebar.classList.remove('open');
            console.log('Sidebar closed');
        } else {
            sidebar.classList.add('open');
            console.log('Sidebar opened');
        }
    });

    if (showBordersCheckbox) {
        showBordersCheckbox.addEventListener('change', () => {
            showBorders = showBordersCheckbox.checked;
            localStorage.setItem('showBorders', JSON.stringify(showBorders));
            if (showBorders) {
                globe.polygonsData(countriesData);
            } else {
                globe.polygonsData([]);
            }
            console.log(`Country borders ${showBorders ? 'shown' : 'hidden'}`);
        });
    }

    const centerOwnLocationButton = document.getElementById('centerOwnLocation');
    centerOwnLocationButton.classList.add('toggle-button');
    centerOwnLocationButton.addEventListener('click', () => {
        globe.pointOfView({
            lat: myIpCoords.lat,
            lng: myIpCoords.lng,
            altitude: 2.5
        }, 1000);
        console.log(`Centering on own location: lat: ${myIpCoords.lat}, lng: ${myIpCoords.lng}`);
    });
    console.log(`Centering on own location: lat: ${myIpCoords.lat}, lng: ${myIpCoords.lng}`);

    let isInternalNetworkCollapsed = localStorage.getItem('isInternalNetworkCollapsed') !== null ? JSON.parse(localStorage.getItem('isInternalNetworkCollapsed')) : false;
    const internalNetworkList = document.getElementById('internalNetworkList');
    if (isInternalNetworkCollapsed) {
        internalNetworkList.classList.add('collapsed');
    }

    let isActiveConnectionsCollapsed = localStorage.getItem('isActiveConnectionsCollapsed') !== null ? JSON.parse(localStorage.getItem('isActiveConnectionsCollapsed')) : false;
    if (isActiveConnectionsCollapsed) {
        activeConnectionsList.classList.add('collapsed');
    }

    let showLocalNetwork = true;
    let showExternalNetwork = true;
    let showTCPOnly = false;
    let showAllUDPPackets = false;
    let isInternalSearchActive = true;

    const toggleInternalNetworkButton = document.getElementById('toggleInternalNetwork');
    toggleInternalNetworkButton.textContent = isInternalNetworkCollapsed ? '▼' : '▲';
    toggleInternalNetworkButton.title = isInternalNetworkCollapsed ? 'Show internal network packets' : 'Hide internal network packets';
    toggleInternalNetworkButton.addEventListener('click', () => {
        isInternalNetworkCollapsed = !isInternalNetworkCollapsed;
        localStorage.setItem('isInternalNetworkCollapsed', JSON.stringify(isInternalNetworkCollapsed));
        toggleInternalNetworkButton.textContent = isInternalNetworkCollapsed ? '▼' : '▲';
        toggleInternalNetworkButton.title = isInternalNetworkCollapsed ? 'Show internal network packets' : 'Hide internal network packets';
        internalNetworkList.classList.toggle('collapsed', isInternalNetworkCollapsed);
        console.log(`Internal network packets ${isInternalNetworkCollapsed ? 'hidden' : 'shown'}`);
    });

    const toggleActiveConnectionsButton = document.getElementById('toggleActiveConnections');
    toggleActiveConnectionsButton.textContent = isActiveConnectionsCollapsed ? '▼' : '▲';
    toggleActiveConnectionsButton.title = isActiveConnectionsCollapsed ? 'Show active connections' : 'Hide active connections';
    toggleActiveConnectionsButton.replaceWith(toggleActiveConnectionsButton.cloneNode(true));
    const newToggleActiveConnectionsButton = document.getElementById('toggleActiveConnections');

    newToggleActiveConnectionsButton.addEventListener('click', () => {
        isActiveConnectionsCollapsed = !isActiveConnectionsCollapsed;
        localStorage.setItem('isActiveConnectionsCollapsed', JSON.stringify(isActiveConnectionsCollapsed));
        newToggleActiveConnectionsButton.textContent = isActiveConnectionsCollapsed ? '▼' : '▲';
        newToggleActiveConnectionsButton.title = isActiveConnectionsCollapsed ? 'Show active connections' : 'Hide active connections';
        activeConnectionsList.classList.toggle('collapsed', isActiveConnectionsCollapsed);

        if (!isActiveConnectionsCollapsed) {
            const viewportHeight = window.innerHeight;
            activeConnectionsList.style.height = `${viewportHeight * 0.5}px`;
        } else {
            activeConnectionsList.style.height = '40px';
        }

        console.log(`Active connections ${isActiveConnectionsCollapsed ? 'hidden' : 'shown'}`);
    });

    const toggleLocalNetworkButton = document.getElementById('toggleLocalNetwork');
    toggleLocalNetworkButton.classList.add('toggle-button');
    toggleLocalNetworkButton.textContent = showLocalNetwork ? '🏠' : '🚪';
    toggleLocalNetworkButton.title = showLocalNetwork ? 'Show local network' : 'Hide local network';

    let debounceTimer;
    toggleLocalNetworkButton.addEventListener('click', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            showLocalNetwork = !showLocalNetwork;
            toggleLocalNetworkButton.textContent = showLocalNetwork ? '🏠' : '🚪';
            toggleLocalNetworkButton.title = showLocalNetwork ? 'Show local network' : 'Hide local network';
            console.log(`Local network ${showLocalNetwork ? 'shown' : 'hidden'}`);
            socket.emit('set_local_network', { showLocalNetwork: showLocalNetwork });
            updateConnectionsList();
            updateInternalNetworkList();
            updateGlobeData();
        }, 300);
    });

    const toggleExternalNetworkButton = document.getElementById('toggleExternalNetwork');
    toggleExternalNetworkButton.classList.add('toggle-button');
    toggleExternalNetworkButton.textContent = showExternalNetwork ? '🌎' : '❌';
    toggleExternalNetworkButton.title = showExternalNetwork ? 'Show external network' : 'Hide external network';
    toggleExternalNetworkButton.addEventListener('click', () => {
        showExternalNetwork = !showExternalNetwork;
        toggleExternalNetworkButton.textContent = showExternalNetwork ? '🌎' : '❌';
        toggleExternalNetworkButton.title = showExternalNetwork ? 'Show external network' : 'Hide external network';
        console.log(`External network ${showExternalNetwork ? 'shown' : 'hidden'}`);
        socket.emit('set_external_network', { showExternalNetwork: showExternalNetwork });
        updateConnectionsList();
        updateInternalNetworkList();
        updateGlobeData();
    });

    const toggleTCPOnlyButton = document.getElementById('toggleTCPOnly');
    toggleTCPOnlyButton.classList.add('toggle-button');
    toggleTCPOnlyButton.textContent = showTCPOnly ? '🔒' : '🌐';
    toggleTCPOnlyButton.title = showTCPOnly ? 'Show TCP connections only' : 'Show all protocols';
    toggleTCPOnlyButton.addEventListener('click', () => {
        showTCPOnly = !showTCPOnly;
        toggleTCPOnlyButton.textContent = showTCPOnly ? '🔒' : '🌐';
        toggleTCPOnlyButton.title = showTCPOnly ? 'Show TCP connections only' : 'Show all protocols';
        console.log(`TCP-only ${showTCPOnly ? 'enabled' : 'disabled'}`);
        socket.emit('set_tcp_only', { showTCPOnly: showTCPOnly });
        updateConnectionsList();
        updateInternalNetworkList();
        updateGlobeData();
    });

    const toggleAllUDPPacketsButton = document.getElementById('toggleAllUDPPackets');
    toggleAllUDPPacketsButton.classList.add('toggle-button');
    toggleAllUDPPacketsButton.textContent = showAllUDPPackets ? '📤' : '📥';
    toggleAllUDPPacketsButton.title = showAllUDPPackets ? 'Show all UDP packets' : 'Show filtered UDP packets';
    toggleAllUDPPacketsButton.addEventListener('click', () => {
        showAllUDPPackets = !showAllUDPPackets;
        toggleAllUDPPacketsButton.textContent = showAllUDPPackets ? '📤' : '📥';
        toggleAllUDPPacketsButton.title = showAllUDPPackets ? 'Show all UDP packets' : 'Show filtered UDP packets';
        console.log(`All UDP packets ${showAllUDPPackets ? 'shown' : 'filtered'}`);
        socket.emit('set_udp_filter', { showAllUDPPackets: showAllUDPPackets });
        updateConnectionsList();
        updateInternalNetworkList();
        updateGlobeData();
    });

    const searchInternalPacketsCheckbox = document.getElementById('searchInternalPackets');
    if (searchInternalPacketsCheckbox) {
        searchInternalPacketsCheckbox.checked = isInternalSearchActive;
        searchInternalPacketsCheckbox.addEventListener('change', () => {
            isInternalSearchActive = searchInternalPacketsCheckbox.checked;
            console.log(`Internal network packet search ${isInternalSearchActive ? 'enabled' : 'disabled'}`);
            socket.emit('set_internal_search', { isInternalSearchActive: isInternalSearchActive });
            updateConnectionsList();
            updateInternalNetworkList();
            updateGlobeData();
        });
    } else {
        console.warn('Checkbox with ID "searchInternalPackets" not found. Internal search remains enabled.');
    }

    const points = {};
    const arcs = {};
    const internalPackets = {};
    const pinnedIPs = {};
    const EXPIRATION_SECONDS = 60;
    const INTERNAL_EXPIRATION_SECONDS = 600;
    const MAX_POINTS = 1000;
    const MAX_INTERNAL_PACKETS = 500;

    function updateConnectionsList() {
        const connectionsList = document.getElementById('connectionsList');
        const connectionCountElement = document.getElementById('connectionCount');
        const fragment = document.createDocumentFragment();

        const allPoints = Object.values(points);
        const filteredPoints = allPoints.filter(p =>
            !p.expired &&
            (showTCPOnly ? p.protocol === 'TCP' : true) &&
            ((showLocalNetwork && isLocalNetwork(p.ip, p.org)) ||
            (showExternalNetwork && !isLocalNetwork(p.ip, p.org)))
        );

        const tcpCount = filteredPoints.filter(p => p.protocol === 'TCP').length;
        const udpCount = filteredPoints.filter(p => p.protocol === 'UDP').length;
        connectionCountElement.textContent = `${filteredPoints.length} connections (TCP: ${tcpCount}, UDP: ${udpCount})`;

        const sortedPoints = filteredPoints.sort((a, b) => {
            const isPinnedA = !!pinnedIPs[a.ip];
            const isPinnedB = !!pinnedIPs[b.ip];
            if (isPinnedA !== isPinnedB) return isPinnedB - isPinnedA;
            return b.last_seen - a.last_seen;
        });

        sortedPoints.forEach(point => {
            const li = document.createElement('li');
            li.style.display = 'flex';
            li.style.justifyContent = 'space-between';
            li.style.alignItems = 'center';
            li.style.padding = '5px';
            li.style.borderBottom = '1px solid #444';
            li.style.cursor = 'pointer';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'pin-checkbox';
            checkbox.checked = !!pinnedIPs[point.ip];
            checkbox.addEventListener('change', () => {
                const isPinned = checkbox.checked;
                socket.emit('pin_ip', { ip: point.ip, isPinned: isPinned });
                console.log(`IP ${point.ip} ${isPinned ? 'pinned' : 'unpinned'}`);
            });

            const textSpan = document.createElement('span');
            textSpan.innerHTML = `
                ${point.ip || 'N/A'} (${point.os || 'Unknown'}) - ${point.country || 'N/A'} - ${point.org || 'N/A'}
                (${point.protocol || 'N/A'}, In: ${point.incoming_count || 0}, Out: ${point.outgoing_count || 0})
            `;
            textSpan.style.fontSize = '10px';
            textSpan.style.lineHeight = '1.4';

            const resetButton = document.createElement('button');
            resetButton.textContent = 'Reset';
            resetButton.style.marginLeft = '10px';
            resetButton.style.padding = '5px';
            resetButton.style.background = '#555';
            resetButton.style.color = 'white';
            resetButton.style.border = 'none';
            resetButton.style.borderRadius = '3px';
            resetButton.style.cursor = 'pointer';
            resetButton.addEventListener('click', () => {
                point.incoming_count = 0;
                point.outgoing_count = 0;
                point.packet_count = 0;
                updateConnectionsList();
                console.log(`Packets for IP ${point.ip} have been reset.`);
            });

            const circle = document.createElement('div');
            circle.style.width = '10px';
            circle.style.height = '10px';
            circle.style.borderRadius = '50%';
            circle.style.background = getCircleColor(point.threat_level);
            circle.style.marginRight = '10px';

            li.addEventListener('click', (e) => {
                if (e.target !== checkbox && e.target !== resetButton) {
                    showDataList(point);
                    if (isValidCoord(point.lat, point.lng)) {
                        globe.pointOfView({
                            lat: point.lat,
                            lng: point.lng,
                            altitude: 2.5
                        }, 1000);
                        console.log(`Centering on IP: ${point.ip}, lat: ${point.lat}, lng: ${point.lng}`);
                    }
                }
            });

            li.appendChild(circle);
            li.appendChild(checkbox);
            li.appendChild(textSpan);
            li.appendChild(resetButton);
            fragment.appendChild(li);
        });

        connectionsList.innerHTML = '';
        connectionsList.appendChild(fragment);
    }

    function updateInternalNetworkList() {
        const internalPacketsList = document.getElementById('internalPacketsList');
        const internalConnectionCountElement = document.getElementById('internalConnectionCount');
        const fragment = document.createDocumentFragment();

        const filteredPackets = Object.values(internalPackets).filter(p =>
            !p.expired &&
            isLocalNetwork(p.ip, p.org) &&
            (showTCPOnly ? p.protocol === 'TCP' : true) &&
            (isInternalSearchActive || pinnedIPs[p.ip])
        );

        const tcpCount = filteredPackets.filter(p => p.protocol === 'TCP').length;
        const udpCount = filteredPackets.filter(p => p.protocol === 'UDP').length;
        internalConnectionCountElement.textContent = `${filteredPackets.length} connections (TCP: ${tcpCount}, UDP: ${udpCount})`;

        const sortedPackets = filteredPackets.sort((a, b) => {
            if (a.incoming_count !== b.incoming_count) return b.incoming_count - a.incoming_count;
            return b.outgoing_count - a.outgoing_count;
        });

        sortedPackets.forEach(packet => {
            const li = document.createElement('li');
            li.style.display = 'flex';
            li.style.justifyContent = 'space-between';
            li.style.alignItems = 'center';
            li.style.padding = '5px';
            li.style.borderBottom = '1px solid #444';
            li.style.cursor = 'pointer';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'pin-checkbox';
            checkbox.checked = !!pinnedIPs[packet.ip];
            checkbox.addEventListener('change', () => {
                const isPinned = checkbox.checked;
                socket.emit('pin_ip', { ip: packet.ip, isPinned: isPinned });
                console.log(`IP ${packet.ip} ${isPinned ? 'pinned' : 'unpinned'}`);
            });

            const textSpan = document.createElement('span');
            textSpan.innerHTML = `
                ${packet.ip || 'N/A'} (${packet.os || 'Unknown'}) - ${packet.country || 'N/A'} - ${packet.org || 'N/A'}
                (${packet.protocol || 'N/A'}, In: ${packet.incoming_count || 0}, Out: ${packet.outgoing_count || 0})
            `;
            textSpan.style.fontSize = '10px';
            textSpan.style.lineHeight = '1.4';

            const resetButton = document.createElement('button');
            resetButton.textContent = 'Reset';
            resetButton.style.marginLeft = '10px';
            resetButton.style.padding = '5px';
            resetButton.style.background = '#555';
            resetButton.style.color = 'white';
            resetButton.style.border = 'none';
            resetButton.style.borderRadius = '3px';
            resetButton.style.cursor = 'pointer';
            resetButton.addEventListener('click', () => {
                packet.incoming_count = 0;
                packet.outgoing_count = 0;
                packet.packet_count = 0;
                updateInternalNetworkList();
                console.log(`Packets for IP ${packet.ip} have been reset.`);
            });

            const circle = document.createElement('div');
            circle.style.width = '10px';
            circle.style.height = '10px';
            circle.style.borderRadius = '50%';
            circle.style.background = getCircleColor(packet.threat_level);
            circle.style.marginRight = '10px';

            li.addEventListener('click', (e) => {
                if (e.target !== checkbox && e.target !== resetButton) {
                    showDataList(packet);
                    if (isValidCoord(packet.lat, packet.lng)) {
                        globe.pointOfView({
                            lat: packet.lat,
                            lng: packet.lng,
                            altitude: 2.5
                        }, 1000);
                        console.log(`Centering on IP: ${packet.ip}, lat: ${packet.lat}, lng: ${packet.lng}`);
                    }
                }
            });

            li.appendChild(circle);
            li.appendChild(checkbox);
            li.appendChild(textSpan);
            li.appendChild(resetButton);
            fragment.appendChild(li);
        });

        internalPacketsList.innerHTML = '';
        internalPacketsList.appendChild(fragment);
    }

    function showDataList(packet) {
        dataList.style.display = 'block';
        dataList.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between;">
                <h3>IP: ${packet.ip || 'N/A'}</h3>
                <button id="closeDataList" title="Close">✖</button>
            </div>
            <ul>
                <li><strong>Hostname:</strong> ${packet.hostname || 'Unknown'}</li>
                <li><strong>OS:</strong> ${packet.os || 'Unknown'}</li>
                <li><strong>MAC Address:</strong> ${packet.mac || 'N/A'}</li>
                <li><strong>Vendor:</strong> ${packet.vendor || 'Unknown'}</li>
                <li><strong>City:</strong> ${packet.city || 'N/A'}</li>
                <li><strong>Country:</strong> ${packet.country || 'N/A'}</li>
                <li><strong>Region:</strong> ${packet.region || 'N/A'}</li>
                <li><strong>Organization:</strong> ${packet.org || 'N/A'}</li>
                <li><strong>Protocol:</strong> ${packet.protocol || 'N/A'}</li>
                <li><strong>Source Port:</strong> ${packet.src_port || 'N/A'}</li>
                <li><strong>Dest Port:</strong> ${packet.dst_port || 'N/A'}</li>
                <li><strong>Last Seen:</strong> ${packet.last_seen ? new Date(packet.last_seen * 1000).toLocaleString() : 'N/A'}</li>
                <li><strong>Incoming Packets:</strong> ${packet.incoming_count || 0}</li>
                <li><strong>Outgoing Packets:</strong> ${packet.outgoing_count || 0}</li>
                <li><strong>Total Packets:</strong> ${packet.packet_count || 0}</li>
                <li><strong>Threat Level:</strong> ${packet.threat_level || 'No Threat'}</li>
            </ul>
        `;
        document.getElementById('closeDataList').addEventListener('click', () => {
            dataList.style.display = 'none';
        });
    }

    function updateGlobeData() {
        const filteredPoints = Object.values(points).filter(p =>
            !p.expired &&
            (showTCPOnly ? p.protocol === 'TCP' : true) &&
            ((showLocalNetwork && isLocalNetwork(p.ip, p.org)) ||
             (showExternalNetwork && !isLocalNetwork(p.ip, p.org)))
        );
        if (isValidCoord(myIpCoords.lat, myIpCoords.lng)) {
            filteredPoints.push(ownIpPoint);
        }
        globe.pointsData(filteredPoints);

        if (showArcs) {
            globe.arcsData(Object.values(arcs).filter(a =>
                !a.expired &&
                (showTCPOnly ? a.protocol === 'TCP' : true) &&
                ((showLocalNetwork && isLocalNetwork(a.ip, a.org)) ||
                 (showExternalNetwork && !isLocalNetwork(a.ip, a.org)))
            ));
        } else {
            globe.arcsData([]);
        }
    }

    socket.on('connect', () => {
        console.log('Socket.IO connected, SID:', socket.id);
        connectionStatus.textContent = 'Connected';
        connectionStatus.style.background = 'rgba(0, 128, 0, 0.8)';
        socket.emit('set_internal_search', { isInternalSearchActive: isInternalSearchActive });
        socket.emit('request_initial_data');
    });

    socket.on('disconnect', () => {
        console.warn('Socket.IO connection lost');
        connectionStatus.textContent = 'Connection lost';
        connectionStatus.style.background = 'rgba(255, 0, 0, 0.8)';
    });

    socket.on('connect_error', (error) => {
        console.error('Socket.IO connection error:', error);
        connectionStatus.textContent = 'Connection error';
        connectionStatus.style.background = 'rgba(255, 0, 0, 0.8)';
    });

    socket.on('reconnect', (attempt) => {
        console.log('Socket.IO reconnected after', attempt, 'attempts');
        connectionStatus.textContent = 'Connected';
        connectionStatus.style.background = 'rgba(0, 128, 0, 0.8)';
        socket.emit('request_initial_data');
    });

    socket.on('heartbeat', (data) => {
        console.log('Heartbeat received:', data.timestamp, 'Active Clients:', data.active_clients);
    });

    socket.on('ip_update', (data) => {
        console.log('Received data:', data);
        if (!data.ip) {
            console.warn("IP missing in data:", data);
            return;
        }
        try {
            if (!isValidCoord(data.lat, data.lon)) {
                console.warn("Invalid coordinates for IP:", data.ip, "lat:", data.lat, "lon:", data.lon);
                return;
            }
            if (data.lat === 0 && data.lon === 0 && data.org !== 'Local Network') return;

            console.log(`Received ip_update: IP=${data.ip}, Local=${isLocalNetwork(data.ip, data.org)}, InternalSearchActive=${isInternalSearchActive}, Incoming: ${data.incoming_count}, Outgoing: ${data.outgoing_count}, Protocol: ${data.protocol}, Last Seen: ${new Date(data.last_seen * 1000).toLocaleString()}, Hostname: ${data.hostname || 'Unknown'}, OS: ${data.os || 'Unknown'}`);

            const ip = data.ip;
            points[ip] = {
                ip: data.ip,
                lat: data.lat,
                lng: data.lon,
                label: `${data.hostname || data.ip} (${data.os || 'Unknown'})`,
                city: data.city,
                country: data.country,
                region: data.region,
                org: data.org,
                protocol: data.protocol,
                src_port: data.src_port,
                dst_port: data.dst_port,
                incoming_count: data.incoming_count || 0,
                outgoing_count: data.outgoing_count || 0,
                color: getCircleColor(data.threat_level),
                last_seen: data.last_seen,
                mac: data.mac,
                vendor: data.vendor,
                packet_count: data.packet_count || 0,
                hostname: data.hostname || 'Unknown',
                os: data.os || 'Unknown',
                threat_level: data.threat_level || 'No Threat',
                expired: false
            };

            arcs[ip] = {
                startLat: data.lat,
                startLng: data.lon,
                endLat: myIpCoords.lat,
                endLng: myIpCoords.lng,
                ip: data.ip,
                city: data.city,
                country: data.country,
                org: data.org,
                protocol: data.protocol,
                incoming_count: data.incoming_count || 0,
                outgoing_count: data.outgoing_count || 0,
                color: (data.city === 'Unknown' || data.country === 'Unknown' || data.org === 'Not available') ? '#FFFFFF' : '#FF0000',
                last_seen: data.last_seen,
                packet_count: data.packet_count || 0,
                hostname: data.hostname || 'Unknown',
                os: data.os || 'Unknown',
                expired: false
            };

            if (isLocalNetwork(data.ip, data.org) && (isInternalSearchActive || pinnedIPs[data.ip])) {
                internalPackets[ip] = {
                    ip: data.ip,
                    lat: data.lat,
                    lng: data.lon,
                    city: data.city,
                    country: data.country,
                    region: data.region,
                    org: data.org,
                    protocol: data.protocol,
                    src_port: data.src_port,
                    dst_port: data.dst_port,
                    incoming_count: data.incoming_count || 0,
                    outgoing_count: data.outgoing_count || 0,
                    last_seen: data.last_seen,
                    mac: data.mac,
                    vendor: data.vendor,
                    packet_count: data.packet_count || 0,
                    hostname: data.hostname || 'Unknown',
                    os: data.os || 'Unknown',
                    expired: false
                };
            }

            if (Object.keys(points).length > MAX_POINTS) {
                const oldestIp = Object.keys(points)
                    .filter(ip => !pinnedIPs[ip] && ip !== 'Your IP')
                    .sort((a, b) => points[a].last_seen - points[b].last_seen)[0];
                if (oldestIp) {
                    delete points[oldestIp];
                    delete arcs[oldestIp];
                }
            }

            if (Object.keys(internalPackets).length > MAX_INTERNAL_PACKETS) {
                const oldestIp = Object.keys(internalPackets)
                    .filter(ip => !pinnedIPs[ip])
                    .sort((a, b) => internalPackets[a].last_seen - internalPackets[b].last_seen)[0];
                if (oldestIp) {
                    delete internalPackets[oldestIp];
                }
            }

            updateGlobeData();
            updateConnectionsList();
            updateInternalNetworkList();
            console.log("IP point and arc updated:", data.ip);
        } catch (e) {
            console.error('Fehler beim Parsen der Socket.IO-Nachricht:', e);
        }
    });

    socket.on('ip_pinned_update', (data) => {
        const { ip, isPinned, packet_count } = data;
        console.log(`Received ip_pinned_update for IP ${ip}, isPinned: ${isPinned}, packet_count: ${packet_count}`);
        if (points[ip]) {
            points[ip].packet_count = packet_count;
        }
        if (arcs[ip]) {
            arcs[ip].packet_count = packet_count;
        }
        if (internalPackets[ip]) {
            internalPackets[ip].packet_count = packet_count;
        }
        pinnedIPs[ip] = isPinned;
        updateConnectionsList();
        updateInternalNetworkList();
        updateGlobeData();
    });

    socket.on('settings_update', (data) => {
        console.log('Einstellungen aktualisiert:', data);
        if (data.is_internal_search_active !== undefined) {
            isInternalSearchActive = data.is_internal_search_active;
            if (searchInternalPacketsCheckbox) {
                searchInternalPacketsCheckbox.checked = isInternalSearchActive;
            }
        }
        if (data.show_all_udp_packets !== undefined) {
            showAllUDPPackets = data.show_all_udp_packets;
            toggleAllUDPPacketsButton.textContent = showAllUDPPackets ? '📶' : '📻';
            toggleAllUDPPacketsButton.title = showAllUDPPackets ? 'Nur gefilterte UDP-Pakete anzeigen' : 'Show all UDP packets';
        }
        if (data.show_local_network !== undefined) {
            showLocalNetwork = data.show_local_network;
            toggleLocalNetworkButton.textContent = showLocalNetwork ? '🌐' : '🌍';
            toggleLocalNetworkButton.title = showLocalNetwork ? 'Hide local network' : 'Lokales Netzwerk einblenden';
        }
        if (data.show_external_network !== undefined) {
            showExternalNetwork = data.show_external_network;
            toggleExternalNetworkButton.textContent = showExternalNetwork ? '🔗' : '🔌';
            toggleExternalNetworkButton.title = showExternalNetwork ? 'Hide external network' : 'Externes Netzwerk einblenden';
        }
        if (data.show_tcp_only !== undefined) {
            showTCPOnly = data.show_tcp_only;
            toggleTCPOnlyButton.textContent = showTCPOnly ? '📡' : '📶';
            toggleTCPOnlyButton.title = showTCPOnly ? 'Show all protocols' : 'Show TCP connections only';
        }
        updateConnectionsList();
        updateInternalNetworkList();
        updateGlobeData();
    });

    socket.on('packet_count_reset', (data) => {
        const { ip } = data;
        const point = points[ip];
        if (point) {
            point.incoming_count = 0;
            point.outgoing_count = 0;
            point.packet_count = 0;
            updateConnectionsList();
            updateInternalNetworkList();
            updateGlobeData();
            console.log(`Pakete für IP ${ip} wurden zurückgesetzt (synchronisiert).`);
        }
    });

    socket.on('pinned_ips_update', (data) => {
        console.log('Received pinned_ips_update:', data);
        for (const ip in data) {
            pinnedIPs[ip] = data[ip].isPinned;
            if (points[ip]) {
                points[ip].packet_count = data[ip].packet_count;
            }
            if (arcs[ip]) {
                arcs[ip].packet_count = data[ip].packet_count;
            }
            if (internalPackets[ip]) {
                internalPackets[ip].packet_count = data[ip].packet_count;
            }
        }
        updateConnectionsList();
        updateInternalNetworkList();
        updateGlobeData();
    });

    setInterval(() => {
        const now = Date.now() / 1000;
        for (const ip in points) {
            if (!pinnedIPs[ip] && ip !== 'Your IP' && now - points[ip].last_seen > EXPIRATION_SECONDS) {
                points[ip].expired = true;
                if (arcs[ip]) {
                    arcs[ip].expired = true;
                }
                console.log("IP-Punkt und Arc entfernt:", ip);
            }
        }
        let hasChanges = false;
        for (const ip in internalPackets) {
            if (!pinnedIPs[ip] && now - internalPackets[ip].last_seen > INTERNAL_EXPIRATION_SECONDS) {
                internalPackets[ip].expired = true;
                console.log("Internes Netzwerkpaket entfernt:", ip);
                hasChanges = true;
            }
        }
        if (hasChanges) {
            updateGlobeData();
            updateConnectionsList();
            updateInternalNetworkList();
        }
    }, 1000);
}

function scheduleExpiration(ip, expirationTime) {
    setTimeout(() => {
        if (!pinnedIPs[ip] && internalPackets[ip]) {
            internalPackets[ip].expired = true;
            console.log("Internes Netzwerkpaket entfernt:", ip);
            updateInternalNetworkList();
        }
    }, expirationTime * 1000);
}