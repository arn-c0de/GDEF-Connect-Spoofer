// static/globe/format.js
//
// Stateless formatting + small DOM helpers. No app state, no side effects
// beyond the explicit DOM nodes they create (toast/notification).

// Map of common destination ports to human-readable service names.
export const PORT_SERVICES = {
    20: 'FTP-DATA', 21: 'FTP',     22: 'SSH',      23: 'Telnet',
    25: 'SMTP',     53: 'DNS',     67: 'DHCP',     68: 'DHCP',
    80: 'HTTP',    110: 'POP3',   143: 'IMAP',    161: 'SNMP',
   443: 'HTTPS',  445: 'SMB',    587: 'SMTPTLS', 993: 'IMAPS',
   995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',  3389: 'RDP',
  5432: 'PG',    5900: 'VNC',   6379: 'Redis',  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt', 27017: 'MongoDB',
};

export function timeAgo(unixTs) {
    const secs = Math.floor(Date.now() / 1000 - unixTs);
    if (secs < 5)    return 'just now';
    if (secs < 60)   return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
}

export function formatNum(n) {
    return (n || 0).toLocaleString();
}

export function formatBytes(bytes) {
    if (bytes < 1024)       return `${bytes} B`;
    if (bytes < 1048576)    return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
    return `${(bytes / 1073741824).toFixed(1)} GB`;
}

export function truncate(str, max) {
    if (!str || str.length <= max) return str || '';
    return str.slice(0, max) + '…';
}

// Small persisted-state helpers (filters + device settings survive a reload).
export function loadJSON(key, fallback) {
    try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; }
    catch (_) { return fallback; }
}
export function saveJSON(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (_) { /* quota/full */ }
}

export function makeThreatBadge(threatLevel) {
    const raw   = (threatLevel || 'no threat').toLowerCase().trim();
    const key   = raw.replace(' ', '-');
    const labels = { 'high': 'HIGH', 'medium': 'MED', 'low': 'LOW', 'no-threat': 'OK', 'no threat': 'OK' };
    const span  = document.createElement('span');
    span.className = `threat-badge threat-${key}`;
    span.textContent = labels[raw] || labels[key] || 'OK';
    return span;
}

export function showToast(message, level = 'info', durationMs = 6000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${level}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), durationMs);
}

export function notifyHighThreat(ip, org, country) {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    new Notification('⚠ High Threat Detected', {
        body: `${ip} — ${org || 'Unknown'} (${country || 'Unknown'})`,
        tag: `threat-${ip}`,  // prevents duplicate OS notifications for the same IP
    });
}

export function escapeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;')
        .replace(/'/g,  '&#039;');
}
