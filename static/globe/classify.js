// static/globe/classify.js
//
// Organisation classification loaded from the backend, plus the threat→colour
// mapping the globe and lists use. The org lists are module-private state;
// loadTrustedOrgs() refreshes them and getCircleColor() reads them.

let trustedOrgs    = [];
let suspiciousOrgs = [];
let dangerousOrgs  = [];

export async function loadTrustedOrgs() {
    try {
        const res = await fetch('/trusted_organisations');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        trustedOrgs    = data.trusted_organisations    || [];
        suspiciousOrgs = data.suspicious_organisations || [];
        dangerousOrgs  = data.dangerous_organisations  || [];
    } catch (err) {
        console.error('Could not load trusted_organisations:', err);
        // Sensible fallbacks so the globe colours still work offline.
        trustedOrgs    = ['Google LLC', 'Amazon.com, Inc.', 'Microsoft Corporation',
                          'Cloudflare, Inc.', 'Apple Inc.', 'Meta Platforms, Inc.',
                          'Akamai Technologies, Inc.'];
        suspiciousOrgs = ['Unknown ISP', 'Generic Hosting', 'Suspected Proxy Service'];
        dangerousOrgs  = ['Malware Host', 'Known Botnet', 'Dark Web Service'];
    }
}

export function getCircleColor(threatLevel, org) {
    if (org && trustedOrgs.includes(org)) return 'green';
    if (threatLevel === 'High')   return 'red';
    if (threatLevel === 'Medium') return 'orange';
    if (threatLevel === 'Low')    return 'yellow';
    return 'white';
}
