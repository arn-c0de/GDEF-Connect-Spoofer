// static/init-globe.js
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