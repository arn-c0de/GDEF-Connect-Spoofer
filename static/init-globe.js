// static/init-globe.js
document.addEventListener('DOMContentLoaded', () => {
    if (window.coords) {
        initializeGlobe(window.coords);
    } else {
        console.error('window.coords is not defined');
    }
});