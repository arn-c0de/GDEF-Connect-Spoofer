# ConnectSpoofer

Ein Echtzeit-Netzwerk-Monitoring- und Visualisierungstool für Windows, das Netzwerkverkehr analysiert und auf einer interaktiven Karte darstellt.

## Features

🌍 **Geo-Visualisierung** - Zeigt Netzwerkverbindungen auf einer interaktiven Weltkarte
🔍 **Packet Sniffing** - Erfasst TCP, UDP und ICMP-Pakete in Echtzeit
🏠 **Lokales Netzwerk** - Erkennt und visualisiert Geräte im lokalen Netzwerk (mDNS)
🛡️ **Bedrohungserkennung** - Integrierte Threat-Intelligence (FireHOL Listen)
📊 **Live-Statistiken** - Echtzeit-Netzwerkstatistiken und Verbindungsanalyse
🎯 **IP-Pinning** - Wichtige IPs pinnen und separat verfolgen
⚙️ **Flexible Filterung** - TCP/UDP Filter, Lokales/Externes Netzwerk Toggle

## Plattform-Support

⚠️ **Aktuell nur für Windows getestet und entwickelt**

Das Tool wurde auf Windows entwickelt und getestet. Theoretisch sollte es auch auf Linux/macOS funktionieren, da es auf Python basiert, jedoch sind **kleinere Anpassungen** erforderlich:
- Interface-Erkennung (aktuell Windows NPF-spezifisch)
- `start.bat` → Shell-Skript für Linux/macOS
- Admin-Rechte-Prüfung (Windows-spezifisch)

🔮 **Zukunft**: Cross-Platform-Support ist geplant und wird in zukünftigen Versionen implementiert.

## Anforderungen

- **OS**: Windows 10/11 (getestet)
- **Python**: 3.8+
- **Rechte**: Administrator-Rechte (für Packet Sniffing)
- **Dependencies**: Npcap oder WinPcap

## Installation

### 1. Npcap installieren
```bash
# Download und Installation von: https://npcap.com/
```

### 2. Repository klonen
```bash
git clone https://github.com/arn-c0de/ConnectSpoofer.git
cd ConnectSpoofer
```

### 3. Starten
```bash
# Als Administrator ausführen:
start.bat
```

Die `start.bat` erledigt automatisch:
- ✅ Erstellt virtuelles Environment (venv)
- ✅ Installiert alle Dependencies aus `requirements.txt`
- ✅ Interface-Auswahl beim ersten Start
- ✅ Startet die Anwendung

## Verwendung

1. **Als Administrator starten**: Rechtsklick auf `start.bat` → "Als Administrator ausführen"
2. **Netzwerk-Interface auswählen**: Beim ersten Start Interface aus der Liste wählen
3. **Browser öffnen**: Automatisch öffnet sich `http://localhost:8000`
4. **Netzwerkverkehr beobachten**: IPs erscheinen auf der Karte in Echtzeit

### Interface neu auswählen
Beim Start der BAT-Datei innerhalb von 5 Sekunden `I` drücken.

## Technologie-Stack

- **Backend**: Python 3, Flask, Flask-SocketIO
- **Packet Sniffing**: Scapy
- **Frontend**: HTML5, JavaScript, Leaflet.js
- **Datenbank**: SQLite3
- **Service Discovery**: Zeroconf (mDNS)

## Konfiguration

Die Konfiguration wird in `database/backend_conf.json` gespeichert:
```json
{
    "network_interface": "\\Device\\NPF_{GUID}"
}
```

## Projektstruktur

```
ConnectSpoofer/
├── app.py                           # Hauptanwendung (Flask-Server, Packet Sniffing)
├── start.bat                        # Launcher mit Auto-Setup
├── select_interface.py              # Interface-Auswahl Tool
├── debug_interfaces.py              # Interface Debug-Tool
├── requirements.txt                 # Python-Dependencies
├── backend_conf.example.json        # Beispiel Backend-Konfiguration
├── database.zip                     # Database Archiv
├── README.md                        # Dokumentation
├── database/                        # SQLite-Datenbanken & Configs
│   ├── backend_conf.json           # Backend-Konfiguration (Interface)
│   ├── geo_data.db                 # SQLite Geo-Datenbank
│   ├── geo_data.db-shm             # SQLite Shared Memory
│   ├── geo_data.db-wal             # SQLite Write-Ahead Log
│   ├── trusted_organisations.json  # Liste vertrauenswürdiger Organisationen
│   └── datasets/                   # GeoIP Datenbanken
│       ├── 1.mmdb                  # MaxMind GeoIP2 Database
│       ├── 2.mmdb                  # MaxMind GeoIP2 Database
│       └── 3.mmdb                  # MaxMind GeoIP2 Database
├── static/                          # Frontend Static Assets
│   ├── globe.js                    # 3D-Globe Visualisierung
│   ├── init-globe.js               # Globe Initialisierung
│   └── styles.css                  # CSS Styling
├── templates/                       # Flask HTML-Templates
│   └── index.html                  # Haupt-Dashboard
└── venv/                           # Virtuelles Environment (auto-erstellt)
```

## Sicherheitshinweise

⚠️ **Nur für defensive Sicherheitsanalysen verwenden**
⚠️ **Benötigt Administrator-Rechte**
⚠️ **Beachte lokale Gesetze bezüglich Netzwerk-Monitoring**

Dieses Tool ist ausschließlich für:
- Netzwerk-Sicherheitsanalysen
- Eigene Netzwerke und Systeme
- Bildungszwecke
- Penetration Testing (mit Erlaubnis)

## Dependencies

```
scapy>=2.5.0
requests>=2.31.0
zeroconf>=0.131.0
flask>=3.0.0
flask-socketio>=5.3.0
python-socketio>=5.11.0
```

## Lizenz

Dieses Projekt ist nur für legale und ethische Zwecke bestimmt. Der Autor übernimmt keine Verantwortung für Missbrauch.

## Troubleshooting

### "NPF nicht gefunden" Fehler
- Npcap installieren: https://npcap.com/
- Bei Installation "WinPcap API-compatible Mode" aktivieren

### Interface-Namen zeigen nur NPF-Pfade
- `D` im Interface-Menü drücken für Debug-Informationen
- Alternativ `debug_interfaces.py` ausführen

### Keine Administrator-Rechte
- BAT-Datei fordert automatisch Admin-Rechte an
- Falls nicht: Rechtsklick → "Als Administrator ausführen"

## Autor

**arn-c0de**
GitHub: [@arn-c0de](https://github.com/arn-c0de)

---

⭐ **Gefällt dir das Projekt? Gib einen Star!** ⭐
