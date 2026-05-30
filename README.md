# ConnectSpoofer
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?logo=windows)
![License](https://img.shields.io/github/license/arn-c0de/ConnectSpoofer?color=green)
![Network](https://img.shields.io/badge/Network-Monitoring-critical?logo=wireshark)
![Map](https://img.shields.io/badge/Visualization-3D%20Globe-blueviolet?logo=googleearth)
![Backend](https://img.shields.io/badge/Backend-Flask-black?logo=flask)


![ConnectSpoofer Screenshot](images/Connectspoofer-link.png)

A real-time network monitoring and visualization tool that analyzes network traffic and displays connections on an interactive 3D globe.

## Features

- **Geo-Visualization** - Displays network connections on an interactive world map
- **Packet Sniffing** - Captures TCP, UDP, and ICMP packets in real-time
- **Local Network** - Detects and visualizes devices on the local network (mDNS)
- **Threat Detection** - Integrated threat intelligence (FireHOL blocklists)
- **Live Statistics** - Real-time network statistics and connection analysis
- **IP Pinning** - Pin important IPs and track them separately
- **Flexible Filtering** - TCP/UDP filters, local/external network toggle

## Platform Support

Supports **Windows**, **Linux**, and **macOS**.

- **Windows**: Run `start.bat` (requests admin rights automatically)
- **Linux/macOS**: Run `./run.sh` (requires root/sudo for packet sniffing)

## Requirements

- **Python**: 3.8+
- **Privileges**: Administrator/root rights (required for packet sniffing)
- **Windows**: Npcap or WinPcap

## Installation

### 1. Install Npcap (Windows only)
```bash
# Download and install from: https://npcap.com/
```

### 2. Clone the repository
```bash
git clone https://github.com/arn-c0de/GDEF-Connect-Spoofer.git
cd GDEF-Connect-Spoofer
```

### 3. Start
```bash
# Windows (run as administrator):
start.bat

# Linux/macOS:
sudo ./run.sh install
sudo ./run.sh start
```

The launcher script automatically:
- Installs required system packages where a supported package manager is available
- Creates a virtual environment (venv)
- Installs all dependencies from `requirements.txt`
- Prompts for interface selection on first start
- Generates all configuration files on first run
- Starts the application in the background

### Linux/macOS service commands
```bash
sudo ./run.sh install   # install dependencies and configure the interface
sudo ./run.sh start     # start in the background
sudo ./run.sh stop      # stop the running app safely
sudo ./run.sh restart   # restart
sudo ./run.sh status    # show running/stopped state
sudo ./run.sh logs      # follow app.log
```

By default the web UI binds to `127.0.0.1:8000`. To expose it on a trusted network:
```bash
sudo APP_HOST=0.0.0.0 SOCKETIO_CORS_ORIGINS=http://YOUR-LAN-IP:8000 ./run.sh restart
```

## Usage

1. **Start with admin/root privileges**
2. **Select a network interface**: Choose an interface from the list on first start
3. **Open your browser**: Navigate to `http://localhost:8000`
4. **Monitor network traffic**: IPs appear on the globe in real-time

### Re-select interface
Run `sudo RESELECT_INTERFACE=1 ./run.sh start`.

## Tech Stack

- **Backend**: Python 3, Flask, Flask-SocketIO
- **Packet Sniffing**: Scapy
- **Frontend**: HTML5, JavaScript, Three.js, Globe.gl
- **Database**: SQLite3
- **Service Discovery**: Zeroconf (mDNS)

## Configuration

Configuration files are generated automatically on first start in the `database/` directory:

- `backend_conf.json` - Network interface selection
- `trusted_organisations.json` - Organization classification (trusted, suspicious, dangerous)

## Project Structure

```
ConnectSpoofer/
├── app.py                           # Main application (Flask server, packet sniffing)
├── start.bat                        # Windows launcher with auto-setup
├── run.sh                           # Linux/macOS launcher with auto-setup
├── select_interface.py              # Interface selection tool
├── debug_interfaces.py              # Interface debugging tool
├── requirements.txt                 # Python dependencies
├── README.md                        # Documentation
├── database/                        # SQLite databases & configs (generated)
│   ├── backend_conf.json           # Backend configuration (generated on first start)
│   ├── trusted_organisations.json  # Trusted organizations list (generated on first start)
│   ├── geo_data.db                 # SQLite geo database (generated)
│   └── datasets/                   # GeoIP databases
│       └── *.mmdb                  # MaxMind GeoIP2 databases
├── static/                          # Frontend static assets
│   ├── globe.js                    # 3D globe visualization
│   ├── init-globe.js               # Globe initialization
│   └── styles.css                  # CSS styling
├── templates/                       # Flask HTML templates
│   └── index.html                  # Main dashboard
└── images/                          # Project images
    └── Connectspoofer-link.png     # Screenshot
```

## Security Notice

**Only use for defensive security analysis**
**Requires administrator/root privileges**
**Comply with local laws regarding network monitoring**

This tool is intended exclusively for:
- Network security analysis
- Your own networks and systems
- Educational purposes
- Penetration testing (with authorization)

## Dependencies

```
scapy>=2.7.0
requests>=2.32.5
zeroconf>=0.148.0
flask>=3.1.2
flask-socketio>=5.6.0
python-socketio>=5.16.0
```

## License

This project is intended for legal and ethical purposes only. The author assumes no responsibility for misuse.

## Troubleshooting

### "NPF not found" error
- Install Npcap: https://npcap.com/
- Enable "WinPcap API-compatible Mode" during installation

### Interface names show only NPF paths
- Press `D` in the interface menu for debug information
- Alternatively run `debug_interfaces.py`

### No administrator privileges
- `start.bat` requests admin rights automatically
- If not: Right-click -> "Run as administrator"
- Linux/macOS: Use `sudo ./run.sh`

## Author

**arn-c0de**
GitHub: [@arn-c0de](https://github.com/arn-c0de)


