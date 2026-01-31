import os
import json
import sys
import re
import socket
import struct
import platform

try:
    from scapy.all import get_if_list, conf
except ImportError:
    print("[FEHLER] Scapy ist nicht installiert!")
    input("Drücke ENTER zum Beenden...")
    sys.exit(1)

BACKEND_CONF_PATH = os.path.join("database", "backend_conf.json")

IS_WINDOWS = sys.platform == 'win32'


def get_friendly_interface_name(iface_name):
    """Gibt einen benutzerfreundlichen Namen fuer das Interface zurueck (plattformuebergreifend)."""
    if IS_WINDOWS:
        return _get_friendly_name_windows(iface_name)
    else:
        return iface_name


def _get_friendly_name_windows(npf_name):
    """Konvertiert NPF-Device-Namen in benutzerfreundliche Namen (Windows)."""
    try:
        from scapy.all import IFACES
        guid_match = re.search(r'\{([A-F0-9\-]+)\}', npf_name, re.IGNORECASE)

        if not guid_match:
            if "Loopback" in npf_name:
                return "Loopback"
            return npf_name

        guid = guid_match.group(1)

        for iface_key, iface_obj in IFACES.items():
            try:
                if guid.upper() in str(iface_key).upper():
                    if hasattr(iface_obj, 'description') and iface_obj.description:
                        desc = iface_obj.description
                        if len(desc) > 50:
                            desc = desc[:47] + "..."
                        return desc
                    elif hasattr(iface_obj, 'name') and iface_obj.name:
                        return iface_obj.name
            except Exception:
                continue

        if "Loopback" in npf_name:
            return "Loopback"
        return f"Interface {guid[:8]}..."

    except Exception as e:
        print(f"[DEBUG] Fehler beim Auslesen von {npf_name}: {e}")
        return npf_name


def get_interface_ip(iface_name):
    """Versucht die IP-Adresse eines Interfaces zu ermitteln (plattformuebergreifend)."""
    try:
        if IS_WINDOWS:
            return _get_ip_windows(iface_name)
        else:
            return _get_ip_unix(iface_name)
    except Exception:
        return None


def _get_ip_windows(npf_name):
    """IP-Adresse ueber Scapy IFACES ermitteln (Windows)."""
    try:
        from scapy.all import IFACES
        guid_match = re.search(r'\{([A-F0-9\-]+)\}', npf_name, re.IGNORECASE)
        if not guid_match:
            return None
        guid = guid_match.group(1)
        for iface_key, iface_obj in IFACES.items():
            if guid.upper() in str(iface_key).upper():
                if hasattr(iface_obj, 'ip') and iface_obj.ip:
                    return iface_obj.ip
        return None
    except Exception:
        return None


def _get_ip_unix(iface_name):
    """IP-Adresse ueber Socket/ioctl ermitteln (Linux/macOS)."""
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface_name[:15].encode('utf-8'))
        )[20:24])
        s.close()
        return ip
    except Exception:
        # Fallback: versuche ueber scapy conf
        try:
            from scapy.all import get_if_addr
            addr = get_if_addr(iface_name)
            if addr and addr != '0.0.0.0':
                return addr
        except Exception:
            pass
        return None


def select_network_interface():
    """Zeigt verfuegbare Netzwerkschnittstellen und laesst den Benutzer eine auswaehlen."""
    print("=" * 70)
    print("   Netzwerkschnittstellen-Auswahl")
    print("   System: " + platform.system() + " " + platform.release())
    print("=" * 70)
    print()

    try:
        interfaces = get_if_list()

        if not interfaces:
            print("[FEHLER] Keine Netzwerkschnittstellen gefunden!")
            if not IS_WINDOWS:
                print("[TIPP] Starte das Skript mit sudo/root-Rechten.")
            input("Druecke ENTER zum Beenden...")
            return False

        # Erstelle Mapping von freundlichen Namen
        interface_mapping = {}
        interface_ips = {}
        for iface in interfaces:
            friendly_name = get_friendly_interface_name(iface)
            interface_mapping[iface] = friendly_name
            interface_ips[iface] = get_interface_ip(iface)

        print("Verfuegbare Netzwerkschnittstellen:")
        print("-" * 70)
        for idx, iface in enumerate(interfaces, 1):
            friendly_name = interface_mapping[iface]
            ip_addr = interface_ips[iface]

            # Markiere wahrscheinlich bestes Interface
            marker = ""
            if not IS_WINDOWS and iface.startswith(('eth', 'en', 'wl', 'wlan', 'ens', 'enp', 'wlp')) and ip_addr:
                marker = " *"

            if ip_addr:
                print(f"{idx}. {friendly_name:<45} (IP: {ip_addr}){marker}")
            else:
                print(f"{idx}. {friendly_name}")
        print("-" * 70)
        if not IS_WINDOWS:
            print("  * = empfohlenes Interface")
        print()
        print("[TIP] Druecke 'D' fuer Debug-Informationen")
        print()

        # Lade aktuelle Konfiguration falls vorhanden
        current_interface = None
        if os.path.exists(BACKEND_CONF_PATH):
            try:
                with open(BACKEND_CONF_PATH, "r") as f:
                    config = json.load(f)
                    current_interface = config.get("network_interface")
                    if current_interface in interfaces:
                        current_idx = interfaces.index(current_interface) + 1
                        friendly_current = interface_mapping[current_interface]
                        print(f"[INFO] Aktuell konfiguriert: #{current_idx} - {friendly_current}")
                        print()
            except Exception as e:
                print(f"[WARNUNG] Fehler beim Laden der Konfiguration: {e}")
                print()

        # Benutzerauswahl
        while True:
            choice = input("Waehle eine Schnittstelle (Nummer) oder druecke ENTER fuer aktuelle Auswahl: ").strip()

            # Debug-Modus
            if choice.upper() == 'D':
                print("\n" + "=" * 70)
                print("DEBUG: Interface-Details")
                print("=" * 70)
                for idx, iface in enumerate(interfaces, 1):
                    print(f"\n#{idx}:")
                    print(f"  Interface-Name: {iface}")
                    print(f"  Anzeigename: {interface_mapping[iface]}")
                    print(f"  IP-Adresse: {interface_ips[iface] or 'Keine'}")
                print("\n" + "=" * 70 + "\n")
                continue

            # Wenn ENTER gedrueckt und aktuelle Config existiert, verwende diese
            if choice == "" and current_interface and current_interface in interfaces:
                selected_interface = current_interface
                friendly_selected = interface_mapping[selected_interface]
                print(f"[INFO] Verwende aktuelle Konfiguration: {friendly_selected}")
                break

            # Validiere Eingabe
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= len(interfaces):
                    selected_interface = interfaces[choice_num - 1]
                    friendly_selected = interface_mapping[selected_interface]
                    print(f"[INFO] Ausgewaehlt: {friendly_selected}")
                    break
                else:
                    print(f"[FEHLER] Bitte waehle eine Nummer zwischen 1 und {len(interfaces)}")
            except ValueError:
                print("[FEHLER] Ungueltige Eingabe. Bitte eine Nummer eingeben.")

        print()

        # Erstelle database Ordner falls nicht vorhanden
        os.makedirs("database", exist_ok=True)

        # Speichere Konfiguration
        config = {"network_interface": selected_interface}
        with open(BACKEND_CONF_PATH, "w") as f:
            json.dump(config, f, indent=4)

        print(f"[INFO] Konfiguration gespeichert in: {BACKEND_CONF_PATH}")
        print()
        return True

    except Exception as e:
        print(f"[FEHLER] Fehler bei der Interface-Auswahl: {e}")
        input("Druecke ENTER zum Beenden...")
        return False

if __name__ == "__main__":
    success = select_network_interface()
    if not success:
        exit(1)
