import os
import json
import sys
import re

# Scapy imports für Windows-Interface-Namen
try:
    from scapy.all import get_if_list, IFACES
except ImportError:
    print("[FEHLER] Scapy ist nicht installiert!")
    input("Drücke ENTER zum Beenden...")
    sys.exit(1)

BACKEND_CONF_PATH = os.path.join("database", "backend_conf.json")

def get_friendly_interface_name(npf_name):
    """Konvertiert NPF-Device-Namen in benutzerfreundliche Namen."""
    try:
        # Extrahiere GUID aus NPF-Namen
        guid_match = re.search(r'\{([A-F0-9\-]+)\}', npf_name)

        if not guid_match:
            # Fallback für Loopback
            if "Loopback" in npf_name:
                return "Loopback"
            return npf_name

        guid = guid_match.group(1)

        # Durchsuche Scapy IFACES nach passendem Interface
        for iface_name, iface_obj in IFACES.items():
            try:
                # Prüfe ob GUID im Namen vorkommt
                if guid in str(iface_name):
                    # Hole beschreibenden Namen
                    if hasattr(iface_obj, 'description') and iface_obj.description:
                        desc = iface_obj.description
                        # Kürze lange Beschreibungen
                        if len(desc) > 50:
                            desc = desc[:47] + "..."
                        return desc
                    elif hasattr(iface_obj, 'name') and iface_obj.name:
                        return iface_obj.name

                # Prüfe auch data Attribut falls vorhanden
                if hasattr(iface_obj, 'data'):
                    data = iface_obj.data
                    if isinstance(data, dict):
                        if 'guid' in data and data['guid'] == guid:
                            if 'description' in data and data['description']:
                                desc = data['description']
                                if len(desc) > 50:
                                    desc = desc[:47] + "..."
                                return desc
                            if 'name' in data and data['name']:
                                return data['name']
            except Exception:
                continue

        # Fallback: Vereinfache NPF-Namen
        if "Loopback" in npf_name:
            return "Loopback"

        # Letzter Fallback: Zeige GUID
        return f"Interface {guid[:8]}..."

    except Exception as e:
        print(f"[DEBUG] Fehler beim Auslesen von {npf_name}: {e}")
        return npf_name

def get_interface_ip(npf_name):
    """Versucht die IP-Adresse eines Interfaces zu ermitteln."""
    try:
        # Extrahiere GUID
        guid_match = re.search(r'\{([A-F0-9\-]+)\}', npf_name)
        if not guid_match:
            return None

        guid = guid_match.group(1)

        # Durchsuche IFACES nach IP
        for iface_name, iface_obj in IFACES.items():
            if guid in str(iface_name):
                if hasattr(iface_obj, 'ip') and iface_obj.ip:
                    return iface_obj.ip
        return None
    except Exception:
        return None

def select_network_interface():
    """Zeigt verfügbare Netzwerkschnittstellen und lässt den Benutzer eine auswählen."""
    print("=" * 70)
    print("   Netzwerkschnittstellen-Auswahl")
    print("=" * 70)
    print()

    try:
        interfaces = get_if_list()

        if not interfaces:
            print("[FEHLER] Keine Netzwerkschnittstellen gefunden!")
            input("Drücke ENTER zum Beenden...")
            return False

        # Erstelle Mapping von freundlichen Namen zu NPF-Namen
        interface_mapping = {}
        interface_ips = {}
        for iface in interfaces:
            friendly_name = get_friendly_interface_name(iface)
            interface_mapping[iface] = friendly_name
            interface_ips[iface] = get_interface_ip(iface)

        print("Verfügbare Netzwerkschnittstellen:")
        print("-" * 70)
        for idx, iface in enumerate(interfaces, 1):
            friendly_name = interface_mapping[iface]
            ip_addr = interface_ips[iface]

            if ip_addr:
                print(f"{idx}. {friendly_name:<45} (IP: {ip_addr})")
            else:
                print(f"{idx}. {friendly_name}")
        print("-" * 70)
        print()
        print("[TIP] Drücke 'D' für Debug-Informationen")
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
            choice = input("Wähle eine Schnittstelle (Nummer) oder drücke ENTER für aktuelle Auswahl: ").strip()

            # Debug-Modus
            if choice.upper() == 'D':
                print("\n" + "=" * 70)
                print("DEBUG: Interface-Details")
                print("=" * 70)
                for idx, iface in enumerate(interfaces, 1):
                    print(f"\n#{idx}:")
                    print(f"  NPF-Name: {iface}")
                    print(f"  Anzeigename: {interface_mapping[iface]}")
                    print(f"  IP-Adresse: {interface_ips[iface] or 'Keine'}")

                    # Zeige IFACES Details
                    import re
                    guid_match = re.search(r'\{([A-F0-9\-]+)\}', iface)
                    if guid_match:
                        guid = guid_match.group(1)
                        for iface_name, iface_obj in IFACES.items():
                            if guid in str(iface_name):
                                print(f"  IFACES Key: {iface_name}")
                                if hasattr(iface_obj, 'description'):
                                    print(f"  Description: {iface_obj.description}")
                                if hasattr(iface_obj, 'name'):
                                    print(f"  Name: {iface_obj.name}")
                                break
                print("\n" + "=" * 70 + "\n")
                continue

            # Wenn ENTER gedrückt und aktuelle Config existiert, verwende diese
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
                    print(f"[INFO] Ausgewählt: {friendly_selected}")
                    break
                else:
                    print(f"[FEHLER] Bitte wähle eine Nummer zwischen 1 und {len(interfaces)}")
            except ValueError:
                print("[FEHLER] Ungültige Eingabe. Bitte eine Nummer eingeben.")

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
        input("Drücke ENTER zum Beenden...")
        return False

if __name__ == "__main__":
    success = select_network_interface()
    if not success:
        exit(1)
