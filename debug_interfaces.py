"""Debug-Skript zum Anzeigen aller verfügbaren Interface-Informationen."""
import sys

try:
    from scapy.all import get_if_list, IFACES, conf
except ImportError:
    print("[FEHLER] Scapy ist nicht installiert!")
    sys.exit(1)

print("=" * 80)
print("DEBUG: Netzwerk-Interface Informationen")
print("=" * 80)
print()

# Zeige alle Interfaces von get_if_list()
print("1. Interfaces von get_if_list():")
print("-" * 80)
interfaces = get_if_list()
for idx, iface in enumerate(interfaces, 1):
    print(f"{idx}. {iface}")
print()

# Zeige alle IFACES Details
print("2. IFACES Dictionary (detailliert):")
print("-" * 80)
for iface_name, iface_obj in IFACES.items():
    print(f"\nInterface: {iface_name}")
    print(f"  Type: {type(iface_obj)}")

    # Zeige alle Attribute
    attrs = dir(iface_obj)
    important_attrs = ['name', 'description', 'guid', 'ip', 'mac', 'network_name', 'data']

    for attr in important_attrs:
        if attr in attrs:
            try:
                value = getattr(iface_obj, attr)
                if value:
                    print(f"  {attr}: {value}")
            except Exception as e:
                print(f"  {attr}: [Fehler beim Auslesen: {e}]")

print()
print("=" * 80)
print("3. Scapy conf.iface (Standard-Interface):")
print(f"  {conf.iface}")
print("=" * 80)

input("\nDrücke ENTER zum Beenden...")
