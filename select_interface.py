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
    print("[ERROR] Scapy is not installed!")
    input("Press ENTER to exit...")
    sys.exit(1)

BACKEND_CONF_PATH = os.path.join("database", "backend_conf.json")

IS_WINDOWS = sys.platform == 'win32'


def get_friendly_interface_name(iface_name):
    """Returns a user-friendly name for the interface (cross-platform)."""
    if IS_WINDOWS:
        return _get_friendly_name_windows(iface_name)
    else:
        return iface_name


def _get_friendly_name_windows(npf_name):
    """Converts NPF device names to user-friendly names (Windows)."""
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
        print(f"[DEBUG] Error reading {npf_name}: {e}")
        return npf_name


def get_interface_ip(iface_name):
    """Attempts to determine the IP address of an interface (cross-platform)."""
    try:
        if IS_WINDOWS:
            return _get_ip_windows(iface_name)
        else:
            return _get_ip_unix(iface_name)
    except Exception:
        return None


def _get_ip_windows(npf_name):
    """Determine IP address via Scapy IFACES (Windows)."""
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
    """Determine IP address via socket/ioctl (Linux/macOS)."""
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
        # Fallback: try via scapy conf
        try:
            from scapy.all import get_if_addr
            addr = get_if_addr(iface_name)
            if addr and addr != '0.0.0.0':
                return addr
        except Exception:
            pass
        return None


def select_network_interface():
    """Shows available network interfaces and lets the user select one."""
    print("=" * 70)
    print("   Network Interface Selection")
    print("   System: " + platform.system() + " " + platform.release())
    print("=" * 70)
    print()

    try:
        interfaces = get_if_list()

        if not interfaces:
            print("[ERROR] No network interfaces found!")
            if not IS_WINDOWS:
                print("[TIP] Run the script with sudo/root privileges.")
            input("Press ENTER to exit...")
            return False

        # Create mapping of friendly names
        interface_mapping = {}
        interface_ips = {}
        for iface in interfaces:
            friendly_name = get_friendly_interface_name(iface)
            interface_mapping[iface] = friendly_name
            interface_ips[iface] = get_interface_ip(iface)

        print("Available network interfaces:")
        print("-" * 70)
        for idx, iface in enumerate(interfaces, 1):
            friendly_name = interface_mapping[iface]
            ip_addr = interface_ips[iface]

            # Mark likely best interface
            marker = ""
            if not IS_WINDOWS and iface.startswith(('eth', 'en', 'wl', 'wlan', 'ens', 'enp', 'wlp')) and ip_addr:
                marker = " *"

            if ip_addr:
                print(f"{idx}. {friendly_name:<45} (IP: {ip_addr}){marker}")
            else:
                print(f"{idx}. {friendly_name}")
        print("-" * 70)
        if not IS_WINDOWS:
            print("  * = recommended interface")
        print()
        print("[TIP] Press 'D' for debug information")
        print()

        # Load current configuration if available
        current_interface = None
        if os.path.exists(BACKEND_CONF_PATH):
            try:
                with open(BACKEND_CONF_PATH, "r") as f:
                    config = json.load(f)
                    current_interface = config.get("network_interface")
                    if current_interface in interfaces:
                        current_idx = interfaces.index(current_interface) + 1
                        friendly_current = interface_mapping[current_interface]
                        print(f"[INFO] Currently configured: #{current_idx} - {friendly_current}")
                        print()
            except Exception as e:
                print(f"[WARNING] Error loading configuration: {e}")
                print()

        # User selection
        while True:
            choice = input("Select an interface (number) or press ENTER for current selection: ").strip()

            # Debug mode
            if choice.upper() == 'D':
                print("\n" + "=" * 70)
                print("DEBUG: Interface Details")
                print("=" * 70)
                for idx, iface in enumerate(interfaces, 1):
                    print(f"\n#{idx}:")
                    print(f"  Interface name: {iface}")
                    print(f"  Display name:   {interface_mapping[iface]}")
                    print(f"  IP address:     {interface_ips[iface] or 'None'}")
                print("\n" + "=" * 70 + "\n")
                continue

            # If ENTER pressed and current config exists, use it
            if choice == "" and current_interface and current_interface in interfaces:
                selected_interface = current_interface
                friendly_selected = interface_mapping[selected_interface]
                print(f"[INFO] Using current configuration: {friendly_selected}")
                break

            # Validate input
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= len(interfaces):
                    selected_interface = interfaces[choice_num - 1]
                    friendly_selected = interface_mapping[selected_interface]
                    print(f"[INFO] Selected: {friendly_selected}")
                    break
                else:
                    print(f"[ERROR] Please choose a number between 1 and {len(interfaces)}")
            except ValueError:
                print("[ERROR] Invalid input. Please enter a number.")

        print()

        # Create database folder if it doesn't exist
        os.makedirs("database", exist_ok=True)

        # Save configuration
        config = {"network_interface": selected_interface}
        with open(BACKEND_CONF_PATH, "w") as f:
            json.dump(config, f, indent=4)

        print(f"[INFO] Configuration saved to: {BACKEND_CONF_PATH}")
        print()
        return True

    except Exception as e:
        print(f"[ERROR] Error during interface selection: {e}")
        input("Press ENTER to exit...")
        return False

if __name__ == "__main__":
    success = select_network_interface()
    if not success:
        exit(1)
