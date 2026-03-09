import nmap
import datetime
import os
import json
from colorama import Fore, Back, Style, init
from report import generate_html, generate_history_html
from recommendations import print_recommendations, calculate_risk_score, RISK_COLORS
from cve_lookup import lookup_cve, print_cves
from sweep import network_sweep, sweep_and_scan
from history import init_db, save_scan, history_menu

init(autoreset=True)

VULN_PORTS = {
    21:   "⚠️  Unencrypted file transfer. Brute-force risk.",
    22:   "ℹ️  Secure shell. Ensure strong passwords/keys.",
    23:   "🚨 DANGER! Unencrypted remote access. Disable it!",
    25:   "⚠️  Mail server. Can be abused for spam relay.",
    53:   "ℹ️  DNS service. Risk of DNS amplification attacks.",
    80:   "⚠️  Unencrypted web server. Upgrade to HTTPS.",
    110:  "⚠️  Unencrypted mail. Credentials sent in plaintext.",
    135:  "🚨 Windows RPC. Common target for exploits.",
    139:  "🚨 Windows file sharing. Common attack vector.",
    143:  "⚠️  Unencrypted mail access.",
    443:  "✅  Encrypted web server. Keep certificates updated.",
    445:  "🚨 DANGER! EternalBlue/WannaCry target. Patch immediately!",
    1433: "🚨 Database exposed! Should not be public-facing.",
    3306: "🚨 Database exposed! Should not be public-facing.",
    3389: "🚨 Remote Desktop. High brute-force risk!",
    5900: "🚨 Remote access. Often misconfigured & unencrypted.",
    6379: "🚨 Often runs with no authentication!",
    8080: "⚠️  Alternative web port. Check for misconfigs.",
    27017:"🚨 Database exposed! Often has no auth by default!",
}

# ─── Banner ────────────────────────────────────────────────────────────────
def print_banner():
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + "        🔍 ADVANCED NMAP NETWORK SCANNER TOOL")
    print(Fore.CYAN + Style.BRIGHT + "              By: [Param]")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)

# ─── Get Targets ───────────────────────────────────────────────────────────
def get_targets():
    print(Fore.WHITE + "\nSelect target type:")
    print("  [1] Single IP          (e.g. 192.168.1.1)")
    print("  [2] Multiple IPs       (e.g. 192.168.1.1,192.168.1.2)")
    print("  [3] Subnet / Range     (e.g. 192.168.1.0/24)")
    print("  [4] Network Sweep      (find all live hosts first)")
    choice = input("\nEnter choice (1/2/3/4): ")
    if choice == "4":
        return "sweep", choice
    target = input("Enter target(s): ")
    return target, choice

# ─── Get Scan Type ─────────────────────────────────────────────────────────
def get_scan_type():
    print(Fore.WHITE + "\nSelect scan type:")
    print("  [1] Basic Scan (fast)")
    print("  [2] Service & Version Detection")
    print("  [3] OS Detection + Services (most detailed)")
    choice = input("\nEnter choice (1/2/3): ")
    options = {
        "1": ("", "Basic Scan"),
        "2": ("-sV", "Service & Version Detection"),
        "3": ("-sV -O", "OS Detection + Services"),
    }
    return options.get(choice, ("", "Basic Scan"))

# ─── Vuln Check ────────────────────────────────────────────────────────────
def check_vuln(port):
    return VULN_PORTS.get(port, None)

# ─── Show Results ──────────────────────────────────────────────────────────
def show_results(scanner, target, scan_type, txt_file):
    now   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + f"  SCAN RESULTS — {now}")
    print(Fore.CYAN + Style.BRIGHT + f"  Target: {target} | Type: {scan_type}")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    lines += ["=" * 60, f"  SCAN RESULTS — {now}", f"  Target: {target} | Type: {scan_type}", "=" * 60]

    all_open_ports = []

    for host in scanner.all_hosts():
        hostname = scanner[host].hostname()
        state    = scanner[host].state()

        print(Fore.WHITE + Style.BRIGHT + f"\n🖥️  Host     : {host}")
        print(Fore.WHITE + f"🌐 Hostname : {hostname}")
        if state == 'up':
            print(Fore.GREEN + Style.BRIGHT + f"📡 State    : {state}")
        else:
            print(Fore.RED + f"📡 State    : {state}")

        lines += [f"\nHost: {host}", f"Hostname: {hostname}", f"State: {state}"]

        for proto in scanner[host].all_protocols():
            print(Fore.BLUE + Style.BRIGHT + f"\n📂 Protocol : {proto.upper()}")
            print(Fore.BLUE + "-" * 50)
            lines += [f"\nProtocol: {proto.upper()}", "-" * 50]

            open_ports = 0

            for port in sorted(scanner[host][proto].keys()):
                info    = scanner[host][proto][port]
                pstate  = info['state']
                service = info.get('name', 'unknown')
                product = info.get('product', '')
                version = info.get('version', '')

                if pstate == 'open':
                    open_ports += 1
                    all_open_ports.append(port)
                    line = f"  ✅ Port {port:5d} | {pstate:6} | {service:15} | {product} {version}"
                    print(Fore.GREEN + Style.BRIGHT + line)
                    lines.append(line)
                    vuln = check_vuln(port)
                    if vuln:
                        print(Fore.YELLOW + f"           └─ {vuln}")
                        lines.append(f"           └─ {vuln}")
                    cves = lookup_cve(service, version)
                    print_cves(port, service, version, cves)
                else:
                    line = f"  ❌ Port {port:5d} | {pstate:6} | {service}"
                    print(Fore.RED + line)
                    lines.append(line)

            summary = f"\n  📊 Open ports found: {open_ports}"
            print(Fore.WHITE + summary)
            lines.append(summary)

        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
            print(Fore.MAGENTA + Style.BRIGHT + "\n🖥️  OS Detection:")
            lines.append("\nOS Detection:")
            for os in scanner[host]['osmatch'][:3]:
                os_line = f"  🔹 {os['name']} (Accuracy: {os['accuracy']}%)"
                print(Fore.MAGENTA + os_line)
                lines.append(os_line)

    print_recommendations(all_open_ports)

    print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 60)
    print(Fore.GREEN + Style.BRIGHT + "           ✅ SCAN COMPLETE!")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    lines += ["\n" + "=" * 60, "           ✅ SCAN COMPLETE!", "=" * 60]

    with open(txt_file, 'w') as f:
        f.write("\n".join(lines))
    print(Fore.WHITE + f"\n💾 TXT Report saved to: {txt_file}")

    return all_open_ports

# ─── Save JSON ─────────────────────────────────────────────────────────────
def save_json(scanner, target, scan_type, json_file):
    json_data = {
        "scan_info": {
            "target":    target,
            "scan_type": scan_type,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "hosts": []
    }
    for host in scanner.all_hosts():
        host_data = {
            "ip":       host,
            "hostname": scanner[host].hostname(),
            "state":    scanner[host].state(),
            "ports":    []
        }
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                info = scanner[host][proto][port]
                host_data["ports"].append({
                    "port":    port,
                    "state":   info['state'],
                    "service": info.get('name', 'unknown'),
                    "product": info.get('product', ''),
                    "version": info.get('version', '')
                })
        json_data["hosts"].append(host_data)

    with open(json_file, 'w') as f:
        json.dump(json_data, f, indent=4)
    print(Fore.WHITE + f"📋 JSON Report saved to: {json_file}\n")

# ─── Single Scan ───────────────────────────────────────────────────────────
def run_single_scan(target, scan_args, scan_type):
    os.makedirs("reports/txt",  exist_ok=True)
    os.makedirs("reports/html", exist_ok=True)
    os.makedirs("reports/json", exist_ok=True)

    print(Fore.YELLOW + f"\n🔍 Running {scan_type} on {target} ...")
    print(Fore.YELLOW + "Please wait...\n")

    scanner = nmap.PortScanner()
    scanner.scan(target, '1-1024', arguments=scan_args)

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    txt_file  = f"reports/txt/scan_{timestamp}.txt"
    html_file = f"reports/html/latest_report.html"
    json_file = f"reports/json/scan_{timestamp}.json"

    all_open_ports = show_results(scanner, target, scan_type, txt_file)
    generate_html(scanner, target, scan_type, html_file)
    save_json(scanner, target, scan_type, json_file)

    print(Fore.WHITE + f"🌐 HTML Report saved to: {html_file}")
# Copy report and show link
    import shutil
    shutil.copy(html_file, '/home/kali/latest_report.html')
    print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 60)
    print(Fore.GREEN + Style.BRIGHT + "  🌐 HTML Report Ready!")
    print(Fore.YELLOW + Style.BRIGHT + "  👉 file:///home/kali/latest_report.html")
    print(Fore.CYAN + "  💡 Open the link above in Firefox!")
# Save to history
    from recommendations import calculate_risk_score
    highest, score = calculate_risk_score(all_open_ports)
    save_scan(scanner, target, scan_type, highest, score)
    print(Fore.WHITE + f"📚 Scan saved to history database!")
    print(Fore.CYAN + "  💡 Press F5 after each scan to refresh!")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60 + "\n")
# Auto open latest HTML report
    import subprocess
    try:
        subprocess.Popen(['su', '-c', f'firefox {html_file}', 'kali'])
    except:
        print(Fore.YELLOW + f"💡 Open report manually: {html_file}")
# Generate history HTML automatically
    import sqlite3
    conn = sqlite3.connect("scan_history.db")
    c = conn.cursor()
    c.execute('SELECT * FROM scans ORDER BY id DESC')
    all_scans = c.fetchall()
    conn.close()
    generate_history_html(all_scans, '/home/kali/history_report.html')
    print(Fore.WHITE + "📊 History Report: file:///home/kali/history_report.html")
# ─── Main ──────────────────────────────────────────────────────────────────
def main():
    init_db()
    print_banner()

    print(Fore.WHITE + "\nWhat do you want to do?")
    print("  [1] Run new scan")
    print("  [2] View scan history")
    print("  [3] Exit")
    choice = input("\nEnter choice (1/2/3): ")

    if choice == "2":
        history_menu()
        return
    elif choice == "3":
        print(Fore.YELLOW + "\nGoodbye! 👋\n")
        return

    target, tchoice = get_targets()

    os.makedirs("reports/txt",  exist_ok=True)
    os.makedirs("reports/html", exist_ok=True)
    os.makedirs("reports/json", exist_ok=True)

    if tchoice == "4":
        sweep_and_scan(run_single_scan)
        return

    scan_args, scan_type = get_scan_type()
    run_single_scan(target, scan_args, scan_type)

if __name__ == "__main__":
    main()
