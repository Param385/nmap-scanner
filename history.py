import sqlite3
import datetime
from colorama import Fore, Style, init

init(autoreset=True)

DB_FILE = "scan_history.db"

# ─── Create Database ───────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT,
            scan_type   TEXT,
            risk_level  TEXT,
            risk_score  INTEGER,
            open_ports  TEXT,
            hosts_found INTEGER,
            timestamp   TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            host        TEXT,
            port        INTEGER,
            state       TEXT,
            service     TEXT,
            product     TEXT,
            version     TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    ''')
    conn.commit()
    conn.close()

# ─── Save Scan ─────────────────────────────────────────────────
def save_scan(scanner, target, scan_type, risk_level, risk_score):
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Collect open ports
    open_ports  = []
    hosts_found = len(scanner.all_hosts())

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                info   = scanner[host][proto][port]
                pstate = info['state']
                if pstate == 'open':
                    open_ports.append(str(port))

    # Save scan summary
    c.execute('''
        INSERT INTO scans (target, scan_type, risk_level, risk_score, open_ports, hosts_found, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (target, scan_type, risk_level, risk_score, ','.join(open_ports), hosts_found, now))

    scan_id = c.lastrowid

    # Save individual ports
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                info = scanner[host][proto][port]
                c.execute('''
                    INSERT INTO ports (scan_id, host, port, state, service, product, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    host,
                    port,
                    info['state'],
                    info.get('name', 'unknown'),
                    info.get('product', ''),
                    info.get('version', '')
                ))

    conn.commit()
    conn.close()
    return scan_id

# ─── View History ──────────────────────────────────────────────
def view_history():
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT * FROM scans ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()

    if not rows:
        print(Fore.YELLOW + "\n  No scan history found.\n")
        return

    print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 80)
    print(Fore.CYAN + Style.BRIGHT + "  📊 SCAN HISTORY")
    print(Fore.CYAN + Style.BRIGHT + "=" * 80)
    print(Fore.WHITE + Style.BRIGHT +
          f"  {'ID':<5} {'Target':<20} {'Scan Type':<30} {'Risk':<10} {'Ports':<15} {'Date'}")
    print(Fore.CYAN + "-" * 80)

    RISK_COLOR = {
        "LOW":      Fore.GREEN,
        "MEDIUM":   Fore.YELLOW,
        "HIGH":     Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }

    for row in rows:
        id_, target, scan_type, risk, score, ports, hosts, ts = row
        color = RISK_COLOR.get(risk, Fore.WHITE)
        ports_display = ports if ports else "none"
        if len(ports_display) > 15:
            ports_display = ports_display[:12] + "..."
        print(f"  {Fore.WHITE}{id_:<5} {Fore.CYAN}{target:<20} {Fore.WHITE}{scan_type:<30} {color}{risk:<10} {Fore.WHITE}{ports_display:<15} {ts}")

    print(Fore.CYAN + Style.BRIGHT + "=" * 80 + "\n")

# ─── Search by IP ──────────────────────────────────────────────
def search_by_ip(ip):
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c    = conn.cursor()
    c.execute('SELECT * FROM scans WHERE target LIKE ? ORDER BY id DESC', (f'%{ip}%',))
    rows = c.fetchall()
    conn.close()

    if not rows:
        print(Fore.YELLOW + f"\n  No scans found for {ip}\n")
        return

    print(Fore.CYAN + Style.BRIGHT + f"\n  🔍 Scan history for: {ip}")
    print(Fore.CYAN + "=" * 80)

    for row in rows:
        id_, target, scan_type, risk, score, ports, hosts, ts = row
        print(Fore.WHITE + f"\n  Scan #{id_} — {ts}")
        print(f"  Target: {Fore.CYAN}{target}")
        print(f"  {Fore.WHITE}Scan Type: {scan_type}")
        print(f"  Risk: {Fore.YELLOW}{risk} (Score: {score})")
        print(f"  {Fore.WHITE}Open Ports: {Fore.GREEN}{ports if ports else 'none'}")
        print(f"  Hosts Found: {hosts}")

        # Show port details
        conn2 = sqlite3.connect(DB_FILE)
        c2    = conn2.cursor()
        c2.execute('SELECT * FROM ports WHERE scan_id=? AND state="open"', (id_,))
        port_rows = c2.fetchall()
        conn2.close()

        if port_rows:
            print(Fore.CYAN + "\n  Port Details:")
            for pr in port_rows:
                _, _, host, port, state, service, product, version = pr
                print(Fore.GREEN + f"    ✅ {host} — Port {port} | {service} | {product} {version}")

    print(Fore.CYAN + "=" * 80 + "\n")

# ─── Show History Menu ─────────────────────────────────────────
def history_menu():
    while True:
        print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 60)
        print(Fore.CYAN + Style.BRIGHT + "  📊 SCAN HISTORY MENU")
        print(Fore.CYAN + Style.BRIGHT + "=" * 60)
        print("  [1] View all scan history")
        print("  [2] Search by IP address")
        print("  [3] Back to main menu")
        choice = input("\n  Enter choice (1/2/3): ")

        if choice == "1":
            view_history()
        elif choice == "2":
            ip = input("  Enter IP to search: ")
            search_by_ip(ip)
        elif choice == "3":
            break
        else:
            print(Fore.RED + "  Invalid choice!")
