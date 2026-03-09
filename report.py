import datetime

def generate_html(scanner, target, scan_type, filename):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    VULN_PORTS = {
        21:   "⚠️ Unencrypted file transfer. Brute-force risk.",
        22:   "ℹ️ Secure shell. Ensure strong passwords/keys.",
        23:   "🚨 DANGER! Unencrypted remote access. Disable it!",
        25:   "⚠️ Mail server. Can be abused for spam relay.",
        53:   "ℹ️ DNS service. Risk of DNS amplification attacks.",
        80:   "⚠️ Unencrypted web server. Upgrade to HTTPS.",
        110:  "⚠️ Unencrypted mail. Credentials sent in plaintext.",
        135:  "🚨 Windows RPC. Common target for exploits.",
        139:  "🚨 Windows file sharing. Common attack vector.",
        143:  "⚠️ Unencrypted mail access.",
        443:  "✅ Encrypted web server. Keep certificates updated.",
        445:  "🚨 DANGER! EternalBlue/WannaCry target. Patch immediately!",
        1433: "🚨 Database exposed! Should not be public-facing.",
        3306: "🚨 Database exposed! Should not be public-facing.",
        3389: "🚨 Remote Desktop. High brute-force risk!",
        5900: "🚨 Remote access. Often misconfigured & unencrypted.",
        6379: "🚨 Often runs with no authentication!",
        8080: "⚠️ Alternative web port. Check for misconfigs.",
        27017:"🚨 Database exposed! Often has no auth by default!",
    }

    RECOMMENDATIONS = {
        21:   ("HIGH",     "FTP Detected",                  ["Disable FTP and replace with SFTP or SCP", "If FTP is required, use FTPS (FTP over SSL)", "Restrict access with firewall rules"]),
        22:   ("LOW",      "SSH Detected",                  ["Disable password authentication, use SSH keys only", "Change default port 22 to a custom port", "Use Fail2Ban to block brute-force attempts"]),
        23:   ("CRITICAL", "Telnet Detected",               ["DISABLE TELNET IMMEDIATELY", "Replace with SSH for all remote access", "Block port 23 on firewall"]),
        25:   ("MEDIUM",   "SMTP Detected",                 ["Disable open relay to prevent spam abuse", "Enable SMTP authentication", "Use TLS encryption"]),
        53:   ("MEDIUM",   "DNS Detected",                  ["Disable DNS recursion if not needed", "Restrict zone transfers", "Keep DNS software patched"]),
        80:   ("MEDIUM",   "HTTP Detected",                 ["Redirect all HTTP traffic to HTTPS", "Install a valid SSL/TLS certificate", "Enable HSTS"]),
        443:  ("LOW",      "HTTPS Detected",                ["Ensure SSL certificate is valid", "Use TLS 1.2 or 1.3 only", "Enable HSTS"]),
        445:  ("CRITICAL", "SMB Detected",                  ["Apply MS17-010 patch immediately", "Block port 445 on external firewall", "Disable SMBv1"]),
        3306: ("CRITICAL", "MySQL Exposed",                 ["Never expose MySQL to the internet", "Bind to localhost only", "Remove anonymous users"]),
        3389: ("HIGH",     "RDP Detected",                  ["Enable Network Level Authentication", "Use VPN instead of direct RDP", "Enable account lockout"]),
        6379: ("CRITICAL", "Redis Exposed",                 ["Redis has NO auth by default", "Bind to localhost only", "Enable authentication"]),
        27017:("CRITICAL", "MongoDB Exposed",               ["Enable MongoDB authentication", "Bind to localhost only", "Never expose to internet"]),
    }

    RISK_COLOR = {
        "LOW":      "#3fb950",
        "MEDIUM":   "#d29922",
        "HIGH":     "#f85149",
        "CRITICAL": "#ff0000",
    }

    # ── Build port rows ─────────────────────────────────────────
    all_open_ports = []
    rows = ""
    summary = {"open": 0, "closed": 0, "filtered": 0}
    hosts_html = ""

    for host in scanner.all_hosts():
        hostname = scanner[host].hostname()
        state    = scanner[host].state()
        os_html  = ""

        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
            os_html = "<div class='os-box'><strong>🖥️ OS Detection:</strong><ul>"
            for os in scanner[host]['osmatch'][:3]:
                os_html += f"<li>{os['name']} — Accuracy: {os['accuracy']}%</li>"
            os_html += "</ul></div>"

        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                info    = scanner[host][proto][port]
                pstate  = info['state']
                service = info.get('name', 'unknown')
                product = info.get('product', '')
                version = info.get('version', '')
                vuln    = VULN_PORTS.get(port, "")

                summary[pstate] = summary.get(pstate, 0) + 1

                if pstate == "open":
                    all_open_ports.append(port)
                    row_class = "open"
                    badge = '<span class="badge open-badge">OPEN</span>'
                elif pstate == "filtered":
                    row_class = "filtered"
                    badge = '<span class="badge filtered-badge">FILTERED</span>'
                else:
                    row_class = "closed"
                    badge = '<span class="badge closed-badge">CLOSED</span>'

                vuln_html = f'<div class="vuln">{vuln}</div>' if vuln and pstate == "open" else ""

                rows += f"""
                <tr class="{row_class}">
                    <td><strong>{host}</strong></td>
                    <td>{port}</td>
                    <td>{proto.upper()}</td>
                    <td>{badge}</td>
                    <td>{service}</td>
                    <td>{product} {version}</td>
                    <td>{vuln_html}</td>
                </tr>"""

        hosts_html += f"""
        <div class="host-card">
            <h3>🖥️ {host} {f'({hostname})' if hostname else ''} — <span class="{'state-up' if state == 'up' else 'state-down'}">{state.upper()}</span></h3>
            {os_html}
        </div>"""

    # ── Build recommendations ────────────────────────────────────
    rec_html = ""
    for port in all_open_ports:
        rec = RECOMMENDATIONS.get(port)
        if rec:
            risk, title, tips = rec
            color = RISK_COLOR.get(risk, "#fff")
            tips_html = "".join(f"<li>{t}</li>" for t in tips)
            rec_html += f"""
            <div class="rec-card" style="border-left: 4px solid {color}">
                <div class="rec-header">
                    <span class="rec-title">Port {port} — {title}</span>
                    <span class="rec-badge" style="background:{color}20; color:{color}">{risk}</span>
                </div>
                <ul class="rec-list">{tips_html}</ul>
            </div>"""

    if not rec_html:
        rec_html = "<p style='color:#8b949e'>No critical recommendations for this scan.</p>"

    # ── Overall Risk ─────────────────────────────────────────────
    risk_scores = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    highest = "LOW"
    total_score = 0
    for port in all_open_ports:
        rec = RECOMMENDATIONS.get(port)
        if rec:
            r = rec[0]
            total_score += risk_scores.get(r, 0)
            if risk_scores.get(r, 0) > risk_scores.get(highest, 0):
                highest = r

    risk_color  = RISK_COLOR.get(highest, "#3fb950")
    risk_emojis = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "CRITICAL": "💀"}
    risk_emoji  = risk_emojis.get(highest, "🟢")

    # ── HTML Template ────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scan Report — {target}</title>
    <meta http-equiv="refresh" content="30">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }}
        header {{ background: #161b22; padding: 30px; border-bottom: 2px solid #21262d; }}
        header h1 {{ color: #58a6ff; font-size: 1.8rem; }}
        header p {{ color: #8b949e; margin-top: 5px; }}
        .container {{ max-width: 1200px; margin: 30px auto; padding: 0 20px; }}
        h2 {{ color: #58a6ff; margin: 30px 0 15px; font-size: 1.2rem; }}

        /* Summary Cards */
        .summary {{ display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }}
        .card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 20px 25px; flex: 1; text-align: center; min-width: 120px; }}
        .card h2 {{ font-size: 2rem; margin: 0; }}
        .card p {{ color: #8b949e; margin-top: 5px; font-size: 0.85rem; }}
        .open-card h2 {{ color: #3fb950; }}
        .filtered-card h2 {{ color: #d29922; }}
        .closed-card h2 {{ color: #f85149; }}
        .info-card h2 {{ color: #58a6ff; font-size: 1.2rem; }}
        .risk-card h2 {{ color: {risk_color}; font-size: 1.5rem; }}

        /* Host Cards */
        .host-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 15px 20px; margin-bottom: 15px; }}
        .host-card h3 {{ font-size: 1rem; color: #c9d1d9; }}
        .state-up {{ color: #3fb950; }}
        .state-down {{ color: #f85149; }}
        .os-box {{ margin-top: 10px; padding: 10px; background: #0d1117; border-radius: 6px; font-size: 0.85rem; }}
        .os-box ul {{ padding-left: 20px; margin-top: 5px; }}
        .os-box li {{ margin: 3px 0; color: #8b949e; }}

        /* Table */
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 10px; overflow: hidden; margin-bottom: 30px; }}
        th {{ background: #21262d; padding: 12px 15px; text-align: left; color: #58a6ff; font-size: 0.85rem; }}
        td {{ padding: 10px 15px; border-bottom: 1px solid #21262d; font-size: 0.85rem; }}
        tr:hover {{ background: #1c2128; }}
        tr.open td {{ border-left: 3px solid #3fb950; }}
        tr.filtered td {{ border-left: 3px solid #d29922; }}
        tr.closed td {{ border-left: 3px solid #f85149; }}
        .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }}
        .open-badge {{ background: #1a4731; color: #3fb950; }}
        .filtered-badge {{ background: #3d2f0a; color: #d29922; }}
        .closed-badge {{ background: #3d1a1a; color: #f85149; }}
        .vuln {{ margin-top: 4px; font-size: 0.78rem; color: #f0883e; }}

        /* Recommendations */
        .rec-card {{ background: #161b22; border-radius: 10px; padding: 15px 20px; margin-bottom: 12px; }}
        .rec-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .rec-title {{ font-weight: bold; color: #c9d1d9; }}
        .rec-badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }}
        .rec-list {{ padding-left: 20px; }}
        .rec-list li {{ margin: 5px 0; color: #8b949e; font-size: 0.85rem; }}

        /* Disclaimer */
        .disclaimer {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 20px; margin-top: 20px; color: #8b949e; font-size: 0.85rem; }}

        footer {{ text-align: center; padding: 30px; color: #8b949e; margin-top: 20px; border-top: 1px solid #21262d; font-size: 0.85rem; }}
.nav {{ display: flex; gap: 15px; margin-bottom: 20px; }}
        .nav a {{ color: #58a6ff; text-decoration: none; padding: 8px 16px; border: 1px solid #21262d; border-radius: 6px; }}
        .nav a:hover {{ background: #21262d; }}
    </style>
</head>
<body>
    <header>
        <h1>🔍 Nmap Scan Report</h1>
        <p>Target: <strong>{target}</strong> &nbsp;|&nbsp; Scan Type: <strong>{scan_type}</strong> &nbsp;|&nbsp; Date: <strong>{now}</strong></p>
    </header>

    <div class="container">
<div class="nav">
            <a href="/home/kali/latest_report.html">🔍 Latest Scan</a>
            <a href="/home/kali/history_report.html">📊 History</a>
        </div>

        <!-- Summary Cards -->
        <div class="summary">
            <div class="card info-card">
                <h2>{target}</h2>
                <p>Target Scanned</p>
            </div>
            <div class="card open-card">
                <h2>{summary.get('open', 0)}</h2>
                <p>Open Ports</p>
            </div>
            <div class="card filtered-card">
                <h2>{summary.get('filtered', 0)}</h2>
                <p>Filtered Ports</p>
            </div>
            <div class="card closed-card">
                <h2>{summary.get('closed', 0)}</h2>
                <p>Closed Ports</p>
            </div>
            <div class="card risk-card">
                <h2>{risk_emoji} {highest}</h2>
                <p>Overall Risk — Score: {total_score}</p>
            </div>
        </div>

        <!-- Hosts -->
        <h2>🖥️ Discovered Hosts</h2>
        {hosts_html}

        <!-- Port Table -->
        <h2>📂 Port Scan Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Security Notes</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>

        <!-- Security Recommendations -->
        <h2>🛡️ Security Recommendations</h2>
        {rec_html}

        <!-- Risk Score -->
        <div class="rec-card" style="border-left: 4px solid {risk_color}; margin-top: 20px;">
            <div class="rec-header">
                <span class="rec-title">{risk_emoji} Overall Risk Level: {highest}</span>
                <span class="rec-badge" style="background:{risk_color}20; color:{risk_color}">{total_score} points</span>
            </div>
        </div>

        <!-- Disclaimer -->
        <div class="disclaimer">
            <strong>⚠️ Disclaimer:</strong> This tool is for educational purposes and authorized network scanning only.
            Always obtain permission before scanning any network or system you do not own. Unauthorized scanning is illegal.
        </div>

    </div>

    <footer>
        <p>Generated by Advanced Nmap Scanner &nbsp;|&nbsp; Portfolio Project &nbsp;|&nbsp; {now}</p>
    </footer>
</body>
</html>"""

    with open(filename, 'w') as f:
        f.write(html)

    print(f"🌐 HTML Report saved to: {filename}")
def generate_history_html(scans, filename):
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    RISK_COLOR = {
        "LOW":      "#3fb950",
        "MEDIUM":   "#d29922",
        "HIGH":     "#f85149",
        "CRITICAL": "#ff0000",
    }

    rows = ""
    for scan in scans:
        id_, target, scan_type, risk, score, ports, hosts, ts = scan
        color = RISK_COLOR.get(risk, "#fff")
        ports_display = ports if ports else "none"
        rows += f"""
        <tr>
            <td>{id_}</td>
            <td><strong>{target}</strong></td>
            <td>{scan_type}</td>
            <td><span class="badge" style="background:{color}20; color:{color}">{risk}</span></td>
            <td>{score}</td>
            <td><span style="color:#3fb950">{ports_display}</span></td>
            <td>{hosts}</td>
            <td>{ts}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan History</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }}
        header {{ background: #161b22; padding: 30px; border-bottom: 2px solid #21262d; }}
        header h1 {{ color: #58a6ff; font-size: 1.8rem; }}
        header p {{ color: #8b949e; margin-top: 5px; }}
        .container {{ max-width: 1200px; margin: 30px auto; padding: 0 20px; }}
        h2 {{ color: #58a6ff; margin: 30px 0 15px; }}
        table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 10px; overflow: hidden; }}
        th {{ background: #21262d; padding: 12px 15px; text-align: left; color: #58a6ff; font-size: 0.85rem; }}
        td {{ padding: 10px 15px; border-bottom: 1px solid #21262d; font-size: 0.85rem; }}
        tr:hover {{ background: #1c2128; }}
        .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }}
        .nav {{ display: flex; gap: 15px; margin-bottom: 20px; }}
        .nav a {{ color: #58a6ff; text-decoration: none; padding: 8px 16px; border: 1px solid #21262d; border-radius: 6px; }}
        .nav a:hover {{ background: #21262d; }}
        footer {{ text-align: center; padding: 30px; color: #8b949e; margin-top: 40px; border-top: 1px solid #21262d; }}
    </style>
</head>
<body>
    <header>
        <h1>📊 Scan History</h1>
        <p>All past scans — Generated: {now}</p>
    </header>
    <div class="container">
        <div class="nav">
            <a href="/home/kali/latest_report.html">🔍 Latest Scan</a>
            <a href="/home/kali/history_report.html">📊 History</a>
        </div>
        <h2>📋 All Scans</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Target</th>
                    <th>Scan Type</th>
                    <th>Risk</th>
                    <th>Score</th>
                    <th>Open Ports</th>
                    <th>Hosts</th>
                    <th>Date</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    <footer>Generated by Advanced Nmap Scanner | Portfolio Project | {now}</footer>
</body>
</html>"""

    with open(filename, 'w') as f:
        f.write(html)
    print(f"📊 History Report saved to: {filename}")
