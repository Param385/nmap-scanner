# ─── Security Recommendations & Risk Scoring ──────────────────────────────

RECOMMENDATIONS = {
    21: {
        "risk": "HIGH",
        "title": "FTP Detected",
        "recommendations": [
            "Disable FTP and replace with SFTP or SCP",
            "If FTP is required, use FTPS (FTP over SSL)",
            "Restrict access with firewall rules",
            "Never allow anonymous FTP login",
        ]
    },
    22: {
        "risk": "LOW",
        "title": "SSH Detected",
        "recommendations": [
            "Disable password authentication, use SSH keys only",
            "Change default port 22 to a custom port",
            "Use Fail2Ban to block brute-force attempts",
            "Restrict SSH access to specific IPs only",
            "Keep OpenSSH updated to latest version",
        ]
    },
    23: {
        "risk": "CRITICAL",
        "title": "Telnet Detected — CRITICAL RISK",
        "recommendations": [
            "DISABLE TELNET IMMEDIATELY",
            "Replace with SSH for all remote access",
            "Block port 23 on firewall",
            "Telnet sends all data including passwords in plaintext",
        ]
    },
    25: {
        "risk": "MEDIUM",
        "title": "SMTP Mail Server Detected",
        "recommendations": [
            "Disable open relay to prevent spam abuse",
            "Enable SMTP authentication",
            "Use TLS encryption for mail transfer",
            "Implement SPF, DKIM, and DMARC records",
        ]
    },
    53: {
        "risk": "MEDIUM",
        "title": "DNS Service Detected",
        "recommendations": [
            "Disable DNS recursion if not needed",
            "Restrict zone transfers to authorized servers only",
            "Keep DNS software patched and updated",
            "Monitor for DNS amplification attack attempts",
        ]
    },
    80: {
        "risk": "MEDIUM",
        "title": "HTTP Web Server Detected",
        "recommendations": [
            "Redirect all HTTP traffic to HTTPS immediately",
            "Install a valid SSL/TLS certificate",
            "Enable HTTP Strict Transport Security (HSTS)",
            "Keep web server software updated",
            "Remove default server banners and version info",
        ]
    },
    110: {
        "risk": "HIGH",
        "title": "POP3 Detected",
        "recommendations": [
            "Use POP3S (POP3 over SSL) instead",
            "Consider migrating to IMAP with TLS",
            "Never transmit credentials in plaintext",
        ]
    },
    135: {
        "risk": "HIGH",
        "title": "Windows RPC Detected",
        "recommendations": [
            "Block port 135 on external firewall immediately",
            "Apply all Windows security patches",
            "This port is commonly exploited in ransomware attacks",
            "Restrict access to internal network only",
        ]
    },
    139: {
        "risk": "HIGH",
        "title": "NetBIOS Detected",
        "recommendations": [
            "Disable NetBIOS over TCP/IP if not needed",
            "Block ports 137-139 on external firewall",
            "Use modern SMB with signing enabled instead",
        ]
    },
    143: {
        "risk": "MEDIUM",
        "title": "IMAP Detected",
        "recommendations": [
            "Use IMAPS (IMAP over SSL/TLS) instead",
            "Enforce strong password policies",
            "Enable two-factor authentication if possible",
        ]
    },
    443: {
        "risk": "LOW",
        "title": "HTTPS Web Server Detected",
        "recommendations": [
            "Ensure SSL/TLS certificate is valid and not expired",
            "Use TLS 1.2 or 1.3 only, disable older versions",
            "Enable HTTP Strict Transport Security (HSTS)",
            "Run regular SSL configuration audits",
        ]
    },
    445: {
        "risk": "CRITICAL",
        "title": "SMB Detected — CRITICAL RISK",
        "recommendations": [
            "Apply MS17-010 patch immediately (EternalBlue/WannaCry)",
            "Block port 445 on external firewall immediately",
            "Disable SMBv1 completely",
            "Enable SMB signing to prevent man-in-the-middle attacks",
            "This port is the #1 target for ransomware attacks",
        ]
    },
    1433: {
        "risk": "CRITICAL",
        "title": "MSSQL Database Exposed",
        "recommendations": [
            "NEVER expose databases directly to the internet",
            "Place database behind a firewall immediately",
            "Use strong, unique passwords for all DB accounts",
            "Disable the SA account or rename it",
            "Enable SQL Server auditing and logging",
        ]
    },
    3306: {
        "risk": "CRITICAL",
        "title": "MySQL Database Exposed",
        "recommendations": [
            "NEVER expose MySQL directly to the internet",
            "Bind MySQL to localhost (127.0.0.1) only",
            "Use firewall rules to restrict access",
            "Remove anonymous user accounts",
            "Disable remote root login",
        ]
    },
    3389: {
        "risk": "HIGH",
        "title": "RDP Remote Desktop Detected",
        "recommendations": [
            "Enable Network Level Authentication (NLA)",
            "Use a VPN instead of exposing RDP directly",
            "Change default RDP port from 3389",
            "Enable account lockout after failed attempts",
            "Keep Windows fully patched against BlueKeep vulnerability",
        ]
    },
    5900: {
        "risk": "HIGH",
        "title": "VNC Remote Access Detected",
        "recommendations": [
            "Never expose VNC directly to the internet",
            "Use VNC over SSH tunnel only",
            "Set a strong VNC password",
            "Consider replacing with more secure remote access tools",
        ]
    },
    6379: {
        "risk": "CRITICAL",
        "title": "Redis Database Exposed",
        "recommendations": [
            "Redis has NO authentication by default — secure immediately",
            "Bind Redis to localhost only",
            "Enable Redis authentication with strong password",
            "Never expose Redis to the internet",
        ]
    },
    8080: {
        "risk": "MEDIUM",
        "title": "Alternative HTTP Port Detected",
        "recommendations": [
            "Check if this service should be publicly accessible",
            "Ensure it is not a misconfigured admin panel",
            "Apply same security hardening as port 80",
        ]
    },
    27017: {
        "risk": "CRITICAL",
        "title": "MongoDB Database Exposed",
        "recommendations": [
            "MongoDB has NO authentication by default",
            "Enable MongoDB authentication immediately",
            "Bind to localhost only",
            "Thousands of MongoDB databases are publicly exposed — don't be one of them",
        ]
    },
}

RISK_SCORES = {
    "LOW":      1,
    "MEDIUM":   2,
    "HIGH":     3,
    "CRITICAL": 4,
}

RISK_COLORS = {
    "LOW":      "🟢",
    "MEDIUM":   "🟡",
    "HIGH":     "🔴",
    "CRITICAL": "💀",
}

def get_recommendations(port):
    return RECOMMENDATIONS.get(port, None)

def calculate_risk_score(open_ports):
    if not open_ports:
        return "LOW", 0

    total  = 0
    highest = "LOW"

    for port in open_ports:
        rec = RECOMMENDATIONS.get(port)
        if rec:
            score = RISK_SCORES[rec['risk']]
            total += score
            if score > RISK_SCORES[highest]:
                highest = rec['risk']

    return highest, total

def print_recommendations(open_ports):
    if not open_ports:
        return

    print("\n" + "=" * 60)
    print("  🛡️  SECURITY RECOMMENDATIONS")
    print("=" * 60)

    for port in open_ports:
        rec = get_recommendations(port)
        if rec:
            risk   = rec['risk']
            emoji  = RISK_COLORS[risk]
            print(f"\n{emoji} Port {port} — {rec['title']}")
            print(f"   Risk Level: {risk}")
            print("   Recommendations:")
            for r in rec['recommendations']:
                print(f"     → {r}")

    # Overall risk score
    highest, total = calculate_risk_score(open_ports)
    emoji = RISK_COLORS[highest]

    print("\n" + "=" * 60)
    print(f"  {emoji} OVERALL RISK LEVEL: {highest}")
    print(f"  📊 Risk Score: {total} points")
    if highest == "CRITICAL":
        print("  ⚠️  IMMEDIATE ACTION REQUIRED!")
    elif highest == "HIGH":
        print("  ⚠️  Address these issues as soon as possible!")
    elif highest == "MEDIUM":
        print("  ℹ️  Review and apply recommendations soon.")
    else:
        print("  ✅ Low risk detected. Keep systems updated.")
    print("=" * 60 + "\n")
