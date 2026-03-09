import urllib.request
import urllib.parse
import json

# Map nmap service names to better search terms
SERVICE_MAP = {
    "ssh":     "openssh",
    "http":    "apache http server",
    "https":   "apache http server",
    "ftp":     "vsftpd",
    "smtp":    "postfix smtp",
    "mysql":   "mysql database",
    "ms-sql":  "microsoft sql server",
    "rdp":     "windows remote desktop",
    "vnc":     "realvnc",
    "telnet":  "telnet server",
    "dns":     "bind dns",
    "smb":     "windows smb",
    "mongodb": "mongodb",
    "redis":   "redis server",
}
def lookup_cve(service, version):
    """Search for CVEs based on service and version"""
    if not service or service == "unknown":
        return []

    try:
        # Map service name to better search term
        search_service = SERVICE_MAP.get(service.lower(), service)
        keyword = search_service
        keyword_encoded = urllib.parse.quote(keyword)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword_encoded}&resultsPerPage=3"

        req = urllib.request.Request(url, headers={'User-Agent': 'NmapScanner/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

        cves = []
        for item in data.get('vulnerabilities', []):
            cve      = item['cve']
            cve_id   = cve['id']
            desc     = cve['descriptions'][0]['value'][:150] + "..."

            severity = "UNKNOWN"
            try:
                metrics = cve.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                elif 'cvssMetricV2' in metrics:
                    severity = metrics['cvssMetricV2'][0]['baseSeverity']
            except:
                pass

            cves.append({
                "id":       cve_id,
                "severity": severity,
                "desc":     desc
            })

        return cves

    except urllib.error.URLError:
        return [{"id": "N/A", "severity": "UNKNOWN", "desc": "⚠️ CVE lookup failed — check internet connection."}]
    except Exception as e:
        print(f"  ⚪ CVE lookup error: {e}")
        return []


def print_cves(port, service, version, cves):
    if not cves:
        return

    SEVERITY_EMOJI = {
        "CRITICAL": "💀",
        "HIGH":     "🔴",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
        "UNKNOWN":  "⚪",
    }

    print(f"\n  🔎 CVE Lookup — Port {port} ({service} {version})")
    print("  " + "-" * 50)
    for cve in cves:
        emoji = SEVERITY_EMOJI.get(cve['severity'], "⚪")
        print(f"  {emoji} {cve['id']} [{cve['severity']}]")
        print(f"     {cve['desc']}")
