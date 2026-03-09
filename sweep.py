import nmap
from colorama import Fore, Style, init

init(autoreset=True)

def network_sweep(subnet):
    """Ping sweep to find all live hosts in a subnet"""
    
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    print(Fore.CYAN + Style.BRIGHT + f"  🌐 NETWORK SWEEP — {subnet}")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    print(Fore.YELLOW + "\n  Scanning for live hosts, please wait...\n")

    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')  # -sn = ping sweep, no port scan

    live_hosts = []

    for host in nm.all_hosts():
        state    = nm[host].state()
        hostname = nm[host].hostname()

        if state == 'up':
            live_hosts.append(host)
            print(Fore.GREEN + Style.BRIGHT + f"  ✅ {host:20} {hostname:30} — UP")
        else:
            print(Fore.RED + f"  ❌ {host:20} — DOWN")

    print(Fore.CYAN + Style.BRIGHT + "\n" + "=" * 60)
    print(Fore.GREEN + Style.BRIGHT + f"  📊 Live hosts found: {len(live_hosts)}")
    print(Fore.CYAN + Style.BRIGHT + "=" * 60 + "\n")

    return live_hosts


def sweep_and_scan(scanner_func):
    """Sweep subnet first, then scan each live host"""
    from colorama import Fore, Style

    subnet = input(Fore.WHITE + "Enter subnet to sweep (e.g. 192.168.1.0/24): ")
    
    live_hosts = network_sweep(subnet)

    if not live_hosts:
        print(Fore.RED + "  ❌ No live hosts found. Exiting.")
        return

    print(Fore.CYAN + Style.BRIGHT + f"\n  🔍 Found {len(live_hosts)} live hosts. Starting deep scan...\n")

    # Ask scan type
    print("Select scan type:")
    print("  [1] Basic Scan (fast)")
    print("  [2] Service & Version Detection")
    print("  [3] OS Detection + Services (most detailed)")
    choice = input("\nEnter choice (1/2/3): ")

    options = {
        "1": ("", "Basic Scan"),
        "2": ("-sV", "Service & Version Detection"),
        "3": ("-sV -O", "OS Detection + Services"),
    }
    scan_args, scan_type = options.get(choice, ("", "Basic Scan"))

    # Scan each live host
    for host in live_hosts:
        print(Fore.YELLOW + Style.BRIGHT + f"\n  🎯 Scanning {host} ...")
        scanner_func(host, scan_args, scan_type)
