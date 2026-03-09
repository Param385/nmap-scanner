from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

def banner(text):
    print(Fore.CYAN + Style.BRIGHT + text)

def success(text):
    print(Fore.GREEN + text)

def warning(text):
    print(Fore.YELLOW + text)

def danger(text):
    print(Fore.RED + Style.BRIGHT + text)

def critical(text):
    print(Back.RED + Fore.WHITE + Style.BRIGHT + text)

def info(text):
    print(Fore.BLUE + text)

def bold(text):
    print(Style.BRIGHT + text)

def dim(text):
    print(Style.DIM + text)

RISK_COLOR = {
    "LOW":      Fore.GREEN  + Style.BRIGHT,
    "MEDIUM":   Fore.YELLOW + Style.BRIGHT,
    "HIGH":     Fore.RED    + Style.BRIGHT,
    "CRITICAL": Back.RED    + Fore.WHITE + Style.BRIGHT,
}

PORT_STATE_COLOR = {
    "open":     Fore.GREEN  + Style.BRIGHT,
    "closed":   Fore.RED,
    "filtered": Fore.YELLOW,
}

def colored_port(port, state, line):
    color = PORT_STATE_COLOR.get(state, "")
    print(color + line)

def colored_risk(risk, text):
    color = RISK_COLOR.get(risk, "")
    print(color + text)
