import dns.resolver

WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev",
    "staging", "test", "vpn", "remote", "portal",
    "blog", "shop", "cdn", "static", "media", "app",
    "login", "secure", "dashboard", "support"
]

def find_subdomains(domain):
    found = []
    print(f"  Scanning {len(WORDLIST)} common subdomains...")
    for sub in WORDLIST:
        candidate = f"{sub}.{domain}"
        try:
            dns.resolver.resolve(candidate, "A")
            found.append(candidate)
            print(f"  FOUND: {candidate}")
        except Exception:
            pass
    return found