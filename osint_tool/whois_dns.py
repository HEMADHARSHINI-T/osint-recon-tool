import whois
import dns.resolver
import requests
from config import IPINFO_TOKEN

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar":     w.registrar,
            "creation_date": str(w.creation_date),
            "expiry_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
            "name_servers":  w.name_servers,
            "org":           w.org,
        }
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain):
    records = {}
    for rtype in ["A", "MX", "TXT", "NS", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    return records

def get_ip_geo(ip):
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            params={"token": IPINFO_TOKEN},
            timeout=5
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}