import requests
from config import EMAILREP_KEY, VIRUSTOTAL_KEY

def check_email_rep(email):
    try:
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers={"Key": EMAILREP_KEY, "User-Agent": "osint-tool"},
            timeout=5
        )
        data = r.json()
        return {
            "reputation":    data.get("reputation"),
            "suspicious":    data.get("suspicious"),
            "references":    data.get("references"),
            "blacklisted":   data.get("details", {}).get("blacklisted"),
            "malicious_activity": data.get("details", {}).get("malicious_activity"),
            "spam":          data.get("details", {}).get("spam"),
        }
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(domain):
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=5
        )
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception as e:
        return {"error": str(e)}