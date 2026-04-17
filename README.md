#  OSINT Recon Tool

A Python-based Open Source Intelligence (OSINT) tool to gather and analyze domain and email security data.

##  Features
- WHOIS lookup for domain ownership details
- DNS record extraction (A, MX, TXT)
- Email breach detection using HaveIBeenPwned API
- Malicious domain analysis via VirusTotal
- IP geolocation using IPInfo
- Subdomain discovery
- Risk score calculation for security assessment
- Interactive web interface using Streamlit

## Tech Stack
- Python
- Streamlit
- requests
- python-whois
- dnspython
- APIs: HaveIBeenPwned, VirusTotal, IPInfo

##  Installation
```bash
pip install requests python-whois dnspython streamlit
