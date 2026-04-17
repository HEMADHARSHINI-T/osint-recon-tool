from whois_dns import get_whois, get_dns_records, get_ip_geo

domain = "github.com"

print("=== WHOIS ===")
whois_result = get_whois(domain)
for key, value in whois_result.items():
    print(f"  {key}: {value}")

print("\n=== DNS RECORDS ===")
dns_result = get_dns_records(domain)
for rtype, values in dns_result.items():
    if values:
        print(f"  {rtype}: {values}")

print("\n=== IP GEOLOCATION ===")
ip = dns_result["A"][0]
print(f"  Checking IP: {ip}")
geo = get_ip_geo(ip)
for key, value in geo.items():
    print(f"  {key}: {value}")