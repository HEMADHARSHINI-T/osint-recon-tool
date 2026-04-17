from breach_vt import check_email_rep, check_virustotal

# Test VirusTotal with a known domain
print("=== VIRUSTOTAL ===")
vt_result = check_virustotal("github.com")
for key, value in vt_result.items():
    print(f"  {key}: {value}")

# Test VirusTotal with a suspicious domain
print("\n=== VIRUSTOTAL (suspicious domain) ===")
vt_bad = check_virustotal("malware.wicar.org")
for key, value in vt_bad.items():
    print(f"  {key}: {value}")

# Test email reputation
print("\n=== EMAIL REPUTATION ===")
email_result = check_email_rep("test@gmail.com")
for key, value in email_result.items():
    print(f"  {key}: {value}")