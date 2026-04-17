def calculate_risk(vt_result, email_result, whois_data, subdomains):
    score = 0
    reasons = []

    # VirusTotal signals (up to 50 pts)
    if isinstance(vt_result, dict) and "malicious" in vt_result:
        mal = vt_result["malicious"]
        sus = vt_result["suspicious"]
        if mal > 0:
            pts = min(mal * 10, 40)
            score += pts
            reasons.append(f"Flagged malicious by {mal} engine(s) (+{pts})")
        if sus > 0:
            score += 10
            reasons.append(f"Flagged suspicious by {sus} engine(s) (+10)")

    # Email reputation signals (up to 30 pts)
    if isinstance(email_result, dict):
        if email_result.get("blacklisted"):
            score += 20
            reasons.append("Email is blacklisted (+20)")
        if email_result.get("malicious_activity"):
            score += 20
            reasons.append("Email linked to malicious activity (+20)")
        if email_result.get("spam"):
            score += 10
            reasons.append("Email flagged as spam (+10)")
        if email_result.get("suspicious"):
            score += 10
            reasons.append("Email marked suspicious (+10)")

    # WHOIS signals (up to 20 pts)
    if isinstance(whois_data, dict):
        if not whois_data.get("org"):
            score += 10
            reasons.append("No registrant org listed (+10)")
        creation = str(whois_data.get("creation_date", ""))
        if "2023" in creation or "2024" in creation or "2025" in creation:
            score += 10
            reasons.append("Domain registered recently (+10)")

    # Subdomain signal
    if len(subdomains) > 5:
        score += 5
        reasons.append(f"Large attack surface: {len(subdomains)} subdomains (+5)")

    score = min(score, 100)

    if score >= 70:
        label = "🔴 High Risk"
    elif score >= 40:
        label = "🟠 Suspicious"
    else:
        label = "🟢 Low Risk"

    return {"score": score, "label": label, "reasons": reasons}