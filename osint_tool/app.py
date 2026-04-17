import streamlit as st
from whois_dns import get_whois, get_dns_records, get_ip_geo
from breach_vt import check_email_rep, check_virustotal
from subdomains import find_subdomains
from risk_score import calculate_risk

st.set_page_config(page_title="OSINT Recon Tool", page_icon="🕵️", layout="wide")
st.title("🕵️ OSINT Recon Tool")
st.caption("Scan any domain or email for public intelligence.")

target = st.text_input("Enter domain or email:", placeholder="example.com or user@example.com")
scan = st.button("🔍 Scan", type="primary")

if scan and target:
    target = target.strip().lower()
    is_email = "@" in target
    domain = target.split("@")[-1] if is_email else target

    with st.spinner("Scanning... please wait"):

        whois_data   = get_whois(domain)
        dns_data     = get_dns_records(domain)
        vt_data      = check_virustotal(domain)
        subs         = find_subdomains(domain)
        ips          = dns_data.get("A", [])
        geo_data     = get_ip_geo(ips[0]) if ips else {}
        email_result = check_email_rep(target) if is_email else {}
        risk         = calculate_risk(vt_data, email_result, whois_data, subs)

    # Risk banner
    score = risk["score"]
    if score >= 70:
        color = "#d32f2f"
    elif score >= 40:
        color = "#f57c00"
    else:
        color = "#388e3c"

    st.markdown(
        f"""<div style="background:{color};color:white;padding:14px 20px;
        border-radius:8px;font-size:18px;font-weight:600;margin:12px 0">
        ⚠️ Risk Score: {score}/100 — {risk['label']}</div>""",
        unsafe_allow_html=True
    )

    if risk["reasons"]:
        with st.expander("Why this score?"):
            for r in risk["reasons"]:
                st.write(f"• {r}")

    # Results grid
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📋 WHOIS")
        if "error" not in whois_data:
            st.write(f"**Registrar:** {whois_data.get('registrar', 'N/A')}")
            st.write(f"**Created:** {whois_data.get('creation_date', 'N/A')}")
            st.write(f"**Expires:** {whois_data.get('expiry_date', 'N/A')}")
            st.write(f"**Org:** {whois_data.get('org', 'N/A')}")
        else:
            st.error(whois_data["error"])

        st.subheader("🌐 DNS Records")
        for rtype, values in dns_data.items():
            if values:
                st.write(f"**{rtype}:** {', '.join(values[:3])}")

    with col2:
        st.subheader("📍 IP Geolocation")
        if geo_data and "error" not in geo_data:
            st.write(f"**IP:** {geo_data.get('ip')}")
            st.write(f"**Location:** {geo_data.get('city')}, {geo_data.get('country')}")
            st.write(f"**ISP:** {geo_data.get('org')}")
        else:
            st.info("No IP resolved.")

        st.subheader("🔴 VirusTotal")
        if isinstance(vt_data, dict) and "malicious" in vt_data:
            col_a, col_b, col_c = st.columns(3)
            col_a.metric("Malicious", vt_data["malicious"])
            col_b.metric("Suspicious", vt_data["suspicious"])
            col_c.metric("Harmless", vt_data["harmless"])
        else:
            st.error(vt_data.get("error", "Unknown error"))

    if is_email:
        st.subheader("📧 Email Reputation")
        if email_result and "error" not in email_result:
            st.write(f"**Reputation:** {email_result.get('reputation', 'N/A')}")
            st.write(f"**Suspicious:** {email_result.get('suspicious', 'N/A')}")
            st.write(f"**Blacklisted:** {email_result.get('blacklisted', 'N/A')}")
            st.write(f"**Spam:** {email_result.get('spam', 'N/A')}")
        else:
            st.warning("Email reputation unavailable — API key pending.")

    st.subheader(f"🔍 Subdomains Found ({len(subs)})")
    if subs:
        for s in subs:
            st.code(s)
    else:
        st.info("No common subdomains discovered.")