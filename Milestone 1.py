import streamlit as st
import pandas as pd
import altair as alt   

st.title("Aviation Cyber Threat Intelligence Platform")

st.sidebar.title("Navigation")
page = st.sidebar.selectbox(
    "Go to",
    ["Introduction & Industry Background", "Stakeholders & User Stories", "CTI Use Case", "Threat Trends", "Critical Assets", "Diamond Models", "Intelligence Buy-In", "Dashboard", "About Team"]
)

if page == "Introduction & Industry Background":
    st.header("Aviation Industry Overview")

    st.subheader("""Key Aviation Services""")
    st.write("""Pilot and flight crew""")
    st.write("""Air Traffic Management""")
    st.write("""Maintenance Crew""")
    st.write("""Emergency Services""")

    st.subheader("""Key Aviation Products""")

if page == "Stakeholders & User Stories":
    st.header("SOC Analyst -Kimberly Jones")

    st.write("""Role: Kimberly is a frontline SOC Analyst responsible for monitoring alerts, identifying suspicious activity, and escalating incidents.

Goals:
- Quickly identify high-priority threats
- Recognize attack patterns and emerging threats
- Reduce investigation time
- Maintain accurate documentation of incidents
- Detect hidden or stealthy threats

User Stories:
- As a SOC Analyst, I want to filter threats in real time so I can quickly identify alerts that require immediate action.
- As a SOC Analyst, I want the dashboard to update dynamically when a threat type is selected so I can prioritize investigations.

Mapped App Features:
- Interactive filters (threat type, actor, asset)
- Dynamic charts and tables
- KPI metrics such as “Threat of the Week” and “Ransomware Events Detected""")
    st.header("CISO -Dr. William Brown")

    st.write("""Role: Dr. Brown is the CISO responsible for cybersecurity strategy, risk reduction, and budget allocation.

Goals:
- Understand high-level global and local threat trends
- Identify targeted critical assets
- Justify cybersecurity investments
- Communicate risk to leadership

User Stories:
- As a CISO, I want a high-level summary of global and local threat trends so I can make informed strategic decisions.
- As a CISO, I want to see which critical assets are most targeted so I can allocate resources effectively.

Mapped App Features:
- Threat Trends section
- Critical Asset Identification
- KPI metrics like “Most Targeted Asset” and “Average Risk Score""")
    st.header("Threat Hunter -Olivia Baptiste")

    st.write("""Role: Olivia is a Threat Hunter who proactively searches for adversary activity and uncovers hidden threats.

Goals:
- Detect adversaries that bypass automated defenses
- Understand attacker behavior and TTPs
- Map attack paths and identify early indicators

User Stories:
- As a Threat Hunter, I want to explore diamond models of active threat actors so I can understand their capabilities and infrastructure.
- As a Threat Hunter, I want to pivot from threat actor to targeted assets so I can identify potential attack paths.

Mapped App Features:
- Diamond Models section
- Dynamic tables that update based on selected threat actor
- Dashboard filters for actors, assets, and capabilities
""")

if page == "CTI Use Case":
    st.header("CTI Use Case")

    st.write("""enter aviation industry overview""")

if page == "Threat Trends":
    st.header("Cyber Threat Trends in Aviation")

    st.write("""enter cyber threat trends in aviation""")

if page == "Critical Assets":
    st.header("Critical Aviation Assets")

    st.write("""enter critical assets""")

if page == "Diamond Models":
    st.header("Threat Diamond Models")

with st.expander("Adversary"):
    st.write("""
**Name:** Group X  
**Motivation:** Financial gain  
**Skill Level:** Advanced  
**Behavior:** Uses spear-phishing, credential harvesting, and exploits unpatched systems  
""")

with st.expander("Capabilities"):
    st.write("""
- Ransomware payload deployment  
- Privilege escalation tools  
- Lateral movement frameworks (e.g., PsExec, Cobalt Strike)  
- Data exfiltration scripts  
- Strong encryption mechanisms  
""")

with st.expander("Infrastructure"):
    st.write("""
- Command‑and‑control (C2) servers  
- Compromised VPN endpoints  
- Bulletproof hosting providers  
- Encrypted communication channels  
""")

with st.expander("Victim"):
    st.write("""
- **Target Sector:** Healthcare organizations  
- **Assets Impacted:** EMR systems, patient databases, imaging servers  
- **Susceptibilities:** Outdated systems, weak MFA, unpatched vulnerabilities  
""")

st.header("Diamond Model: SilentHook (Phishing Actor)")

with st.expander("Adversary"):
    st.write("""
**Name:** SilentHook  
**Motivation:** Credential theft and initial access brokerage  
**Skill Level:** Intermediate  
**Behavior:** Mass phishing campaigns, MFA fatigue attacks, impersonation of trusted services  
""")

with st.expander("Capabilities"):
    st.write("""
- Email spoofing and domain impersonation  
- MFA push‑bombing  
- Credential harvesting kits  
- Automated phishing frameworks  
""")

with st.expander("Infrastructure"):
    st.write("""
- Disposable phishing domains  
- Cloud‑hosted landing pages  
- Redirect chains to evade detection  
- Compromised email accounts used as relays  
""")

with st.expander("Victim"):
    st.write("""
- **Target Sector:** Aviation & Transportation  
- **Assets Impacted:** Employee email accounts, SSO portals, HR systems  
- **Susceptibilities:** High email volume, lack of phishing awareness, weak MFA enforcement  
""")

if page == "Intelligence Buy-In":
    st.header("Intelligence Buy-In")

    st.write("""enter aviation industry overview""")

if page == "Dashboard":
    st.header("Threat Dashboard")

    data = pd.DataFrame({
        "threat_type": ["Ransomware", "Phishing", "DDoS", "Insider Threat", "Ransomware", "Phishing"],
        "severity": [9, 4, 6, 3, 8, 5],
        "asset": ["Database", "Email Server", "Web App", "HR System", "Database", "Email Server"],
        "date": pd.date_range("2024-01-01", periods=6)
    })

    threat_filter = st.selectbox(
        "Select Threat Type:",
        options=["All"] + sorted(data["threat_type"].unique())
    )

    if threat_filter != "All":
        filtered = data[data["threat_type"] == threat_filter]
    else:
        filtered = data

    st.subheader("Key Metrics")
    col1, col2 = st.columns(2)
    col1.metric("Total Events", len(filtered))
    col2.metric("Average Severity", round(filtered["severity"].mean(), 2))

    st.subheader("Threat Severity Over Time")
    chart = (
        alt.Chart(filtered)
        .mark_line(point=True)
        .encode(
            x="date:T",
            y="severity:Q",
            color="threat_type:N"
        )
    )
    st.altair_chart(chart, use_container_width=True)

    st.subheader("Threat Event Details")
    st.dataframe(filtered)


if page == "About Team":
    st.header("Team Contributions")

    st.write("""Ashley Mohamed:""")
    st.write("""Tiffany Morgan:""")
    st.write("""Mitali Patel:""")
    st.write("""Elizabeth Powell:""")
    st.write("""Ricardo Scully:""")
