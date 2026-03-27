import streamlit as st
import pandas as pd
import altair as alt
import plotly.graph_objects as go
import json
import requests
from datetime import datetime 
 
# ──────────────────────────────────────────────
# GLOBAL STYLES
# ──────────────────────────────────────────────
st.markdown("""
<style>
.stApp { background-color: #140006; color: #f8e6ec; }
[data-testid="stHeader"] { background: #140006; border-bottom: 1px solid #3a0014; }
section[data-testid="stSidebar"] { background: #1c0009; }
section[data-testid="stSidebar"] * { color: #f8e6ec !important; }
h1 { color: #ff2f75 !important; text-align: center; font-weight: 800; }
h2, h3 { color: #ff2f75 !important; }
p, li { color: #f8e6ec; }
div[data-baseweb="select"] > div { background-color: #2a000f; border: 1px solid #4d001a; border-radius: 10px; color: white; }
ul { background-color: #1c0009 !important; }
[data-testid="stMetric"] { background: #2a000f; border: 1px solid #4d001a; border-radius: 14px; padding: 15px; box-shadow: 0 0 10px rgba(255, 47, 117, 0.15); }
.stButton > button { background-color: #ff2f75; color: white; border-radius: 12px; border: none; font-weight: 600; }
.stButton > button:hover { background-color: #cc0052; }
details { background-color: #1c0009; border-radius: 10px; border: 1px solid #4d001a; }
[data-testid="stDataFrame"] { background-color: #140006; border: 1px solid #3a0014; }
[data-testid="stAlert"] { border-radius: 10px; }
.block-container { background-color: transparent; }
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
ul, ol { background-color: transparent !important; }
li { background-color: transparent !important; }
[data-testid="stMarkdownContainer"] ul { background-color: transparent !important; }
[data-testid="stMarkdownContainer"] { background-color: transparent !important; }
</style>
""", unsafe_allow_html=True)
 
# ──────────────────────────────────────────────
# RANSOMWARE.LIVE API HELPERS
# ──────────────────────────────────────────────
BASE_URL = "https://api.ransomware.live/v2"
HEADERS  = {"User-Agent": "AviationCTI-Research/1.0"}
 
# Activity sector names used by ransomware.live
TRANSPORT_SECTORS = {"Transportation Systems", "Transportation/Logistics", "Aerospace"}
 
# Keywords to flag aviation victims from broader datasets
AVIATION_KEYWORDS = [
    "airline", "airways", "airport", "aviation", "air lines",
    "flight", "aircraft", "aero", "jetblue", "southwest", "delta",
    "united air", "american air", "spirit air", "frontier", "allegiant",
    "cargo air", "air freight", "air traffic", "faa", "air force",
    "helicopter", "aviat", "runway", "terminal"
]
 
def fetch_json(endpoint: str):
    try:
        r = requests.get(f"{BASE_URL}/{endpoint}", headers=HEADERS, timeout=15)
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None
 
@st.cache_data(ttl=3600)
def get_us_transport_victims() -> pd.DataFrame:
    """
    countryvictims/US fields:
      post_title, group_name, published, activity, country, website, description
    """
    raw = fetch_json("countryvictims/US")
    if not raw or not isinstance(raw, list):
        return pd.DataFrame()
    rows = []
    for v in raw:
        if v.get("activity", "") in TRANSPORT_SECTORS:
            rows.append({
                "Victim":      v.get("post_title", "Unknown"),
                "Group":       v.get("group_name", "Unknown"),
                "Attack Date": v.get("published", ""),
                "Sector":      v.get("activity", ""),
                "Country":     v.get("country", "US"),
                "Website":     v.get("website", ""),
                "Description": v.get("description", ""),
            })
    return pd.DataFrame(rows)
 
@st.cache_data(ttl=3600)
def get_recent_aviation_victims() -> pd.DataFrame:
    """
    recentvictims fields:
      victim, group, attackdate, country, activity, description, domain, url
    """
    raw = fetch_json("recentvictims")
    if not raw or not isinstance(raw, list):
        return pd.DataFrame()
    rows = []
    for v in raw:
        combined = (str(v.get("victim","")) + " " + str(v.get("description",""))).lower()
        if any(kw in combined for kw in AVIATION_KEYWORDS):
            rows.append({
                "Victim":      v.get("victim", "Unknown"),
                "Group":       v.get("group", "Unknown"),
                "Attack Date": v.get("attackdate", ""),
                "Country":     v.get("country", ""),
                "Sector":      v.get("activity", ""),
                "Description": v.get("description", ""),
                "URL":         v.get("url", ""),
            })
    return pd.DataFrame(rows)
 
@st.cache_data(ttl=3600)
def get_group_victims(group_name: str) -> pd.DataFrame:
    """
    groupvictims/<name> fields:
      victim, group, attackdate, country, activity, description, domain, url
    """
    slug = group_name.lower().replace(" ", "")
    raw  = fetch_json(f"groupvictims/{slug}")
    if not raw or not isinstance(raw, list):
        return pd.DataFrame()
    rows = []
    for v in raw:
        rows.append({
            "Victim":      v.get("victim", "Unknown"),
            "Group":       v.get("group", group_name),
            "Attack Date": v.get("attackdate", ""),
            "Country":     v.get("country", ""),
            "Sector":      v.get("activity", ""),
            "Description": v.get("description", ""),
        })
    return pd.DataFrame(rows)
 
@st.cache_data(ttl=3600)
def get_all_group_names() -> list:
    raw = fetch_json("groups")
    if not raw or not isinstance(raw, list):
        return []
    return sorted([g.get("name", "") for g in raw if g.get("name")])
 
def parse_dates(df: pd.DataFrame, col: str = "Attack Date") -> pd.DataFrame:
    if col in df.columns:
        df = df.copy()
        df[col] = pd.to_datetime(df[col], errors="coerce")
    return df
 
def api_status(df: pd.DataFrame, label: str):
    if df.empty:
        st.warning(f"No {label} data returned from ransomware.live — API may be rate-limited or temporarily unavailable.")
    else:
        st.success(f"Live data loaded: **{len(df)}** records from ransomware.live")
 
# ──────────────────────────────────────────────
# NAVIGATION
# ──────────────────────────────────────────────
st.title("Aviation Cyber Threat Intelligence Platform")
 
st.sidebar.title("Navigation")
page = st.sidebar.selectbox("Go to", [
    "Introduction & Industry Background",
    "Stakeholders & User Stories",
    "CTI Use Case",
    "Threat Trends",
    "Critical Assets",
    "Diamond Models",
    "Intelligence Buy-In",
    "Live Ransomware Intel",
    "Dashboard",
    "Milestone Updates",
    "About Team",
])
 
# ──────────────────────────────────────────────
if page == "Introduction & Industry Background":
    st.header("Aviation Industry Overview")
    st.markdown("""
This Cyber Threat Intelligence (CTI) platform focuses on the **domestic commercial aviation industry**,
specifically U.S.-based airlines, airports, and supporting aviation systems.
 
The aviation industry is a critical component of the global transportation and logistics ecosystem,
enabling the movement of passengers and cargo. Within the domestic context, commercial airlines operate
high-frequency flights that rely on seamless coordination between multiple systems and stakeholders.
 
Due to its role in economic development, national connectivity, and critical infrastructure,
aviation is a high-value target for cyber threats.
""")
 
    st.subheader("Key Services & Products")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
- Domestic passenger transportation (U.S. flights)
- Airline reservation and ticketing systems
- Airport operations and ground services
- Air cargo and logistics support
""")
    with col2:
        st.markdown("""
- Air traffic coordination and navigation systems
- Aircraft maintenance and repair (MRO) systems
- Baggage handling and tracking systems
- Aviation support systems (onboard and airport IT)
""")
 
    st.subheader("Overall Size & Impact")
    st.write("""
The aviation industry is a major contributor to the global and U.S. economy. According to industry data,
the global airline industry generated hundreds of billions of dollars in revenue, with continued growth
in passenger traffic expected in the coming years.
 
In the United States, civil aviation supports millions of jobs and contributes significantly to GDP.
Domestic commercial flights make up a large portion of this activity, operating at high volume and
requiring constant system availability. Because of this scale, disruptions caused by cyber incidents
can have widespread financial and operational consequences.
""")
 
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Industry Revenue", "$700B+")
    with col2: st.metric("U.S. Economic Impact", "~4% GDP")
    with col3: st.metric("Dependency on IT Systems", "Critical")
 
    st.subheader("Major Industry Players")
    st.markdown("""
- Commercial airlines (e.g., Delta Air Lines, American Airlines, Southwest Airlines)
- Airport authorities and operators
- Air navigation service providers (e.g., FAA air traffic control systems)
- Aircraft manufacturers such as Boeing
- Technology providers supporting airline and airport IT infrastructure
 
Collaboration between these entities is essential for operations but increases cybersecurity risks
due to shared systems and data environments.
""")
 
    st.subheader("Importance of Information Technology")
    st.write("""
Information technology is mission-critical to modern aviation. Aircraft are often described as
"flying networks" because they rely on interconnected digital systems for communication, navigation,
and operations. Domestic airlines and airports depend on IT systems to maintain efficiency, safety,
and customer service.
""")
    st.markdown("""
**Key systems include:**
- Flight planning and management systems
- Reservation and booking platforms
- Passenger data and identity management systems
- Baggage handling and tracking systems
- Operational technology (OT) in airport infrastructure
- Cloud platforms and data analytics tools
""")
 
    st.warning("""
As the aviation industry continues its digital transformation, the attack surface expands.
Increased connectivity between systems creates more opportunities for cyber threat actors
to exploit vulnerabilities, making cybersecurity a top priority.
""")
 
    st.subheader("Why This Matters for Cyber Threat Intelligence")
    st.success("""
The aviation industry's reliance on interconnected IT and operational systems makes it especially
vulnerable to cyber threats. For domestic commercial aviation, even small disruptions can lead to
nationwide delays, financial loss, and safety concerns.
 
Understanding the structure of the industry and its dependence on technology is essential for
developing an effective Cyber Threat Intelligence (CTI) platform that supports proactive defense.
""")
 
# ──────────────────────────────────────────────
elif page == "Stakeholders & User Stories":
    st.header("SOC Analyst - Kimberly Jones")
    st.write("""
Role: Kimberly is a frontline SOC Analyst responsible for monitoring alerts, identifying suspicious activity, and escalating incidents.
 
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
- KPI metrics such as "Threat of the Week" and "Ransomware Events Detected"
""")
 
    st.header("CISO - Dr. William Brown")
    st.write("""
Role: Dr. Brown is the CISO responsible for cybersecurity strategy, risk reduction, and budget allocation.
 
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
- KPI metrics like "Most Targeted Asset" and "Average Risk Score"
""")
 
    st.header("Threat Hunter - Olivia Baptiste")
    st.write("""
Role: Olivia is a Threat Hunter who proactively searches for adversary activity and uncovers hidden threats.
 
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
 
# ──────────────────────────────────────────────
elif page == "CTI Use Case":
    st.header("CTI Use Case")
    st.markdown("""
### Problem
The aviation industry faces increasing cyber threats targeting airline IT systems,
airport infrastructure, and aircraft operational technology. Existing CTI solutions
lack real-time, aviation-specific intelligence.
 
### Decisions Enabled
- Prioritization of high-risk aviation threats
- Early detection of ransomware and phishing campaigns
- Risk-based protection of critical aviation assets
- Improved IT/OT security integration
 
### Why This Data & Analytics
Open-source intelligence, ransomware tracking, phishing feeds, and attack-surface
monitoring directly reflect real-world aviation threats and support proactive defense.
""")
 
# ──────────────────────────────────────────────
elif page == "Threat Trends":
    st.header("Cyber Threat Trends in Aviation")
    st.markdown("""
### Threat Landscape Overview
 
The global aviation industry faces a rapidly evolving threat landscape characterized by a shift from traditional cybercrime to sophisticated, intelligence-driven operations. Globally, organizations are experiencing a constant increase in breach frequency, with cyber threats becoming a core tool of global power.
 
Within the aviation sector, key exploits frequently target vulnerabilities in Air Traffic Control (ATC) systems and unpatched legacy Research and Development systems, which are often difficult to update due to their integration with specialized hardware. Additionally, there is a growing focus on operational technologies and interconnected *"flying networks,"* where aircraft rely on complex software for navigation and communication.
 
---
 
### Targeted Areas in Aviation
 
- Passenger databases containing large volumes of personally identifiable information (PII)
- Flight scheduling and crew management systems
- Mission-critical ground operations and airport infrastructure
 
These attacks are carried out by a wide range of threat actors, including:
 
- Financially motivated cyber-extortion groups such as **Black Basta**, which use malware like Qakbot to disrupt operations
- Nation-state actors such as **APT40**, which conduct industrial espionage to steal sensitive intellectual property
- Insider threats, both intentional and accidental, due to the large number of employees with access to critical systems
""")
 
# ──────────────────────────────────────────────
elif page == "Critical Assets":
    st.header("Critical Aviation Assets")
    st.markdown("""
### Critical Assets in Aviation
 
**Air Traffic Control (ATC) and Navigation Systems**
These systems are used by air navigation service providers to maintain the safe movement of aircraft. Their value lies in ensuring passenger safety. A breach could result in catastrophic failures, flight disruptions, or unauthorized airspace violations.
 
**Flight Scheduling and Crew Management Systems**
Used by airline operations centers and SOC analysts, these systems coordinate flight logistics and staffing. If compromised, often through ransomware, they can halt operations entirely, leading to significant financial and operational impacts.
 
**Passenger Data and Reservation Platforms**
These systems store sensitive passenger information and support booking and identity management. A breach can lead to identity theft, reputational damage, and regulatory penalties.
 
**Next-Generation Flight Control Blueprints (Intellectual Property)**
High-value digital assets used by aircraft manufacturers such as Boeing and Airbus. A breach could result in long-term economic damage and loss of technological superiority.
 
**Onboard Digital Systems and Avionics**
Often described as "flying networks," these systems are used by flight crews for real-time navigation and aircraft health monitoring. If compromised — for example, through GPS spoofing or ADS-B manipulation — aircraft become vulnerable during active in-flight operations.
""")
 
# ──────────────────────────────────────────────
elif page == "Diamond Models":
    st.header("Threat Diamond Models")
    st.write("Select a model to view its Diamond Model representation.")
    st.subheader("Diamond Model Builder (Multiple Models)")
 
    model_choice = st.selectbox("Choose a Diamond Model", [
        "Model 1: Ground Operations Lockdown",
        "Model 2: Espionage"
    ])
 
    col3, col4 = st.columns(2)
 
    model1 = {
        "adversary":      {"operator": ["Black Basta (SPT)"], "customer": ["Cyber-extortion syndicate (financially motivated)"]},
        "capability":     {"arsenal": ["Qakbot (Qbot) for initial access", "Black Basta ransomware"], "capacity": ["High – Living off the Land (PowerShell, native tools)"]},
        "infrastructure": {"type1": ["Compromised RDP Gateway – exposed remote desktop port"], "type2": ["C2 Beacon via Cobalt Strike (HTTP/S disguised traffic)"]},
        "victim":         {"persona": ["Kimberly Jones – SOC Analyst monitoring RDP logs"], "assets": ["Flight scheduling systems", "Crew management systems"], "susceptibilities": ["Alert fatigue – overwhelmed by high volume of minor alerts"]},
    }
    model2 = {
        "adversary":      {"operator": ["APT40 – nation-state group"], "customer": ["Rival state-owned aircraft manufacturer"]},
        "capability":     {"arsenal": ["Custom Web Shell", "Specialized data compression tools"], "capacity": ["Advanced – Living off the Land (admin tools for stealth)"]},
        "infrastructure": {"type1": ["Compromised VPS (neutral country C2 hub)"], "type2": ["Compromised IoT devices (airport security cameras as hop points)"]},
        "victim":         {"persona": ["Olivia Baptist – Threat Hunter (MITRE ATT&CK expert)"], "assets": ["Next-Gen Flight Control Blueprint (Intellectual Property)"], "susceptibilities": ["Unpatched legacy R&D systems tied to specialized hardware"]},
    }
 
    active_model = model1 if model_choice.startswith("Model 1") else model2
 
    with col3:
        adversary_operator      = st.selectbox("Adversary Operator",               active_model["adversary"]["operator"])
        adversary_customer      = st.selectbox("Adversary Customer",                active_model["adversary"]["customer"])
        capability_arsenal      = st.selectbox("Arsenal",                           active_model["capability"]["arsenal"])
        capability_capacity     = st.selectbox("Capacity",                          active_model["capability"]["capacity"])
        infrastructure_type1    = st.selectbox("Infrastructure Type 1 (Required)",  active_model["infrastructure"]["type1"])
        infrastructure_type2    = st.selectbox("Infrastructure Type 2 (Optional)",  active_model["infrastructure"]["type2"])
        victim_persona          = st.selectbox("Victim Persona",                    active_model["victim"]["persona"])
        victim_assets           = st.selectbox("Critical Assets",                   active_model["victim"]["assets"])
        victim_susceptibilities = st.selectbox("Susceptibilities",                  active_model["victim"]["susceptibilities"])
 
        diamond = {
            "model":          model_choice,
            "adversary":      {"operator": adversary_operator, "customer": adversary_customer},
            "capability":     {"arsenal": capability_arsenal,  "capacity": capability_capacity},
            "infrastructure": {"type1_required": infrastructure_type1, "type2_optional": infrastructure_type2},
            "victim":         {"persona": victim_persona, "assets": victim_assets, "susceptibilities": victim_susceptibilities},
        }
        st.download_button("Download Diamond Model (JSON)",
                           data=json.dumps(diamond, indent=2),
                           file_name=f"{model_choice.replace(' ','_').lower()}.json")
 
    with col4:
        fig2 = go.Figure()
        coords = {"Adversary": (0,1), "Infrastructure": (-1,0), "Capability": (1,0), "Victim": (0,-1)}
        labels = {
            "Adversary":      f"{adversary_operator}\n{adversary_customer}",
            "Infrastructure": f"{infrastructure_type1}\n{infrastructure_type2}",
            "Capability":     f"{capability_arsenal}\n{capability_capacity}",
            "Victim":         f"{victim_persona}\n{victim_assets}\n{victim_susceptibilities}",
        }
        for a, b in [("Adversary","Infrastructure"),("Adversary","Capability"),("Infrastructure","Victim"),("Capability","Victim")]:
            xa,ya = coords[a]; xb,yb = coords[b]
            fig2.add_trace(go.Scatter(x=[xa,xb], y=[ya,yb], mode="lines", line=dict(color="gray"), showlegend=False))
        fig2.add_trace(go.Scatter(
            x=[coords[k][0] for k in coords], y=[coords[k][1] for k in coords],
            mode="markers+text", text=[f"{k}\n{labels[k]}" for k in coords],
            textposition="middle center", marker=dict(size=40, color="#4C78A8"), showlegend=False,
        ))
        fig2.update_layout(height=350, xaxis=dict(visible=False), yaxis=dict(visible=False), margin=dict(l=20,r=20,t=20,b=20))
        st.plotly_chart(fig2, use_container_width=True)
 
# ──────────────────────────────────────────────
elif page == "Intelligence Buy-In":
    st.header("Intelligence Buy-In")
    st.markdown("""
This section explains why a Cyber Threat Intelligence (CTI) platform is valuable for
organizations involved in **domestic commercial aviation**, including airlines, airports,
and supporting service providers.
""")
 
    st.subheader("Why Intelligence Matters")
    st.write("""
Domestic commercial aviation depends on highly interconnected digital systems such as reservation
platforms, passenger identity systems, baggage handling systems, airline communications, maintenance
systems, and airport operational technology. Because these systems support high-volume, time-sensitive
operations, cyberattacks can create immediate operational, financial, and reputational damage.
""")
 
    st.subheader("Current Threat Landscape")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
**Major threats affecting domestic commercial flights:**
- **Ransomware & Cyberattacks:** The top threat in aviation. If any part of the airport's IT infrastructure goes down, it results in delays and financial loss.
- **Data Breaches:** Airline databases hold millions of flyers' records. A breach exposes PII and could end up sold on the dark web.
- **Social Engineering:** Phishing campaigns targeting employees lead to leaked credentials and unauthorized database access.
- **Insider Threats:** Accidental or purposeful misuse of information by trusted personnel.
- **GPS Spoofing/Jamming:** Navigation interference could cause direct safety issues for passengers mid-air.
""")
    with col2:
        st.info("""
Aviation organizations are attractive targets because they manage:
- Large volumes of customer data
- High-value operational systems
- Critical transportation infrastructure
- Time-sensitive services where downtime is costly
""")
 
    st.subheader("Shifting to Threat Intelligence")
    st.write("""
Aviation should move from the traditional outlook of cybersecurity to an intelligence-driven approach.
Traditional cybersecurity focuses on responding AFTER an attack happens. In aviation, that approach is
faulty when even a small disruption can impact flights, departures, and user accounts at scale.
Implementing a CTI strategy allows threats to be anticipated and disruptions minimized.
""")
 
    st.subheader("Business Impact of Breaches")
    kpi1, kpi2, kpi3 = st.columns(3)
    with kpi1: st.metric("Operational Risk", "High")
    with kpi2: st.metric("Passenger Data Exposure Risk", "Severe")
    with kpi3: st.metric("Need for Proactive CTI", "Critical")
 
    st.markdown("""
**Consequences of a cyber incident in domestic aviation:**
- **Flight disruptions:** delays, cancellations, and system outages
- **Financial loss:** downtime, recovery costs, and lost revenue
- **Reputation damage:** reduced passenger trust and brand harm
- **Regulatory pressure:** increased scrutiny after breaches involving customer data
- **Safety concerns:** indirect impacts when critical systems are disrupted
""")
 
    st.subheader("How a CTI Platform Reduces Risk")
    st.markdown("""
**Our proposed CTI platform would help by:**
- Monitoring ransomware activity affecting airlines and airports
- Identifying phishing infrastructure impersonating airline brands or employee portals
- Detecting exposed internet-facing assets through sources such as Shodan and Censys
- Tracking threat trends relevant to domestic commercial aviation
- Supporting faster and more informed security decisions
""")
 
    st.success("""
An intelligence-driven security approach can help domestic aviation organizations reduce operational
disruptions, protect passenger data, improve incident response, and strengthen resilience against
evolving cyber threats.
""")
 
    st.subheader("Executive Summary")
    st.write("""
For domestic commercial aviation, cybersecurity is not just an IT issue — it is an operational and
business issue. Because airlines and airports depend on always-available digital services, developing
a CTI platform is a valuable investment that improves visibility into emerging threats and supports
faster, smarter defense decisions.
""")
 
# ──────────────────────────────────────────────
# PAGE: Live Ransomware Intel
# ──────────────────────────────────────────────
elif page == "Live Ransomware Intel":
    st.header("Live Ransomware Intelligence")
    st.markdown("""
> **Data Source:** [ransomware.live](https://www.ransomware.live) — a public threat intelligence platform
> tracking ransomware group activity, victims, and attack trends in real time.
> Data is pulled live via the ransomware.live v2 API and cached for 60 minutes.
""")
 
    tab1, tab2, tab3 = st.tabs([
        "U.S. Transportation & Aerospace",
        "Aviation Keyword Scanner",
        "Group Deep Dive"
    ])
 
    # ── TAB 1 ──────────────────────────────────────────────────────
    with tab1:
        st.subheader("U.S. Transportation & Aerospace – Ransomware Victims")
        st.caption("Source: `GET /v2/countryvictims/US` filtered to Transportation Systems, Transportation/Logistics, and Aerospace sectors")
 
        with st.spinner("Fetching live data from ransomware.live..."):
            df_t = get_us_transport_victims()
 
        api_status(df_t, "U.S. Transportation/Aerospace")
 
        if not df_t.empty:
            df_t = parse_dates(df_t)
 
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Victims", len(df_t))
            c2.metric("Ransomware Groups", df_t["Group"].nunique())
            valid = df_t["Attack Date"].dropna()
            c3.metric("Most Recent Attack", valid.max().strftime("%Y-%m-%d") if not valid.empty else "N/A")
            c4.metric("Sectors Covered", df_t["Sector"].nunique())
 
            col_f1, col_f2 = st.columns(2)
            with col_f1:
                groups = ["All"] + sorted(df_t["Group"].dropna().unique().tolist())
                sel_g  = st.selectbox("Filter by Group", groups, key="t_group")
            with col_f2:
                sectors = ["All"] + sorted(df_t["Sector"].dropna().unique().tolist())
                sel_s   = st.selectbox("Filter by Sector", sectors, key="t_sector")
 
            df_view = df_t.copy()
            if sel_g != "All": df_view = df_view[df_view["Group"]  == sel_g]
            if sel_s != "All": df_view = df_view[df_view["Sector"] == sel_s]
 
            st.dataframe(df_view[["Victim","Group","Sector","Attack Date","Website"]], use_container_width=True)
 
            df_chart = df_view.dropna(subset=["Attack Date"]).copy()
            if not df_chart.empty:
                df_chart["Year-Month"] = df_chart["Attack Date"].dt.to_period("M").astype(str)
                monthly = df_chart.groupby("Year-Month").size().reset_index(name="Attacks")
                bar = (
                    alt.Chart(monthly).mark_bar(color="#ff2f75")
                    .encode(
                        x=alt.X("Year-Month:O", title="Month", sort=None),
                        y=alt.Y("Attacks:Q", title="Victims"),
                        tooltip=["Year-Month","Attacks"]
                    )
                    .properties(title="U.S. Transport/Aerospace Ransomware Attacks Over Time")
                )
                st.altair_chart(bar, use_container_width=True)
 
            if df_t["Group"].nunique() > 1:
                gc = df_t["Group"].value_counts().reset_index()
                gc.columns = ["Group","Count"]
                pie = go.Figure(go.Pie(
                    labels=gc["Group"], values=gc["Count"], hole=0.4,
                    marker=dict(colors=["#ff2f75","#cc0052","#ff6699","#990040","#ff99bb",
                                        "#aa003a","#ff4488","#7a0030","#ffb3cc","#550020"])
                ))
                pie.update_layout(title="Victims by Ransomware Group",
                                  paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#f8e6ec"))
                st.plotly_chart(pie, use_container_width=True)
 
            st.download_button(
                "Download Data (JSON)",
                data=df_t.to_json(orient="records", date_format="iso", indent=2),
                file_name="us_transport_aerospace_ransomware.json",
                mime="application/json"
            )
 
    # ── TAB 2 ──────────────────────────────────────────────────────
    with tab2:
        st.subheader("Aviation Keyword Scanner")
        st.caption("Source: `GET /v2/recentvictims` — 100 most recent global victims scanned for aviation-related terms")
        st.markdown(f"**Keywords:** `{', '.join(AVIATION_KEYWORDS)}`")
 
        with st.spinner("Scanning recent victims for aviation relevance..."):
            df_av = get_recent_aviation_victims()
 
        api_status(df_av, "aviation-specific")
 
        if not df_av.empty:
            df_av = parse_dates(df_av)
 
            c1, c2, c3 = st.columns(3)
            c1.metric("Aviation-Linked Victims", len(df_av))
            c2.metric("Countries Affected",       df_av["Country"].nunique())
            c3.metric("Groups Involved",          df_av["Group"].nunique())
 
            st.dataframe(df_av[["Victim","Group","Attack Date","Country","Sector","Description"]], use_container_width=True)
 
            df_av2 = df_av.dropna(subset=["Attack Date"]).copy()
            if not df_av2.empty:
                df_av2["Year-Month"] = df_av2["Attack Date"].dt.to_period("M").astype(str)
                monthly2 = df_av2.groupby("Year-Month").size().reset_index(name="Victims")
                line = (
                    alt.Chart(monthly2).mark_line(point=True, color="#ff2f75")
                    .encode(
                        x=alt.X("Year-Month:O", title="Month", sort=None),
                        y=alt.Y("Victims:Q"),
                        tooltip=["Year-Month","Victims"]
                    )
                    .properties(title="Aviation Ransomware Victim Trend (Recent 100)")
                )
                st.altair_chart(line, use_container_width=True)
        else:
            st.info("No aviation-specific matches in the most recent 100 victims. The cache refreshes hourly — check back later.")
 
    # ── TAB 3 ──────────────────────────────────────────────────────
    with tab3:
        st.subheader("Ransomware Group Deep Dive")
        st.caption("Source: `GET /v2/groupvictims/<group>` — full victim history for any group")
 
        priority_groups = ["blackbasta","lockbit","alphv","cl0p","akira","ransomhub",
                           "play","dragonforce","qilin","bianlian"]
 
        with st.spinner("Loading group list..."):
            all_groups = get_all_group_names()
 
        group_options = sorted(set(priority_groups + all_groups)) if all_groups else priority_groups
        selected_group = st.selectbox("Select Ransomware Group", group_options, key="grp_dive")
 
        if st.button("Fetch Group Victims"):
            with st.spinner(f"Pulling all victims for **{selected_group}**..."):
                df_grp = get_group_victims(selected_group)
 
            if df_grp.empty:
                st.warning(f"No victim data returned for '{selected_group}'. The group name may be slightly different in the API.")
            else:
                df_grp = parse_dates(df_grp)
                st.success(f"**{len(df_grp)}** total victims attributed to **{selected_group}**.")
 
                us_only = st.checkbox("Show U.S. victims only", value=True, key="grp_us")
                if us_only:
                    df_grp = df_grp[df_grp["Country"].str.upper() == "US"]
                    st.caption(f"Filtered to **{len(df_grp)}** U.S. victims.")
 
                aviation_only = st.checkbox("Show aviation-related victims only", value=False, key="grp_av")
                if aviation_only:
                    mask = df_grp.apply(
                        lambda r: any(kw in (str(r["Victim"]) + " " + str(r["Description"])).lower()
                                      for kw in AVIATION_KEYWORDS), axis=1
                    )
                    df_grp = df_grp[mask]
                    st.caption(f"Filtered to **{len(df_grp)}** aviation-related victims.")
 
                st.dataframe(df_grp[["Victim","Group","Attack Date","Country","Sector","Description"]],
                             use_container_width=True)
 
                df_grp2 = df_grp.dropna(subset=["Attack Date"]).copy()
                if not df_grp2.empty:
                    df_grp2["Year-Month"] = df_grp2["Attack Date"].dt.to_period("M").astype(str)
                    mg = df_grp2.groupby("Year-Month").size().reset_index(name="Victims")
                    bar2 = (
                        alt.Chart(mg).mark_bar(color="#ff2f75")
                        .encode(
                            x=alt.X("Year-Month:O", title="Month", sort=None),
                            y=alt.Y("Victims:Q"),
                            tooltip=["Year-Month","Victims"]
                        )
                        .properties(title=f"{selected_group} – Victim Timeline")
                    )
                    st.altair_chart(bar2, use_container_width=True)
 
                st.download_button(
                    f"Download {selected_group} Data (JSON)",
                    data=df_grp.to_json(orient="records", date_format="iso", indent=2),
                    file_name=f"{selected_group}_victims.json",
                    mime="application/json"
                )
 
    st.divider()
    st.caption(
        "Data sourced from [ransomware.live](https://www.ransomware.live) — "
        "a public threat intelligence platform by Julien Mousqueton. "
        "For research and educational purposes only. Cache refreshes every 60 minutes."
    )
 
# ──────────────────────────────────────────────
elif page == "Dashboard":
    st.header("Threat Dashboard")
 
    data = pd.DataFrame({
        "threat_type": ["Ransomware","Phishing","DDoS","Insider Threat","Ransomware","Phishing"],
        "severity":    [9, 4, 6, 3, 8, 5],
        "asset":       ["Database","Email Server","Web App","HR System","Database","Email Server"],
        "date":        pd.date_range("2024-01-01", periods=6)
    })
 
    threat_filter = st.selectbox("Select Threat Type:", options=["All"] + sorted(data["threat_type"].unique()))
    filtered = data if threat_filter == "All" else data[data["threat_type"] == threat_filter]
 
    st.subheader("Key Metrics")
    col1, col2 = st.columns(2)
    col1.metric("Total Events", len(filtered))
    col2.metric("Average Severity", round(filtered["severity"].mean(), 2))
 
    st.subheader("Threat Severity Over Time")
    chart = alt.Chart(filtered).mark_line(point=True).encode(x="date:T", y="severity:Q", color="threat_type:N")
    st.altair_chart(chart, use_container_width=True)
 
    st.subheader("Threat Event Details")
    st.dataframe(filtered)
 
# ──────────────────────────────────────────────
elif page == "Milestone Updates":
    st.header("Milestone 1 Updates")
    st.markdown("""
<div style="background-color:#1c0009;border:1px solid #4d001a;padding:20px;border-radius:12px;">
<h4 style="color:#ff2f75;">Milestone 1 Checklist</h4>
<ul style="color:#f8e6ec;">
<li>✔ Initial Streamlit app structure created</li>
<li>✔ Industry background section implemented</li>
<li>✔ Stakeholders and user stories added</li>
<li>✔ CTI use case section created</li>
<li>✔ Threat trends section initialized</li>
<li>✔ Critical assets section initialized</li>
<li>✔ Diamond models created</li>
<li>✔ Dashboard starter implemented</li>
<li>✔ Intelligence buy-in section completed</li>
<li>✔ Live Ransomware Intel section added (ransomware.live API)</li>
</ul>
</div>
    """, unsafe_allow_html=True)
 
# ──────────────────────────────────────────────
elif page == "About Team":
    st.header("Team Contributions")
    st.subheader("Ashley Mohamed:")
    st.write("""Created the Streamlit foundation, completed sections "Introduction & Industry Background" and "Intelligence Buy-In", created the README file, and submitted.""")
    st.write("3/26/2026")
    st.subheader("Tiffany Morgan:")
    st.write("""Conducted research on aviation threat trends using industry reports and CTI sources, Identified and ranked critical aviation assets based on impact and vulnerability, Reviewed milestone content for clarity and cohesion before submission""")
    st.write("3/26/2026")
    st.subheader("Mitali Patel:")
    st.write("""Created the Diamond Models for aviation threat scenarios, Selected and validated CTI data sources to support intelligence-driven modeling, Coordinated team communication, meeting scheduling, and instructor updates.""")
    st.write("3/26/2026")
    st.subheader("Elizabeth Powell:")
    st.write("""Developed stakeholder analysis and user stories to guide the app’s design and CTI relevance, Researched existing aviation CTI platforms and summarized their capabilities, Performed final editing and handled the official milestone submission  """)
    st.write("3/26/2026")
    st.subheader("Ricardo Scully:")
    st.write("""Designed the CTI use case and ensured the app’s threat-modeling logic aligned with aviation risks, Structured the threat‑model‑backed design section to support the app’s intelligence workflow, Proofread milestone deliverables for accuracy, grammar, and technical consistency""")
    st.write("3/26/2026")
