import streamlit as st
import pandas as pd
import requests
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="SOC Master Dashboard", page_icon="🛡️", layout="wide")

# --- SECRETS MANAGEMENT ---
OTX_KEY = st.secrets.get("OTX_API_KEY", "")
THREATFOX_KEY = st.secrets.get("THREATFOX_KEY", "")
URLHAUS_KEY = st.secrets.get("URLHAUS_KEY", "")

# --- 🔄 REFRESH LOGIC ---
st.sidebar.title("⚙️ Dashboard Settings")
refresh_interval = st.sidebar.selectbox(
    "Set Refresh Rate:",
    options=[5, 10, 30, 60],
    format_func=lambda x: f"Every {x} Minutes"
)
count = st_autorefresh(interval=refresh_interval * 60 * 1000, key="ctirefresh")

# --- DATA FETCHING FUNCTIONS ---
@st.cache_data(ttl=3600)
def fetch_cisa_with_severity():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url).json()
        df = pd.DataFrame(res["vulnerabilities"])
        df['Severity'] = "CRITICAL (Exploited)"
        df['dateAdded'] = pd.to_datetime(df['dateAdded']).dt.strftime('%Y-%m-%d')
        return df.sort_values(by='dateAdded', ascending=False)
    except: pass
    return pd.DataFrame()

@st.cache_data(ttl=300)
def fetch_urlhaus():
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    headers = {"Auth-Key": URLHAUS_KEY} if URLHAUS_KEY else {}
    try:
        res = requests.get(url, headers=headers).json()
        if res.get("query_status") == "ok":
            df = pd.DataFrame(res["urls"])
            df['tags'] = df['tags'].apply(lambda x: ', '.join(x) if isinstance(x, list) else 'none')
            unique_hosts = df['host'].dropna().unique()[:100].tolist()
            geo_res = requests.post("http://ip-api.com/batch?fields=query,lat,lon,country", json=unique_hosts).json()
            geo_df = pd.DataFrame(geo_res).rename(columns={'query': 'host'})
            return pd.merge(df, geo_df, on='host', how='left')
    except: pass
    return pd.DataFrame()

@st.cache_data(ttl=300)
def fetch_threatfox():
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": THREATFOX_KEY} if THREATFOX_KEY else {}
    try:
        res = requests.post(url, json={"query": "get_iocs", "days": 1}, headers=headers).json()
        if res.get("query_status") == "ok":
            return pd.DataFrame(res["data"])
    except: pass
    return pd.DataFrame()

@st.cache_data(ttl=300)
def fetch_apt_pulses(search_term="APT"):
    """Fetches the latest threat intelligence pulses matching an APT search"""
    if not OTX_KEY: return pd.DataFrame()
    # Query OTX for the latest pulses modified containing the search term
    url = f"https://otx.alienvault.com/api/v1/search/pulses?q={search_term}&sort=-modified&limit=15"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        res = requests.get(url, headers=headers).json()
        if "results" in res and res["results"]:
            df = pd.DataFrame(res["results"])
            df['Date'] = pd.to_datetime(df['modified']).dt.strftime('%Y-%m-%d')
            df['Tags'] = df['tags'].apply(lambda x: ', '.join(x[:5]) if isinstance(x, list) else 'none')
            # Rename columns for the UI
            df = df.rename(columns={'name': 'Campaign / Report', 'author_name': 'Reporter', 'indicator_count': 'IOCs'})
            return df[['Date', 'Campaign / Report', 'Reporter', 'IOCs', 'Tags']]
    except Exception as e: 
        print(e)
    return pd.DataFrame()

def query_otx_ip(ip_address):
    if not OTX_KEY: return {"error": "AlienVault API Key missing in secrets"}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {"pulses": data.get("pulse_info", {}).get("count", 0), "country": data.get("base_indicator", {}).get("country", "Unknown")}
        return {"error": f"HTTP Status {response.status_code}"}
    except Exception as e: return {"error": str(e)}

# ==========================================
# --- DASHBOARD LAYOUT ---
# ==========================================

# Sidebar OTX Tool
with st.sidebar:
    st.markdown("---")
    st.subheader("🔍 IP Investigation")
    target_ip = st.text_input("Enter IPv4 Address:")
    if st.button("Investigate IP"):
        if target_ip:
            with st.spinner('Querying OTX...'):
                otx_data = query_otx_ip(target_ip)
                if "error" in otx_data: 
                    st.error(otx_data["error"])
                else:
                    st.success("Target Analyzed")
                    st.metric("Associated Threat Pulses", otx_data["pulses"])
                    st.write(f"**Origin Country:** {otx_data['country']}")

# Main Dashboard Header
st.title("🛡️ SOC Master Dashboard")
st.caption(f"Last Refresh: {pd.Timestamp.now().strftime('%H:%M:%S')} (Interval: {refresh_interval}m)")

# --- TOP ROW: TACTICAL INTEL ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("🌐 URLhaus Telemetry")
    df_u = fetch_urlhaus()
    if not df_u.empty:
        st.map(df_u.dropna(subset=['lat', 'lon']), size=20, color="#ff4b4b")
        st.dataframe(df_u[['host', 'country', 'tags']].head(5), use_container_width=True)

with col2:
    st.subheader("🦊 ThreatFox C2 Feed")
    df_t = fetch_threatfox()
    if not df_t.empty:
        st.dataframe(df_t[['ioc', 'ioc_type', 'malware_printable']].head(10), use_container_width=True)

st.markdown("---")

# --- BOTTOM ROW: STRATEGIC INTEL ---
col3, col4 = st.columns(2)

with col3:
    st.subheader("🚨 Actively Exploited CVEs (CISA)")
    df_cisa = fetch_cisa_with_severity()
    if not df_cisa.empty:
        st.dataframe(
            df_cisa[['dateAdded', 'cveID', 'vulnerabilityName', 'Severity']].head(15), 
            use_container_width=True
        )

with col4:
    st.subheader("🥷 APT Intel & Campaign Tracker")
    # Live Search Bar for APTs
    apt_search = st.text_input("Search Actor, Campaign, or Region:", value="APT", placeholder="e.g., Lazarus, Cozy Bear, APT29...")
    
    df_apt = fetch_apt_pulses(apt_search)
    if not df_apt.empty:
        st.dataframe(df_apt, use_container_width=True)
    else:
        st.info(f"No recent reports found for '{apt_search}'. Check your OTX API key.")
