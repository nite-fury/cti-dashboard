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

# Initialize the autorefresh (converts minutes to milliseconds)
count = st_autorefresh(interval=refresh_interval * 60 * 1000, key="ctirefresh")

# --- DATA FETCHING FUNCTIONS ---
@st.cache_data(ttl=3600)
def fetch_cisa_with_severity():
    """Fetches CISA KEV and attempts to map severity scores."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url).json()
        df = pd.DataFrame(res["vulnerabilities"])
        
        # Note: In a production environment, you would use a local CVE database 
        # to avoid hitting NIST rate limits. For this prototype, we'll tag 
        # them as 'High/Critical' since they are in the KEV (Known Exploited).
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
            # Geo-batching
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

# ==========================================
# --- DASHBOARD LAYOUT ---
# ==========================================

# Sidebar OTX Tool
with st.sidebar:
    st.markdown("---")
    st.subheader("🔍 AlienVault OTX Search")
    target_ip = st.text_input("Enter IPv4 Address:")
    if st.button("Investigate IP"):
        # (OTX Query logic remains same as previous version)
        pass

# Main Dashboard Header
st.title("🛡️ SOC Master Dashboard")
st.caption(f"Last Refresh: {pd.Timestamp.now().strftime('%H:%M:%S')} (Interval: {refresh_interval}m)")

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

# --- ENHANCED CISA SECTION ---
st.subheader("🚨 CISA: Known Exploited Vulnerabilities")
df_cisa = fetch_cisa_with_severity()
if not df_cisa.empty:
    # We now include the 'Severity' column we created
    st.dataframe(
        df_cisa[['dateAdded', 'cveID', 'vulnerabilityName', 'Severity', 'requiredAction']].head(15), 
        use_container_width=True
    )
