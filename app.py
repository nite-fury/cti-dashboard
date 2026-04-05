import streamlit as st
import pandas as pd
import requests
import plotly.express as px

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="SOC Single-Pane Dashboard", page_icon="🛡️", layout="wide")

# --- SECRETS MANAGEMENT ---
OTX_KEY = st.secrets.get("OTX_API_KEY", "")
THREATFOX_KEY = st.secrets.get("THREATFOX_KEY", "")
URLHAUS_KEY = st.secrets.get("URLHAUS_KEY", "")

# --- DATA FETCHING FUNCTIONS ---
@st.cache_data(ttl=300)
def fetch_urlhaus_with_geo():
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    headers = {"Auth-Key": URLHAUS_KEY} if URLHAUS_KEY else {}
    try:
        res = requests.get(url, headers=headers).json()
        if res.get("query_status") == "ok":
            df = pd.DataFrame(res["urls"])
            df['tags'] = df['tags'].apply(lambda x: ', '.join(x) if isinstance(x, list) else 'none')
            
            # Geo-location batch logic (Top 100 to avoid rate limits)
            unique_hosts = df['host'].dropna().unique()[:100].tolist()
            geo_url = "http://ip-api.com/batch?fields=query,lat,lon,country"
            geo_res = requests.post(geo_url, json=unique_hosts).json()
            geo_df = pd.DataFrame(geo_res).rename(columns={'query': 'host'})
            
            return pd.merge(df, geo_df, on='host', how='left')
    except Exception as e: pass
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

@st.cache_data(ttl=3600)
def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url).json()
        df = pd.DataFrame(res["vulnerabilities"])
        df['dateAdded'] = pd.to_datetime(df['dateAdded']).dt.strftime('%Y-%m-%d')
        return df.sort_values(by='dateAdded', ascending=False)
    except: pass
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
# --- DASHBOARD LAYOUT & UI ---
# ==========================================

# --- STREAM 1: OTX INVESTIGATION (SIDEBAR) ---
with st.sidebar:
    st.title("🔍 AlienVault OTX")
    st.markdown("Query suspicious IPs from the feeds here.")
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
        else:
            st.warning("Enter an IP first.")

# --- MAIN DASHBOARD ---
st.title("🛡️ SOC Master Dashboard")
st.markdown("Real-time telemetry of malicious infrastructure and vulnerabilities.")

# Top Grid: URLhaus and ThreatFox side-by-side
col1, col2 = st.columns(2)

# --- STREAM 2: URLHAUS (LEFT COLUMN) ---
with col1:
    st.subheader("🌐 URLhaus: Malware Distribution")
    df_urlhaus = fetch_urlhaus_with_geo()
    if not df_urlhaus.empty:
        # Map
        map_data = df_urlhaus.dropna(subset=['lat', 'lon'])
        if not map_data.empty:
            st.map(map_data, size=20, color="#ff4b4b", use_container_width=True)
        # Table
        st.dataframe(df_urlhaus[['date_added', 'host', 'tags']].head(8), use_container_width=True)
    else:
        st.info("URLhaus data unavailable.")

# --- STREAM 3: THREATFOX (RIGHT COLUMN) ---
with col2:
    st.subheader("🦊 ThreatFox: Active C2 Servers")
    df_tf = fetch_threatfox()
    if not df_tf.empty:
        # Chart
        malware_counts = df_tf['malware_printable'].value_counts().head(8).reset_index()
        malware_counts.columns = ['Malware Family', 'Active Servers']
        fig = px.bar(malware_counts, x='Malware Family', y='Active Servers', color='Active Servers', color_continuous_scale='Oranges')
        fig.update_layout(margin=dict(l=0, r=0, t=0, b=0), height=300) # Keep chart compact
        st.plotly_chart(fig, use_container_width=True)
        # Table
        st.dataframe(df_tf[['first_seen', 'ioc', 'malware_printable']].head(8), use_container_width=True)
    else:
        st.info("ThreatFox data unavailable.")

st.markdown("---")

# --- STREAM 4: CISA KEV (BOTTOM ROW, FULL WIDTH) ---
st.subheader("🚨 CISA: Known Exploited Vulnerabilities (KEVs)")
df_cisa = fetch_cisa_kev()
if not df_cisa.empty:
    st.dataframe(df_cisa[['dateAdded', 'cveID', 'vulnerabilityName', 'requiredAction']].head(10), use_container_width=True)
else:
    st.info("CISA KEV catalog unavailable.")
