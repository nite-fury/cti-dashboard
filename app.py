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
    """Fetches the latest threat intelligence pulses with robust error handling"""
    if not OTX_KEY: 
        st.error("AlienVault API Key is missing from secrets.")
        return pd.DataFrame()
        
    url = "https://otx.alienvault.com/api/v1/search/pulses"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    
    # Using the params dictionary automatically handles URL encoding for spaces
    params = {
        "q": search_term,
        "sort": "-modified",
        "limit": 15
    }
    
    try:
        res = requests.get(url, headers=headers, params=params)
        
        # 1. Check if AlienVault is angry at us (e.g., 403 Forbidden, 429 Rate Limit)
        if res.status_code != 200:
            st.error(f"OTX API Error {res.status_code}: {res.reason}")
            return pd.DataFrame()
            
        data = res.json()
        
        # 2. Check if we actually got results back
        if "results" in data and len(data["results"]) > 0:
            df = pd.DataFrame(data["results"])
            
            # 3. Safely extract data using .get() to prevent KeyErrors if OTX omits a field
            df['Date'] = pd.to_datetime(df.get('modified', pd.Timestamp.now())).dt.strftime('%Y-%m-%d')
            
            # Safely handle tags which might be missing or empty
            if 'tags' in df.columns:
                df['Tags'] = df['tags'].apply(lambda x: ', '.join(x[:5]) if isinstance(x, list) else 'none')
            else:
                df['Tags'] = 'none'
                
            df['Campaign / Report'] = df.get('name', 'Unknown Campaign')
            df['Reporter'] = df.get('author_name', 'Unknown')
            df['IOCs'] = df.get('indicator_count', 0)
            
            return df[['Date', 'Campaign / Report', 'Reporter', 'IOCs', 'Tags']]
            
        else:
            # The search was successful, but no campaigns matched the keyword
            return pd.DataFrame()
            
    except Exception as e: 
        # 4. Print Python errors directly to the UI so we can debug them
        st.error(f"Data Processing Error: {str(e)}")
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
# --- SIDEBAR NAVIGATION & SETTINGS ---
# ==========================================
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/c/c2/Cyber_security_icon.svg/512px-Cyber_security_icon.svg.png", width=50)
    st.title("Navigation")
    
    # The Navigation Menu
    page = st.radio(
        "Select a Module:",
        ["🌐 Global Telemetry (URLhaus)", "🦊 C2 Infrastructure (ThreatFox)", "🚨 Strategic Intel (CISA & APTs)", "🔍 Deep Dive IP Investigation"]
    )
    
    st.markdown("---")
    st.subheader("⚙️ Settings")
    refresh_interval = st.selectbox("Auto-Refresh Rate:", options=[5, 10, 30, 60], format_func=lambda x: f"Every {x} Minutes")

# Initialize the autorefresh
count = st_autorefresh(interval=refresh_interval * 60 * 1000, key="ctirefresh")

# ==========================================
# --- PAGE ROUTING LOGIC ---
# ==========================================

st.caption(f"Last Data Refresh: {pd.Timestamp.now().strftime('%H:%M:%S')}")

# --- PAGE 1: URLHAUS ---
if page == "🌐 Global Telemetry (URLhaus)":
    st.title("🌐 URLhaus: Malware Distribution")
    st.markdown("Live telemetry of malicious URLs and their geographical hosting locations.")
    
    df_u = fetch_urlhaus()
    if not df_u.empty:
        # Give the map the full width of the top screen
        st.map(df_u.dropna(subset=['lat', 'lon']), size=25, color="#ff4b4b", use_container_width=True)
        st.markdown("---")
        
        col1, col2 = st.columns([1, 2])
        with col1:
            tag_counts = df_u['tags'].str.split(', ').explode().value_counts().head(10).reset_index()
            tag_counts.columns = ['Tag', 'Count']
            fig = px.bar(tag_counts, x='Tag', y='Count', color='Count', color_continuous_scale='Reds', title="Top Malware Families")
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.subheader("Recent Host Detections")
            st.dataframe(df_u[['date_added', 'host', 'country', 'tags']].head(15), use_container_width=True)
    else:
        st.info("No URLhaus data available.")

# --- PAGE 2: THREATFOX ---
elif page == "🦊 C2 Infrastructure (ThreatFox)":
    st.title("🦊 ThreatFox: Command & Control")
    st.markdown("Tracking active C2 servers communicating over the public internet.")
    
    df_t = fetch_threatfox()
    if not df_t.empty:
        malware_counts = df_t['malware_printable'].value_counts().head(15).reset_index()
        malware_counts.columns = ['Malware Family', 'Active Servers']
        fig = px.bar(malware_counts, x='Malware Family', y='Active Servers', color='Active Servers', color_continuous_scale='Oranges')
        # Full width chart
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("---")
        st.subheader("Latest C2 Indicators of Compromise")
        st.dataframe(df_t[['first_seen', 'ioc', 'ioc_type', 'malware_printable']].head(20), use_container_width=True)
    else:
        st.info("No ThreatFox data found.")

# --- PAGE 3: STRATEGIC INTEL ---
elif page == "🚨 Strategic Intel (CISA & APTs)":
    st.title("🚨 Strategic Intelligence")
    st.markdown("Monitor high-level actor campaigns and actively exploited network vulnerabilities.")
    
    # Stack them vertically for maximum readability
    st.subheader("🥷 APT Campaign Tracker")
    apt_search = st.text_input("Search Threat Actor or Campaign:", value="APT", placeholder="e.g., Lazarus, MuddyWater...")
    df_apt = fetch_apt_pulses(apt_search)
    if not df_apt.empty:
        st.dataframe(df_apt, use_container_width=True)
    
    st.markdown("---")
    
    st.subheader("🚨 CISA Known Exploited Vulnerabilities")
    df_cisa = fetch_cisa_with_severity()
    if not df_cisa.empty:
        st.dataframe(df_cisa[['dateAdded', 'cveID', 'vulnerabilityName', 'Severity', 'requiredAction']].head(20), use_container_width=True)

# --- PAGE 4: IP INVESTIGATION ---
elif page == "🔍 Deep Dive IP Investigation":
    st.title("🔍 Deep Dive IP Investigation")
    st.markdown("Query suspicious IP addresses against AlienVault OTX.")
    
    # Centered search box layout
    col_left, col_mid, col_right = st.columns([1, 2, 1])
    with col_mid:
        st.markdown("### Target IP Address")
        target_ip = st.text_input("IPv4 Address:", placeholder="e.g., 8.8.8.8", label_visibility="collapsed")
        
        if st.button("Run Global Scan", use_container_width=True):
            if target_ip:
                with st.spinner('Querying Threat Intel Sources...'):
                    otx_data = query_otx_ip(target_ip)
                    
                    st.markdown("---")
                    st.success(f"Scan complete for: **{target_ip}**")
                    
                    if "error" in otx_data: 
                        st.error(otx_data["error"])
                    else:
                        st.metric("Total Associated Threat Pulses", otx_data["pulses"])
                        st.write(f"**Origin Country:** {otx_data['country']}")
            else:
                st.warning("Please enter a valid IP address.")
