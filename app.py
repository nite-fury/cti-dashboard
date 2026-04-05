import streamlit as st
import pandas as pd
import requests
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

# ==========================================
# --- PAGE CONFIGURATION ---
# ==========================================
st.set_page_config(page_title="SOC Master Dashboard", page_icon="🛡️", layout="wide")

# ==========================================
# --- SECRETS MANAGEMENT ---
# ==========================================
OTX_KEY = st.secrets.get("OTX_API_KEY", "")
THREATFOX_KEY = st.secrets.get("THREATFOX_KEY", "")
URLHAUS_KEY = st.secrets.get("URLHAUS_KEY", "")

# ==========================================
# --- DATA FETCHING FUNCTIONS ---
# ==========================================

@st.cache_data(ttl=3600)
def fetch_cisa_with_severity():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url).json()
        df = pd.DataFrame(res["vulnerabilities"])
        df['Severity'] = "CRITICAL (Exploited)"
        df['dateAdded'] = pd.to_datetime(df['dateAdded']).dt.strftime('%Y-%m-%d')
        # Link directly to the NIST National Vulnerability Database
        df['Reference URL'] = "https://nvd.nist.gov/vuln/detail/" + df['cveID']
        return df.sort_values(by='dateAdded', ascending=False)
    except Exception as e: pass
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
            # Use direct URLhaus reference if available, otherwise fallback to malicious URL
            df['Reference URL'] = df.get('urlhaus_reference', df['url'])
            
            # Geo-location mapping (Batch 100 max)
            unique_hosts = df['host'].dropna().unique()[:100].tolist()
            geo_res = requests.post("http://ip-api.com/batch?fields=query,lat,lon,country", json=unique_hosts).json()
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
            df = pd.DataFrame(res["data"])
            
            # ThreatFox ID linkage
            if 'id' in df.columns:
                # Safely strip any '.0' if Pandas converted the column to floats
                def format_url(val):
                    try:
                        clean_id = str(int(float(val)))
                        return f"https://threatfox.abuse.ch/ioc/{clean_id}"
                    except:
                        return "https://threatfox.abuse.ch/"
                
                df['Reference URL'] = df['id'].apply(format_url)
            else:
                df['Reference URL'] = "https://threatfox.abuse.ch/"
            return df
    except Exception as e: pass
    return pd.DataFrame()

@st.cache_data(ttl=300)
def fetch_apt_pulses(search_term="APT"):
    """Robust APT Fetching with Error Handling"""
    if not OTX_KEY: 
        st.error("AlienVault API Key missing from secrets.")
        return pd.DataFrame()
        
    url = "https://otx.alienvault.com/api/v1/search/pulses"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    params = {"q": search_term, "sort": "-modified", "limit": 15}
    
    try:
        res = requests.get(url, headers=headers, params=params)
        if res.status_code != 200:
            st.error(f"OTX API Error {res.status_code}: {res.reason}")
            return pd.DataFrame()
            
        data = res.json()
        if "results" in data and len(data["results"]) > 0:
            df = pd.DataFrame(data["results"])
            df['Date'] = pd.to_datetime(df.get('modified', pd.Timestamp.now())).dt.strftime('%Y-%m-%d')
            df['Tags'] = df['tags'].apply(lambda x: ', '.join(x[:5]) if isinstance(x, list) else 'none') if 'tags' in df.columns else 'none'
            df['Campaign / Report'] = df.get('name', 'Unknown Campaign')
            df['Reporter'] = df.get('author_name', 'Unknown')
            df['IOCs'] = df.get('indicator_count', 0)
            
            # Pulse web links
            if 'id' in df.columns:
                df['Reference URL'] = "https://otx.alienvault.com/pulse/" + df['id'].astype(str)
            else:
                df['Reference URL'] = "https://otx.alienvault.com/"
                
            return df[['Date', 'Campaign / Report', 'Reporter', 'IOCs', 'Tags', 'Reference URL']]
    except Exception as e: 
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
    st.image("https://img.icons8.com/color/96/000000/security-checked--v1.png", width=60)
    st.title("Navigation")
    
    page = st.radio(
        "Select a Module:",
        ["🌐 Global Telemetry (URLhaus)", "🦊 C2 Infrastructure (ThreatFox)", "🚨 Strategic Intel (CISA & APTs)", "🔍 Deep Dive IP Investigation"]
    )
    
    st.markdown("---")
    st.subheader("⚙️ Settings")
    refresh_interval = st.selectbox("Auto-Refresh Rate:", options=[5, 10, 30, 60], format_func=lambda x: f"Every {x} Minutes")

# Initialize autorefresh
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
            st.dataframe(
                df_u[['date_added', 'host', 'country', 'tags', 'Reference URL']].head(15), 
                use_container_width=True,
                column_config={"Reference URL": st.column_config.LinkColumn("Source Link", display_text="View intel ↗")}
            )
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
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("---")
        
        st.subheader("Latest C2 Indicators of Compromise")
        st.dataframe(
            df_t[['first_seen', 'ioc', 'ioc_type', 'malware_printable', 'Reference URL']].head(20), 
            use_container_width=True,
            column_config={"Reference URL": st.column_config.LinkColumn("Source Link", display_text="View on ThreatFox ↗")}
        )
    else:
        st.info("No ThreatFox data found.")

# --- PAGE 3: STRATEGIC INTEL ---
elif page == "🚨 Strategic Intel (CISA & APTs)":
    st.title("🚨 Strategic Intelligence")
    st.markdown("Monitor high-level actor campaigns and actively exploited network vulnerabilities.")
    
    st.subheader("🥷 APT Campaign Tracker")
    apt_search = st.text_input("Search Threat Actor or Campaign:", value="APT", placeholder="e.g., Lazarus, MuddyWater...")
    df_apt = fetch_apt_pulses(apt_search)
    
    if not df_apt.empty:
        st.dataframe(
            df_apt, 
            use_container_width=True,
            column_config={"Reference URL": st.column_config.LinkColumn("Source Link", display_text="Read Report ↗")}
        )
        
    st.markdown("---")
    
    st.subheader("🚨 CISA Known Exploited Vulnerabilities")
    df_cisa = fetch_cisa_with_severity()
    if not df_cisa.empty:
        st.dataframe(
            df_cisa[['dateAdded', 'cveID', 'vulnerabilityName', 'Severity', 'requiredAction', 'Reference URL']].head(20), 
            use_container_width=True,
            column_config={"Reference URL": st.column_config.LinkColumn("Source Link", display_text="View on NIST ↗")}
        )

# --- PAGE 4: IP INVESTIGATION ---
elif page == "🔍 Deep Dive IP Investigation":
    st.title("🔍 Deep Dive IP Investigation")
    st.markdown("Query suspicious IP addresses against AlienVault OTX.")
    
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
