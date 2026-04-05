import streamlit as st
import pandas as pd
import requests
import plotly.express as px

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Advanced CTI Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Advanced Cyber Threat Intelligence")

# --- SECRETS MANAGEMENT ---
OTX_KEY = st.secrets.get("OTX_API_KEY", "")
THREATFOX_KEY = st.secrets.get("THREATFOX_KEY", "")

# --- DATA FETCHING FUNCTIONS ---
@st.cache_data(ttl=300)
def fetch_urlhaus():
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    try:
        res = requests.get(url).json()
        if res.get("query_status") == "ok":
            df = pd.DataFrame(res["urls"])
            df['tags'] = df['tags'].apply(lambda x: ', '.join(x) if isinstance(x, list) else 'none')
            return df
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

@st.cache_data(ttl=3600)
def fetch_cisa_kev():
    """Fetches actively exploited vulnerabilities"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url).json()
        df = pd.DataFrame(res["vulnerabilities"])
        df['dateAdded'] = pd.to_datetime(df['dateAdded']).dt.strftime('%Y-%m-%d')
        df = df.sort_values(by='dateAdded', ascending=False)
        return df
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

# --- DASHBOARD UI ---
tab1, tab2, tab3, tab4 = st.tabs(["🌐 URLhaus Feed", "🦊 ThreatFox IOCs", "🚨 CISA KEVs", "🔍 IP Investigation"])

with tab1:
    df_urlhaus = fetch_urlhaus()
    if not df_urlhaus.empty:
        col1, col2 = st.columns([2, 1])
        with col1:
            st.subheader("Top Malware Families")
            tag_counts = df_urlhaus['tags'].str.split(', ').explode().value_counts().head(10).reset_index()
            tag_counts.columns = ['Tag', 'Count']
            fig = px.bar(tag_counts, x='Tag', y='Count', color='Count', color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)
        with col2:
            st.subheader("Recent URL Detections")
            st.dataframe(df_urlhaus[['date_added', 'url', 'tags']].head(10), use_container_width=True)
    else: st.info("No URLhaus data available.")

with tab2:
    df_tf = fetch_threatfox()
    if not df_tf.empty:
        col1, col2 = st.columns([2, 1])
        with col1:
            st.subheader("Active C2 Infrastructure")
            malware_counts = df_tf['malware_printable'].value_counts().head(10).reset_index()
            malware_counts.columns = ['Malware', 'Count']
            fig2 = px.bar(malware_counts, x='Malware', y='Count', color='Count', color_continuous_scale='Oranges')
            st.plotly_chart(fig2, use_container_width=True)
        with col2:
            st.subheader("Latest C2 IOCs")
            st.dataframe(df_tf[['first_seen', 'ioc', 'ioc_type', 'malware_printable']].head(10), use_container_width=True)
    else: st.info("No ThreatFox data found.")

with tab3:
    st.subheader("CISA Known Exploited Vulnerabilities")
    st.markdown("Monitor actively exploited CVEs. A major zero-day here often precedes market movement for cybersecurity vendors.")
    df_cisa = fetch_cisa_kev()
    if not df_cisa.empty:
        st.dataframe(df_cisa[['dateAdded', 'cveID', 'vulnerabilityName', 'requiredAction']].head(50), use_container_width=True)
    else: st.info("Could not fetch CISA KEV catalog.")

with tab4:
    st.subheader("Deep Dive IP Investigation")
    target_ip = st.text_input("Enter IPv4 Address (e.g., 8.8.8.8):")
    if st.button("Investigate"):
        if target_ip:
            with st.spinner('Querying AlienVault OTX...'):
                otx_data = query_otx_ip(target_ip)
                
                st.info("👽 **AlienVault OTX Results**")
                if "error" in otx_data: 
                    st.error(otx_data["error"])
                else:
                    st.metric("Associated Pulses", otx_data["pulses"])
                    st.write(f"**Origin:** {otx_data['country']}")