import streamlit as st
import pandas as pd
import requests
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
import ipaddress
import base64
import whois
from ipwhois import IPWhois

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
VT_KEY = st.secrets.get("VT_API_KEY", "")

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
            df['Reference URL'] = df.get('urlhaus_reference', df['url'])
            
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
            if 'id' in df.columns:
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
    if not OTX_KEY: return pd.DataFrame()
    url = "https://otx.alienvault.com/api/v1/search/pulses"
    headers = {"X-OTX-API-KEY": OTX_KEY}
    params = {"q": search_term, "sort": "-modified", "limit": 15}
    try:
        res = requests.get(url, headers=headers, params=params)
        if res.status_code == 200:
            data = res.json()
            if "results" in data and len(data["results"]) > 0:
                df = pd.DataFrame(data["results"])
                df['Date'] = pd.to_datetime(df.get('modified', pd.Timestamp.now())).dt.strftime('%Y-%m-%d')
                df['Tags'] = df['tags'].apply(lambda x: ', '.join(x[:5]) if isinstance(x, list) else 'none') if 'tags' in df.columns else 'none'
                df['Campaign / Report'] = df.get('name', 'Unknown Campaign')
                df['Reporter'] = df.get('author_name', 'Unknown')
                df['IOCs'] = df.get('indicator_count', 0)
                
                if 'id' in df.columns:
                    df['Reference URL'] = "https://otx.alienvault.com/pulse/" + df['id'].astype(str)
                else:
                    df['Reference URL'] = "https://otx.alienvault.com/"
                return df[['Date', 'Campaign / Report', 'Reporter', 'IOCs', 'Tags', 'Reference URL']]
    except Exception as e: pass
    return pd.DataFrame()

# ==========================================
# --- ENRICHMENT ENGINE FUNCTIONS ---
# ==========================================

def check_indicator_type(indicator):
    try:
        ipaddress.ip_address(indicator)
        return "IP"
    except ValueError:
        return "URL/DOMAIN"

def query_virustotal(indicator, ind_type):
    if not VT_KEY: return {"error": "VirusTotal API Key missing"}
    headers = {"x-apikey": VT_KEY}
    try:
        if ind_type == "IP":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
        else:
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0) + stats.get("undetected", 0),
                "total_engines": sum(stats.values())
            }
        elif response.status_code == 404:
            return {"error": "Indicator not found in VirusTotal database."}
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e: return {"error": str(e)}

def query_whois(indicator, ind_type):
    if ind_type == "IP":
        try:
            obj = IPWhois(indicator)
            res = obj.lookup_rdap()
            return {
                "type": "IP",
                "org": res.get("asn_description", "Unknown"),
                "country": res.get("asn_country_code", "Unknown"),
                "ip_block": res.get("network", {}).get("cidr", "Unknown")
            }
        except Exception as e: 
            return {"error": f"IP WHOIS failed: {str(e)}"}
    else:
        try:
            w = whois.whois(indicator)
            return {
                "type": "Domain",
                "registrar": w.registrar or "Unknown",
                "creation_date": str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
                "country": w.country or "Unknown"
            }
        except Exception as e: 
            return {"error": "WHOIS lookup failed or domain is protected."}

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

# --- NEW: Abuse.ch Enrichment Functions ---
def query_urlhaus_indicator(indicator):
    """Checks if a domain/IP is known to host malware payloads"""
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    data = {"host": indicator}
    # URLhaus host endpoint often accepts standard POST form data
    try:
        res = requests.post(url, data=data).json()
        if res.get("query_status") == "ok":
            urls = res.get("urls", [])
            return {"hit": True, "count": len(urls), "first_seen": res.get("firstseen", "Unknown")}
        else:
            return {"hit": False, "msg": "Clean. No known payload hosting."}
    except Exception as e:
        return {"error": str(e)}

def query_threatfox_indicator(indicator):
    """Checks if a domain/IP is a known Command & Control (C2) node"""
    url = "https://threatfox-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": THREATFOX_KEY} if THREATFOX_KEY else {}
    payload = {"query": "search_ioc", "search_term": indicator}
    try:
        res = requests.post(url, json=payload, headers=headers).json()
        if res.get("query_status") == "ok":
            data = res.get("data", [])
            # Extract unique malware family names associated with this indicator
            malware = list(set([item.get("malware_printable", "Unknown") for item in data]))
            return {"hit": True, "count": len(data), "malware": malware}
        else:
            return {"hit": False, "msg": "Clean. No known C2 activity."}
    except Exception as e:
        return {"error": str(e)}

# ==========================================
# --- SIDEBAR NAVIGATION & SETTINGS ---
# ==========================================

with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-checked--v1.png", width=60)
    st.title("Navigation")
    
    page = st.radio(
        "Select a Module:",
        ["🌐 Global Telemetry (URLhaus)", "🦊 C2 Infrastructure (ThreatFox)", "🚨 Strategic Intel (CISA & APTs)", "🔬 Multi-Source Enrichment"]
    )
    
    st.markdown("---")
    st.subheader("⚙️ Settings")
    refresh_interval = st.selectbox("Auto-Refresh Rate:", options=[5, 10, 30, 60], format_func=lambda x: f"Every {x} Minutes")

count = st_autorefresh(interval=refresh_interval * 60 * 1000, key="ctirefresh")
st.caption(f"Last Data Refresh: {pd.Timestamp.now().strftime('%H:%M:%S')}")

# ==========================================
# --- PAGE ROUTING LOGIC ---
# ==========================================

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

# --- PAGE 4: MULTI-SOURCE ENRICHMENT ---
elif page == "🔬 Multi-Source Enrichment":
    st.title("🔬 Multi-Source Indicator Enrichment")
    st.markdown("Simultaneously query VirusTotal, AlienVault, WHOIS, URLhaus, and ThreatFox.")
    
    col_left, col_mid, col_right = st.columns([1, 2, 1])
    with col_mid:
        st.markdown("### Target Indicator")
        target_indicator = st.text_input("Enter IP, Domain, or URL:", placeholder="e.g., 8.8.8.8 or evil-domain.com", label_visibility="collapsed")
        
        if st.button("Run Global Scan", use_container_width=True):
            if target_indicator:
                ind_type = check_indicator_type(target_indicator)
                st.markdown("---")
                st.success(f"Scanning **{ind_type}**: {target_indicator}")
                
                with st.spinner('Querying Threat Intel Sources...'):
                    # Fetching from all 5 sources
                    vt_data = query_virustotal(target_indicator, ind_type)
                    otx_data = query_otx_ip(target_indicator) if ind_type == "IP" else {"error": "OTX IP check skipped for domain."}
                    whois_data = query_whois(target_indicator, ind_type)
                    urlhaus_data = query_urlhaus_indicator(target_indicator)
                    threatfox_data = query_threatfox_indicator(target_indicator)
                    
                    # --- ROW 1: Broad Intelligence ---
                    res_col1, res_col2, res_col3 = st.columns(3)
                    
                    with res_col1:
                        st.info("🦠 **VirusTotal**")
                        if "error" in vt_data:
                            st.error(vt_data["error"])
                        else:
                            mal_count = vt_data['malicious']
                            if mal_count > 0:
                                st.error(f"**{mal_count} / {vt_data['total_engines']}** Engines flagged")
                            else:
                                st.success(f"**0 / {vt_data['total_engines']}** Engines flagged. Clean.")
                            st.write(f"Suspicious: {vt_data['suspicious']}")
                            
                    with res_col2:
                        st.info("👽 **AlienVault OTX**")
                        if "error" in otx_data:
                            if "skipped" in otx_data["error"]:
                                st.write("*(OTX domain check disabled)*")
                            else:
                                st.error(otx_data["error"])
                        else:
                            st.metric("Associated Pulses", otx_data["pulses"])
                            st.write(f"**Origin:** {otx_data['country']}")
                            
                    with res_col3:
                        st.info("🌐 **Registration / Routing**")
                        if "error" in whois_data:
                            st.warning(whois_data["error"])
                        else:
                            if whois_data["type"] == "Domain":
                                st.write(f"**Registrar:** {whois_data['registrar']}")
                                st.write(f"**Registered:** {whois_data['creation_date'][:10] if whois_data['creation_date'] else 'Unknown'}")
                                st.write(f"**Country:** {whois_data['country']}")
                            else:
                                st.write(f"**ISP / Org:** {whois_data['org']}")
                                st.write(f"**Country:** {whois_data['country']}")
                                st.write(f"**IP Block:** `{whois_data['ip_block']}`")
                                
                    st.markdown("---")
                    st.markdown("#### 🇨🇭 Abuse.ch Community Intel")
                    
                    # --- ROW 2: Specific Community Intel ---
                    res_col4, res_col5 = st.columns(2)
                    
                    with res_col4:
                        st.info("🌐 **URLhaus (Malware Payload Host)**")
                        if "error" in urlhaus_data:
                            st.error(urlhaus_data["error"])
                        elif urlhaus_data.get("hit"):
                            st.error(f"⚠️ **Known Malware Host**")
                            st.write(f"**Historical URLs Hosted:** {urlhaus_data['count']}")
                            st.write(f"**First Seen:** {urlhaus_data['first_seen']}")
                        else:
                            st.success(urlhaus_data["msg"])
                            
                    with res_col5:
                        st.info("🦊 **ThreatFox (Command & Control)**")
                        if "error" in threatfox_data:
                            st.error(threatfox_data["error"])
                        elif threatfox_data.get("hit"):
                            st.error(f"⚠️ **Known C2 Infrastructure**")
                            st.write(f"**Related IOCs:** {threatfox_data['count']}")
                            st.write(f"**Associated Malware:** {', '.join(threatfox_data['malware'])}")
                        else:
                            st.success(threatfox_data["msg"])
            else:
                st.warning("Please enter a valid IP or Domain.")
