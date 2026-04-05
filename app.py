# --- PAGE 4: MULTI-SOURCE INDICATOR ENRICHMENT ---
elif page == "🔍 Deep Dive IP Investigation": # You can rename this in the sidebar if you wish
    st.title("🔬 Multi-Source Indicator Enrichment")
    st.markdown("Simultaneously query VirusTotal, AlienVault OTX, and WHOIS records.")
    
    col_left, col_mid, col_right = st.columns([1, 2, 1])
    with col_mid:
        st.markdown("### Target Indicator")
        target_indicator = st.text_input("Enter IP, Domain, or URL:", placeholder="e.g., 8.8.8.8 or evil-domain.com", label_visibility="collapsed")
        
        if st.button("Run Global Scan", use_container_width=True):
            if target_indicator:
                # 1. Determine Type
                ind_type = check_indicator_type(target_indicator)
                st.markdown("---")
                st.success(f"Scanning **{ind_type}**: {target_indicator}")
                
                with st.spinner('Querying Threat Intel Sources...'):
                    # 2. Fetch Data from all sources simultaneously
                    vt_data = query_virustotal(target_indicator, ind_type)
                    otx_data = query_otx_ip(target_indicator) if ind_type == "IP" else {"error": "OTX IP check skipped for domain."}
                    whois_data = query_whois(target_indicator, ind_type)
                    
                    # 3. Layout the Results in a 3-Column Grid
                    res_col1, res_col2, res_col3 = st.columns(3)
                    
                    # --- VIRUSTOTAL RESULTS ---
                    with res_col1:
                        st.info("🦠 **VirusTotal**")
                        if "error" in vt_data:
                            st.error(vt_data["error"])
                        else:
                            # Color code the result metric
                            mal_count = vt_data['malicious']
                            if mal_count > 0:
                                st.error(f"**{mal_count} / {vt_data['total_engines']}** Engines flagged as Malicious")
                            else:
                                st.success(f"**0 / {vt_data['total_engines']}** Engines flagged. Clean.")
                            st.write(f"Suspicious: {vt_data['suspicious']}")
                            
                    # --- ALIENVAULT OTX RESULTS ---
                    with res_col2:
                        st.info("👽 **AlienVault OTX**")
                        if "error" in otx_data:
                            if "skipped" in otx_data["error"]:
                                st.write("*(Domain search currently requires separate OTX function)*")
                            else:
                                st.error(otx_data["error"])
                        else:
                            st.metric("Associated Pulses", otx_data["pulses"])
                            st.write(f"**Origin:** {otx_data['country']}")
                            
                    # --- WHOIS RESULTS ---
                    with res_col3:
                        st.info("🌐 **WHOIS Record**")
                        if "error" in whois_data:
                            st.warning(whois_data["error"])
                        else:
                            st.write(f"**Registrar:** {whois_data['registrar']}")
                            st.write(f"**Registered:** {whois_data['creation_date'][:10] if whois_data['creation_date'] else 'Unknown'}")
                            st.write(f"**Country:** {whois_data['country']}")
            else:
                st.warning("Please enter a valid IP or Domain.")
