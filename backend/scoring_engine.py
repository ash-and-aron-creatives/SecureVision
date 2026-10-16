def determine_epss_band(percentile: float):
    if percentile is None: return 'Missing'
    if percentile > 0.95: return 'High (>0.95)'
    if percentile >= 0.20: return 'Med (0.2-0.95)'
    return 'Low (<0.2)'

def determine_cvss_band(cvss: float):
    if cvss is None: return 'Low (0.0-3.9)'
    if cvss >= 9.0: return 'Crit (9.0+)'
    if cvss >= 7.0: return 'High (7.0-8.9)'
    if cvss >= 4.0: return 'Med (4.0-6.9)'
    return 'Low (0.0-3.9)'

def calculate_priority(in_kev: bool, internet_facing: bool, criticality: int, epss_percentile: float, cvss_score: float):
    epss_band = determine_epss_band(epss_percentile)
    cvss_band = determine_cvss_band(cvss_score)
    
    priority = 'Low'
    reason = []
    
    # 1. KEV Rules
    if in_kev:
        reason.append("Vulnerability is actively exploited in the wild (CISA KEV).")
        if internet_facing or criticality >= 4:
            priority = 'Critical'
            if internet_facing: reason.append("Asset is directly exposed to the Internet.")
            if criticality >= 4: reason.append(f"Asset has high business criticality ({criticality}/5).")
        elif not internet_facing and criticality < 4:
            priority = 'High'
            reason.append(f"Asset is internal with lower criticality ({criticality}/5), preventing Critical tier.")
            
    # 2. EPSS High Rules
    elif epss_band == 'High (>0.95)':
        reason.append(f"High predictive probability of exploitation (EPSS Percentile: {epss_percentile*100:.1f}%).")
        if internet_facing or criticality >= 4:
            priority = 'Critical'
            if internet_facing: reason.append("Asset is directly exposed to the Internet.")
            if criticality >= 4: reason.append(f"Asset has high business criticality ({criticality}/5).")
        else:
            priority = 'High'
            reason.append("Asset is internal, preventing Critical tier.")
            
    # 3. CVSS Critical Rules
    elif cvss_band == 'Crit (9.0+)':
        reason.append(f"Base severity is Critical (CVSS: {cvss_score}).")
        if internet_facing:
            priority = 'Critical'
            reason.append("Asset is exposed to the Internet.")
        elif criticality >= 4:
            priority = 'High'
            reason.append(f"Asset has high business criticality ({criticality}/5).")
        else:
            priority = 'Medium'
            reason.append("Internal asset limits maximum severity.")
            
    # 4. EPSS Medium Rules
    elif epss_band == 'Med (0.2-0.95)':
        reason.append(f"Moderate predictive probability of exploitation (EPSS Percentile: {epss_percentile*100:.1f}%).")
        if criticality >= 4:
            priority = 'High'
            reason.append(f"Escalated due to high asset criticality ({criticality}/5).")
        else:
            priority = 'Medium'
            
    # 5. Fallback Rules
    elif cvss_band == 'High (7.0-8.9)':
        priority = 'Medium'
        reason.append(f"Base severity is High (CVSS: {cvss_score}), but lacks active threat intelligence.")
    else:
        priority = 'Low'
        reason.append(f"Low predictive threat and base severity (CVSS: {cvss_score}).")
        
    explanation = " ".join(reason)
    return priority, explanation
