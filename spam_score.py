import csv
import json
from collections import Counter
import math
import re

# ============================================================================
# ENHANCED SPAM SCORING SYSTEM
# ============================================================================

def load_data(filename):
    """Load CSV data"""
    with open(filename, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)

def save_data(filename, rows, fieldnames):
    """Save CSV data"""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def safe_float(value, default=0):
    """Safely convert to float"""
    try:
        if value is None or value == '' or str(value).lower() in ['unknown', 'n/a', 'none', '-']:
            return None
        return float(value)
    except:
        return None

def safe_int(value, default=0):
    """Safely convert to int"""
    val = safe_float(value, default)
    return int(val) if val is not None else None

def is_yes(value):
    """Check if value is Yes"""
    if value is None:
        return None
    return str(value).strip().lower() == 'yes'

def is_no(value):
    """Check if value is No"""
    if value is None:
        return None
    return str(value).strip().lower() == 'no'

def has_data(value):
    """Check if field has actual data"""
    if value is None or value == '':
        return False
    if str(value).lower() in ['unknown', 'n/a', 'none', '-', 'null']:
        return False
    return True

# ============================================================================
# DOMAIN ANALYSIS FUNCTIONS
# ============================================================================

def calculate_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text or len(text) == 0:
        return 0
    
    # Remove dots and common separators for cleaner entropy calculation
    text = text.replace('.', '').replace('-', '').replace('_', '')
    
    if len(text) == 0:
        return 0
    
    # Calculate character frequency
    char_freq = {}
    for char in text:
        char_freq[char] = char_freq.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0
    text_len = len(text)
    for count in char_freq.values():
        probability = count / text_len
        entropy -= probability * math.log2(probability)
    
    return entropy

def calculate_digit_ratio(text):
    """Calculate ratio of digits in text"""
    if not text or len(text) == 0:
        return 0
    
    digits = sum(1 for c in text if c.isdigit())
    return digits / len(text)

def calculate_hyphen_ratio(text):
    """Calculate ratio of hyphens in text"""
    if not text or len(text) == 0:
        return 0
    
    hyphens = text.count('-')
    return hyphens / len(text)

def calculate_special_char_count(text):
    """Count special characters (non-alphanumeric, excluding dots)"""
    if not text:
        return 0
    
    # Count characters that are not letters, digits, dots, or hyphens
    special = sum(1 for c in text if not c.isalnum() and c not in ['.', '-', '_'])
    return special

def analyze_domain_structure(domain):
    """Analyze domain name structure"""
    if not domain:
        return {
            'length': 0,
            'entropy': 0,
            'digit_ratio': 0,
            'hyphen_ratio': 0,
            'special_chars': 0,
            'subdomain_count': 0
        }
    
    domain_lower = domain.lower()
    
    # Remove www. if present
    if domain_lower.startswith('www.'):
        domain_lower = domain_lower[4:]
    
    # Count subdomains
    parts = domain_lower.split('.')
    subdomain_count = max(0, len(parts) - 2)  # -2 for domain.tld
    
    # Get main domain (without TLD) for analysis
    if len(parts) >= 2:
        main_domain = '.'.join(parts[:-1])  # Everything except last part (TLD)
    else:
        main_domain = domain_lower
    
    return {
        'length': len(domain_lower),
        'entropy': calculate_entropy(main_domain),
        'digit_ratio': calculate_digit_ratio(main_domain),
        'hyphen_ratio': calculate_hyphen_ratio(main_domain),
        'special_chars': calculate_special_char_count(main_domain),
        'subdomain_count': subdomain_count
    }

def check_nameserver_reputation(nameserver):
    """Check if nameserver is from known provider"""
    if not nameserver:
        return 'unknown'
    
    ns_lower = str(nameserver).lower()
    
    # Trusted providers
    trusted = [
        'cloudflare', 'google', 'aws', 'amazon', 'azure', 'microsoft',
        'godaddy', 'namecheap', 'digitalocean', 'linode', 'route53',
        'ns1.com', 'dnsimple', 'dnsmadeeasy', 'ultradns', 'akamai'
    ]
    
    # Suspicious providers
    suspicious = [
        'freenom', '000webhost', 'hostinger', 'beget', 'afraid',
        'duckdns', 'noip', 'dynu', 'freedns', 'tempns'
    ]
    
    for provider in trusted:
        if provider in ns_lower:
            return 'trusted'
    
    for provider in suspicious:
        if provider in ns_lower:
            return 'suspicious'
    
    return 'unknown'

def check_registrar_reputation(registrar):
    """Check registrar reputation"""
    if not registrar:
        return 'unknown'
    
    reg_lower = str(registrar).lower()
    
    trusted = [
        'godaddy', 'namecheap', 'google', 'amazon', 'cloudflare',
        'enom', 'tucows', 'network solutions', 'gandi', 'hover',
        'dreamhost', 'bluehost', 'name.com', 'dynadot', 'porkbun'
    ]
    
    suspicious = [
        'freenom', 'cheapdomains', 'anonymous', 'privacy', 'offshore',
        'bitcoinregistrar', 'instantdomains'
    ]
    
    for provider in trusted:
        if provider in reg_lower:
            return 'trusted'
    
    for provider in suspicious:
        if provider in reg_lower:
            return 'suspicious'
    
    return 'unknown'

def check_asn_reputation(asn_org):
    """Check ASN/hosting reputation"""
    if not asn_org:
        return 'unknown'
    
    asn_lower = str(asn_org).lower()
    
    trusted = [
        'google', 'amazon', 'microsoft', 'cloudflare', 'akamai',
        'digitalocean', 'linode', 'ovh', 'hetzner', 'vultr',
        'oracle', 'alibaba', 'fastly', 'rackspace'
    ]
    
    suspicious = [
        'bulletproof', 'darkserver', 'vpsproxy', 'cheapvps',
        'tor', 'proxy', 'anonymous', 'offshore'
    ]
    
    for provider in trusted:
        if provider in asn_lower:
            return 'trusted'
    
    for provider in suspicious:
        if provider in asn_lower:
            return 'suspicious'
    
    return 'unknown'

# ============================================================================
# MAIN SCORING LOGIC
# ============================================================================

def score_domain(row):
    """
    Score a domain from 0-100
    0 = Definitely spam/malicious
    100 = Definitely legitimate
    """
    
    score = 50.0
    flags = []
    evidence = []
    
    # ========================================================================
    # CRITICAL RED FLAGS (Instant disqualification)
    # ========================================================================
    
    if is_yes(row.get('Blacklisted')):
        return 0, ["BLACKLISTED"], ["Domain is blacklisted"]
    
    if is_yes(row.get('Phishing_Found')):
        return 0, ["PHISHING"], ["Phishing site detected"]
    
    if is_yes(row.get('Malware_Found')):
        return 0, ["MALWARE"], ["Malware detected"]
    
    if is_yes(row.get('SSL_Expired')):
        return 5, ["SSL_EXPIRED"], ["SSL certificate expired"]
    
    # ========================================================================
    # DOMAIN AGE (Very strong signal)
    # ========================================================================
    
    age_days = safe_int(row.get('WHOIS_AgeDays'))
    if age_days is not None:
        if age_days < 7:
            score -= 35
            flags.append("BRAND_NEW_<7D")
            evidence.append(f"Domain only {age_days} days old")
        elif age_days < 30:
            score -= 25
            flags.append("VERY_NEW_<30D")
            evidence.append(f"Domain {age_days} days old")
        elif age_days < 90:
            score -= 15
            flags.append("NEW_<90D")
            evidence.append(f"Domain {age_days} days old")
        elif age_days < 180:
            score -= 8
            flags.append("RECENT_<180D")
        elif age_days > 1825:  # 5 years
            score += 25
            flags.append("MATURE_5YRS+")
            evidence.append(f"Domain {int(age_days/365)} years old")
        elif age_days > 365:
            score += 15
            flags.append("ESTABLISHED_1YR+")
            evidence.append(f"Domain {age_days} days old")
    else:
        score -= 5
        flags.append("AGE_UNKNOWN")
    
    # ========================================================================
    # DOMAIN STRUCTURE ANALYSIS
    # ========================================================================
    
    domain = str(row.get('ParentDomain', ''))
    structure = analyze_domain_structure(domain)
    
    # Domain length
    if structure['length'] > 50:
        score -= 15
        flags.append("VERY_LONG_DOMAIN")
        evidence.append(f"Domain length {structure['length']} chars")
    elif structure['length'] > 35:
        score -= 8
        flags.append("LONG_DOMAIN")
    
    # Entropy (randomness)
    entropy = safe_float(row.get('Entropy'))
    if entropy is None and structure['entropy'] > 0:
        entropy = structure['entropy']
    
    if entropy is not None:
        if entropy > 4.5:
            score -= 18
            flags.append("VERY_HIGH_ENTROPY")
            evidence.append(f"High randomness (entropy {entropy:.2f})")
        elif entropy > 4.0:
            score -= 10
            flags.append("HIGH_ENTROPY")
    
    # Digit ratio
    digit_ratio = safe_float(row.get('DigitsRatio'))
    if digit_ratio is None and structure['digit_ratio'] > 0:
        digit_ratio = structure['digit_ratio']
    
    if digit_ratio is not None:
        if digit_ratio > 0.5:
            score -= 15
            flags.append("HIGH_DIGITS")
            evidence.append(f"Many digits ({digit_ratio*100:.0f}%)")
        elif digit_ratio > 0.3:
            score -= 8
            flags.append("MODERATE_DIGITS")
    
    # Hyphen ratio
    hyphen_ratio = safe_float(row.get('HyphenRatio'))
    if hyphen_ratio is None and structure['hyphen_ratio'] > 0:
        hyphen_ratio = structure['hyphen_ratio']
    
    if hyphen_ratio is not None:
        if hyphen_ratio > 0.3:
            score -= 12
            flags.append("MANY_HYPHENS")
            evidence.append(f"Many hyphens ({hyphen_ratio*100:.0f}%)")
        elif hyphen_ratio > 0.2:
            score -= 6
            flags.append("SOME_HYPHENS")
    
    # Special characters
    special_count = safe_int(row.get('SpecialCharsCount'))
    if special_count is None and structure['special_chars'] > 0:
        special_count = structure['special_chars']
    
    if special_count is not None and special_count > 3:
        score -= 10
        flags.append("SPECIAL_CHARS")
        evidence.append(f"{special_count} special characters")
    
    # Subdomain count
    subdomain_count = safe_int(row.get('SubdomainCount'))
    if subdomain_count is None and structure['subdomain_count'] > 0:
        subdomain_count = structure['subdomain_count']
    
    if subdomain_count is not None and subdomain_count > 3:
        score -= 10
        flags.append("MANY_SUBDOMAINS")
        evidence.append(f"{subdomain_count} subdomains")
    
    # ========================================================================
    # SUSPICIOUS PATTERNS IN DOMAIN
    # ========================================================================
    
    domain_lower = domain.lower()
    
    # Suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.club', '.online', '.site', '.win', 
                       '.loan', '.click', '.link',
                       '.download', '.zip', '.review', '.stream', '.trade', '.vip', '.fun']
    if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
        score -= 20
        flags.append("SUSPICIOUS_TLD")
        evidence.append("Uses suspicious TLD")
    
    # Good TLDs
    good_tlds = ['.com', '.org', '.edu', '.gov', '.net', '.co.uk', '.de', '.fr']
    if any(domain_lower.endswith(tld) for tld in good_tlds):
        score += 5
        flags.append("STANDARD_TLD")
    
    # Suspicious keywords
    suspicious_keywords = ['verify', 'secure', 'account', 'update', 'confirm', 
                          'suspended', 'locked', 'login', 'banking', 'paypal',
                          'signin', 'password', 'urgent', 'action', 'validate']
    keyword_count = sum(1 for kw in suspicious_keywords if kw in domain_lower)
    if keyword_count > 0:
        penalty = min(keyword_count * 10, 25)
        score -= penalty
        flags.append(f"SUSPICIOUS_KW_{keyword_count}")
        evidence.append(f"{keyword_count} suspicious keywords in domain")
    
    # ========================================================================
    # INFRASTRUCTURE & NAMESERVERS
    # ========================================================================
    
    # Nameserver reputation
    ns_records = row.get('NS_Records')
    if has_data(ns_records):
        ns_rep = check_nameserver_reputation(ns_records)
        if ns_rep == 'trusted':
            score += 10
            flags.append("TRUSTED_NS")
        elif ns_rep == 'suspicious':
            score -= 15
            flags.append("SUSPICIOUS_NS")
            evidence.append("Suspicious nameserver")
        else:
            score -= 3
            flags.append("UNKNOWN_NS")
    else:
        score -= 8
        flags.append("NO_NS_DATA")
    
    # MX Records (mail servers)
    mx_count = safe_int(row.get('MX_Records_Count'))
    if mx_count is not None:
        if mx_count == 0:
            score -= 12
            flags.append("NO_MAIL_SERVER")
            evidence.append("No mail server configured")
        elif mx_count > 0:
            score += 5
            flags.append("HAS_MAIL_SERVER")
    
    # Registrar reputation
    registrar = row.get('WHOIS_Registrar')
    if has_data(registrar):
        reg_rep = check_registrar_reputation(registrar)
        if reg_rep == 'trusted':
            score += 8
            flags.append("TRUSTED_REGISTRAR")
        elif reg_rep == 'suspicious':
            score -= 12
            flags.append("SUSPICIOUS_REGISTRAR")
            evidence.append("Suspicious registrar")
    
    # ASN/Hosting reputation
    asn_org = row.get('ASN_Org')
    if has_data(asn_org):
        asn_rep = check_asn_reputation(asn_org)
        if asn_rep == 'trusted':
            score += 8
            flags.append("TRUSTED_HOSTING")
        elif asn_rep == 'suspicious':
            score -= 15
            flags.append("SUSPICIOUS_HOSTING")
            evidence.append("Suspicious hosting provider")
    
    # WHOIS privacy
    if is_yes(row.get('WHOIS_Privacy')):
        score -= 8
        flags.append("WHOIS_HIDDEN")
    
    # ========================================================================
    # SSL/HTTPS (Strong security signal)
    # ========================================================================
    
    if is_yes(row.get('HTTP_Only')):
        score -= 25
        flags.append("NO_HTTPS")
        evidence.append("No HTTPS support")
    
    if is_no(row.get('SSL_Valid')):
        score -= 20
        flags.append("SSL_INVALID")
        evidence.append("Invalid SSL certificate")
    
    if is_yes(row.get('Self_Signed')):
        score -= 15
        flags.append("SELF_SIGNED_SSL")
        evidence.append("Self-signed SSL certificate")
    
    ssl_days = safe_int(row.get('SSL_ValidDays'))
    if ssl_days is not None and ssl_days < 30:
        score -= 10
        flags.append("SSL_EXPIRING_SOON")
    
    if is_yes(row.get('SSL_Valid')) and not is_yes(row.get('Self_Signed')):
        score += 10
        flags.append("SSL_VALID")
    
    # ========================================================================
    # EMAIL AUTHENTICATION
    # ========================================================================
    
    spf_valid = is_yes(row.get('SPF_Status'))
    dkim_valid = is_yes(row.get('DKIM_Status'))
    dmarc_valid = is_yes(row.get('DMARC_Status'))
    
    auth_count = sum([spf_valid or False, dkim_valid or False, dmarc_valid or False])
    
    if auth_count == 3:
        score += 20
        flags.append("FULL_EMAIL_AUTH")
        evidence.append("Complete email authentication (SPF+DKIM+DMARC)")
    elif auth_count == 2:
        score += 10
        flags.append("PARTIAL_EMAIL_AUTH")
    elif auth_count == 0:
        score -= 15
        flags.append("NO_EMAIL_AUTH")
        evidence.append("Missing email authentication")
    
    if is_yes(row.get('DNSSEC_Status')):
        score += 5
        flags.append("DNSSEC_ENABLED")
    
    # ========================================================================
    # REPUTATION & PRESENCE
    # ========================================================================
    
    # PageRank
    pagerank = safe_int(row.get('PageRank'))
    if pagerank is not None:
        if pagerank >= 7:
            score += 30
            flags.append("HIGH_PAGERANK")
            evidence.append(f"PageRank {pagerank}/10")
        elif pagerank >= 5:
            score += 25
            flags.append("GOOD_PAGERANK")
        elif pagerank >= 3:
            score += 10
            flags.append("MODERATE_PAGERANK")
        else:
            score -= 10
            flags.append("LOW_PAGERANK")
    
    # Archive history
    archive_count = safe_int(row.get('Archive_Count'))
    if archive_count is not None:
        if archive_count > 100:
            score += 18
            flags.append("WELL_ARCHIVED")
            evidence.append(f"{archive_count} archive snapshots")
        elif archive_count > 50:
            score += 12
            flags.append("GOOD_ARCHIVE")
        elif archive_count > 10:
            score += 6
            flags.append("SOME_ARCHIVE")
        elif archive_count == 0:
            score -= 12
            flags.append("NO_ARCHIVE")
            evidence.append("No archive history")
    
    # ========================================================================
    # CONTENT & BEHAVIOR
    # ========================================================================
    
    if is_yes(row.get('Hidden_Content')):
        score -= 20
        flags.append("HIDDEN_CONTENT")
        evidence.append("Contains hidden content")
    
    redirect_count = safe_int(row.get('Redirect_Count'))
    if redirect_count is not None and redirect_count > 3:
        score -= 15
        flags.append("MANY_REDIRECTS")
        evidence.append(f"{redirect_count} redirects")
    
    if is_yes(row.get('Contact_Info_Missing')):
        score -= 8
        flags.append("NO_CONTACT_INFO")
    
    if is_yes(row.get('Privacy_Policy_Missing')):
        score -= 6
        flags.append("NO_PRIVACY_POLICY")
    
    social_count = safe_int(row.get('Social_Links_Count'))
    if social_count is not None and social_count == 0:
        score -= 5
        flags.append("NO_SOCIAL_PRESENCE")
    elif social_count is not None and social_count > 3:
        score += 5
        flags.append("GOOD_SOCIAL_PRESENCE")
    
    # Content quality indicators
    content_length = safe_int(row.get('Content_Length'))
    if content_length is not None:
        if content_length < 100:
            score -= 12
            flags.append("MINIMAL_CONTENT")
        elif content_length < 300:
            score -= 6
            flags.append("SHORT_CONTENT")
    
    keyword_stuffing = safe_float(row.get('Keyword_Stuffing'))
    if keyword_stuffing is not None and keyword_stuffing > 0.3:
        score -= 15
        flags.append("KEYWORD_STUFFING")
        evidence.append(f"Keyword stuffing detected ({keyword_stuffing*100:.0f}%)")
    
    # ========================================================================
    # DATA CONFIDENCE ADJUSTMENT
    # ========================================================================
    
    # Critical fields for scoring
    critical_fields = [
        'WHOIS_AgeDays', 'SSL_Valid', 'SPF_Status', 'DKIM_Status', 'DMARC_Status',
        'PageRank', 'Archive_Count', 'Blacklisted', 'NS_Records', 'MX_Records_Count'
    ]
    
    available_data = sum(1 for field in critical_fields if has_data(row.get(field)))
    data_ratio = available_data / len(critical_fields)
    
    # Adjust confidence based on data availability
    if data_ratio < 0.3:
        confidence = 0.3
        score = 50 + (score - 50) * confidence
        flags.append("LOW_DATA_CONFIDENCE")
        evidence.append(f"Only {available_data}/{len(critical_fields)} key fields available")
    elif data_ratio < 0.5:
        confidence = 0.6
        score = 50 + (score - 50) * confidence
        flags.append("MODERATE_DATA_CONFIDENCE")
    
    # ========================================================================
    # FINAL SCORE
    # ========================================================================
    
    score = max(0, min(100, score))
    
    return round(score, 2), flags, evidence

# ============================================================================
# RISK CLASSIFICATION
# ============================================================================

def classify_risk(score):
    """Classify risk based on score"""
    if score >= 80:
        return "TRUSTED"
    elif score >= 65:
        return "LOW_RISK"
    elif score >= 45:
        return "MEDIUM_RISK"
    elif score >= 25:
        return "HIGH_RISK"
    else:
        return "CRITICAL"

# ============================================================================
# MAIN PROCESSING
# ============================================================================

def main():
    input_file = "domains_enriched.csv"
    output_file = "domains_scored.csv"
    
    print("="*80)
    print("ENHANCED DOMAIN SPAM SCORING SYSTEM")
    print("="*80)
    print("\nLoading domains...")
    
    rows = load_data(input_file)
    print(f"✓ Loaded {len(rows)} domains\n")
    
    print("Scoring domains...")
    print("Analyzing: Domain structure, entropy, infrastructure, reputation, security...")
    print()
    
    for i, row in enumerate(rows, 1):
        score, flags, evidence = score_domain(row)
        
        row['SpamScore'] = score
        row['RiskLevel'] = classify_risk(score)
        row['Flags'] = ';'.join(flags)
        row['Evidence'] = ' | '.join(evidence[:3])
        
        if i % 100 == 0:
            print(f"  Processed {i}/{len(rows)}...")
    
    print(f"  Processed {len(rows)}/{len(rows)}")
    
    # Save results
    fieldnames = list(rows[0].keys())
    save_data(output_file, rows, fieldnames)
    
    # Print summary
    print_summary(rows)
    
    print(f"\n{'='*80}")
    print(f"✓ Complete! Results saved to: {output_file}")
    print(f"{'='*80}\n")

# ============================================================================
# SUMMARY STATISTICS
# ============================================================================

def print_summary(rows):
    """Print comprehensive summary"""
    print("\n" + "="*80)
    print("SCORING SUMMARY")
    print("="*80)
    
    scores = [float(row['SpamScore']) for row in rows]
    
    # Score distribution with visual bars
    print("\nScore Distribution:")
    bins = [
        (0, 25, "CRITICAL"),
        (25, 45, "HIGH_RISK"),
        (45, 65, "MEDIUM_RISK"),
        (65, 80, "LOW_RISK"),
        (80, 100, "TRUSTED")
    ]
    
    for min_score, max_score, label in bins:
        count = sum(1 for s in scores if min_score <= s < max_score)
        pct = (count / len(scores) * 100) if scores else 0
        bar = "█" * int(pct / 2)
        print(f"  {label:12s} ({min_score:3d}-{max_score:3d}): {count:5d} ({pct:5.1f}%) {bar}")
    
    # Statistics
    print(f"\nScore Statistics:")
    mean = sum(scores) / len(scores)
    variance = sum((s - mean) ** 2 for s in scores) / len(scores)
    std_dev = math.sqrt(variance)
    
    print(f"  Mean:        {mean:6.2f}")
    print(f"  Median:      {sorted(scores)[len(scores)//2]:6.2f}")
    print(f"  Std Dev:     {std_dev:6.2f}")
    print(f"  Min:         {min(scores):6.2f}")
    print(f"  Max:         {max(scores):6.2f}")
    
    sorted_scores = sorted(scores)
    q1 = sorted_scores[len(scores)//4]
    q3 = sorted_scores[3*len(scores)//4]
    print(f"  Q1:          {q1:6.2f}")
    print(f"  Q3:          {q3:6.2f}")
    print(f"  IQR:         {q3-q1:6.2f}")
    
    # Risk level distribution
    risk_counts = Counter(row['RiskLevel'] for row in rows)
    print(f"\nRisk Level Distribution:")
    for level in ["CRITICAL", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "TRUSTED"]:
        count = risk_counts.get(level, 0)
        pct = (count / len(rows) * 100) if rows else 0
        print(f"  {level:15s}: {count:5d} ({pct:5.1f}%)")
    
    # Top flags
    all_flags = []
    for row in rows:
        if row.get('Flags'):
            all_flags.extend(row['Flags'].split(';'))
    
    if all_flags:
        flag_counts = Counter(all_flags)
        print(f"\nTop 20 Most Common Flags:")
        for i, (flag, count) in enumerate(flag_counts.most_common(20), 1):
            pct = (count / len(rows) * 100)
            print(f"  {i:2d}. {flag:35s}: {count:5d} ({pct:5.1f}%)")
    
    # Example domains from each category
    print(f"\n{'='*80}")
    print("SAMPLE DOMAINS BY RISK LEVEL")
    print("="*80)
    
    for level in ["CRITICAL", "HIGH_RISK", "MEDIUM_RISK", "LOW_RISK", "TRUSTED"]:
        level_domains = [row for row in rows if row['RiskLevel'] == level]
        if level_domains:
            print(f"\n{level} ({len(level_domains)} domains):")
            print("-" * 80)
            for row in level_domains[:3]:
                domain = row.get('ParentDomain', 'Unknown')[:40]
                score = row['SpamScore']
                top_flags = ';'.join(row.get('Flags', '').split(';')[:3])
                evidence = row.get('Evidence', '')[:60]
                
                print(f"  Score: {score:6.2f} | {domain:40s}")
                if top_flags:
                    print(f"  Flags: {top_flags}")
                if evidence:
                    print(f"  Evidence: {evidence}")
                print()

if __name__ == "__main__":
    main()