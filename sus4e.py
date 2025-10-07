#!/usr/bin/env python3
"""
holistic_domain_check_full.py
Collects DNS, WHOIS, ASN, SSL, PageRank, Archive, Domain Structure, Content & Phishing signals
and outputs domains_enriched.csv
"""
import csv
import ipaddress
import socket
import ssl
import math
from urllib.parse import urlparse
from datetime import datetime, timezone
import requests
import tldextract
import whois
import dns.resolver
import dns.reversename
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.exception
import time
import os
import pandas as pd


# ------------------------
# Configuration
# ------------------------
TRUSTED_NS_SUBSTR = ["cloudflare", "google", "aws", "amazon", "microsoft"]
WEAK_PROVIDERS_SUBSTR = ["beget", "freenom", "000webhost", "hostinger"]
SUSPICIOUS_ASN_ORG_SUBSTR = ["bulletproof", "abuse", "darkserver"]
NEW_DOMAIN_DAYS = 30
YOUNG_DOMAIN_DAYS = 180
EXPIRY_SOON_DAYS = 180
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
API_KEY = "8kcck8c8kwc400w080cgkcwgccgwswgc08sgosgs"  # replace with your key
API_URL = "https://openpagerank.com/api/v1.0/getPageRank"
WHOIS_DB = r'C:\Users\yash.ru\Desktop\sus\sus4\whois.csv'

# ------------------------
# WHOIS Cache Management
# ------------------------
def parse_date_flexible(date_str):
    """Parse date in various formats"""
    if not date_str or pd.isna(date_str) or str(date_str).strip() == '':
        return None
    
    date_str = str(date_str).strip()
    
    # Try DD-MM-YYYY format first (your CSV format)
    try:
        return datetime.strptime(date_str, "%d-%m-%Y").replace(tzinfo=timezone.utc)
    except:
        pass
    
    # Try ISO format
    try:
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except:
        pass
    
    # Try other common formats
    formats = [
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%d/%m/%Y",
        "%Y/%m/%d"
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except:
            continue
    
    return None

def load_whois_cache(whois_db_path):
    """Load existing WHOIS data from CSV"""
    if not os.path.exists(whois_db_path):
        print(f"WHOIS cache file not found: {whois_db_path}")
        return {}
    
    try:
        df = pd.read_csv(whois_db_path)
        cache = {}
        
        for _, row in df.iterrows():
            domain = str(row['domain']).strip()
            
            # Parse dates
            creation_date = parse_date_flexible(row.get('creation_date'))
            expiration_date = parse_date_flexible(row.get('expiration_date'))
            
            # Get registrar
            registrar = row.get('registrar')
            if pd.notna(registrar) and str(registrar).strip() != '':
                registrar = str(registrar).strip()
            else:
                registrar = None
            
            cache[domain] = {
                'creation_date': creation_date.isoformat() if creation_date else None,
                'expiration_date': expiration_date.isoformat() if expiration_date else None,
                'registrar': registrar,
                'nameserver1': row.get('nameserver1') if pd.notna(row.get('nameserver1')) else None,
                'nameserver2': row.get('nameserver2') if pd.notna(row.get('nameserver2')) else None,
                'nameserver3': row.get('nameserver3') if pd.notna(row.get('nameserver3')) else None
            }
        
        print(f"Loaded {len(cache)} domains from WHOIS cache")
        print(f"Sample cached domains: {list(cache.keys())[:5]}")
        return cache
    except Exception as e:
        print(f"Error loading WHOIS cache: {e}")
        import traceback
        traceback.print_exc()
        return {}

def format_date_to_csv(date_obj):
    """Format datetime object to DD-MM-YYYY for CSV"""
    if not date_obj:
        return None
    
    if isinstance(date_obj, str):
        try:
            date_obj = datetime.fromisoformat(date_obj.replace('Z', '+00:00'))
        except:
            return date_obj
    
    if isinstance(date_obj, datetime):
        return date_obj.strftime("%d-%m-%Y")
    
    return None

def save_whois_cache(whois_db_path, cache_data):
    """Save WHOIS cache back to CSV in DD-MM-YYYY format"""
    try:
        rows = []
        for domain, data in cache_data.items():
            # Get dates
            creation_date_str = data.get('creation_date')
            expiration_date_str = data.get('expiration_date')
            
            # Parse dates if they're in ISO format
            creation_date = parse_date_flexible(creation_date_str)
            expiration_date = parse_date_flexible(expiration_date_str)
            
            # Calculate lifespan and creation_year
            lifespan = None
            creation_year = None
            
            if creation_date and expiration_date:
                try:
                    lifespan = (expiration_date - creation_date).days // 365  # in years
                    creation_year = creation_date.year
                except:
                    pass
            elif creation_date:
                creation_year = creation_date.year
            
            # Format dates back to DD-MM-YYYY
            creation_date_formatted = format_date_to_csv(creation_date)
            expiration_date_formatted = format_date_to_csv(expiration_date)
            
            rows.append({
                'domain': domain,
                'creation_date': creation_date_formatted,
                'expiration_date': expiration_date_formatted,
                'lifespan': lifespan,
                'creation_year': creation_year,
                'registrar': data.get('registrar') if data.get('registrar') else '',
                'nameserver1': data.get('nameserver1') if data.get('nameserver1') else '',
                'nameserver2': data.get('nameserver2') if data.get('nameserver2') else '',
                'nameserver3': data.get('nameserver3') if data.get('nameserver3') else ''
            })
        
        df = pd.DataFrame(rows)
        # Sort by domain for easier reading
        df = df.sort_values('domain')
        df.to_csv(whois_db_path, index=False)
        print(f"Updated WHOIS cache saved to: {whois_db_path} ({len(rows)} domains)")
    except Exception as e:
        print(f"Error saving WHOIS cache: {e}")
        import traceback
        traceback.print_exc()

def get_whois_from_cache_or_fetch(domain, whois_cache, new_whois_data):
    """Get WHOIS info from cache or fetch if not available"""
    if domain in whois_cache:
        cached = whois_cache[domain]
        creation_date = cached.get('creation_date')
        expiration_date = cached.get('expiration_date')
        
        # Parse dates
        created = None
        expires = None
        
        if creation_date:
            created = parse_date_flexible(creation_date)
        
        if expiration_date:
            expires = parse_date_flexible(expiration_date)
        
        # Calculate age and expiry days
        now = datetime.now(timezone.utc)
        age_days = None
        expiry_days = None
        
        if created:
            age_days = (now - created).days
        
        if expires:
            expiry_days = (expires - now).days
        
        registrar = cached.get('registrar')
        if not registrar or registrar == '':
            registrar = "Unknown"
        
        return {
            "Registrar": registrar,
            "Created": created.isoformat() if created else None,
            "Expires": expires.isoformat() if expires else None,
            "AgeDays": age_days,
            "ExpiryDays": expiry_days,
            "WHOIS_Privacy": "No"  # Not stored in cache
        }
    else:
        # Fetch from WHOIS
        whois_info = get_whois_info(domain)
        
        # Store in new_whois_data for later cache update
        new_whois_data[domain] = {
            'creation_date': whois_info.get('Created'),
            'expiration_date': whois_info.get('Expires'),
            'registrar': whois_info.get('Registrar'),
            'nameserver1': None,
            'nameserver2': None,
            'nameserver3': None
        }
        
        return whois_info

# ------------------------
# DNS Helpers
# ------------------------
def safe_resolve(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5.0)
        if record_type == "MX":
            return [str(r.exchange).rstrip('.') for r in answers]
        elif record_type == "TXT":
            out = []
            for r in answers:
                sval = b"".join(r.strings).decode("utf-8","ignore")
                out.append(sval)
            return out
        elif record_type == "SOA":
            a = answers[0]
            return [f"Primary NS: {a.mname}, Admin: {a.rname}"]
        elif record_type == "CNAME":
            return [str(r.target).rstrip('.') for r in answers]
        else:
            return [str(r).rstrip('.') for r in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return None
    except Exception:
        return []

def get_ptr_records_from_ips(a_records):
    ptrs = []
    for ip in a_records:
        try:
            ipaddress.ip_address(ip)
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, "PTR", lifetime=5.0)
            for r in answers:
                ptrs.append(str(r).rstrip('.'))
        except Exception:
            continue
    return ptrs

def get_parent_domain(domain):
    ext = tldextract.extract(domain)
    parent = getattr(ext, "top_domain_under_public_suffix", None)
    if not parent:
        # Fallback: return domain as-is
        return domain
    return parent

def fetch_with_fallback(domain, parent, record_type):
    r = safe_resolve(domain, record_type)
    if r is None:
        parent_r = safe_resolve(parent, record_type)
        if parent_r is None:
            return None
        return parent_r or []
    if r == []:
        parent_r = safe_resolve(parent, record_type)
        if parent_r is None:
            return None
        return parent_r or []
    return r

# ------------------------
# WHOIS & ASN
# ------------------------
def get_whois_info(domain):
    out = {"Registrar": None, "Created": None, "Expires": None, "AgeDays": None, "ExpiryDays": None, "WHOIS_Privacy": "No"}
    try:
        w = whois.whois(domain)
        created = w.creation_date
        expires = w.expiration_date
        registrar = getattr(w, "registrar", None)
        privacy = "Yes" if getattr(w, "privacy", None) else "No"
        if isinstance(created, list):
            created = min([d for d in created if d is not None]) if any(created) else None
        if isinstance(expires, list):
            expires = max([d for d in expires if d is not None]) if any(expires) else None
        now = datetime.now(timezone.utc)
        if isinstance(created, datetime) and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if isinstance(expires, datetime) and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        age_days = (now - created).days if created else None
        expiry_days = (expires - now).days if expires else None
        out.update({
            "Registrar": registrar or "Unknown",
            "Created": created.isoformat() if created else None,
            "Expires": expires.isoformat() if expires else None,
            "AgeDays": age_days,
            "ExpiryDays": expiry_days,
            "WHOIS_Privacy": privacy
        })
    except Exception:
        pass
    return out

def get_ip_reputation(a_records):
    from ipwhois import IPWhois
    for ip in a_records:
        try:
            if ip == "None":
                continue
            ipobj = ipaddress.ip_address(ip)
            if ipobj.is_private:
                return {"ASN": "PRIVATE", "Org": "Private", "Country": None, "IP_Reputation": "Private"}
            obj = IPWhois(str(ip))
            res = obj.lookup_rdap(asn_methods=["whois","http"])
            asn = res.get("asn", None)
            asn_desc = res.get("asn_description", None)
            asn_cc = res.get("asn_country_code", None)
            return {"ASN": asn or "Unknown","Org": asn_desc or "Unknown","Country": asn_cc or "Unknown","IP_Reputation":"Unknown"}
        except Exception:
            continue
    return {"ASN": None,"Org": None,"Country": None,"IP_Reputation": None}

# ------------------------
# Domain Structure
# ------------------------
def get_domain_structure(domain):
    ext = tldextract.extract(domain)
    parent = getattr(ext, "top_domain_under_public_suffix", None) or domain
    subdomain = ext.subdomain
    domain_len = len(parent)
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    digits_ratio = sum(c.isdigit() for c in parent) / max(len(parent),1)
    hyphen_ratio = parent.count('-') / max(len(parent),1)
    entropy = -sum(p*math.log2(p) for p in [(parent.count(c)/len(parent)) for c in set(parent)] if p>0)
    return {
        "ParentDomain": parent,
        "DomainLength": domain_len,
        "SubdomainCount": subdomain_count,
        "DigitsRatio": round(digits_ratio,2),
        "HyphenRatio": round(hyphen_ratio,2),
        "Entropy": round(entropy,2)
    }

# ------------------------
# HTML Content
# ------------------------
def fetch_html(domain):
    try:
        url = f"http://{domain}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.text
    except:
        return ""
    return ""

def parse_content_signals(html):
    soup = BeautifulSoup(html, 'html.parser')
    content_len = len(soup.get_text(strip=True))
    outbound_links = len([a for a in soup.find_all('a', href=True) if urlparse(a['href']).netloc])
    words = [w.lower() for w in soup.get_text().split() if len(w)>2]
    word_freq = {w: words.count(w) for w in set(words)}
    top_words_count = sum(sorted(word_freq.values(), reverse=True)[:5])
    keyword_ratio = round(top_words_count / max(len(words),1),2)
    hidden_content = "Yes" if soup.find_all(style=lambda x: x and "display:none" in x.lower()) else "No"
    return {
        "Content_Length": content_len,
        "Outbound_Links": outbound_links,
        "Keyword_Stuffing": keyword_ratio,
        "Hidden_Content": hidden_content
    }

# ------------------------
# Phishing Check
# ------------------------
def check_phishtank(domain):
    try:
        payload = {"url": domain, "format": "json"}
        r = requests.post(PHISHTANK_API_URL, data=payload, timeout=10)
        if r.status_code == 200:
            res = r.json()
            if res.get("results", {}).get("valid"):
                return "Yes"
    except:
        pass
    return "No"

# ------------------------
# SSL / TLS
# ------------------------
def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer']).get('organizationName')
            not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            tls_version = s.version()
            return {
                "SSL_Cert_Issuer": issuer,
                "SSL_Expiry": not_after.isoformat(),
                "SSL_Valid": "Yes" if not_after > datetime.utcnow() else "No",
                "Self_Signed": "Yes" if issuer.lower() == domain.lower() else "No",
                "TLS_Version": tls_version
            }
    except:
        return {
            "SSL_Cert_Issuer": None,
            "SSL_Expiry": None,
            "SSL_Valid": "No",
            "Self_Signed": "Unknown",
            "TLS_Version": None
        }
    

def fetch_pagerank(domain):
    try:
        headers = {'API-OPR': API_KEY}
        params = [('domains[]', domain)]
        resp = requests.get(API_URL, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("response", []):
                if item.get("domain") == domain:
                    pr_int = item.get("page_rank_integer")
                    pr_score = item.get("page_rank_decimal")
                    return pr_int if pr_int != 0 else None, pr_score if pr_score != 0 else None
    except Exception:
        pass
    return None, None


def parse_txt_for_email_security(txt_records):
    spf = "Yes" if any("v=spf1" in x.lower() for x in txt_records) else "No"
    return spf, None, None

def check_dnssec(domain):
    try:
        ans = dns.resolver.resolve(domain, 'DNSKEY')
        return "Yes" if ans else "No"
    except Exception:
        return "No"



# ------------------------
# Process Domain
# ------------------------
def process_single_domain(domain, whois_cache, new_whois_data, pagerank_data={}):
    row = {}
    parent = get_parent_domain(domain)
    
    # Domain Structure
    row.update(get_domain_structure(domain))
    
    # DNS Records
    a_records = fetch_with_fallback(domain, parent, "A") or []
    row["A_Records"] = ";".join(a_records)
    ptr_records = get_ptr_records_from_ips(a_records)
    row["PTR_Records"] = ";".join(ptr_records)
    mx_records = fetch_with_fallback(domain, parent, "MX") or []
    row["MX_Records"] = ";".join(mx_records)
    ns_records = fetch_with_fallback(domain, parent, "NS") or []
    row["NS_Records"] = ";".join(ns_records)
    txt_records = fetch_with_fallback(domain, parent, "TXT") or []
    row["TXT_Records"] = ";".join(txt_records)
    soa_records = fetch_with_fallback(domain, parent, "SOA") or []
    row["SOA_Record"] = ";".join(soa_records)
    cname_records = safe_resolve(domain, "CNAME") or []
    row["CNAME_Record"] = ";".join(cname_records)
    
    # WHOIS (from cache or fetch)
    who = get_whois_from_cache_or_fetch(parent, whois_cache, new_whois_data)
    row.update({
        "WHOIS_Created": who.get("Created"),
        "WHOIS_AgeDays": who.get("AgeDays"),
        "WHOIS_ExpiresDays": who.get("ExpiryDays"),
        "WHOIS_Registrar": who.get("Registrar"),
        "WHOIS_Privacy": who.get("WHOIS_Privacy")
    })
    
    # ASN
    asn_info = get_ip_reputation(a_records)
    row.update({
        "ASN": asn_info.get("ASN"),
        "ASN_Org": asn_info.get("Org"),
        "ASN_Country": asn_info.get("Country"),
        "IP_Reputation": asn_info.get("IP_Reputation")
    })
    
    # Content Signals
    html = fetch_html(domain)
    row.update(parse_content_signals(html))
    
    # SSL/TLS
    row.update(check_ssl(domain))
    
    # Phishing
    row["Phishing_Found"] = check_phishtank(parent)
    
    # PageRank
    pr_int, pr_score = fetch_pagerank(domain)
    row["PageRank"] = pr_int
    row["PageRank_Score"] = pr_score
    
    # Archive count placeholder
    row["Archive_Count"] = None

    spf_status, _, _ = parse_txt_for_email_security(txt_records)
    dmarc_status = "Yes" if safe_resolve(f"_dmarc.{domain}", "TXT") else "No"
    dkim_status = "Yes" if safe_resolve(f"default._domainkey.{domain}", "TXT") else "No"
    
    row["SPF_Status"] = spf_status
    row["DKIM_Status"] = dkim_status
    row["DMARC_Status"] = dmarc_status

    row["DNSSEC_Status"] = check_dnssec(domain)
        

    return row

# ------------------------
# Main Processing
# ------------------------
def process_domains(input_file="domains.txt", output_file="domains_enriched.csv", max_workers=20, pagerank_data={}):
    # Load WHOIS cache
    whois_cache = load_whois_cache(WHOIS_DB)
    
    # Read domains
    with open(input_file,"r") as f:
        domains = [line.strip() for line in f if line.strip()]
    
    print(f"\nDomains from input file: {domains[:5]}...")  # Debug
    
    # Get parent domains for WHOIS check
    parent_domains = {}
    for d in domains:
        parent = get_parent_domain(d)
        parent_domains[parent] = d
        print(f"Domain: {d} -> Parent: {parent}")  # Debug
    
    # Check which domains are in cache
    domains_in_cache = []
    domains_not_in_cache = []
    
    for parent in parent_domains.keys():
        if parent in whois_cache:
            domains_in_cache.append(parent)
        else:
            domains_not_in_cache.append(parent)
    
    print(f"\nTotal domains to process: {len(domains)}")
    print(f"Unique parent domains: {len(parent_domains)}")
    print(f"Domains with cached WHOIS data: {len(domains_in_cache)}")
    if domains_in_cache:
        print(f"  Examples: {domains_in_cache[:3]}")
    print(f"Domains without cached WHOIS data: {len(domains_not_in_cache)}")
    if domains_not_in_cache:
        print(f"  Examples: {domains_not_in_cache[:3]}")
    
    # Ask user if they want to fetch missing WHOIS data
    fetch_missing = True
    if domains_not_in_cache:
        response = input(f"\nDo you want to fetch WHOIS data for the remaining {len(domains_not_in_cache)} domains? (yes/no): ").strip().lower()
        fetch_missing = response in ['yes', 'y']
        
        if not fetch_missing:
            print("Skipping WHOIS fetch for domains not in cache. They will have blank WHOIS data.")
    
    # Prepare new WHOIS data dictionary
    new_whois_data = {}
    
    # If not fetching, add empty entries for missing domains
    if not fetch_missing:
        for domain in domains_not_in_cache:
            whois_cache[domain] = {
                'creation_date': None,
                'expiration_date': None,
                'registrar': None,
                'nameserver1': None,
                'nameserver2': None,
                'nameserver3': None
            }
    
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(process_single_domain, d, whois_cache, new_whois_data, pagerank_data): d for d in domains}
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                row = future.result()
                results.append(row)
                print(f"Processed {domain}")
            except Exception as e:
                print(f"Failed {domain}: {e}")
    
    # Update WHOIS cache with new data
    if new_whois_data:
        print(f"\nUpdating WHOIS cache with {len(new_whois_data)} new entries...")
        whois_cache.update(new_whois_data)
        save_whois_cache(WHOIS_DB, whois_cache)
    
    # CSV Header (all signals)
    fieldnames = [
        "ParentDomain","DomainLength","SubdomainCount","DigitsRatio","HyphenRatio","Entropy",
        "A_Records","AAAA_Records","PTR_Records","MX_Records","NS_Records","TXT_Records",
        "SOA_Record","CNAME_Record","SPF_Status","DKIM_Status","DMARC_Status","DNSSEC_Status",
        "WHOIS_Created","WHOIS_AgeDays","WHOIS_ExpiresDays","WHOIS_Registrar","WHOIS_Privacy",
        "ASN","ASN_Org","ASN_Country","IP_Reputation",
        "PageRank","PageRank_Score",
        "SSL_Cert_Issuer","SSL_Expiry","SSL_Valid","Self_Signed","TLS_Version",
        "Content_Length","Outbound_Links","Keyword_Stuffing","Hidden_Content",
        "Phishing_Found","Archive_Count"
    ]
    
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\nFinished. {len(results)} domains saved to: {output_file}")

# ------------------------
# Entry
# ------------------------
if __name__ == "__main__":
    process_domains("domains.txt", "domains_enriched.csv")