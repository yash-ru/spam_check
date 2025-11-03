import streamlit as st
import pandas as pd
import sus4e
import spam_score
from io import StringIO
import time

def process_domains(domains_input):
    # Split input into individual domains
    domains = [domain.strip() for domain in domains_input.split("\n") if domain.strip()]
    
    # Load WHOIS cache
    whois_cache = sus4e.load_whois_cache(sus4e.WHOIS_DB)
    
    # Create a dictionary to store new WHOIS data
    new_whois_data = {}
    
    results = []
    
    # Process each domain with progress bar
    progress = st.progress(0)
    for i, domain in enumerate(domains):
        result = sus4e.process_single_domain(domain, whois_cache, new_whois_data)
        score, flags, evidence = spam_score.score_domain(result)
        
        # Format output
        result.update({
            "Domain": domain,
            "AuthorityScore": score,
            "RiskLevel": spam_score.classify_risk(score),
            "Flags": ';'.join(flags),
            "Evidence": ' | '.join(evidence[:3])
        })
        
        results.append(result)
        
        # Update progress bar
        progress.progress((i + 1) / len(domains))
        time.sleep(0.1)  # Simulate time taken for processing
    
    # Convert results to DataFrame for display
    results_df = pd.DataFrame(results)
    
    return results_df

# Streamlit app entry point
def main():
    st.title("Domain Spam checker")
    
    domains_input = st.text_area("Enter domains to check (one per line)")
    
    if st.button("Check Domains"):
        if domains_input.strip():
            results_df = process_domains(domains_input)
            
            # Display main results (Domain, SpamScore, Flags)
            st.write("Results:")
            results_summary = results_df[["Domain", "AuthorityScore", "RiskLevel", "Flags"]]
            st.dataframe(results_summary)
            
            # Expandable rows for detailed view
            for index, row in results_df.iterrows():
                with st.expander(f"Details for {row['Domain']}"):
                    st.write(row)
            
            # Download results as CSV
            csv = results_df.to_csv(index=False)
            st.download_button("Download CSV", csv, "domain_results.csv", "text/csv")
        else:
            st.error("Please enter at least one domain")
    
if __name__ == "__main__":

    main()

