"""
Run SLA analysis on your existing processed data
"""
import pandas as pd
from network_incident_etl import analyze_sla_breaches

def main():
    # Load your existing processed data
    df = pd.read_csv("data/processed/IM_Network_EMEA_2025_redacted_clean_analysed.csv")
    
    print(f"📊 Analyzing {len(df)} incidents...")
    
    # Run SLA analysis
    analysis = analyze_sla_breaches(df)
    
    print("\n🔍 SLA BREACH ANALYSIS RESULTS:")
    print("=" * 50)
    
    for key, value in analysis.items():
        if key == 'worst_cases':
            print(f"\n{key.upper()}:")
            for case in value:
                print(f"  - ID: {case['id_hash'][:8]}... | "
                      f"Category: {case['patternCategory']} | "
                      f"Priority: {case['priority']} | "
                      f"Resolution: {case['resolutionTimeBizHrs']:.1f}hrs")
        else:
            print(f"{key}: {value}")

if __name__ == "__main__":
    main()