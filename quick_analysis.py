import pandas as pd
import sys
sys.path.append('scripts')
from network_incident_etl import analyze_sla_breaches

# Load the processed data
df = pd.read_csv('data/processed/IM_Network_EMEA_2025_analyzed_clean_clean.csv')
analysis = analyze_sla_breaches(df)

print('🔍 SLA BREACH ANALYSIS:')
print(f'Breach Rate: {analysis["breach_rate"]*100:.1f}%')
print(f'Total Breaches: {analysis["total_breaches"]}')
print(f'Avg Breach Time: {analysis["avg_breach_time_hrs"]:.1f} hours')
print('\nTop Breach Categories:')
for cat, count in list(analysis['breach_by_category'].items())[:5]:
    print(f'  {cat}: {count}') 