"""
Quick Trend Analysis for ServiceNow Data
Run this script to get immediate trend insights from your processed data
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import numpy as np

def load_data():
    """Load and prepare data for trend analysis"""
    df = pd.read_csv("data/processed/IM_Network_EMEA_2025_redacted_clean_analysed.csv")
    df['openedDate'] = pd.to_datetime(df['openedDate'])
    df['resolvedDate'] = pd.to_datetime(df['resolvedDate'])
    return df

def analyze_sla_trends(df):
    """Analyze SLA performance trends"""
    print("📊 SLA PERFORMANCE TRENDS")
    print("=" * 50)
    
    # Weekly SLA performance
    weekly_sla = df.groupby('week').agg({
        'slaBreach': ['count', 'sum', 'mean'],
        'resolutionTimeBizHrs': 'mean',
        'id_hash': 'count'
    }).round(2)
    
    # Flatten column names
    weekly_sla.columns = ['total_incidents', 'total_breaches', 'breach_rate', 'avg_resolution_hrs', 'incident_count']
    
    print(f"📈 Weekly SLA Performance Summary:")
    print(f"Best performing week: Week {weekly_sla['breach_rate'].idxmin()} ({weekly_sla['breach_rate'].min()*100:.1f}% breach rate)")
    print(f"Worst performing week: Week {weekly_sla['breach_rate'].idxmax()} ({weekly_sla['breach_rate'].max()*100:.1f}% breach rate)")
    
    # Calculate trend
    recent_4_weeks = weekly_sla.tail(4)['breach_rate'].mean()
    earlier_4_weeks = weekly_sla.head(4)['breach_rate'].mean()
    trend_direction = "📈 Improving" if recent_4_weeks < earlier_4_weeks else "📉 Deteriorating"
    
    print(f"Trend direction: {trend_direction}")
    print(f"Recent 4 weeks avg breach rate: {recent_4_weeks*100:.1f}%")
    print(f"Earlier 4 weeks avg breach rate: {earlier_4_weeks*100:.1f}%")
    
    return weekly_sla

def analyze_category_evolution(df):
    """Track category trends over time"""
    print(f"\n🔍 CATEGORY EVOLUTION ANALYSIS")
    print("=" * 50)
    
    # Weekly category distribution
    category_weekly = df.groupby(['week', 'patternCategory']).size().unstack(fill_value=0)
    
    # Calculate growth rates
    category_growth = {}
    for category in category_weekly.columns:
        recent_avg = category_weekly[category].tail(4).mean()
        earlier_avg = category_weekly[category].head(4).mean()
        if earlier_avg > 0:
            growth_rate = ((recent_avg - earlier_avg) / earlier_avg) * 100
            category_growth[category] = growth_rate
    
    # Sort by growth rate
    sorted_growth = sorted(category_growth.items(), key=lambda x: x[1], reverse=True)
    
    print("📈 Fastest Growing Issue Categories:")
    for category, growth in sorted_growth[:5]:
        if growth > 0:
            print(f"  • {category}: +{growth:.1f}% growth")
    
    print("\n📉 Declining Issue Categories:")
    for category, growth in sorted_growth[-5:]:
        if growth < 0:
            print(f"  • {category}: {growth:.1f}% decline")
    
    return category_weekly, category_growth

def analyze_resolution_trends(df):
    """Analyze resolution time trends"""
    print(f"\n⏱️ RESOLUTION TIME TRENDS")
    print("=" * 50)
    
    # Weekly resolution times by category
    resolution_trends = df.groupby(['week', 'patternCategory'])['resolutionTimeBizHrs'].mean().unstack(fill_value=0)
    
    # Calculate improvement rates for each category
    category_improvements = {}
    for category in resolution_trends.columns:
        if resolution_trends[category].sum() > 0:
            recent_avg = resolution_trends[category].tail(4).mean()
            earlier_avg = resolution_trends[category].head(4).mean()
            if earlier_avg > 0:
                improvement = ((earlier_avg - recent_avg) / earlier_avg) * 100
                category_improvements[category] = improvement
    
    # Sort by improvement
    sorted_improvements = sorted(category_improvements.items(), key=lambda x: x[1], reverse=True)
    
    print("🚀 Most Improved Resolution Times:")
    for category, improvement in sorted_improvements[:5]:
        if improvement > 0:
            print(f"  • {category}: {improvement:.1f}% faster")
    
    print("\n🐌 Deteriorating Resolution Times:")
    for category, improvement in sorted_improvements[-5:]:
        if improvement < 0:
            print(f"  • {category}: {abs(improvement):.1f}% slower")
    
    return category_improvements

def analyze_cost_trends(df):
    """Analyze cost impact trends"""
    print(f"\n💰 COST IMPACT TRENDS")
    print("=" * 50)
    
    # Calculate weekly costs (assuming $75/hour loaded cost)
    hourly_cost = 75
    df['cost_impact'] = df['userImpactEstimate'] * df['resolutionTimeBizHrs'] * hourly_cost
    
    weekly_costs = df.groupby('week')['cost_impact'].sum()
    
    # Cost trend analysis
    recent_4_weeks_cost = weekly_costs.tail(4).mean()
    earlier_4_weeks_cost = weekly_costs.head(4).mean()
    cost_trend = ((recent_4_weeks_cost - earlier_4_weeks_cost) / earlier_4_weeks_cost) * 100
    
    print(f"Weekly cost trend: {cost_trend:+.1f}%")
    print(f"Recent 4 weeks avg cost: ${recent_4_weeks_cost:,.0f}/week")
    print(f"Earlier 4 weeks avg cost: ${earlier_4_weeks_cost:,.0f}/week")
    print(f"Projected quarterly impact: ${weekly_costs.sum():,.0f}")
    
    # Top cost drivers
    category_costs = df.groupby('patternCategory')['cost_impact'].sum().sort_values(ascending=False)
    print(f"\n💸 Top Cost Categories:")
    for category, cost in category_costs.head(5).items():
        print(f"  • {category}: ${cost:,.0f}")
    
    return weekly_costs, category_costs

def generate_predictions(df):
    """Generate simple predictions and early warnings"""
    print(f"\n🔮 PREDICTIVE INSIGHTS")
    print("=" * 50)
    
    # Volume prediction
    weekly_volumes = df.groupby('week').size()
    recent_trend = weekly_volumes.tail(4).mean() - weekly_volumes.head(4).mean()
    projected_next_week = weekly_volumes.iloc[-1] + recent_trend
    
    print(f"📊 Volume Forecast:")
    print(f"  • Current week volume: {weekly_volumes.iloc[-1]} incidents")
    print(f"  • Projected next week: {projected_next_week:.0f} incidents")
    print(f"  • Trend: {'📈 Increasing' if recent_trend > 0 else '📉 Decreasing'}")
    
    # SLA risk assessment
    recent_breach_rate = df.groupby('week')['slaBreach'].mean().tail(4).mean()
    if recent_breach_rate > 0.6:
        risk_level = "🔴 HIGH RISK"
    elif recent_breach_rate > 0.4:
        risk_level = "🟡 MEDIUM RISK"
    else:
        risk_level = "🟢 LOW RISK"
    
    print(f"\n⚠️ SLA Risk Assessment:")
    print(f"  • Current risk level: {risk_level}")
    print(f"  • Recent breach rate: {recent_breach_rate*100:.1f}%")
    
    # Capacity warnings
    print(f"\n🚨 Capacity Warnings:")
    for category in df['patternCategory'].value_counts().head(5).index:
        cat_data = df[df['patternCategory'] == category]
        recent_volume = cat_data.groupby('week').size().tail(4).mean()
        historical_avg = cat_data.groupby('week').size().mean()
        if recent_volume > historical_avg * 1.3:  # 30% above average
            print(f"  • {category}: Volume up {((recent_volume/historical_avg-1)*100):.0f}% vs historical avg")

def executive_summary(df):
    """Generate executive summary"""
    print(f"\n🎯 EXECUTIVE SUMMARY")
    print("=" * 60)
    
    # Key metrics
    total_incidents = len(df)
    breach_rate = df['slaBreach'].mean() * 100
    avg_resolution = df['resolutionTimeBizHrs'].mean()
    total_cost = (df['userImpactEstimate'] * df['resolutionTimeBizHrs'] * 75).sum()
    
    print(f"📊 Current Quarter Performance:")
    print(f"  • Total Incidents: {total_incidents}")
    print(f"  • SLA Breach Rate: {breach_rate:.1f}%")
    print(f"  • Avg Resolution Time: {avg_resolution:.1f} hours")
    print(f"  • Total Productivity Cost: ${total_cost:,.0f}")
    
    # Top issues
    top_categories = df['patternCategory'].value_counts().head(3)
    print(f"\n🔥 Top Issue Categories:")
    for category, count in top_categories.items():
        print(f"  • {category}: {count} incidents")
    
    # Recommendations
    print(f"\n💡 Key Recommendations:")
    if breach_rate > 50:
        print(f"  🔴 URGENT: SLA performance critical - immediate process review needed")
    if df[df['patternCategory'] == 'WiFi_Connection']['slaBreach'].sum() > 20:
        print(f"  📶 WiFi infrastructure investment recommended")
    if df[df['patternCategory'] == 'VPN_Access']['slaBreach'].sum() > 20:
        print(f"  🔒 VPN capacity/vendor review recommended")
    if avg_resolution > 100:
        print(f"  👥 Consider additional L2/L3 technical resources")

def main():
    """Main analysis function"""
    print("🔍 ServiceNow Trend Analysis Report")
    print("=" * 60)
    print(f"📅 Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Load data
    df = load_data()
    print(f"📊 Analyzing {len(df)} incidents from {df['openedDate'].min().date()} to {df['openedDate'].max().date()}")
    
    # Run all analyses
    weekly_sla = analyze_sla_trends(df)
    category_weekly, category_growth = analyze_category_evolution(df)
    category_improvements = analyze_resolution_trends(df)
    weekly_costs, category_costs = analyze_cost_trends(df)
    generate_predictions(df)
    executive_summary(df)
    
    print(f"\n✅ Analysis Complete!")
    print(f"💾 Consider saving these insights for executive presentation")

if __name__ == "__main__":
    main()
