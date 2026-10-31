"""Overview page for AI-WAF Streamlit Dashboard.

Displays traffic KPIs, timeline distribution, attack categories, and top blocked IPs.
"""
from datetime import timedelta
import streamlit as st
import plotly.express as px
import pandas as pd
from dashboard import db_reader

st.set_page_config(page_title="AI-WAF - Overview", layout="wide", page_icon="📊")
st.title("📊 Traffic & Threat Overview")


@st.fragment(run_every=timedelta(seconds=2))
def render_overview():
    """Renders real-time metrics and charts from SQLite read-only connection."""
    # 1. Top KPI metrics (تم إضافة or {} لحماية الكود من رجوع قيمة None)
    counts = db_reader.get_event_counts(since=0) or {}
    col1, col2, col3, col4 = st.columns(4)
    total = counts.get("total", 0)
    blocked = counts.get("blocked", 0)
    allowed = counts.get("allowed", 0)
    block_rate = (blocked / total * 100) if total > 0 else 0.0

    col1.metric("Total Requests", f"{total:,}")
    col2.metric("Blocked Attacks", f"{blocked:,}", delta=f"{blocked} blocked", delta_color="inverse")
    col3.metric("Allowed Requests", f"{allowed:,}")
    col4.metric("Block Rate", f"{block_rate:.1f}%")

    st.divider()

    # 2. Charts section
    left_col, right_col = st.columns(2)
    with left_col:
        st.subheader("Traffic Timeline")
        # حماية ضد رجوع None
        timeline_data = db_reader.get_events_timeline(since=0, bucket_seconds=60) or []
        if timeline_data:
            df_timeline = pd.DataFrame(timeline_data)
            fig_time = px.line(
                df_timeline,
                x="timestamp_bucket",
                y="count",
                color="action",
                title="Requests over Time",
                color_discrete_map={"allow": "#28a745", "block": "#dc3545", "monitor": "#ffc107"},
            )
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("No traffic recorded yet.")

    with right_col:
        st.subheader("Attack Classification")
        # حماية ضد رجوع None
        attacks_data = db_reader.get_attack_distribution(since=0) or []
        if attacks_data:
            df_attacks = pd.DataFrame(attacks_data)
            fig_pie = px.pie(
                df_attacks,
                names="attack_type",
                values="count",
                title="Attacks by Category",
                hole=0.4,
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No attack events detected yet.")

    st.divider()

    # 3. Top blocked IPs table
    st.subheader("Top Malicious IPs")
    # حماية ضد رجوع None
    top_ips = db_reader.get_top_ips(since=0, limit=10) or []
    if top_ips:
        st.dataframe(pd.DataFrame(top_ips), use_container_width=True)
    else:
        st.info("No blocked IPs recorded.")


render_overview()