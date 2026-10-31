"""Main Streamlit application for the AI-WAF Monitoring Dashboard.

Renders real-time telemetry, traffic volumes, threat breakdowns,
and interactive event auditing logs.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import timedelta
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# إضافة جذر المشروع تلقائياً لمسارات البحث لمنع ModuleNotFoundError عند الاستيراد
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from dashboard import db_reader
except ImportError:
    import db_reader  # Fallback import محلي

# Configure Streamlit page parameters
st.set_page_config(
    page_title="AI-WAF Dashboard",
    layout="wide",
    page_icon="🛡️",
)


def render_header() -> None:
    """Render page title, status indicator, and descriptive subtitle."""
    st.title("🛡️ Next-Gen AI-WAF Security Operations Center")
    st.markdown("لوحة مراقبة أمن المعلومات والتحكم اللحظي بالهجمات (Real-Time SOC Dashboard).")


def render_metric_cards(event_counts: Dict[str, int]) -> None:
    """Render the top-level KPI metrics cards.

    Displays Total Requests, Blocked count, Allowed count, and Block Rate percentage.

    Args:
        event_counts (dict[str, int]): Summary counts of traffic decisions.
    """
    total = event_counts.get("total", 0)
    blocked = event_counts.get("blocked", 0)
    allowed = event_counts.get("allowed", 0)
    block_rate = (blocked / total * 100) if total > 0 else 0.0

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Total Requests", value=f"{total:,}")
    with col2:
        st.metric(label="Blocked Attacks", value=f"{blocked:,}", delta="Threats", delta_color="inverse")
    with col3:
        st.metric(label="Allowed Requests", value=f"{allowed:,}")
    with col4:
        st.metric(label="Block Rate", value=f"{block_rate:.2f}%")


def render_timeline_chart(timeline_data: List[Dict[str, Any]]) -> None:
    """Render Plotly time series chart of requests colored by action.

    Args:
        timeline_data (list[dict[str, Any]]): Time-bucketed traffic series.
    """
    if not timeline_data:
        st.info("لا توجد بيانات زمنية كافية للعرض حالياً.")
        return

    df = pd.DataFrame(timeline_data)
    fig = px.line(df, x="timestamp", y="count", color="action", markers=True, title="Traffic Trend Over Time")
    st.plotly_chart(fig, use_container_width=True)


def render_attack_distribution_chart(attack_data: List[Dict[str, Any]]) -> None:
    """Render Plotly bar chart depicting distribution across attack categories.

    Args:
        attack_data (list[dict[str, Any]]): Frequency counts by attack classification.
    """
    if not attack_data:
        st.info("لا توجد بيانات هجمات مسجلة للعرض.")
        return

    df = pd.DataFrame(attack_data)
    fig = px.bar(df, x="attack_type", y="count", color="attack_type", title="Attack Categories Breakdown")
    st.plotly_chart(fig, use_container_width=True)


def render_top_ips_table(top_ips: List[Dict[str, Any]]) -> None:
    """Render dataframe view displaying top offending IP addresses.

    Args:
        top_ips (list[dict[str, Any]]): Top blocked IP statistics.
    """