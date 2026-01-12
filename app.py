# ✅ PATCH: v3 demo-ready — improve compliance scoring + fix pie legend categories
#
# Apply the two changes below to your existing app.py v3 code.
# (1) Compliance scoring now penalizes Medium + breach_rate.
# (2) Pie chart now only shows severities with Count > 0 (legend + labels aligned).

# ──────────────────────────────────────────────────────────────────────────────
# 1) Replace the Framework Compliance block with this (DROP-IN)
# ──────────────────────────────────────────────────────────────────────────────

# --- place this inside the `if results:` dashboard section, replacing the
#     existing "Framework Compliance Analysis (Data-driven heuristic)" block ---

st.subheader("⚖️ Framework Compliance Analysis (Data-driven heuristic)")

breaches = sum(1 for r in results if not r["pass"])
breach_rate = (breaches / total * 100) if total else 0.0

# Revised data-driven heuristic:
# - penalizes Critical/High heavily
# - penalizes Medium moderately (so Medium FAILs matter)
# - also reflects overall breach rate (so "1/2 breaches" can't still be 100% compliant)
compliance_scores = {
    "EU AI Act": {
        "score": max(
            0.0,
            100.0
            - pct["Critical"] * 2.0
            - pct["High"] * 1.2
            - pct["Medium"] * 0.6
            - breach_rate * 0.3,
        ),
        "details": "Risk assessment, transparency, human oversight",
    },
    "OWASP LLM Top 10": {
        "score": max(
            0.0,
            100.0
            - pct["Critical"] * 2.5
            - pct["High"] * 1.5
            - pct["Medium"] * 0.8
            - breach_rate * 0.4,
        ),
        "details": "Prompt injection, data leakage, output handling",
    },
    "NIST AI RMF": {
        "score": max(
            0.0,
            100.0
            - pct["Critical"] * 1.8
            - pct["High"] * 1.0
            - pct["Medium"] * 0.5
            - breach_rate * 0.3,
        ),
        "details": "Governance, map/measure/manage, controls",
    },
    "ISO 27001": {
        "score": max(
            0.0,
            100.0
            - pct["Critical"] * 2.2
            - pct["High"] * 1.3
            - pct["Medium"] * 0.7
            - breach_rate * 0.3,
        ),
        "details": "ISMS alignment; risk & control maturity",
    },
}

compliance_df = pd.DataFrame(
    [
        {
            "Framework": k,
            "Score": v["score"],
            "Status": (
                "Compliant"
                if v["score"] >= 80
                else ("Partial" if v["score"] >= 60 else "Non-Compliant")
            ),
        }
        for k, v in compliance_scores.items()
    ]
)

bar_fig = px.bar(
    compliance_df,
    x="Framework",
    y="Score",
    color="Status",
    color_discrete_map={
        "Compliant": "#22c55e",
        "Partial": "#f59e0b",
        "Non-Compliant": "#ef4444",
    },
    range_y=[0, 100],
)
st.plotly_chart(bar_fig, use_container_width=True)

with st.expander("Framework scoring basis", expanded=False):
    st.write(
        "Scores are computed from this run’s observed severity distribution and breach rate (not hardcoded)."
    )
    st.markdown(f"- **Breach rate:** {breach_rate:.1f}% ({breaches}/{total})")
    for name, data in compliance_scores.items():
        st.markdown(f"**{name}** — {data['details']}")


# ──────────────────────────────────────────────────────────────────────────────
# 2) Fix pie legend to only include severities with Count > 0 (DROP-IN)
# ──────────────────────────────────────────────────────────────────────────────

# --- replace your pie chart dataframe creation with this filtered version ---
# Find the section:
#   sev_df = pd.DataFrame({"Severity": list(buckets.keys()), "Count": list(buckets.values())})
# Replace it with:

sev_df = (
    pd.DataFrame({"Severity": list(buckets.keys()), "Count": list(buckets.values())})
    .query("Count > 0")
    .copy()
)

pie = px.pie(
    sev_df,
    values="Count",
    names="Severity",
    color="Severity",
    color_discrete_map=SEVERITY_COLORS,
    hole=0.6,
)
pie.update_traces(textposition="inside", textinfo="percent+label")
st.plotly_chart(pie, use_container_width=True)
