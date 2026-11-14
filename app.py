"""app.py - Network traffic analysis dashboard (Streamlit). Run: python -m streamlit run app.py"""
import hashlib
import os
import tempfile

import pandas as pd
import plotly.express as px
import streamlit as st

from ai_engine import ask_ai, build_context
from pcap_analyzer import analyze_pcap

st.set_page_config(page_title="PCAP Dashboard", layout="wide")
st.title("📡 Network Traffic Analysis Dashboard")


@st.cache_data(show_spinner="Analyzing capture...")
def load(data: bytes, suffix: str, digest: str):
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
        f.write(data)
        path = f.name
    try:
        return analyze_pcap(path)
    finally:
        os.unlink(path)


# ------------------------------------------------------------- FR-1: input
up = st.sidebar.file_uploader("Upload a capture file", type=["pcap", "pcapng"])
if not up:
    st.info("Upload a .pcap or .pcapng file in the sidebar to get started.")
    st.stop()

raw = up.getvalue()
try:
    res = load(raw, os.path.splitext(up.name)[1], hashlib.md5(raw).hexdigest())
except Exception as e:
    st.error(f"Could not analyze the file: {e}")
    st.stop()

for w in res.warnings[:10]:
    st.warning(w)
if len(res.warnings) > 10:
    st.warning(f"... and {len(res.warnings) - 10} more warnings.")

S, pk, tx = res.summary, res.packets, res.transactions
tab1, tab2, tab3 = st.tabs(["📊 Overview", "🌐 HTTP Transactions", "🤖 Ask AI"])

# ------------------------------------------------------------- FR-2..FR-4
with tab1:
    c = st.columns(4)
    c[0].metric("Total packets", f"{S['total_packets']:,}")
    c[1].metric("Duration (seconds)", S["duration_sec"])
    c[2].metric("Start time", S["start_time"])
    c[3].metric("End time", S["end_time"])

    left, right = st.columns(2)
    with left:
        st.subheader("Top Talkers")
        tt = pd.DataFrame(S["top_talkers"], columns=["IP", "Packets"])
        st.dataframe(tt, use_container_width=True, hide_index=True)
        fig = px.bar(tt, x="IP", y="Packets", title="Top Talkers")
        st.plotly_chart(fig, use_container_width=True)
    with right:
        st.subheader("Protocol distribution")
        pr = pd.DataFrame(list(S["protocols"].items()), columns=["Protocol", "Packets"])
        st.plotly_chart(px.pie(pr, names="Protocol", values="Packets"), use_container_width=True)

    st.subheader("Traffic volume over time")
    width = max(S["duration_sec"] / 60, 0.001)
    t = pk.assign(bucket=((pk["time"] - S["start_epoch"]) // width) * width)
    ts_df = t.groupby("bucket", as_index=False)["length"].sum()
    ts_df.columns = ["Seconds from start", "Bytes"]
    st.plotly_chart(px.line(ts_df, x="Seconds from start", y="Bytes"), use_container_width=True)

# ------------------------------------------------------------- FR-5..FR-7
selected_id = None
with tab2:
    if tx.empty:
        st.info("No HTTP transactions were found in the capture (the traffic may be encrypted - HTTPS).")
    else:
        f1, f2, f3 = st.columns(3)
        methods = f1.multiselect("Method", sorted(tx["Method"].dropna().unique()))
        statuses = f2.multiselect("Status", sorted(tx["Status"].dropna().astype(int).unique()))
        q = f3.text_input("Search Host/URI")
        view = tx
        if methods:
            view = view[view["Method"].isin(methods)]
        if statuses:
            view = view[view["Status"].isin(statuses)]
        if q:
            m = view["Host"].fillna("").str.contains(q, case=False) | \
                view["URI"].fillna("").str.contains(q, case=False)
            view = view[m]
        st.caption(f"{len(view)} of {len(tx)} transactions · "
                   f"{S['unanswered_requests']} requests without a response")
        st.dataframe(view, use_container_width=True, hide_index=True)

        if len(view):
            st.subheader("Transaction details")
            selected_id = st.selectbox(
                "Select a transaction", view["ID"].tolist(),
                format_func=lambda i: "#{} · {} {}{}".format(
                    i, tx.loc[tx.ID == i, "Method"].iloc[0],
                    tx.loc[tx.ID == i, "Host"].iloc[0] or "",
                    tx.loc[tx.ID == i, "URI"].iloc[0] or ""))
            d = res.tx_details[selected_id]
            a, b = st.columns(2)
            with a:
                st.markdown("**Request**")
                st.code(d["req_head"], language="http")
                if d["req_body"]:
                    st.code(d["req_body"][:4000])
            with b:
                st.markdown("**Response**")
                if d["resp_head"]:
                    st.code(d["resp_head"], language="http")
                    if d["resp_body"]:
                        st.code(d["resp_body"][:4000])
                else:
                    st.warning("No response was found for this request.")

# ------------------------------------------------------------- FR-8..FR-11
with tab3:
    st.caption("The AI receives only the structured data extracted from the capture - not the PCAP file itself.")
    use_sel = st.checkbox("Include the transaction selected in the HTTP tab (for questions about that stream)",
                          value=True, disabled=selected_id is None)
    if "history" not in st.session_state:
        st.session_state.history = []
    question = st.text_input("Ask a question about the traffic",
                             placeholder="What is the slowest request? How many requests were sent to example.com?")
    if st.button("Send", type="primary") and question.strip():
        sel = res.tx_details.get(selected_id) if (use_sel and selected_id) else None
        ctx = build_context(S, tx, sel, selected_id)
        with st.spinner("Thinking..."):
            ans = ask_ai(question, ctx)
        st.session_state.history.insert(0, (question, ans))
    for qn, an in st.session_state.history:
        st.markdown(f"**❓ {qn}**")
        st.markdown(an)
        st.divider()