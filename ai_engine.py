"""ai_engine.py - מנוע תשאול AI (FR-8..FR-11).

ל-AI נשלחים רק נתונים מובנים שחולצו (סיכום + טבלת טרנזקציות + אגרגציות מחושבות),
אף פעם לא קובץ ה-PCAP הגולמי. מפתח ה-API נקרא ממשתנה סביבה ANTHROPIC_API_KEY.
"""
from __future__ import annotations

import json
import os

import pandas as pd
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
MAX_TX_ROWS = 400
MAX_DETAIL_CHARS = 6000

SYSTEM_PROMPT = """You are a network-traffic analysis assistant.
You receive ONLY structured data extracted from a PCAP file: a summary, precomputed
aggregates, an HTTP transactions table, and optionally the full details of one selected transaction.

Rules:
1. Answer ONLY from the provided data. If the data does not contain the answer, say so explicitly.
2. Never guess or invent values. For counting/min/max questions, prefer the PRECOMPUTED AGGREGATES
   section; otherwise compute carefully from the table.
3. EVERY answer must end with an "Evidence" section listing the exact Frame numbers
   (Request Frame / Response Frame) and/or timestamps the answer relies on.
4. A missing Status/Response Time means the request had no matching response in the capture.
5. Answer in the same language as the user's question. Be concise."""


def _aggregates(tx: pd.DataFrame) -> dict:
    if tx.empty:
        return {"note": "no HTTP transactions found"}
    agg = {
        "requests_per_host": tx["Host"].fillna("(no Host header)").value_counts().to_dict(),
        "requests_per_method": tx["Method"].value_counts().to_dict(),
        "status_code_counts": tx["Status"].dropna().astype(int).value_counts().to_dict(),
        "unanswered_requests": int(tx["Status"].isna().sum()),
    }
    timed = tx.dropna(subset=["Response Time (ms)"])
    if not timed.empty:
        cols = ["ID", "Method", "Host", "URI", "Status", "Response Time (ms)",
                "Request Frame", "Response Frame"]
        agg["slowest_5"] = timed.nlargest(5, "Response Time (ms)")[cols].to_dict("records")
        agg["fastest_1"] = timed.nsmallest(1, "Response Time (ms)")[cols].to_dict("records")
    return agg


def build_context(summary: dict, tx: pd.DataFrame, selected: dict | None = None,
                  selected_id: int | None = None) -> str:
    clean = {k: v for k, v in summary.items() if k not in ("start_epoch", "end_epoch")}
    parts = [
        "## CAPTURE SUMMARY\n" + json.dumps(clean, ensure_ascii=False, default=str, indent=1),
        "## PRECOMPUTED AGGREGATES (computed over ALL transactions)\n"
        + json.dumps(_aggregates(tx), ensure_ascii=False, default=str, indent=1),
    ]
    shown = tx.head(MAX_TX_ROWS)
    note = "" if len(tx) <= MAX_TX_ROWS else f" (first {MAX_TX_ROWS} of {len(tx)} rows)"
    parts.append(f"## HTTP TRANSACTIONS TABLE{note}\n" + shown.to_csv(index=False))
    if selected:
        txt = json.dumps({"transaction_id": selected_id, **selected}, ensure_ascii=False, indent=1)
        parts.append("## SELECTED TRANSACTION DETAILS\n" + txt[:MAX_DETAIL_CHARS])
    return "\n\n".join(parts)


def ask_ai(question: str, context: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        return "⚠️ לא הוגדר משתנה הסביבה GEMINI_API_KEY. ראה הוראות ב-README."
    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model=MODEL,
            contents=f"{context}\n\n## QUESTION\n{question}",
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0,
                max_output_tokens=4096,
            ),
        )
        if resp.text:
            return resp.text
        return "⚠️ ה-AI לא החזיר תשובה (ייתכן שנחסם על ידי מסנני הבטיחות). נסה לנסח מחדש."
    except Exception as e:
        return f"⚠️ שגיאה בקריאה ל-AI: {e}"
