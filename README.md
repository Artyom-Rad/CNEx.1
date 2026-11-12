# PCAP Dashboard V1

Dashboard לניתוח תעבורת רשת: טעינת PCAP/PCAPNG, סטטיסטיקות, חילוץ טרנזקציות HTTP ותשאול AI.

## קבצים
- `app.py` – ממשק Streamlit
- `pcap_analyzer.py` – פענוח חבילות, סטטיסטיקות והתאמת Request/Response
- `ai_engine.py` – בניית הקשר מובנה ושליחה למודל (ללא ה-PCAP הגולמי)
- `requirements.txt`

## הרצה
```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY="your-key"                   # Windows: set ANTHROPIC_API_KEY=your-key
# אופציונלי: export CLAUDE_MODEL="claude-sonnet-5-5"

streamlit run app.py
```
לאחר מכן יש להעלות קובץ `.pcap` / `.pcapng` בסרגל הצד.

## הערות
- מפתח ה-API נקרא רק ממשתנה סביבה – אין לשמור אותו בקוד.
- ללא מפתח, כל החלקים פועלים חוץ מלשונית ה-AI.
- מגבלות ידועות: HTTPS מוצפן אינו מפוענח; תוכן chunked/gzip מוצג גולמי; ה-Body נחתך ל-4000 בתים.
- כדי להחליף ספק AI (OpenAI/Gemini) יש לשנות רק את הפונקציה `ask_ai` ב-`ai_engine.py`.

## בדיקות מומלצות (QA)
- QA-1: הרץ 5 שאלות שתשובותיהן ידועות מ-Wireshark (הבקשה האיטית ביותר, Status לבקשה מסוימת, ספירת בקשות ל-Host, וכו') והשווה.
- QA-2: תעד מקרה שבו ה-AI טעה (למשל קבצים עם >400 טרנזקציות, שבהם הטבלה נחתכת) – המערכת כבר שולחת אגרגציות מחושבות מראש כדי לצמצם טעויות; ניתן לשפר את `SYSTEM_PROMPT` בהתאם.
