# PCAP Dashboard V1

A network-traffic analysis dashboard built with Streamlit. Load a PCAP/PCAPNG file, explore statistics, inspect extracted HTTP transactions, and ask questions about the traffic using Google Gemini.

## Features

- Load `.pcap` / `.pcapng` files from the sidebar
- Capture statistics and charts
- HTTP request/response matching, with full details for a selected transaction
- **Ask AI**: natural-language questions about the traffic, answered by the Gemini API
  - The AI receives only structured data extracted from the capture (summary, precomputed aggregates, an HTTP transactions table, and optionally one selected transaction) - never the raw PCAP file
  - Every answer ends with an "Evidence" section listing the frame numbers/timestamps it relies on

## Project structure

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI |
| `pcap_analyzer.py` | Packet parsing, statistics, request/response matching |
| `ai_engine.py` | Builds the structured context and queries the Gemini API |
| `requirements.txt` | Python dependencies |
| `.env.example` | Template for the API key file |

## Requirements

- Python 3.10+
- A free Gemini API key (only needed for the Ask AI tab): https://aistudio.google.com/apikey

## Setup

### 1. Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
If PowerShell blocks the script, run once:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**macOS / Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 3. Provide your Gemini API key

The key is **not** included in this repository. Create your own and provide it in one of two ways.

**Option A - `.env` file (recommended):**

Copy `.env.example` to `.env` and put your key in it:
```
GEMINI_API_KEY=your-key-here
```

**Option B - environment variable:**

```powershell
# Windows PowerShell
$env:GEMINI_API_KEY="your-key-here"
```
```bash
# macOS / Linux
export GEMINI_API_KEY="your-key-here"
```

Optional: choose a different model (default is `gemini-3.8-flash`):
```
GEMINI_MODEL=gemini-3.8-flash
```

### 4. Run

```bash
python -m streamlit run app.py
```

Then upload a `.pcap` / `.pcapng` file in the sidebar.

> Use `python -m streamlit` rather than plain `streamlit`. This guarantees Streamlit runs with the same Python (and the same virtual environment) that your packages were installed into.

## Notes

- Never commit your API key. `.env` is listed in `.gitignore`.
- Without an API key, everything works except the Ask AI tab, which shows a message explaining the key is missing.
- The AI provider is isolated in the `ask_ai` function in `ai_engine.py`; to switch providers, only that function needs to change.

## Known limitations

- Encrypted HTTPS traffic is not decrypted.
- Chunked / gzip-encoded bodies are shown raw.
- Response bodies are truncated to 4000 bytes in the UI.
- Only the first 400 transactions are sent to the AI as a table. Precomputed aggregates (per-host counts, status codes, slowest/fastest requests) are computed over all transactions to reduce errors on large captures.

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'dotenv'` (or `google`) | Install into the active environment: `python -m pip install -r requirements.txt` |
| `python -m streamlit` says Streamlit is not found | Streamlit is not installed in the active venv. Run `python -m pip install -r requirements.txt` |
| `source venv/bin/activate` fails on Windows | Use `.\venv\Scripts\Activate.ps1` (PowerShell) or `venv\Scripts\activate.bat` (cmd) |
| "GEMINI_API_KEY is not set" in the AI tab | Create `.env` or set the environment variable, then restart Streamlit |

## Suggested QA

- **QA-1:** Ask 5 questions whose answers are known from Wireshark (slowest request, status of a specific request, request count per host, etc.) and compare.
- **QA-2:** Document a case where the AI was wrong (for example, captures with more than 400 transactions where the table is truncated) and tune `SYSTEM_PROMPT` accordingly.