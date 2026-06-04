# Phishing Detector

A Streamlit app that analyzes URLs for phishing signals and returns a risk score with explanations.

## Features

- URL length analysis
- IP address detection in the host
- HTTP vs HTTPS check
- Suspicious keyword detection
- Subdomain count analysis
- Suspicious top-level domain detection
- Random-looking URL pattern detection
- Streamlit UI with risk level coloring (Safe / Suspicious / Dangerous)
- SQLite history for previously checked URLs
- Optional VirusTotal v3 lookup via API key

## Files

- `app.py` — Streamlit user interface
- `analyzer.py` — URL threat detection logic
- `virustotal.py` — VirusTotal v3 API integration
- `database.py` — SQLite history tracking
- `config.py` — App configuration (DB path)
- `requirements.txt` — Pinned Python dependencies
- `README.md` — Project overview and instructions

## Local Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. (Optional) Add a VirusTotal API key:

Create `.streamlit/secrets.toml`:

```toml
VIRUSTOTAL_API_KEY = "your_api_key_here"
```

> Get a free key at https://www.virustotal.com/gui/my-apikey

3. Run the app:

```bash
streamlit run app.py
```

## Deploying to Streamlit Cloud

1. Push this repository to GitHub (`.streamlit/secrets.toml` is already git-ignored).
2. Go to [share.streamlit.io](https://share.streamlit.io) and create a new app pointing to `app.py`.
3. In the Streamlit Cloud dashboard, go to **Settings → Secrets** and add:

```toml
VIRUSTOTAL_API_KEY = "your_api_key_here"
```

> ⚠️ **SQLite limitation**: `history.db` is stored on the local filesystem. On Streamlit Cloud, the filesystem is ephemeral — history will reset on each redeploy. For persistent history in production, replace the SQLite backend in `database.py` with a cloud database (e.g. Supabase, PlanetScale, or Streamlit's built-in connections).

## Usage

Enter a URL in the input box, click **Analyze**, and review:
- **Risk level** — Safe, Suspicious, or Dangerous
- **Confidence score** — how certain the classifier is
- **Flags** — which heuristic checks were triggered
- **VirusTotal** — results from 70+ antivirus engines (if API key is configured)

The sidebar shows history of the last 15 checks.
