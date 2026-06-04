import os

# VirusTotal API Key
# Get it from: https://www.virustotal.com/gui/my-apikey
# Store as environment variable: VT_API_KEY
VT_API_KEY = os.environ.get("VT_API_KEY")

# Database configuration
DB_PATH = "history.db"
