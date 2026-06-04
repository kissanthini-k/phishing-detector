"""
VirusTotal URL scanning integration using the v3 API.

Strategy:
  1. Check if VT already has a cached report for the URL (instant).
  2. If no cached report, submit for a new scan and poll briefly.
"""

import base64
import time
import requests
from requests.exceptions import RequestException

VT_API_BASE = "https://www.virustotal.com/api/v3"


def _headers(api_key: str) -> dict:
    return {"x-apikey": api_key, "Accept": "application/json"}


def _url_id(url: str) -> str:
    """Encode a URL into the VirusTotal v3 URL identifier (base64url, no padding)."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def check_url(url: str, api_key: str) -> dict:
    """
    Look up a URL on VirusTotal using the v3 API.

    First checks for a cached report (fast). If none exists, submits
    for a new scan and polls up to 3 times with a short wait.

    Returns:
        dict with keys: success, positives, total, message, analysis_id
    """
    if not api_key:
        return {
            "success": False,
            "positives": 0,
            "total": 0,
            "message": "VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to Streamlit secrets.",
            "analysis_id": None,
        }

    try:
        # Step 1: Try cached report first (instant, no quota cost)
        cached = _get_cached_report(url, api_key)
        if cached:
            return cached

        # Step 2: No cached report — submit for a fresh scan
        analysis_id = _submit_url_for_analysis(url, api_key)
        if not analysis_id:
            return {
                "success": False,
                "positives": 0,
                "total": 0,
                "message": "Failed to submit URL for scanning.",
                "analysis_id": None,
            }

        # Step 3: Poll for results (up to 3 retries × 5s = 15s max)
        return _fetch_analysis_report(analysis_id, api_key)

    except RequestException as e:
        return {
            "success": False,
            "positives": 0,
            "total": 0,
            "message": f"VirusTotal API error: {str(e)}",
            "analysis_id": None,
        }
    except Exception as e:
        return {
            "success": False,
            "positives": 0,
            "total": 0,
            "message": f"Unexpected error: {str(e)}",
            "analysis_id": None,
        }


def _get_cached_report(url: str, api_key: str) -> dict | None:
    """
    Check if VirusTotal already has a report for this URL.
    Returns a result dict if found, or None if not cached.
    """
    endpoint = f"{VT_API_BASE}/urls/{_url_id(url)}"
    try:
        response = requests.get(endpoint, headers=_headers(api_key), timeout=10)
        if response.status_code == 404:
            return None  # URL not in VT database yet
        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if not stats:
            return None
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        positives = malicious + suspicious
        total = sum(stats.values())
        return {
            "success": True,
            "positives": positives,
            "total": total,
            "message": f"{positives} / {total} engines flagged this URL (cached result)",
            "analysis_id": None,
        }
    except Exception:
        return None  # Fall through to fresh scan


def _submit_url_for_analysis(url: str, api_key: str) -> str | None:
    """Submit a URL for a fresh scan and return the analysis ID."""
    response = requests.post(
        f"{VT_API_BASE}/urls",
        headers=_headers(api_key),
        data={"url": url},
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("data", {}).get("id")


def _fetch_analysis_report(analysis_id: str, api_key: str) -> dict:
    """
    Poll the analysis endpoint until the scan completes.
    Gives up after 3 retries (≈15s) and returns a friendly message.
    """
    endpoint = f"{VT_API_BASE}/analyses/{analysis_id}"

    for attempt in range(3):
        response = requests.get(endpoint, headers=_headers(api_key), timeout=15)
        response.raise_for_status()
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        status = attributes.get("status", "")

        if status in ("queued", "in-progress"):
            if attempt < 2:
                time.sleep(5)
                continue
            # Still not ready — tell the user to retry
            return {
                "success": False,
                "positives": 0,
                "total": 0,
                "message": "VirusTotal is still scanning this URL. Try again in 30 seconds.",
                "analysis_id": analysis_id,
            }

        stats = attributes.get("stats", {})
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        return {
            "success": True,
            "positives": positives,
            "total": total,
            "message": f"{positives} / {total} engines flagged this URL",
            "analysis_id": analysis_id,
        }

    return {
        "success": False,
        "positives": 0,
        "total": 0,
        "message": "Could not retrieve scan report.",
        "analysis_id": analysis_id,
    }
