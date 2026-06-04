"""
VirusTotal URL scanning integration using the v3 API.

Step 1: Submit URL for analysis → returns analysis ID
Step 2: Fetch analysis result using the ID → returns verdict with stats
"""

import time
import requests
from requests.exceptions import RequestException

VT_API_BASE = "https://www.virustotal.com/api/v3"


def check_url(url: str, api_key: str) -> dict:
    """
    Scan a URL using VirusTotal's v3 API.

    Args:
        url: The URL to scan
        api_key: VirusTotal API key

    Returns:
        dict with keys:
            - success: bool
            - positives: int (number of engines that flagged it)
            - total: int (total engines that scanned it)
            - message: str (human readable status)
            - analysis_id: str (if available)
    """

    if not api_key:
        return {
            "success": False,
            "positives": 0,
            "total": 0,
            "message": "VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in Streamlit secrets.",
            "analysis_id": None,
        }

    try:
        analysis_id = _submit_url_for_analysis(url, api_key)
        if not analysis_id:
            return {
                "success": False,
                "positives": 0,
                "total": 0,
                "message": "Failed to submit URL for analysis.",
                "analysis_id": None,
            }

        report = _fetch_analysis_report(analysis_id, api_key)
        return report

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


def _headers(api_key: str) -> dict:
    return {"x-apikey": api_key, "Accept": "application/json"}


def _submit_url_for_analysis(url: str, api_key: str) -> str | None:
    """
    Submit a URL for analysis and return the analysis ID.

    Endpoint: POST https://www.virustotal.com/api/v3/urls
    """
    endpoint = f"{VT_API_BASE}/urls"
    response = requests.post(
        endpoint,
        headers=_headers(api_key),
        data={"url": url},
        timeout=15,
    )
    response.raise_for_status()
    data = response.json()
    return data.get("data", {}).get("id")


def _fetch_analysis_report(analysis_id: str, api_key: str) -> dict:
    """
    Fetch the analysis report for a given analysis ID.

    Endpoint: GET https://www.virustotal.com/api/v3/analyses/{id}

    Returns report with malicious/total counts from data.attributes.stats.
    """
    endpoint = f"{VT_API_BASE}/analyses/{analysis_id}"

    max_retries = 4
    for attempt in range(max_retries):
        response = requests.get(endpoint, headers=_headers(api_key), timeout=15)
        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        status = attributes.get("status", "")

        # Still queued or running — wait and retry
        if status in ("queued", "in-progress"):
            if attempt < max_retries - 1:
                time.sleep(3)
                continue
            else:
                return {
                    "success": False,
                    "positives": 0,
                    "total": 0,
                    "message": "Scan is still in progress. Please try again in a moment.",
                    "analysis_id": analysis_id,
                }

        stats = attributes.get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        # positives = engines that flagged as malicious or suspicious
        positives = malicious + suspicious
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
        "message": "Could not retrieve analysis report.",
        "analysis_id": analysis_id,
    }
