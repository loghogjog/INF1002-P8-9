#---Alvan---#
import email
import base64
import os

import requests
import time
import re
from urllib.parse import urlparse
from dotenv import load_dotenv

def extract_eml_txt(file_stream):
    """
    Extracts the text content from an uploaded .eml file stream.
    """
    file_stream.seek(0)
    email_msg = email.message_from_binary_file(file_stream)
    extracted_text = ""
    if email_msg.is_multipart():
        for part in email_msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    extracted_text += payload.decode(errors="ignore")
    else:
        payload = email_msg.get_payload(decode=True)
        if payload:
            extracted_text = payload.decode(errors="ignore")

    return extracted_text

def extract_urls(text):
    """
    extracts all url from extracted text
    """
    urls = []
    words = text.replace('"', ' ').replace("'", " ").replace(">", " ").replace("<", " ").split()
    for word in words:
        if word.startswith("http://") or word.startswith("https://"):
            clean = word.strip(".,;!?)]}")
            if clean not in urls:
                urls.append(clean)
    return urls

def is_ip_addr(url):
    """
    Check for ip addresses within urls
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        parts = host.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            if not (0 <= int(part) <= 255):
                return False
        return True
    except Exception:
        return False

def push_to_virustotal(url):
    """
    Push urls to virus total to check for malicious domains.
    """
    load_dotenv()
    api_key = os.environ.get('URL_SCAN_API_KEY')
    submit_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    try:
        response = requests.post(submit_url, data={"url": url}, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "error", "details": str(e)}

    data = response.json()
    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        return {"url": url, "status": "error", "details": "No analysis ID returned"}

    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(5):
        time.sleep(2)
        report_resp = requests.get(report_url, headers=headers)
        if report_resp.status_code != 200:
            continue
        report_data = report_resp.json()
        status = report_data.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            stats = report_data["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            harmless = stats.get("harmless", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + harmless + suspicious + undetected
            result_status = (
                "malicious" if malicious > 0 else
                "suspicious" if suspicious > 0 else
                "clean"
            )

            encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            link = f"https://www.virustotal.com/gui/url/{encoded_url}"

            return {
                "url": url,
                "status": result_status,
                "positives": malicious,
                "total": total,
                "permalink": link
            }

    return {"url": url, "status": "pending", "details": "Scan not ready yet"}

def evaluate_url_risk(url, vt_result):
    """
    Assigns weights to the URLs based on indicators and VirusTotal results.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    risk_rules = []
    weight = 0

    if is_ip_addr(url):
        risk_rules.append(("URL uses IP address instead of domain", "High", 70))
        weight += 70

    shorten = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "buff.ly"]
    if any(s in domain for s in shorten):
        risk_rules.append(("URL shortener", "Low", 20))
        weight += 20

    if re.search(r"hxxp|%[0-9a-fA-F]{2}|0x", url):
        risk_rules.append(("Encoded URL detected", "Medium", 40))
        weight += 40

    if any(ord(c) > 127 for c in domain):
        risk_rules.append(("Internationalized domain trick (IDN homograph attack)", "High", 60))
        weight += 60

    vt_status = vt_result.get("status", "unknown")
    if vt_status == "malicious":
        risk_rules.append(("Detected as malicious on VirusTotal", "Critical", 100))
        weight += 100
    elif vt_status == "suspicious":
        risk_rules.append(("Flagged as suspicious on VirusTotal", "High", 60))
        weight += 60

    if weight <= 50:
        final_risk = "Info"
    elif weight <= 100:
        final_risk = "Suspicious"
    else:
        final_risk = "Critical"


    return {"url": url, "verdict": vt_status, "total_weight": min(100, weight), "final_risk": final_risk, "details": risk_rules, "virustotal_link": vt_result.get("permalink", "")}
