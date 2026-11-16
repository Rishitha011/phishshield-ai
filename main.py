from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
from datetime import datetime, timezone
import whois
import re

app = FastAPI(title="PhishShield AI Engine", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str
    message_text: str = ""

def check_domain_age(domain: str):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            return age_days
    except Exception:
        return None
    return None

@app.post("/scan")
def scan_content(data: ScanRequest):
    risk_score = 0
    flags = []
    raw_url = data.url.strip()

    if raw_url:
        parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
        domain = parsed.netloc.lower()

        # 1. HTTPS Check
        if parsed.scheme != "https":
            risk_score += 20
            flags.append("Connection is not encrypted (missing HTTPS).")

        # 2. Domain Age Check (Newly registered domains are high-risk)
        age_days = check_domain_age(domain)
        if age_days is not None and age_days < 30:
            risk_score += 45
            flags.append(f"Domain was registered very recently ({age_days} days ago) — common in phishing campaigns.")

        # 3. URL Structure & Keyword Traps
        suspicious_keywords = ["login", "verify", "update", "secure", "account", "banking", "signin", "wallet", "kyc"]
        if any(k in raw_url.lower() for k in suspicious_keywords):
            risk_score += 25
            flags.append("URL contains credential-harvesting or KYC keywords.")

        if "@" in raw_url:
            risk_score += 40
            flags.append("URL contains an '@' symbol used to mask the true destination.")

        if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
            risk_score += 45
            flags.append("URL points to a raw IP address instead of a legitimate domain.")

    # 4. Social Engineering & Scam Intent Analysis
    urgency_words = ["immediate", "urgent", "suspend", "action required", "click here", "verify now", "blocked", "pan card", "upi", "otp"]
    if any(w in data.message_text.lower() for w in urgency_words):
        risk_score += 30
        flags.append("Message uses psychological urgency or financial/OTP coercion tactics.")

    risk_score = min(risk_score, 100)
    status = "High Risk — Phishing Detected" if risk_score >= 50 else ("Suspicious — Proceed with Caution" if risk_score > 0 else "Low Risk — Safe")

    return {
        "url": raw_url,
        "risk_score": risk_score,
        "status": status,
        "flags": flags
    }