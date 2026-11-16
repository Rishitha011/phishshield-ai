from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re

app = FastAPI(title="PhishShield AI API", version="1.0")

# Allow frontend/browser extensions to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str
    message_text: str = ""

@app.get("/")
def home():
    return {"message": "PhishShield AI Engine is Live!", "docs": "/docs"}

@app.post("/scan")
def scan_content(data: ScanRequest):
    risk_score = 0
    flags = []

    # 1. URL Keyword & Structure Checks
    suspicious_keywords = ["login", "verify", "update", "secure", "account", "banking", "signin", "wallet"]
    if any(keyword in data.url.lower() for keyword in suspicious_keywords):
        risk_score += 30
        flags.append("URL contains sensitive credential-harvesting keywords.")

    if "@" in data.url:
        risk_score += 40
        flags.append("URL contains an '@' symbol used to obscure the true destination.")

    if re.search(r"http://\d+\.\d+\.\d+\.\d+", data.url):
        risk_score += 45
        flags.append("URL uses a raw IP address instead of a verified domain name.")

    # 2. Social Engineering Intent Check in Text
    urgency_words = ["immediate", "urgent", "suspend", "action required", "click here", "verify now", "blocked"]
    if any(word in data.message_text.lower() for word in urgency_words):
        risk_score += 30
        flags.append("Message uses high-pressure psychological urgency triggers.")

    # Cap score at 100
    risk_score = min(risk_score, 100)

    # Determine Verdict
    status = "Safe"
    if risk_score >= 50:
        status = "High Risk - Phishing Detected"
    elif risk_score > 0:
        status = "Suspicious - Proceed with Caution"

    return {
        "url": data.url,
        "risk_score": risk_score,
        "status": status,
        "flags": flags
    }