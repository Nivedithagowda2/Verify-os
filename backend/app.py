"""
VerifyMe backend — checks a forwarded WhatsApp-style message for misinformation and scams.

Agent 1 (Claim Extractor): Gemini pulls out specific, checkable factual claims from the
                            pasted message.
Agent 2 (Live Verifier):    Each claim is independently checked against live web data using
                            Gemini + Google Search grounding (not just the model's memory).
Agent 3 (Scam Pattern Matcher): The raw message is separately scanned for manipulation/scam
                            patterns (urgency, OTP requests, fake deadlines, phishing links)
                            — this catches scams even when there's no "fact" to verify.
Final step: everything is combined into one shareable verdict card.

Run locally:
    export GEMINI_API_KEY=your_key_here
    python app.py

Deploy to Cloud Run:
    gcloud run deploy verifyme --source . --set-env-vars GEMINI_API_KEY=your_key_here --allow-unauthenticated
"""

import os
import json
import re
import time
import hashlib
import base64
import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from google import genai
from google.genai import types

load_dotenv()  # reads the .env file in this folder and loads GEMINI_API_KEY

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB upload limit, keeps things fast for a demo

API_KEY = os.environ.get("GEMINI_API_KEY")
if not API_KEY:
    print("WARNING: GEMINI_API_KEY not set. Create a .env file (see .env.example) before running.")

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    print("WARNING: VIRUSTOTAL_API_KEY not set. Real malware scanning and URL threat checks "
          "will be skipped — get a free key at https://www.virustotal.com/gui/my-apikey")

VT_BASE = "https://www.virustotal.com/api/v3"

client = genai.Client(api_key=API_KEY)

MODEL = "gemini-2.5-flash"  # fast + supports grounding; swap to gemini-2.5-pro for deeper reasoning


def call_gemini_with_retry(fn, *args, max_retries=3, **kwargs):
    """
    Gemini occasionally returns 503 UNAVAILABLE when Google's servers are under high
    demand — this is transient, not a bug in this code. Retry with a short backoff
    before giving up, so a single busy moment doesn't fail the whole request.
    """
    last_error = None
    for attempt in range(max_retries):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_error = e
            if "503" in str(e) or "UNAVAILABLE" in str(e):
                time.sleep(2 * (attempt + 1))  # 2s, 4s, 6s backoff
                continue
            raise  # not a transient error — fail immediately
    raise last_error

# File extensions that are almost never legitimately shared in a casual chat message
# and are commonly used to disguise executables/installers as harmless-looking files.
RISKY_EXTENSIONS = {
    ".exe": "Windows executable — can run arbitrary code on the recipient's PC",
    ".apk": "Android app installer — can be malware outside the Play Store",
    ".scr": "Windows screensaver file — a classic disguise for executables",
    ".bat": "Windows batch script — can run commands automatically",
    ".cmd": "Windows command script — can run commands automatically",
    ".js": "Standalone script file — can run code if double-clicked",
    ".vbs": "Visual Basic script — a classic malware delivery format",
    ".jar": "Java executable — can run arbitrary code",
    ".msi": "Windows installer — can install software silently",
    ".iso": "Disk image — sometimes used to smuggle executables past filters",
}

# Extensions sometimes used as disguises: a "double extension" trick like invoice.pdf.exe
DOUBLE_EXTENSION_PATTERN = re.compile(r"\.(pdf|docx?|xlsx?|jpg|jpeg|png)\.(exe|scr|bat|js|vbs|jar)$", re.IGNORECASE)


def extract_json(text: str):
    """Gemini sometimes wraps JSON in ```json fences — strip them before parsing."""
    cleaned = re.sub(r"^```(json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    return json.loads(cleaned)


# ---------- Agent 0: Screenshot Reader (Vision OCR) ----------
def agent_read_screenshot(image_bytes: bytes, mime_type: str) -> str:
    """Extracts the message text from a screenshot of a WhatsApp/SMS/email forward."""
    image_part = types.Part.from_bytes(data=image_bytes, mime_type=mime_type)
    prompt = (
        "This is a screenshot of a forwarded WhatsApp, SMS, or email message. "
        "Transcribe ONLY the actual message text being forwarded — ignore UI chrome like "
        "timestamps, contact names, status bars, or app icons. "
        "Respond with just the plain transcribed text, nothing else."
    )
    response = call_gemini_with_retry(
        client.models.generate_content, model=MODEL, contents=[image_part, prompt]
    )
    return response.text.strip()


# ---------- Agent 4: URL Risk Checker ----------
def agent_check_urls(message_text: str) -> dict:
    """
    Pattern-based URL risk check. This flags suspicious structure (lookalike domains,
    link shorteners, mismatched display text) — it does NOT browse the link or check it
    against a live threat-intelligence database, so it's a heuristic signal, not a guarantee.
    """
    urls = re.findall(r"https?://[^\s]+|www\.[^\s]+", message_text)
    if not urls:
        return {"urls_found": [], "any_risky": False}

    prompt = (
        "Analyze these URL(s) found in a forwarded message for phishing/scam risk signals: "
        "lookalike or misspelled brand domains (e.g. arnazon.com, paypa1.com), use of link "
        "shorteners (bit.ly, tinyurl, etc — these hide the real destination), suspicious "
        "or unrelated top-level domains, excessive subdomains, or urgency-coded paths "
        "(like /verify-now, /account-locked).\n\n"
        f"URLs:\n{json.dumps(urls)}\n\n"
        "Respond ONLY with JSON in this exact shape, nothing else:\n"
        '{"urls": [{"url": "...", "risk": "high" | "medium" | "low", "reason": "short plain-language reason"}], '
        '"any_risky": true | false}'
    )
    response = call_gemini_with_retry(client.models.generate_content, model=MODEL, contents=prompt)
    try:
        result = extract_json(response.text)
        result["urls_found"] = result.pop("urls", [])
        return result
    except Exception:
        return {"urls_found": [{"url": u, "risk": "unknown", "reason": "Could not analyze this link."} for u in urls], "any_risky": False}


# ---------- Agent 7: Real URL/Website Fraud Check (VirusTotal) ----------
def vt_check_url(url: str) -> dict:
    """
    Real threat-intelligence lookup using VirusTotal's URL endpoint — checks the URL
    against 70+ security engines and blocklists (this aggregates many sources, including
    Google Safe Browsing data, plus Kaspersky, Sophos, and others). Reuses the same
    VIRUSTOTAL_API_KEY already used for file scanning, so no second API key is needed.
    """
    if not VT_API_KEY:
        return {"checked": False, "reason": "VIRUSTOTAL_API_KEY not configured — skipping real threat-intelligence lookup."}

    headers = {"x-apikey": VT_API_KEY}

    try:
        # VT identifies URLs by a base64 (no padding) encoding of the URL string.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        lookup = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=20)

        if lookup.status_code == 404:
            # Not seen before — submit it for a fresh scan.
            submit = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=20)
            submit.raise_for_status()
            analysis_id = submit.json()["data"]["id"]

            for _ in range(4):  # ~4 x 5s = 20s max wait, hackathon-friendly bound
                time.sleep(5)
                poll = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=20)
                if poll.status_code != 200:
                    continue
                attrs = poll.json()["data"]["attributes"]
                if attrs.get("status") == "completed":
                    stats = attrs.get("stats", {})
                    return _format_vt_url_result(url, stats, from_cache=False)

            return {"checked": False, "reason": "Scan submitted but still in progress — try again in a minute."}

        lookup.raise_for_status()
        attrs = lookup.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return _format_vt_url_result(url, stats, from_cache=True)

    except Exception as e:
        return {"checked": False, "reason": f"VirusTotal URL lookup failed: {e}"}


def _format_vt_url_result(url: str, stats: dict, from_cache: bool) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0
    flagged = malicious + suspicious

    return {
        "checked": True,
        "from_cache": from_cache,
        "is_flagged": flagged > 0,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total_engines,
        "summary": (
            f"{flagged} of {total_engines} security engines flagged this URL"
            if flagged > 0 else
            f"0 of {total_engines} security engines flagged this URL"
        ),
    }


def agent_check_single_url(url: str) -> dict:
    """
    Full check for one standalone URL pasted by the user (the 'is this website a fraud'
    feature): real VirusTotal threat-intelligence lookup + Gemini reasoning over structural
    red flags (lookalike domain, suspicious TLD, shorteners, etc).
    """
    vt_result = vt_check_url(url)

    prompt = (
        f'Analyze this URL for phishing/scam/fraud risk signals: "{url}"\n\n'
        "Look for: lookalike or misspelled brand domains (e.g. arnazon.com, paypa1.com), "
        "link shorteners hiding the real destination, suspicious or unusual top-level "
        "domains, excessive subdomains, urgency-coded paths (/verify-now, /account-locked), "
        "or anything else that looks like a phishing/fraud structure.\n\n"
        'Respond ONLY with JSON in this exact shape, nothing else:\n'
        '{"risk": "high" | "medium" | "low", '
        '"red_flags": ["short label", ...], '
        '"explanation": "one short, plain-language sentence"}'
    )
    response = call_gemini_with_retry(client.models.generate_content, model=MODEL, contents=prompt)
    try:
        pattern_result = extract_json(response.text)
    except Exception:
        pattern_result = {"risk": "unknown", "red_flags": [], "explanation": "Could not analyze this URL's structure."}

    # Real VirusTotal detection always wins — it's actual confirmed-threat data, not a guess.
    if vt_result.get("checked") and vt_result.get("is_flagged"):
        overall_risk = "high"
    else:
        overall_risk = pattern_result.get("risk", "unknown")

    return {
        "url": url,
        "overall_risk": overall_risk,
        "threat_intel": vt_result,
        "pattern_check": pattern_result,
    }


# ---------- Agent 5: File Risk Checker ----------
def agent_check_file(filename: str, file_bytes: bytes) -> dict:
    """
    Heuristic file-risk check based on filename/extension patterns. This is NOT a malware
    scanner — it does not inspect file contents for known malware signatures the way an
    antivirus engine does. It flags risky file types and common disguise tricks
    (e.g. invoice.pdf.exe) so the user knows to be cautious before opening.
    """
    lower_name = filename.lower()
    ext = os.path.splitext(lower_name)[1]

    flags = []
    risk = "low"

    if DOUBLE_EXTENSION_PATTERN.search(lower_name):
        flags.append("Disguised double extension (looks like a document but is actually a program)")
        risk = "high"

    if ext in RISKY_EXTENSIONS:
        flags.append(RISKY_EXTENSIONS[ext])
        risk = "high"

    # Basic magic-byte sanity check: does the file content match what the extension claims?
    header = file_bytes[:8]
    looks_like_exe = header[:2] == b"MZ"  # Windows executables start with "MZ"
    if looks_like_exe and ext not in (".exe", ".dll", ".msi", ".scr"):
        flags.append(f"File content looks like a Windows program, but is named like a '{ext}' file — strong disguise signal")
        risk = "high"

    if not flags:
        flags.append("No obvious risky extension or disguise pattern detected")

    return {
        "filename": filename,
        "risk": risk,
        "flags": flags,
        "disclaimer": "This is a heuristic filename/structure check, not a full malware scan. When in doubt, don't open unexpected files from forwards.",
    }


# ---------- Agent 6: Real Malware Scan via VirusTotal (70+ AV engines) ----------
def vt_scan_file(file_bytes: bytes, filename: str) -> dict:
    """
    Real malware detection using the VirusTotal public API (free tier).
    Strategy: first check by file hash (instant, no upload needed, works if VT has
    seen this exact file before). If unknown, upload the file for fresh analysis and
    poll briefly for a result. Free tier is rate-limited (~4 req/min), so polling is
    capped to keep the demo responsive.
    """
    if not VT_API_KEY:
        return {
            "scanned": False,
            "reason": "VIRUSTOTAL_API_KEY not configured — skipping real malware scan.",
        }

    headers = {"x-apikey": VT_API_KEY}
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    # Step 1: instant lookup by hash — works if this exact file was ever scanned before.
    lookup = requests.get(f"{VT_BASE}/files/{sha256}", headers=headers, timeout=20)

    if lookup.status_code == 200:
        attrs = lookup.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return _format_vt_result(sha256, stats, attrs, from_cache=True)

    if lookup.status_code != 404:
        return {"scanned": False, "reason": f"VirusTotal lookup failed (HTTP {lookup.status_code})."}

    # Step 2: not seen before — upload for a fresh scan.
    try:
        upload = requests.post(
            f"{VT_BASE}/files",
            headers=headers,
            files={"file": (filename, file_bytes)},
            timeout=30,
        )
        upload.raise_for_status()
        analysis_id = upload.json()["data"]["id"]
    except Exception as e:
        return {"scanned": False, "reason": f"Could not upload file to VirusTotal: {e}"}

    # Step 3: poll briefly for the result. Hackathon-friendly: short, bounded wait —
    # full sandbox analysis can take longer than this, so we report "scan in progress"
    # honestly if it doesn't finish in time rather than blocking the demo.
    for _ in range(4):  # ~4 x 5s = 20s max wait
        time.sleep(5)
        poll = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=20)
        if poll.status_code != 200:
            continue
        status = poll.json()["data"]["attributes"].get("status")
        if status == "completed":
            stats = poll.json()["data"]["attributes"].get("stats", {})
            return _format_vt_result(sha256, stats, {}, from_cache=False)

    return {
        "scanned": False,
        "reason": "VirusTotal scan submitted but still in progress — try again in a minute, or check virustotal.com directly with this hash.",
        "sha256": sha256,
    }


def _format_vt_result(sha256: str, stats: dict, attrs: dict, from_cache: bool) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0
    flagged = malicious + suspicious

    return {
        "scanned": True,
        "sha256": sha256,
        "from_cache": from_cache,  # True = matched a hash VT already knew; False = freshly uploaded
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total_engines,
        "verdict": "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "clean"),
        "known_name": attrs.get("meaningful_name"),
        "summary": (
            f"{flagged} of {total_engines} antivirus engines flagged this file"
            if flagged > 0 else
            f"0 of {total_engines} antivirus engines flagged this file"
        ),
    }


# ---------- Agent 1: Claim Extractor ----------
def agent_extract_claims(message_text: str) -> list[str]:
    prompt = (
        "You are reading a forwarded WhatsApp-style message. Extract every discrete, "
        "independently-checkable factual claim from it (not opinions, not vague statements). "
        "Each claim should be a short, self-contained sentence. "
        "If the message makes no checkable factual claims at all (e.g. it's purely a phishing "
        "link or payment request with no factual statement), return an empty array. "
        "Respond ONLY with a JSON array of strings, nothing else.\n\n"
        f"Message:\n{message_text}"
    )
    response = call_gemini_with_retry(client.models.generate_content, model=MODEL, contents=prompt)
    try:
        claims = extract_json(response.text)
        if isinstance(claims, list):
            return [str(c) for c in claims][:6]  # cap at 6 claims to keep demo fast
    except Exception:
        pass
    return []


# ---------- Agent 2: Live Verifier (grounded with live search) ----------
def agent_verify_claim(claim: str) -> dict:
    grounding_tool = types.Tool(google_search=types.GoogleSearch())
    config = types.GenerateContentConfig(tools=[grounding_tool])

    prompt = (
        f'Fact-check this exact claim using current, real information from the web: "{claim}"\n\n'
        'Respond ONLY with JSON in this exact shape, nothing else:\n'
        '{"verdict": "verified" | "contradicted" | "unverifiable", '
        '"confidence": 0-100, '
        '"explanation": "one short, plain-language sentence a non-technical person could understand"}'
    )

    response = call_gemini_with_retry(client.models.generate_content, model=MODEL, contents=prompt, config=config)

    try:
        result = extract_json(response.text)
    except Exception:
        result = {"verdict": "unverifiable", "confidence": 0, "explanation": "Could not verify this claim right now."}

    result["claim"] = claim
    return result


# ---------- Agent 3: Scam Pattern Matcher ----------
def agent_scam_check(message_text: str) -> dict:
    prompt = (
        "Analyze this forwarded message for common scam / manipulation patterns: artificial "
        "urgency or fake deadlines, requests for OTP/PIN/passwords, requests for money or "
        "'processing fees', suspicious links, fake official letterheads, too-good-to-be-true "
        "offers, or threats (account blocked, legal action, etc).\n\n"
        "Respond ONLY with JSON in this exact shape, nothing else:\n"
        '{"is_scam_pattern": true | false, '
        '"patterns_found": ["short label", ...], '
        '"explanation": "one short, plain-language sentence"}\n\n'
        f"Message:\n{message_text}"
    )
    response = call_gemini_with_retry(client.models.generate_content, model=MODEL, contents=prompt)
    try:
        return extract_json(response.text)
    except Exception:
        return {"is_scam_pattern": False, "patterns_found": [], "explanation": "Could not analyze for scam patterns."}


# ---------- Final verdict synthesis ----------
def compute_verdict(verifications: list[dict], scam_result: dict, url_result: dict = None) -> dict:
    if scam_result.get("is_scam_pattern"):
        return {
            "headline": "Scam Pattern Detected",
            "color": "contradicted",
            "summary": scam_result.get("explanation", "This message matches known scam patterns."),
        }

    if url_result and url_result.get("any_risky"):
        risky_urls = [u for u in url_result.get("urls_found", []) if u.get("risk") in ("high", "medium")]
        return {
            "headline": "Suspicious Link Detected",
            "color": "contradicted",
            "summary": f"{len(risky_urls)} link(s) in this message show phishing risk signals — be cautious before clicking.",
        }

    if not verifications:
        return {
            "headline": "No Checkable Claims Found",
            "color": "unverifiable",
            "summary": "This message doesn't contain a specific factual claim to verify, but check the scam-pattern result below.",
        }

    weights = {"verified": 1.0, "unverifiable": 0.5, "contradicted": 0.0}
    total = sum(weights.get(v["verdict"], 0.5) for v in verifications)
    score = round((total / len(verifications)) * 100)

    contradicted_count = sum(1 for v in verifications if v["verdict"] == "contradicted")

    if contradicted_count > 0:
        headline = "Likely False"
        color = "contradicted"
        summary = f"{contradicted_count} of {len(verifications)} claim(s) were contradicted by live sources."
    elif score >= 75:
        headline = "Likely True"
        color = "verified"
        summary = "All checkable claims were verified against current sources."
    else:
        headline = "Unverifiable"
        color = "unverifiable"
        summary = "We couldn't independently confirm these claims — be cautious before sharing."

    return {"headline": headline, "color": color, "summary": summary, "score": score}


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "VerifyMe backend",
        "status": "running",
        "note": "This is the API server, not the webpage. Open frontend/index.html in your browser to use the actual app.",
        "endpoints": {
            "health_check": "/api/health",
            "verify_message": "POST /api/check (JSON: {message: string})",
            "verify_screenshot": "POST /api/check-image (form-data: image file)",
            "check_file_risk": "POST /api/check-file (form-data: file)",
            "check_url_fraud": "POST /api/check-url (JSON: {url: string})"
        }
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(force=True)
    message_text = (data or {}).get("message", "").strip()

    if not message_text:
        return jsonify({"error": "message is required"}), 400

    try:
        claims = agent_extract_claims(message_text)
        verifications = [agent_verify_claim(c) for c in claims]
        scam_result = agent_scam_check(message_text)
        url_result = agent_check_urls(message_text)
        verdict = compute_verdict(verifications, scam_result, url_result)

        return jsonify({
            "message": message_text,
            "claims": verifications,
            "scam_check": scam_result,
            "url_check": url_result,
            "verdict": verdict,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/check-image", methods=["POST"])
def check_image():
    """
    Accepts an uploaded screenshot, transcribes the message text from it via Gemini Vision,
    then runs it through the exact same pipeline as /api/check.
    """
    if "image" not in request.files:
        return jsonify({"error": "image file is required (field name: image)"}), 400

    image_file = request.files["image"]
    image_bytes = image_file.read()
    mime_type = image_file.mimetype or "image/jpeg"

    try:
        transcribed_text = agent_read_screenshot(image_bytes, mime_type)

        if not transcribed_text:
            return jsonify({"error": "Could not read any text from this image"}), 400

        claims = agent_extract_claims(transcribed_text)
        verifications = [agent_verify_claim(c) for c in claims]
        scam_result = agent_scam_check(transcribed_text)
        url_result = agent_check_urls(transcribed_text)
        verdict = compute_verdict(verifications, scam_result, url_result)

        return jsonify({
            "message": transcribed_text,
            "transcribed_from_image": True,
            "claims": verifications,
            "scam_check": scam_result,
            "url_check": url_result,
            "verdict": verdict,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/check-file", methods=["POST"])
def check_file():
    """
    Two layers of file safety checking:
    1. Instant heuristic check (filename/extension/disguise patterns) — always runs, no delay.
    2. Real malware scan via VirusTotal (70+ antivirus engines) — genuine detection, not a guess.
       Skipped automatically if VIRUSTOTAL_API_KEY isn't set.
    """
    if "file" not in request.files:
        return jsonify({"error": "file is required (field name: file)"}), 400

    uploaded = request.files["file"]
    filename = uploaded.filename or "unknown"
    file_bytes = uploaded.read()

    if len(file_bytes) == 0:
        return jsonify({"error": "uploaded file is empty"}), 400

    try:
        heuristic_result = agent_check_file(filename, file_bytes)
        vt_result = vt_scan_file(file_bytes, filename)

        # Combine into one overall verdict — real AV detection (if available) takes priority
        # over heuristics, since it's actual detection rather than a pattern guess.
        if vt_result.get("scanned") and vt_result.get("verdict") == "malicious":
            overall_risk = "high"
        elif vt_result.get("scanned") and vt_result.get("verdict") == "suspicious":
            overall_risk = "medium"
        else:
            overall_risk = heuristic_result["risk"]

        return jsonify({
            "filename": filename,
            "overall_risk": overall_risk,
            "heuristic_check": heuristic_result,
            "malware_scan": vt_result,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/check-url", methods=["POST"])
def check_url():
    """
    Standalone website fraud checker: paste just a URL, get back a real verdict.
    Combines VirusTotal (real, multi-engine threat-intelligence lookup) with
    Gemini's structural pattern analysis (lookalike domains, shorteners, etc).
    """
    data = request.get_json(force=True)
    url = (data or {}).get("url", "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400

    # Basic sanity normalization — add a scheme if the user pasted a bare domain.
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    try:
        result = agent_check_single_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
