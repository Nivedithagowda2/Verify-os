# VerifyMe — Check Before You Forward

An AI-powered verification layer for India's biggest misinformation and scam channel — WhatsApp forwards. 

---

## 🚨 The Problem

Every day, millions of people in India receive forwarded WhatsApp messages they aren't sure about — a health scare, a "your bank account will be blocked" warning, a too-good-to-be-true investment offer, or a fake job opportunity. Most people either believe it and act on it, or ignore it and hope for the best. There's no fast, easy way to actually check.

### 📉 The Scale of Harm
The impact of this unchecked ecosystem is real, dangerous, and growing rapidly:
* **₹22,495 crore** lost to cybercrime in India in 2025 — up 24% from 2024.
* **28.15 lakh** cybercrime complaints registered in 2025 alone.
* **51%** of fraud victims never report what happened due to social stigma or complexity.
* **60%+** of Indian internet users have encountered fake news on WhatsApp.

### 🔒 The Structural Challenge
WhatsApp is end-to-end encrypted, meaning no platform — not even WhatsApp itself — can moderate forwarded content at scale. The only realistic fix is to give users a fast, independent way to verify a message themselves, the moment they receive it.

--- 

## ✅ The Solution

**VerifyMe** lets anyone check a suspicious forward in seconds. Users can paste text, upload a screenshot, drop a file, or paste a link. 

The content is passed through a multi-agent AI verification pipeline that returns a single, clear, color-coded verdict designed to be screenshotted or copied directly back into a family group chat:

| Verdict | Meaning |
| :--- | :--- |
| 🟢 **Likely True** | Claims verified and supported against live web sources. |
| 🔴 **Likely False** | One or more claims explicitly contradicted by live web sources. |
| 🟡 **Scam Pattern Detected** | Core indicators of fraud, manipulation, or phishing tactics identified. | 

---

## 🔍 How It Works — 4-Agent Pipeline    

VerifyMe runs four independent verification agents on every submission to ensure multi-layered analysis:

### 🤖 Agent 1 — Claim Extractor
Gemini reads the incoming message and isolates specific, checkable factual claims. It strips away opinions or emotional filler to target concrete sentences that can be verified.
* *Example:* `"hot lemon water cures cancer"` $\rightarrow$ extracted as a checkable factual claim.

### 🌐 Agent 2 — Live Verifier
Each extracted claim is independently checked against live web sources using **Google Search grounding**. This prevents the model from hallucinating or relying on outdated internal memory. This live verification step differentiates VerifyMe from standard static LLM interactions.

### ⚠️ Agent 3 — Scam Pattern Matcher
Separately scans the raw text for behavioral manipulation patterns that signal a scam, even when no specific factual claim is present. It hunts for:
* Artificial urgency (*"act in 24 hours or lose access"*)
* Requests for OTPs, PINs, or credentials
* Demands for processing fees or advance taxes
* Phishing link architectures
* Impersonation of official institutions (RBI, banks, utilities)

### 🛡️ Agent 4 — Threat-Intel Scan (Files & Links)
For uploaded files and submitted URLs, this agent initiates a live scan across 70+ security engines via the **VirusTotal API** for real-time malicious signature matching. For files, it additionally analyzes filename and extension disguise structures (e.g., detecting `document.pdf.exe` tricks).

---

## 🏗️ Architecture

```text
               User input (Text / Screenshot / File / URL)
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │   Agent 1             │  Gemini extracts checkable
                       │   Claim Extractor     │  factual claims
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │   Agent 2             │  Each claim verified against live web
                       │   Live Verifier       │  via Google Search grounding
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │   Agent 3             │  Message scanned for urgency, OTP
                       │   Scam Pattern Matcher│  requests, fake deadlines & phishing
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │   Agent 4             │  Files and URLs checked against
                       │   Threat-Intel Scan   │  70+ security engines via VirusTotal
                       └───────────┬───────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │   Verdict             │  Likely True / Likely False /
                       │   Synthesizer         │  Scam Pattern Detected
                       └───────────────────────┘
```



## ✨ Features

| Tab | What it does |
| :--- | :--- |
| 📝 **Paste Text** | Paste any forwarded message and check it instantly. |
| 📷 **Screenshot** | Powered by **Gemini Vision** to read the message text out of the image automatically. |
| 📎 **Check a File** | Filename heuristics + real VirusTotal scan across 70+ antivirus engines. |
| 🔗 **Check a Website** | URL pattern analysis + VirusTotal threat-intelligence lookup. |

---

## 🛠️ Tech Stack

| Layer | Technology Used |
| :--- | :--- |
| **Frontend** | HTML / CSS / JavaScript (single-page, no framework, no install) |
| **Backend** | Python (Flask), Dockerized |
| **Deployment** | Google Cloud Run |
| **AI Engine** | Gemini 2.5 Flash with Google Search grounding |
| **Screenshot OCR** | Gemini Vision (multimodal) |
| **Malware / URL Scanning** | VirusTotal API (70+ engines) |

---

## 🔑 Environment Variables

| Variable | Required | Description |
| :--- | :---: | :--- |
| `GEMINI_API_KEY` | ✅ Yes | Powers all AI agents. Free at AI Studio. |
| `VIRUSTOTAL_API_KEY` | Optional | Real malware and URL scanning. Free tier allows 500 req/day. |

---

## 🚀 Getting Started

### 1. Get your API keys
* **Gemini API key (Required)** — Get it free at [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
* **VirusTotal API key (Optional)** — Get it free at [virustotal.com/gui/my-apikey](https://virustotal.com/gui/my-apikey)

### 2. Run the backend
Open your terminal and run the following commands:

```bash
cd backend
python -m venv venv

# Activate virtual environment
# On Mac/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment keys
cp .env.example .env  # Open .env and paste your actual keys inside

# Run the server
python app.py

The backend server will run natively at http://localhost:8080

```

### 3. Run the frontend
Open a second, separate terminal window and serve the interface:

```bash
cd frontend
python -m http.server 5500

Open http://localhost:5500 in your preferred web browser.

```

## ☁️ Deploy to Cloud Run

To package your containerized backend application and host it in production, utilize this deployment command setup:

```bash
cd backend
gcloud run deploy verifyme \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY=your_key,VIRUSTOTAL_API_KEY=your_key
```

## 🌐 Live Demo

You can interact with the live deployment configuration here:  
👉 **[https://verifyme-912849302401.asia-south1.run.app](https://verifyme-912849302401.asia-south1.run.app)**

---

## 📄 License

This project is licensed under the terms of the **MIT License**.



