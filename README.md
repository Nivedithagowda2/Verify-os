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



## 📁 File structure

```
verifyme/
├── README.md                 ← you are here
├── backend/
│   ├── app.py                ← the AI logic (6 agents: claim extraction, live
│   │                            verification, scam patterns, URL risk, file
│   │                            risk, screenshot OCR)
│   ├── requirements.txt      ← list of Python packages needed
│   ├── Dockerfile            ← used only when deploying to Cloud Run
│   ├── .env.example           ← shows you where the API key goes
│   └── .env                  ← YOU create this — your real key goes here (never share this file)
└── frontend/
    └── index.html             ← the webpage UI (3 tabs: text / screenshot / file)
```

### Honest scope notes (mention these to judges)
- **File checker** flags risky extensions and disguise tricks (like `invoice.pdf.exe`) — it is **not** a full malware/antivirus scan of file contents against signature databases. That's a deliberately honest scope, not a missing feature.
- **URL checker** flags structurally suspicious links (lookalike domains, shorteners) using pattern reasoning — it doesn't browse the link live or check a threat-intelligence database, so treat it as a heuristic signal.

---

## 🔑 Step 1 — Get a free Gemini API key

1. Go to **https://aistudio.google.com/app/apikey**
2. Sign in with your Google account
3. Click **"Create API key"**
4. Copy the long string it gives you (looks like `AIzaSy...`)

This is free and takes under a minute.

---

## 📝 Step 2 — Paste your API key in the right place

This is the part people get confused about, so to be precise:

1. Open the `backend` folder in VS Code
2. Find the file called **`.env.example`**
3. Make a **copy** of it and rename the copy to exactly **`.env`** (no ".example" at the end)
   - In VS Code: right-click `.env.example` → "Copy" → right-click the folder → "Paste" → rename the new file to `.env`
4. Open `.env` and replace `paste_your_gemini_key_here` with your real Gemini key, so it looks like:

```
GEMINI_API_KEY=AIzaSyD4xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

5. (Optional, but powers two features: file scanning AND website checking) Get a free VirusTotal key too:
   - Go to **https://www.virustotal.com/gui/my-apikey**
   - Sign up / sign in, then copy your API key from that page
   - Paste it into the same `.env` file on the `VIRUSTOTAL_API_KEY=` line

If you skip the VirusTotal key, everything else still works — the file-upload and
website-check features will just show a message saying the real scan was skipped,
while still showing the instant heuristic/structural checks.

6. Save the file.

That's it — **`app.py` automatically reads this `.env` file** when it starts. You never paste the key directly into any code file. This also keeps your key safe if you ever push this project to GitHub (the `.gitignore` file already excludes `.env` from being committed).

---

## ▶️ Step 3 — Run the backend (in VS Code)

Open a terminal inside VS Code (`Terminal` → `New Terminal`), then:

```bash
cd backend
python -m venv venv
```

Activate the virtual environment:

```bash
# Mac/Linux:
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Run the server:

```bash
python app.py
```

If it worked, you'll see something like:

```
* Running on http://127.0.0.1:8080
```

Leave this terminal running — this is your backend, it needs to stay on.

**Quick test** (open a second terminal, don't close the first one):

```bash
curl -X POST http://localhost:8080/api/check -H "Content-Type: application/json" -d "{\"message\": \"Drinking hot lemon water every morning cures cancer, doctors confirm this!\"}"
```

If you get a JSON response back with a verdict, your backend is working.

---

## 🖥️ Step 4 — Run the frontend

⚠️ **Important:** don't just double-click `index.html` — browsers block the
connection to your backend when a page is opened as a raw `file://` path.
You need to serve it through a real local server instead. Easiest way, no
extra install needed:

Open a **new terminal** (keep Step 3's backend terminal running separately):

```bash
cd frontend
python -m http.server 5500
```

Now open your browser and go to:

```
http://localhost:5500
```

Your address bar should show `http://localhost:5500/`, not `file://...` —
that's the part that matters. It will automatically connect to your backend
at `http://localhost:8080` as long as Step 3's terminal is still running.

Type a message, click **Check Message**, and you should see claims being
verified live. You can also try the **Screenshot** and **Check a File** tabs
the same way.

---




## 🎤 Demo script 

**Text tab:**
1. Paste a real or realistic scam/misinformation forward — a health claim, a bank warning with a link, a job offer.
2. Watch the claims get extracted, then verified live against the web.
3. Point out scam-pattern tags (urgency, OTP request) and any link-risk results that appear.
4. Show the final verdict card — mention it's checked against **live** web data, not just Gemini guessing from memory.
5. Click "Copy verdict to share" — this is the exact thing a user would forward back into their family group.
6. Switch to the file-upload tab, upload a suspicious-looking file, and show both checks running: the instant filename/structure check, then the real VirusTotal scan (70+ antivirus engines) confirming whether it's actually flagged as malware.
7. Switch to the "Check a Website" tab, paste a suspicious-looking URL, and show the real VirusTotal lookup (70+ security engines) alongside the structural pattern check (lookalike domains, shorteners, etc).

**Screenshot tab:**
6. Upload a screenshot of a WhatsApp/SMS forward (even a photo of your own phone screen works).
7. Show the transcribed text appearing, then the same verification pipeline running on it.

**File tab:**
8. Upload any file — try a normal `.pdf` first (shows low risk), then rename a test file to something like `invoice.pdf.exe` and upload it to show the disguise-detection flag.
9. Be upfront with judges: this is a heuristic filename/structure check, not a full malware scan — that's a deliberate, honest scope choice.

---

