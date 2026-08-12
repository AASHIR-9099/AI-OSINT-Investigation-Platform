# AI-Powered OSINT Investigation Platform

An AI-powered **Open-Source Intelligence (OSINT) Investigation Platform** that combines multiple OSINT tools into a unified investigation workflow with automated result processing, account verification, evidence-based confidence scoring, and locally hosted AI-assisted analysis.

The platform is designed primarily for **username and email investigations** and provides both structured investigation results and a web-based dashboard.

---

## Overview

The AI-Powered OSINT Investigation Platform provides a centralized workflow for investigating **usernames and email addresses** across multiple publicly available OSINT sources.

A **Python/FastAPI backend** orchestrates the investigation process. It launches the appropriate OSINT tools, parses and merges their output, verifies discovered profiles, filters false positives, calculates confidence scores, prepares structured intelligence, and sends the resulting evidence to a locally hosted **Llama 3.2 (3B)** model through **Ollama**.

The frontend provides a unified dashboard for initiating investigations and viewing:

* discovered accounts
* verification status
* confidence scores
* confidence explanations
* GitHub intelligence
* email intelligence
* risk/threat assessment
* AI-generated investigation summaries
* raw structured intelligence output

The system is designed around an **evidence-first approach**. Tool detections are treated as candidate findings rather than automatic proof of account ownership.

---

# Core Investigation Flow

```text
Target
  │
  ├── Username
  │      │
  │      ├── Sherlock
  │      ├── Maigret
  │      ├── Blackbird
  │      ├── WhatsMyName
  │      └── GitFive
  │
  └── Email
         │
         ├── GHunt
         ├── Holehe
         └── HIBP (optional)
               │
               ▼
        Result Collection
               │
               ▼
        Parsing & Merging
               │
               ▼
          Verification
               │
               ▼
      False-Positive Filtering
               │
               ▼
        Confidence Scoring
               │
               ▼
      Intelligence Preparation
               │
               ▼
         Ollama / Llama
               │
               ▼
        AI Investigation Summary
               │
               ▼
        Frontend Dashboard
```

---

# Features

## Username Investigation

* Multi-platform username discovery
* Sherlock integration
* Maigret integration
* Blackbird integration
* WhatsMyName-based checking
* GitFive GitHub intelligence
* Cross-tool result correlation
* Profile verification
* False-positive filtering
* Per-account confidence scoring
* Overall investigation confidence scoring

## Email Investigation

* GHunt Google-account intelligence
* Holehe account-registration intelligence
* Optional Have I Been Pwned breach intelligence
* Separate email confidence model
* Structured email intelligence
* Tool execution-status reporting

## Verification and Confidence

* Profile verification
* Cross-tool corroboration
* Direct page-evidence checks
* Platform-specific verification
* False-positive rejection
* Per-account confidence values
* Overall investigation confidence
* Confidence levels
* Confidence reasons
* Confidence breakdown

## AI Analysis

* Local Llama inference through Ollama
* Evidence-based investigation summary
* Important-findings extraction
* Confidence explanation
* Risk/threat reporting
* Structured analyst-style report
* No external AI API required for Llama analysis

## Dashboard

* Investigation target input
* Live investigation progress
* Discovered-account display
* Confidence visualization
* Verification status
* GitHub intelligence
* Email intelligence
* AI-generated summary
* Raw Intelligence Output

---

# Integrated OSINT Components

| Component          | Investigation Type | Purpose                            |
| ------------------ | ------------------ | ---------------------------------- |
| Sherlock           | Username           | Social-account discovery           |
| Maigret            | Username           | Username enumeration               |
| Blackbird          | Username           | Social-account discovery           |
| WhatsMyName        | Username           | Dataset-driven username validation |
| GitFive            | Username           | GitHub intelligence                |
| GHunt              | Email              | Google-account OSINT               |
| Holehe             | Email              | Email registration checks          |
| HIBP               | Email              | Optional breach intelligence       |
| Ollama / Llama 3.2 | Both               | Local AI analysis                  |

> **Note:** WhatsMyName does not require a separate application installation in this project. The platform uses the bundled `data/wmn-data.json` dataset directly.

---

# Technology Stack

| Component          | Technology                                         |
| ------------------ | -------------------------------------------------- |
| Backend            | Python, FastAPI                                    |
| API Server         | Uvicorn                                            |
| Frontend           | HTML, CSS, JavaScript                              |
| Local AI Model     | Llama 3.2 (3B)                                     |
| AI Runtime         | Ollama                                             |
| HTTP Processing    | Requests                                           |
| Progress Interface | Rich                                               |
| Username OSINT     | Sherlock, Maigret, Blackbird, WhatsMyName, GitFive |
| Email OSINT        | GHunt, Holehe, optional HIBP                       |
| Recommended OS     | Kali Linux                                         |
| Python             | Python 3.10+                                       |

---

# Project Structure

A simplified view of the project is shown below:

```text
AI-OSINT-Investigation-Platform/
│
├── api.py
├── investigator.py
├── ai_analyzer.py
├── ollama_ai.py
│
├── sherlock_tool.py
├── maigret_tool.py
├── blackbird_tool.py
├── gitfive_tool.py
├── ghunt_tool.py
├── holehe_tool.py
├── whatsmyname_tool.py
├── hibp_tool.py
│
├── email_parser.py
├── parser.py
├── username_validation.py
│
├── verification/
│   ├── engine.py
│   ├── confidence.py
│   ├── generic.py
│   └── github.py
│
├── data/
│   └── wmn-data.json
│
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
│
├── tests/
│
└── README.md
```

---

# Requirements

The recommended environment is:

* **Kali Linux**
* Python **3.10 or newer**
* Git
* Python virtual-environment support
* pip / pipx
* Internet connectivity for OSINT queries
* Ollama
* Llama 3.2 (3B)

A GPU is helpful for faster Llama inference but is not required if Ollama can run the model on the available hardware.

---

# Important Installation Note

The current project configuration expects several external tools in specific locations.

For the default Kali Linux user `kali`, the expected locations are:

| Tool             | Expected Location                      |
| ---------------- | -------------------------------------- |
| Sherlock         | Available through system `PATH`        |
| Maigret          | `/home/kali/maigret/venv/bin/python`   |
| Blackbird        | `/home/kali/blackbird/`                |
| Blackbird Python | `/home/kali/blackbird/venv/bin/python` |
| GitFive          | `/home/kali/GitFive/`                  |
| GitFive Python   | `/home/kali/GitFive/venv/bin/python`   |
| GHunt            | `~/GHunt/venv/bin/ghunt`               |
| Holehe           | `~/holehe/venv/bin/holehe`             |
| WhatsMyName      | Bundled inside this repository         |

**For the easiest installation, use the default Kali username `kali` and follow the directory names exactly, including capitalization.**

If your Linux username is not `kali`, update the corresponding path constants in:

```text
maigret_tool.py
blackbird_tool.py
gitfive_tool.py
ghunt_tool.py
holehe_tool.py
```

before running the platform.

---

# Installation

## 1. Install Basic System Requirements

On Kali Linux:

```bash
sudo apt update

sudo apt install -y \
    git \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    pipx
```

Make sure pipx applications are available in your PATH:

```bash
pipx ensurepath
```

For the current terminal session, you can also run:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Verify Python:

```bash
python3 --version
```

Python 3.10 or newer is recommended.

---

# 2. Clone the OSINT Platform

From your home directory:

```bash
cd ~

git clone https://github.com/AASHIR-9099/AI-OSINT-Investigation-Platform.git

cd AI-OSINT-Investigation-Platform
```

---

# 3. Create the Platform Virtual Environment

Create a dedicated environment for the FastAPI backend:

```bash
cd ~/AI-OSINT-Investigation-Platform

python3 -m venv .venv

source .venv/bin/activate
```

Upgrade pip:

```bash
python -m pip install --upgrade pip
```

Install the main Python dependencies:

```bash
python -m pip install \
    fastapi \
    uvicorn \
    pydantic \
    requests \
    rich
```

If a `requirements.txt` file is available in the repository, use:

```bash
python -m pip install -r requirements.txt
```

instead.

---

# 4. Install Sherlock

Sherlock must be available through the system PATH because the backend searches for the `sherlock` executable.

Install it with pipx:

```bash
pipx install sherlock-project
```

Make sure the pipx binary directory is available:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Verify:

```bash
sherlock --help
```

If the help screen appears, Sherlock is ready.

---

# 5. Install Maigret

The project currently expects Maigret's Python environment at:

```text
/home/kali/maigret/venv/bin/python
```

Create that environment:

```bash
cd ~

mkdir -p maigret

cd maigret

python3 -m venv venv

./venv/bin/python -m pip install --upgrade pip

./venv/bin/python -m pip install maigret
```

Verify:

```bash
/home/kali/maigret/venv/bin/python -m maigret --help
```

If the Maigret help screen appears, the installation is ready.

---

# 6. Install Blackbird

The backend expects Blackbird at:

```text
/home/kali/blackbird
```

Install it:

```bash
cd ~

git clone https://github.com/p1ngul1n0/blackbird.git

cd blackbird

python3 -m venv venv

./venv/bin/python -m pip install --upgrade pip

./venv/bin/python -m pip install -r requirements.txt
```

Verify:

```bash
/home/kali/blackbird/venv/bin/python \
    /home/kali/blackbird/blackbird.py \
    --help
```

The project uses Blackbird's local Python environment and `blackbird.py` directly.

---

# 7. Install GitFive

The backend currently expects GitFive at:

```text
/home/kali/GitFive
```

Install it using the exact directory capitalization:

```bash
cd ~

git clone https://github.com/mxrch/GitFive.git

cd GitFive

python3 -m venv venv

./venv/bin/python -m pip install --upgrade pip

./venv/bin/python -m pip install .
```

Verify the project entry point:

```bash
/home/kali/GitFive/venv/bin/python \
    /home/kali/GitFive/main.py \
    --help
```

GitFive requires authentication before full GitHub intelligence can be collected.

Run:

```bash
/home/kali/GitFive/venv/bin/gitfive login
```

Complete the authentication process requested by GitFive.

> Using a secondary research account is recommended when appropriate for authorized OSINT testing.

---

# 8. Install GHunt

The backend expects GHunt at:

```text
~/GHunt/venv/bin/ghunt
```

Install it:

```bash
cd ~

git clone https://github.com/mxrch/GHunt.git

cd GHunt

python3 -m venv venv

./venv/bin/python -m pip install --upgrade pip

./venv/bin/python -m pip install .
```

Verify:

```bash
~/GHunt/venv/bin/ghunt --help
```

GHunt requires authentication before email investigations can use Google-account intelligence.

Run:

```bash
~/GHunt/venv/bin/ghunt login
```

Follow GHunt's authentication instructions.

After login, verify that the email module is available:

```bash
~/GHunt/venv/bin/ghunt email --help
```

---

# 9. Install Holehe

The backend expects Holehe at:

```text
~/holehe/venv/bin/holehe
```

Install it:

```bash
cd ~

git clone https://github.com/megadose/holehe.git

cd holehe

python3 -m venv venv

./venv/bin/python -m pip install --upgrade pip

./venv/bin/python -m pip install .
```

Verify:

```bash
~/holehe/venv/bin/holehe --help
```

---

# 10. WhatsMyName Configuration

No separate WhatsMyName application installation is required.

The project directly loads the bundled dataset:

```text
~/AI-OSINT-Investigation-Platform/data/wmn-data.json
```

Verify that the file exists:

```bash
ls ~/AI-OSINT-Investigation-Platform/data/wmn-data.json
```

If the file is displayed, the WhatsMyName component is available.

---

# 11. Install Ollama

Install Ollama on Linux:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify:

```bash
ollama --version
```

Pull the model required by the project:

```bash
ollama pull llama3.2:3b
```

Verify:

```bash
ollama list
```

You should see:

```text
llama3.2:3b
```

---

# 12. Start Ollama

If Ollama is not already running as a service:

```bash
ollama serve
```

Leave that terminal running.

If Ollama reports that port `11434` is already in use, Ollama is probably already running as a service.

You can verify the model directly:

```bash
ollama run llama3.2:3b
```

Enter a short test prompt.

Exit the interactive model using:

```text
/bye
```

---

# 13. Configure the Ollama URL

This step is **important**.

The current source code supports the environment variable:

```text
OLLAMA_URL
```

For a normal installation where Ollama and the FastAPI backend run on the **same Kali Linux machine**, set:

```bash
export OLLAMA_URL="http://127.0.0.1:11434/api/generate"
```

Run this command in the same terminal from which you will start FastAPI.

You can verify that Ollama is responding with:

```bash
ollama list
```

If Ollama is running on another machine, replace `127.0.0.1` with that system's reachable IP address.

Example:

```bash
export OLLAMA_URL="http://192.168.1.50:11434/api/generate"
```

---

# 14. Optional HIBP Email Breach Intelligence

The platform supports optional **Have I Been Pwned** email-breach intelligence.

Email-breach lookup requires an HIBP API key.

Without the key, the investigation still runs, but the HIBP component is reported as **Not Configured**.

To enable it:

```bash
export HIBP_API_KEY="YOUR_HIBP_API_KEY"
```

Set the variable in the same environment used to start FastAPI.

Do **not** hard-code or commit your API key into the repository.

---

# Installation Verification

Before starting the platform, verify each component.

## Sherlock

```bash
sherlock --help
```

## Maigret

```bash
/home/kali/maigret/venv/bin/python -m maigret --help
```

## Blackbird

```bash
/home/kali/blackbird/venv/bin/python \
    /home/kali/blackbird/blackbird.py \
    --help
```

## GitFive

```bash
/home/kali/GitFive/venv/bin/python \
    /home/kali/GitFive/main.py \
    --help
```

## GHunt

```bash
~/GHunt/venv/bin/ghunt --help
```

## Holehe

```bash
~/holehe/venv/bin/holehe --help
```

## WhatsMyName Dataset

```bash
ls ~/AI-OSINT-Investigation-Platform/data/wmn-data.json
```

## Ollama

```bash
ollama list
```

The following should be present:

```text
llama3.2:3b
```

---

# Running the Platform

Three components are required:

1. Ollama
2. FastAPI backend
3. Frontend web server

---

## Terminal 1 — Ollama

If Ollama is not already running as a service:

```bash
ollama serve
```

---

## Terminal 2 — FastAPI Backend

Open another terminal:

```bash
cd ~/AI-OSINT-Investigation-Platform

source .venv/bin/activate
```

Configure local Ollama:

```bash
export OLLAMA_URL="http://127.0.0.1:11434/api/generate"
```

If HIBP is configured:

```bash
export HIBP_API_KEY="YOUR_HIBP_API_KEY"
```

Start FastAPI:

```bash
python -m uvicorn api:app --reload
```

The API should be available at:

```text
http://127.0.0.1:8000
```

Test it in another terminal:

```bash
curl http://127.0.0.1:8000/
```

A successful response indicates that the backend is online.

FastAPI's interactive documentation is available at:

```text
http://127.0.0.1:8000/docs
```

---

## Terminal 3 — Frontend

Open another terminal:

```bash
cd ~/AI-OSINT-Investigation-Platform/frontend

python3 -m http.server 5500
```

The dashboard will be available at:

```text
http://127.0.0.1:5500
```

Open that address in a browser.

---

# Quick Start

Once everything has been installed and configured:

## Terminal 1

```bash
ollama serve
```

Skip this terminal if Ollama is already running as a service.

## Terminal 2

```bash
cd ~/AI-OSINT-Investigation-Platform

source .venv/bin/activate

export OLLAMA_URL="http://127.0.0.1:11434/api/generate"

python -m uvicorn api:app --reload
```

## Terminal 3

```bash
cd ~/AI-OSINT-Investigation-Platform/frontend

python3 -m http.server 5500
```

Then open:

```text
http://127.0.0.1:5500
```

---

# Username Investigation

For username targets, the backend runs multiple OSINT engines:

```text
Username
   │
   ├── Sherlock
   ├── Maigret
   ├── Blackbird
   ├── WhatsMyName
   └── GitFive
          │
          ▼
     Result Merge
          │
          ▼
      Verification
          │
          ▼
 False-Positive Filtering
          │
          ▼
   Confidence Scoring
          │
          ▼
      AI Analysis
```

Results reported by OSINT enumeration tools are treated as **candidate findings**.

The platform subsequently attempts to verify those findings before using them as stronger investigation evidence.

---

# Email Investigation

For an email address, the investigation flow uses:

```text
Email
  │
  ├── GHunt
  ├── Holehe
  └── HIBP (optional)
        │
        ▼
 Email Result Processing
        │
        ▼
  Confidence Scoring
        │
        ▼
    AI Analysis
```

### GHunt

GHunt attempts to obtain publicly available Google-related intelligence associated with the supplied email address.

The platform only treats matching email and Google-account evidence as valid GHunt evidence.

### Holehe

Holehe checks whether an email address appears to be registered with supported online services.

Positive findings are incorporated into the email investigation pipeline.

### HIBP

HIBP provides optional breach intelligence.

If `HIBP_API_KEY` is not configured, the platform does not fabricate a result. Instead, HIBP is clearly marked as not configured.

---

# Confidence Scoring

Confidence scoring is performed by the backend.

The confidence system is designed to answer:

> **How confident is the system in the collected investigation evidence associated with the supplied target?**

It is **not** simply based on the number of discovered accounts.

For username investigations, the scoring system can consider factors such as:

* cross-tool corroboration
* direct profile-page evidence
* platform-specific verification
* high-value identity platforms
* available profile metadata
* verification failures
* rejected false-positive findings

Email investigations use a separate confidence model appropriate to email intelligence.

The backend produces:

```text
confidence
confidence_level
confidence_reasons
confidence_breakdown
```

Individual accounts can also contain their own confidence and verification information.

---

# Raw Intelligence Output

The frontend displays the structured backend investigation response as **Raw Intelligence Output**.

The raw result can include:

```text
target
username
accounts
confidence
confidence_level
confidence_reasons
confidence_breakdown
holehe
ghunt
gitfive
hibp
whatsmyname
summary
email_tool_status
ai_summary
```

This makes the underlying investigation evidence visible instead of showing only the summarized dashboard view.

---

# AI Analysis

After collection, verification, filtering and confidence scoring, the backend prepares relevant intelligence for the locally hosted Llama model.

```text
Collected OSINT
      │
      ▼
Result Processing
      │
      ▼
Verification
      │
      ▼
Confidence Scoring
      │
      ▼
Evidence Preparation
      │
      ▼
FastAPI
      │
      ▼
Ollama
      │
      ▼
Llama 3.2 (3B)
      │
      ▼
AI Investigation Summary
```

The AI layer is intended to **report and summarize the evidence already collected by the backend**.

It does not replace the backend confidence calculation.

The generated analysis can contain:

* Investigation Overview
* Important Findings
* Account and Platform Information
* Confidence Explanation
* Risk Indicators
* Threat Assessment
* Conclusion

The AI-generated result is returned to the frontend as:

```text
ai_summary
```

and is also available within the raw investigation response.

---

# Verification Philosophy

The platform follows several important OSINT principles.

### Tool Detection Is Not Automatic Verification

A result returned by an enumeration tool is initially a candidate finding.

### Multiple Results Do Not Automatically Mean High Confidence

Finding many profiles does not automatically produce a 100% confidence score.

### Verification Precedes Confidence

Username findings are checked before final confidence is calculated.

### False Positives Are Filtered

Candidates identified as false positives are excluded from the retained username evidence.

### Username Correlation Is Not Identity Proof

The presence of the same username across several services does not automatically establish that every account belongs to the same real-world person.

### AI Does Not Replace Deterministic Confidence

The Llama model summarizes the backend evidence. The backend confidence engine remains authoritative.

---

# Investigation Output

A successful investigation provides three major layers of information.

## 1. Dashboard Results

Human-readable presentation of:

* accounts
* platforms
* verification
* confidence
* investigation summary

## 2. Raw Intelligence

Structured backend data showing the evidence and confidence calculations.

## 3. AI Investigation Summary

A concise locally generated analyst-style report derived from the processed investigation evidence.

---

# Troubleshooting

## Sherlock Not Found

Error:

```text
Sherlock executable was not found
```

Check:

```bash
which sherlock
```

If nothing is returned:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then:

```bash
sherlock --help
```

---

## Maigret Not Found

Check:

```bash
ls /home/kali/maigret/venv/bin/python
```

If the file does not exist, repeat the Maigret installation steps.

---

## Blackbird Not Found

Check:

```bash
ls /home/kali/blackbird/blackbird.py

ls /home/kali/blackbird/venv/bin/python
```

Both files must exist.

---

## GitFive Not Found

Check:

```bash
ls /home/kali/GitFive/main.py

ls /home/kali/GitFive/venv/bin/python
```

If GitFive runs but does not return authenticated intelligence, repeat:

```bash
/home/kali/GitFive/venv/bin/gitfive login
```

---

## GHunt Missing Executable

Check:

```bash
ls ~/GHunt/venv/bin/ghunt
```

If authentication has not been completed:

```bash
~/GHunt/venv/bin/ghunt login
```

---

## Holehe Missing Executable

Check:

```bash
ls ~/holehe/venv/bin/holehe
```

If it does not exist, reinstall Holehe inside its virtual environment.

---

## WhatsMyName Data Missing

Check:

```bash
ls ~/AI-OSINT-Investigation-Platform/data/wmn-data.json
```

If this file is missing, restore it from the repository.

---

## Ollama Connection Error

First check:

```bash
ollama list
```

Then make sure the required model exists:

```text
llama3.2:3b
```

If necessary:

```bash
ollama pull llama3.2:3b
```

Make sure Ollama is running:

```bash
ollama serve
```

For a local Ollama installation, configure:

```bash
export OLLAMA_URL="http://127.0.0.1:11434/api/generate"
```

Then restart the FastAPI backend from the same terminal environment.

---

## AI Summary Reports an Error

The OSINT investigation can complete even if the Llama summary fails.

Check:

1. Ollama is running.
2. `llama3.2:3b` is installed.
3. `OLLAMA_URL` is correct.
4. The FastAPI process inherited the `OLLAMA_URL` environment variable.

Verify:

```bash
echo $OLLAMA_URL
```

Expected for a local installation:

```text
http://127.0.0.1:11434/api/generate
```

---

## HIBP Shows "Not Configured"

This is expected if no HIBP API key has been supplied.

To enable HIBP email breach checks:

```bash
export HIBP_API_KEY="YOUR_HIBP_API_KEY"
```

Restart the FastAPI backend after setting it.

---

# Recommended Pre-Run Check

Before demonstrating the project, run:

```bash
sherlock --help

/home/kali/maigret/venv/bin/python -m maigret --help

/home/kali/blackbird/venv/bin/python \
    /home/kali/blackbird/blackbird.py \
    --help

/home/kali/GitFive/venv/bin/python \
    /home/kali/GitFive/main.py \
    --help

~/GHunt/venv/bin/ghunt --help

~/holehe/venv/bin/holehe --help

ls ~/AI-OSINT-Investigation-Platform/data/wmn-data.json

ollama list
```

Then verify the backend:

```bash
curl http://127.0.0.1:8000/
```

If all required components respond correctly, the system is ready for an investigation.

---

# Security and Ethical Use

This project is intended for:

* authorized cybersecurity research
* cybersecurity education
* OSINT research
* digital investigations
* academic research
* security analysis

Only investigate accounts, email addresses, systems and information that:

* you own,
* you are authorized to investigate, or
* are lawfully accessible as public information.

Do not use the platform for unauthorized access, harassment, stalking, credential theft, privacy violations or other unlawful activity.

The developers are not responsible for misuse of this software.

Users are responsible for ensuring that their use complies with applicable laws, platform terms and authorization requirements.

---

# Limitations

OSINT results should not automatically be treated as proof of identity or account ownership.

Possible limitations include:

* username reuse by unrelated individuals
* outdated third-party OSINT datasets
* platform anti-bot protections
* rate limits
* temporary network errors
* profile privacy settings
* authentication requirements
* changes to third-party websites or APIs
* incomplete public information
* false-positive candidate results

The verification and confidence pipeline is intended to reduce these problems, but no automated OSINT system can guarantee perfect attribution.

---

# Development Status

The platform currently focuses on:

* username investigation
* email investigation
* verification
* confidence scoring
* false-positive reduction
* local AI-assisted reporting
* unified dashboard presentation

The architecture is modular so that additional OSINT sources and investigation capabilities can be integrated in future versions.

---

# Project Information

**Project:** AI-Powered OSINT Investigation Platform

**Type:** Final Year Project / Cybersecurity OSINT Platform

**Primary Backend:** Python / FastAPI

**Frontend:** HTML / CSS / JavaScript

**AI:** Llama 3.2 (3B)

**AI Runtime:** Ollama

**Primary Environment:** Kali Linux

**Investigation Types:** Username and Email

**Core Design Principle:** Evidence-driven OSINT with verification before confidence scoring

---

# Disclaimer

This software is provided for **authorized, educational and research purposes**.

OSINT findings may be incomplete, outdated or incorrect and should be independently validated before being used for operational, legal or investigative decisions.

Use this software responsibly and lawfully.
