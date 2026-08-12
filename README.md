# AI-Powered OSINT Investigation Platform

An AI-powered **Open-Source Intelligence (OSINT) Investigation Platform** that combines multiple OSINT tools into a unified investigation workflow with automated result processing, account verification, confidence scoring, and AI-assisted analysis.

## Overview

The platform provides a centralized interface for investigating **usernames and email addresses** using multiple OSINT sources.

A **Python/FastAPI backend** manages the investigation workflow, executes OSINT tools, processes their results, verifies discovered accounts, calculates confidence scores, and sends relevant intelligence to a locally hosted **Llama 3.2 (3B) model through Ollama** for AI-assisted analysis.

The frontend provides a dashboard for initiating investigations and viewing discovered accounts, intelligence, confidence information, threat assessments, and AI-generated reports.

## Features

* Username investigation
* Email investigation
* Social account discovery
* Multi-tool OSINT collection
* Automated investigation workflow
* Account verification
* Confidence scoring
* GitHub intelligence
* Email intelligence
* AI-assisted investigation analysis
* Threat-level assessment
* Unified investigation dashboard
* Raw intelligence output
* Confidence-based result classification
* Local AI inference using Llama through Ollama

## Integrated OSINT Tools

The platform integrates multiple OSINT tools, including:

* Sherlock
* Maigret
* Blackbird
* WhatsMyName
* GitFive
* GHunt
* Holehe

## Backend

The backend is built using **Python and FastAPI** and acts as the main orchestration layer of the platform.

It is responsible for:

* Receiving investigation requests
* Identifying the target type
* Running the appropriate OSINT tools
* Collecting tool results
* Parsing OSINT output
* Processing discovered accounts
* Verifying account findings
* Calculating confidence scores
* Combining intelligence from multiple sources
* Sending processed intelligence to the AI analysis layer
* Returning structured investigation results to the frontend

### Backend Technologies

* Python
* FastAPI
* Uvicorn
* Subprocess-based OSINT tool execution
* Custom verification pipeline
* Custom confidence-scoring system

## AI Analysis

The platform integrates **Llama 3.2 (3B)** through **Ollama** for local AI-assisted investigation analysis.

The FastAPI backend sends processed OSINT intelligence to the locally hosted Llama model.

The AI analysis can generate:

* Investigation summaries
* Relevant findings
* Confidence assessments
* Threat-level assessments
* Intelligence correlation
* Structured investigation reports

### Local AI Architecture

```text
OSINT Results
      │
      ▼
Result Processing
      │
      ▼
Verification & Confidence Scoring
      │
      ▼
FastAPI Backend
      │
      ▼
Ollama
      │
      ▼
Llama 3.2 (3B)
      │
      ▼
AI Investigation Analysis
      │
      ▼
Frontend Dashboard
```

Running Llama locally through Ollama allows the AI analysis pipeline to operate without relying on an external AI API.

## Frontend

The frontend provides a web-based dashboard for interacting with the backend and displaying investigation results.

It provides:

* Investigation input
* Investigation status
* Discovered accounts
* GitHub intelligence
* Confidence information
* Threat-level assessment
* Social account intelligence
* AI-generated investigation analysis
* Raw intelligence output

### Frontend Technologies

* HTML
* CSS
* JavaScript

## Technology Stack

| Component        | Technology                                                        |
| ---------------- | ----------------------------------------------------------------- |
| Backend          | Python, FastAPI                                                   |
| Server           | Uvicorn                                                           |
| Frontend         | HTML, CSS, JavaScript                                             |
| AI Model         | Llama 3.2 (3B)                                                    |
| AI Runtime       | Ollama                                                            |
| OSINT Tools      | Sherlock, Maigret, Blackbird, WhatsMyName, GitFive, GHunt, Holehe |
| Operating System | Kali Linux                                                        |

## Architecture

```text
                         ┌─────────────────────┐
                         │   Frontend Dashboard │
                         │   HTML/CSS/JavaScript│
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   FastAPI Backend   │
                         │   Investigation API │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
             Username Investigation          Email Investigation
                    │                               │
          ┌─────────┼─────────┐             ┌───────┴───────┐
          ▼         ▼         ▼             ▼               ▼
      Sherlock  Maigret   Blackbird       GHunt           Holehe
          │         │         │             │               │
          └─────────┼─────────┘             └───────┬───────┘
                    │                               │
                    └──────────────┬────────────────┘
                                   ▼
                         ┌─────────────────────┐
                         │  Result Processing  │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ Verification Engine │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ Confidence Scoring  │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │   Ollama / Llama    │
                         │    AI Analysis      │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ Investigation Report│
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ Frontend Dashboard  │
                         └─────────────────────┘
```

## Project Structure

```text
OSINT_CLI/
│
├── api.py
├── investigator.py
├── email_parser.py
├── confidence.py
│
├── verification/
│
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
│
├── tools/
│
└── ...
```

> The project structure may change as additional modules and integrations are added.

## Requirements

Before running the platform, make sure the following are installed:

* Python 3
* FastAPI
* Uvicorn
* Ollama
* Llama 3.2 (3B)
* Required OSINT tools
* Kali Linux or another compatible Linux environment

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/AASHIR-9099/OSINT_CLI.git
cd OSINT_CLI
```

### 2. Install Python Dependencies

If a `requirements.txt` file is provided:

```bash
pip install -r requirements.txt
```

### 3. Install and Configure Ollama

Make sure Ollama is installed and available on your system.

Pull the required Llama model:

```bash
ollama pull llama3.2:3b
```

Verify that the model is installed:

```bash
ollama list
```

### 4. Configure OSINT Tools

Make sure the required OSINT tools are installed and accessible to the backend.

The platform currently integrates:

```text
Sherlock
Maigret
Blackbird
WhatsMyName
GitFive
GHunt
Holehe
```

## Running the Project

### Start the Backend

From the project root:

```bash
cd ~/OSINT_CLI
python -m uvicorn api:app --reload
```

The backend will start at:

```text
http://127.0.0.1:8000
```

### Start the Frontend

Open a **new terminal** and run:

```bash
cd ~/OSINT_CLI/frontend
python -m http.server 5500
```

The frontend will be available at:

```text
http://127.0.0.1:5500
```

Open the address in your browser.

### Start Ollama

If Ollama is not already running:

```bash
ollama serve
```

If Ollama is already running as a system service, you do not need to start it manually.

Verify that the Llama model is available:

```bash
ollama list
```

You should see:

```text
llama3.2:3b
```

## Quick Start

After installation, the typical setup is:

### Terminal 1 — Backend

```bash
cd ~/OSINT_CLI
python -m uvicorn api:app --reload
```

### Terminal 2 — Frontend

```bash
cd ~/OSINT_CLI/frontend
python -m http.server 5500
```

### Ollama

Make sure Ollama is running:

```bash
ollama serve
```

Then open:

```text
http://127.0.0.1:5500
```

## Investigation Workflow

The general investigation workflow is:

```text
Target Input
     │
     ▼
Target Identification
     │
     ├── Username
     │
     └── Email
           │
           ▼
      OSINT Collection
           │
           ▼
      Result Parsing
           │
           ▼
       Verification
           │
           ▼
    Confidence Scoring
           │
           ▼
      AI Analysis
           │
           ▼
    Investigation Report
```

## Confidence Scoring

The platform uses a confidence-scoring system to evaluate discovered accounts using multiple verification and intelligence signals.

This helps distinguish between:

* High-confidence findings
* Medium-confidence findings
* Low-confidence findings

The verification pipeline is designed to reduce the likelihood of presenting unverified or potentially false matches as confirmed accounts.

## Email Investigation

For email targets, the platform can use dedicated email intelligence tools including:

### GHunt

GHunt is used to collect publicly available Google-related intelligence associated with an email address.

### Holehe

Holehe checks whether an email address is associated with accounts on supported online services.

The collected results are processed by the backend and incorporated into the investigation results.

## Username Investigation

For username targets, the platform can use multiple username-search tools to identify potential accounts across supported platforms.

Results from different sources are processed and verified before being presented to the user.

## Local AI Processing

The AI analysis component runs locally using:

```text
Ollama
   │
   ▼
Llama 3.2 (3B)
```

This allows investigation intelligence to be analyzed locally rather than requiring a remote AI API for the analysis stage.

## Disclaimer

This project is intended for:

* Authorized security research
* Cybersecurity education
* OSINT research
* Digital investigations
* Security analysis

Only investigate accounts, email addresses, systems, and information that you are authorized to investigate or that are publicly available and lawful to access.

The developers are not responsible for misuse of this project.

## Project Information

**Project:** AI-Powered OSINT Investigation Platform

**Primary Backend:** Python / FastAPI

**Frontend:** HTML / CSS / JavaScript

**AI:** Llama 3.2 (3B) / Ollama

**Environment:** Kali Linux
