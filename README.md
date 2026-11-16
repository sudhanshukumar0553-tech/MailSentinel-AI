# MailSentinel AI — Advanced Email Security & Phishing Defense Platform

MailSentinel AI is a production-oriented email security platform that combines **Dual-Tier Machine Learning (Scikit-Learn TF-IDF)**, **Heuristic Security Parsers (SPF, DKIM, DMARC, Shannon Entropy)**, and an **Autonomous SOC Investigation Agent (Hugging Face `smolagents.ToolCallingAgent` with `openai/gpt-oss-20b`)** in a sleek, cybersecurity-themed dark dashboard.

---

## 1. System Architecture

```
[React 19 Frontend] (Port 5173) ──HTTP REST──> [FastAPI Backend] (Port 8000)
                                                    │
             ┌──────────────────────────────────────┼──────────────────────────────────────┐
             ▼                                      ▼                                      ▼
    [Machine Learning]                     [Security Parsers]                     [smolagents AI]
  • Model 1: Spam (TF-IDF + LR)          • Header Analyzer (SPF/DKIM)           • ToolCallingAgent
  • Model 2: Phishing (TF-IDF + LR)      • URL Defanger & Shannon Entropy       • openai/gpt-oss-20b
  • Baseline: Naive Bayes                • Risk Scoring Engine                  • 6 Dedicated Tools
             │                                      │                                      │
             └──────────────────────────────────────┴──────────────────────────────────────┘
                                                    │
                                                    ▼
                                     [Database: SQLite / PostgreSQL]
```

### Core Technologies:
- **Backend**: Python 3.14, FastAPI, Pydantic v2, SQLAlchemy 2.0 Async, aiosqlite / psycopg.
- **Machine Learning**: Scikit-Learn (TF-IDF, Logistic Regression, Multinomial Naive Bayes), joblib.
- **AI Agent**: Hugging Face `smolagents` (v1.26), `ToolCallingAgent`, `InferenceClientModel`, `openai/gpt-oss-20b`.
- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, Lucide Icons, Recharts.

---

## 2. Hardened Security & Zero-Trust Principles

1. **Zero Execution Policy**:
   - Email attachments are identified and counted by MIME type; they are **never executed or saved to executable paths**.
   - URLs are **never opened, fetched, or resolved over the network**. All URLs are immediately defanged (`hxxps[://]domain[.]com`) to prevent accidental clicks.
2. **Prompt Injection & Indirect Jailbreak Defense**:
   - Untrusted email content is wrapped in `<UNTRUSTED_EMAIL_DATA>` delimiter envelopes.
   - The AI agent's system prompt forbids following instructions inside email text and restricts analysis strictly to passive forensic tool calls.
3. **Secret Protection**:
   - Hugging Face access tokens (`HF_TOKEN`) are strictly confined to `backend/.env`.
   - `backend/.env` is ignored by Git (`.gitignore`).
   - Logging and string representations automatically redact the token (`*** Configured ***`).
4. **Transparent Header Handling**:
   - Validating SPF/DKIM requires transport headers. If plain text is pasted without transport headers, the platform explicitly notes: *"Headers not provided; SPF/DKIM/DMARC authentication not evaluated"* rather than claiming authentication passed.
5. **No False Safety Claims**:
   - Extracted links are analyzed lexically (Shannon entropy, TLD risk, punycode). The platform never falsely claims a link is "100% safe" without independent reputation verification.

---

## 3. Project Structure

```
EMAILSPAM PROJECT/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/        # Health, Scan, Agent, Analytics, Models, History
│   │   ├── core/                    # Config (Pydantic Settings), Security, Exceptions, Logging
│   │   ├── db/                      # Async SQLAlchemy Engine, Session, and ORM Models
│   │   ├── ml/                      # TF-IDF, Dataset Loader, Models, Evaluation, Trainer
│   │   ├── ai/                      # smolagents ToolCallingAgent & 6 Dedicated Tools
│   │   ├── services/                # Email Parser, Header Analyzer, URL Entropy, Risk Engine
│   │   ├── schemas/                 # Pydantic Request/Response validation models
│   │   └── main.py                  # FastAPI Application Entry Point
│   ├── tests/                       # Complete Pytest Suite (18 tests passing 100%)
│   ├── scripts/
│   │   ├── train.py                 # Dataset training & artifact generation CLI
│   │   └── seed_demo.py             # Realistic incident seeder for demonstration
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/
│   ├── src/
│   │   ├── api/                     # Type-safe API client
│   │   ├── components/              # ScannerPage, DashboardPage, AgentPage, ModelHubPage, HistoryPage
│   │   ├── types/                   # TypeScript interfaces matching backend models
│   │   ├── utils/                   # Threat color formatters & helpers
│   │   ├── App.tsx                  # App shell & router
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
│
├── docker-compose.yml               # Multi-container production deployment
├── pytest.ini                       # Pytest configuration
└── README.md
```

---

## 4. Quickstart Guide

### Prerequisites:
- Python 3.10+
- Node.js 18+
- Git

### Backend Setup:
```bash
# 1. Install backend dependencies
pip install -r backend/requirements.txt

# 2. Configure environment variables
# Copy .env.example to backend/.env and add your Hugging Face token:
# HF_TOKEN=hf_...
# HF_MODEL_ID=openai/gpt-oss-20b

# 3. Seed demonstration security incidents (optional)
python backend/scripts/seed_demo.py

# 4. Start the FastAPI backend server (Port 8000)
python backend/app/main.py
```
Backend API documentation will be available at: `http://localhost:8000/docs`.

### Running Automated Tests:
```bash
python -m pytest backend/tests
```
All 18 tests cover configuration masking, database CRUD, email parsing, header verification, URL defanging, smolagents tools, and end-to-end API endpoints.

---

## 5. Machine Learning Training

To train the dual binary classifiers from scratch using Hugging Face datasets:

```bash
python backend/scripts/train.py --samples 5000
```
- **Spam Dataset**: `bvk/ENRON-spam` (Columns: `email`, `label`, `filename`)
- **Phishing Dataset**: `zefang-liu/phishing-email-dataset` (Columns: `Email Text`, `Email Type`)
- **Trained Artifacts**: Saved to `backend/app/ml/artifacts/` (`.joblib` format).

---

## 6. Docker Deployment

To launch the complete multi-service stack (FastAPI Backend + React Frontend + PostgreSQL Database) in isolated containers:

```bash
docker compose up --build
```
- **Web Dashboard**: `http://localhost:5173`
- **FastAPI API & Swagger**: `http://localhost:8000/docs`

