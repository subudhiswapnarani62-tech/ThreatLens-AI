# ThreatLens AI

> **AI-Assisted Embedded Security Validation & Threat Modeling Engine for Connected Vehicles**

ThreatLens AI is an automated cybersecurity threat modeling, risk assessment, and architecture change validation platform designed for embedded systems and modern connected vehicles. It automates STRIDE threat generation, attack surface identification, risk scoring, CWE recommendation mapping, and regression revalidation across evolving electronic control unit (ECU) topologies.

---

## 🚀 Key Features

- **Automated Attack Surface Discovery:** Identifies internal and external attack vectors across CAN, Automotive Ethernet, Bluetooth, Wi-Fi, and Diagnostic/OBD-II interfaces.
- **STRIDE Threat Modeling Engine:** Generates specific, contextualized threats categorized by Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
- **Quantitative Risk Scoring:** Multi-factor scoring (Impact, Exploitability, Exposure) mapped to qualitative severity tiers (Critical, High, Medium, Low).
- **CWE Recommendation Mapping:** Maps discovered threat vectors to authoritative Common Weakness Enumeration (CWE) mitigations (e.g., CWE-20, CWE-306, CWE-319, CWE-400).
- **Architecture Change Detection (V1 vs V2):** Invariant comparison engine detecting added, removed, or modified components/interfaces with deterministic diffing.
- **Security Test Revalidation:** Automatically determines which security validation test cases require revalidation (`NEEDS_REVALIDATION`) upon architecture delta.
- **Simulated Test Harness:** Execution harness evaluating control assertions with clear simulation transparency and physical automotive hardware disclaimers.
- **Cybersecurity Operations Dashboard:** High-contrast dark mode React dashboard featuring summary metric cards, interactive architecture graphs, STRIDE filtering, and test execution consoles.

---

## 🛠️ System Architecture

- **Backend:** FastAPI (Python 3.12+) running on port `8001`
- **Frontend:** React 18 + Vite running on port `5173`
- **Port Isolation:** Specifically configured on port `8001` to prevent conflicts with other services (such as Splunk on port 8000).

```
ThreatLens-AI/
├── backend/
│   ├── analyzer.py               # Threat modeling orchestrator
│   ├── comparison_engine.py      # Architecture diff & test revalidation logic
│   ├── cwe_engine.py             # CWE pattern matcher & mitigations
│   ├── main.py                   # FastAPI application & REST endpoints
│   ├── risk_engine.py            # Quantitative risk scoring model
│   ├── security_engine.py        # Attack surface discovery rules
│   └── threat_engine.py          # STRIDE rules engine
├── frontend/
│   ├── src/
│   │   ├── App.jsx               # Interactive cybersecurity dashboard
│   │   ├── index.css             # Dark-theme tactical UI styling
│   │   ├── main.jsx              # React application entrypoint
│   │   └── vehicle_v1.json       # Frontend baseline dataset
│   ├── index.html                # HTML entry
│   ├── package.json              # NPM dependencies
│   └── vite.config.js            # Vite configuration & dev proxy
├── knowledge_base/
│   └── cwe_patterns.json         # CWE knowledge base
├── test_data/
│   └── vehicle_v1.json           # Canonical baseline vehicle topology
├── tests/
│   ├── test_rigorous_verification.py # Master 22-test automated regression suite
│   └── qa_verification_runner.py     # End-to-end QA validation runner
├── requirements.txt              # Python dependencies
└── .gitignore                    # Git exclusions
```

---

## 🚦 Getting Started

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 2. Backend Setup
```bash
# Clone the repository
git clone https://github.com/<your-username>/ThreatLens-AI.git
cd ThreatLens-AI

# Create and activate a virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the FastAPI backend (Port 8001)
python backend/main.py
# Or with uvicorn directly:
uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload
```

The API will be available at:
- Health check: `http://127.0.0.1:8001/api/health`
- Interactive API Docs (Swagger): `http://127.0.0.1:8001/docs`

### 3. Frontend Setup
In a new terminal window:
```bash
cd frontend

# Install dependencies
npm install

# Start Vite development server (Port 5173)
npm run dev
```

Open your browser at `http://localhost:5173` to view the dashboard.

---

## 🧪 Testing & Verification

Run the automated backend test suites:
```bash
# Run master 22-test regression suite
python -m unittest -v tests/test_rigorous_verification.py

# Run comprehensive end-to-end QA validation harness
python tests/qa_verification_runner.py
```

Run the frontend production build verification:
```bash
cd frontend
npm run build
```

---

## 🔒 Security & Safe Testing Notice

This tool evaluates software models and specifications for connected vehicle network architectures. Simulated test cases validate software assertion policies and do not transmit live CAN frames, RF signals, or OBD-II payloads to physical hardware. Physical verification requires dedicated Hardware-in-the-Loop (HIL) benches and approved RF testing environments.
