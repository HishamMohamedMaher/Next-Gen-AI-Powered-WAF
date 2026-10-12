# 🛡️ Next-Gen AI-WAF

AI-powered Web Application Firewall with layered detection (Signatures + ML).

Next-Gen AI-WAF combines fast signature-based matching (CRS / custom patterns) with machine learning classifiers (Logistic Regression / LightGBM) to inspect incoming HTTP requests, detect malicious payloads (SQLi, XSS, Path Traversal, etc.), enforce rate limits, and provide real-time telemetry via a dashboard.

---

## 🏛️ Architecture Overview

The system operates as a reverse proxy sitting in front of upstream target applications (e.g., OWASP Juice Shop):

```
Client Traffic ---> [ Next-Gen AI-WAF :8080 ] ---> [ Upstream App :3000 ]
                           │
       ┌───────────────────┴───────────────────┐
       ▼                                       ▼
 [ Pipeline Detection ]                 [ SQLite / Logs ]
 ├─ IP Reputation / GeoIP                      │
 ├─ Rate Limiting / Token Bucket               ▼
 ├─ Regex & Signature Rules             [ Streamlit Dashboard :8501 ]
 ├─ Feature Extraction
 └─ ML Inference (LR / LightGBM)
```

1. **Layer 1 - Threat Intelligence & Rate Limiting**: AbuseIPDB, GeoIP checks, and token bucket rate limiters.
2. **Layer 2 - Deterministic Rule Engine**: Fast regex-based signatures for known attack patterns.
3. **Layer 3 - Machine Learning Layer**: TF-IDF and character n-gram feature extraction evaluated by ML classifiers for zero-day and obfuscated attacks.
4. **Proxy & Action**: Passes legitimate traffic to upstream or blocks malicious requests with standard 403 responses and logs telemetry.

---

## 🚀 Quick Start

Run the entire stack using Docker Compose:

```bash
# 1. Clone repository & configure environment
cp .env.example .env

# 2. Launch WAF and target application (Juice Shop)
docker compose up -d

# 3. (Optional) Launch with analytics dashboard
docker compose --profile full up -d
```

- **WAF Gateway**: `http://localhost:8080`
- **Juice Shop Upstream**: Protected behind WAF proxy
- **Streamlit Dashboard**: `http://localhost:8501`

---

## 📁 Project Structure

```
ai-waf/
├── config.yaml                  # Core configuration file
├── docker-compose.yml           # Multi-container orchestration
├── Dockerfile.waf               # WAF gateway image
├── Dockerfile.dashboard         # Streamlit dashboard image
├── requirements.txt             # WAF runtime dependencies
├── requirements-dashboard.txt   # Dashboard dependencies
├── requirements-training.txt    # ML training dependencies
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore patterns
├── README.md                    # Project documentation
├── rules/                       # Detection signatures and rules
├── trained_models/              # Serialized ML models and checksums
│   ├── .gitkeep
│   └── checksums.sha256
├── data/                        # Persistent logs and telemetry DB
│   └── .gitkeep
├── waf/                         # WAF core engine
│   ├── main.py                  # ASGI application entrypoint
│   ├── config.py                # Pydantic configuration models
│   ├── pipeline.py              # Detection pipeline orchestrator
│   ├── proxy.py                 # Reverse proxy handler
│   ├── rules/                   # Rule matching engine
│   ├── ml/                      # ML inference engine
│   ├── utils/                   # Helpers, rate limiting, IP checking
│   └── storage/                 # Database logging & telemetry
├── dashboard/                   # Streamlit analytics application
│   └── app.py
├── training/                    # Dataset processing and ML training
│   ├── prepare_data.py
│   └── train_lr.py
└── tests/                       # Unit and integration tests
```

---

## 🧩 Components

- **FastAPI / Uvicorn Reverse Proxy**: High-throughput async reverse proxy intercepting and inspecting HTTP requests.
- **Rule Engine**: Evaluates query parameters, headers, and body payloads against customizable rule sets.
- **ML Classifier Pipeline**: Extracts payload features and evaluates confidence scores to block unknown attack vectors.
- **Telemetry & Logging**: Records blocked and forwarded transactions to SQLite for auditing and analysis.
- **Streamlit Dashboard**: Real-time visualization of attacks, blocked IP addresses, and performance metrics.

---

## ⚙️ Configuration

System behavior is defined in `config.yaml`:
- **Proxy Settings**: Upstream target host and port.
- **Detection Modes**: `blocking` vs `monitoring_only`.
- **Thresholds**: ML probability score cutoff for blocking decisions.
- **Rate Limiting**: Requests per minute / burst limits per IP.
- **Logging**: Log levels and SQLite telemetry paths.

---

## 💻 Development

### Local Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-training.txt
```

### Running Locally

```bash
# Start WAF service
uvicorn waf.main:app --host 0.0.0.0 --port 8080 --reload

# Start Dashboard
streamlit run dashboard/app.py --server.port 8501
```

---

## 🧪 Testing

### Automated Unit & Integration Tests

```bash
pytest tests/ -v
```

### Security & Penetration Testing

Validate WAF protection against industry tools:

- **SQLMap**:
  ```bash
  sqlmap -u "http://localhost:8080/rest/products/search?q=test" --batch
  ```
- **OWASP ZAP**:
  Run an automated baseline or active scan targeting `http://localhost:8080`.

---

## 👥 Team

- Core Development Team (Placeholder)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
