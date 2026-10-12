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
├── docker-compose.yml           # Multi-container orchestration (WAF, Juice Shop, Dashboard)
├── Dockerfile.waf               # WAF gateway production image
├── Dockerfile.dashboard         # Streamlit dashboard image
├── requirements.txt             # WAF runtime dependencies
├── requirements-dashboard.txt   # Dashboard dependencies
├── requirements-training.txt    # ML training & evaluation dependencies
├── config.yaml                  # Core WAF configuration & thresholds
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore rules
├── README.md                    # Project documentation
│
├── waf/                         # WAF Core Engine
│   ├── __init__.py
│   ├── main.py                  # FastAPI ASGI entrypoint & lifespan lifecycle
│   ├── proxy.py                 # Async reverse proxy & backend forwarder
│   ├── context.py               # RequestContext builder & body parser
│   ├── normalizer.py            # Iterative multi-layer URL/HTML/Unicode normalizer
│   ├── config_manager.py        # YAML configuration loader & hot-reload
│   ├── models.py                # Core dataclasses (RequestContext, DetectionResult, etc.)
│   ├── signatures.py            # Deterministic regex signature engine with ReDoS guard
│   ├── feature_extractor.py     # Structural feature extractor & entropy calculator
│   ├── ai_engine.py             # Model loader, predictor, calibrator & warm-up
│   ├── detector.py              # Central decision orchestrator & fail-open pipeline
│   ├── rate_limiter.py          # In-memory Token Bucket rate limiter
│   ├── threat_intel.py          # AbuseIPDB API client with SQLite cache
│   ├── blacklist.py             # In-memory dynamic IP blacklist & strike tracker
│   ├── geoip.py                 # MaxMind / DB-IP GeoIP enrichment
│   ├── event_queue.py           # Async non-blocking queue & background batch writer
│   ├── db.py                    # SQLite telemetry database manager (WAL mode)
│   └── alerts.py                # Alert generation & dedup engine
│
├── dashboard/                   # Streamlit SOC Dashboard
│   ├── __init__.py
│   ├── app.py                   # Main dashboard landing page
│   ├── db_reader.py             # Read-only SQLite query interface
│   └── pages/
│       ├── 1_overview.py        # Real-time traffic metrics & Plotly attack charts
│       └── 2_alerts.py          # Security alerts viewer & incident acknowledgment
│
├── rules/                       # Detection Signatures
│   └── rules.json               # 28 regex attack rules (SQLi, XSS, Traversal, CMDi)
│
├── training/                    # ML Training & Offline Pipelines
│   ├── __init__.py
│   ├── clean_data.py            # Dataset cleaning, deduplication & signature scan
│   ├── prepare_features.py      # Feature engineering & stratified train/val/test splits
│   ├── train_lr.py              # TF-IDF character n-grams + Logistic Regression training
│   ├── train_lgbm.py            # Structural feature LightGBM training (optional)
│   ├── calibrate.py             # Probability calibration utilities (isotonic)
│   ├── evaluate.py              # Evaluation metrics, confusion matrix & reports
│   └── notebooks/
│       └── training.ipynb       # Interactive training notebook for Google Colab
│
├── tests/                       # Automated Test Suite (pytest)
│   ├── __init__.py
│   ├── conftest.py              # Pytest fixtures & async test client
│   ├── test_proxy.py            # Reverse proxy & body handling tests
│   ├── test_context.py          # Context builder & parsing tests
│   ├── test_normalizer.py       # Obfuscation & normalization unit tests
│   ├── test_signatures.py       # Signature matching & ReDoS protection tests
│   ├── test_detector.py         # Full detection pipeline integration tests
│   ├── test_rate_limiter.py     # Token bucket rate limiting tests
│   ├── test_integration.py      # End-to-end attack blocking tests
│   └── payloads/                # Attack & benign evaluation payloads
│       ├── sqli.txt             # 30 SQL injection payloads
│       ├── xss.txt              # 20 XSS payloads
│       ├── traversal.txt        # 15 Path traversal payloads
│       ├── cmdi.txt             # 15 Command injection payloads
│       └── benign.txt           # 20 Benign real-world requests
│
├── scripts/                     # Operational & Benchmark Scripts
│   ├── generate_baseline.py     # Records legitimate Juice Shop user sessions
│   ├── benchmark.py             # Latency measurement benchmark (p50/p95/p99)
│   └── demo.py                  # Automated live presentation attack script
│
├── docs/                        # Architecture & Planning Documentation
│   ├── architecture.md          # Full engineering architecture specification
│   ├── team_tasks.md            # Team member work breakdown & learning roadmap
│   ├── evaluation.md            # Survival plan, risk analysis & KPI definitions
│   ├── threat_model.md          # Formal STRIDE / Attack vector threat model
│   └── decisions.md             # Architecture Decision Records (ADRs)
│
├── trained_models/              # Exported Models & Integrity Checksums
│   ├── .gitkeep
│   └── checksums.sha256
│
└── data/                        # Local Storage (gitignored)
    └── .gitkeep
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
