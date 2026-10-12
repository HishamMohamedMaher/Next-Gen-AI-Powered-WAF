# AI-WAF Architecture Decision Record (ADR)

This document tracks significant design, technology, and architectural decisions made throughout the lifecycle of the AI-WAF project.

| Date | Decision | Rationale | Alternatives Considered |
|---|---|---|---|
| 2026-10-01 | **Chose FastAPI over Flask** | Native asynchronous concurrency (`async`/`await`), ASGI throughput, and built-in Pydantic data validation are essential for a non-blocking reverse proxy with minimal proxy overhead. | Flask + gevent / WSGI (synchronous blocking I/O, lower throughput for high-concurrency proxying). |
| 2026-10-02 | **Chose SQLite over PostgreSQL** | Zero external daemon dependency, zero network overhead for audit writes, and simplified single-node deployment. Sufficient for local logging and reporting. | PostgreSQL / MySQL (excess operational overhead and added network latency for single-instance prototype). |
| 2026-10-03 | **Chose TF-IDF + Logistic Regression over Deep Learning** | Inference latency budget must remain strictly under 5ms per request. TF-IDF + Logistic Regression delivers sub-millisecond evaluation with high interpretability and minimal CPU/memory footprint. | BERT / RoBERTa / Transformer models (excessive latency > 50ms, required GPU hardware). |
| 2026-10-05 | **Dropped Telegram / SIEM integrations** | Focused core project scope on accurate attack detection, normalization, reverse proxying, and the local monitoring dashboard without external webhook dependencies. | SIEM (Splunk / ELK) or Telegram alerting bots (introduced complex external dependencies and network failure modes). |
| 2026-10-06 | **Dropped CNN / Isolation Forest models** | Pre-filtering with regex signatures combined with TF-IDF provides high precision. Unsupervised Isolation Forest produced excessive false positive rates on benign Juice Shop query variations. | Convolutional Neural Networks (CNN) for character sequences; Isolation Forest for unsupervised anomaly detection. |
| 2026-10-08 | **Chose Streamlit over React for Dashboard** | Rapid prototyping in pure Python allowed immediate sharing of internal data models and SQLite database access without requiring a dedicated REST API or complex frontend build toolchain. | React / Vue SPA (longer development turnaround, dual-stack codebase maintenance). |
