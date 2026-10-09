# 🎨 PII Firewall — Frontend Application

## Overview
This folder contains the **Frontend UI layer** for the PII Firewall project. It provides an ultra-clean, minimalist interactive dashboard built with **Streamlit**.

## Structure
```
frontend/
├── app.py             # Main Streamlit web application & simulation pipeline
├── run_frontend.py    # Convenient python runner to start the frontend
└── README.md          # Frontend documentation
```

## Running the Frontend
From the project root:
```bash
# Option 1: Direct python launcher
python frontend/run_frontend.py

# Option 2: Streamlit CLI
streamlit run frontend/app.py

# Option 3: Root proxy
streamlit run app.py
```
Open **`http://localhost:8501`** in your browser.

## Features
- **Minimalist Query Box:** Clean prompt input area pre-filled with real-world scenarios.
- **Privacy Action Controls:** Dropdown to select between `MASK`, `TOKENIZE`, and `REDACT`.
- **7-Step Real-Time Pipeline:** Detailed visual audit tracing:
  1. User prompt reception & entity classification
  2. Whole-prompt recursive PII detection & context analysis
  3. Privacy transformation (Masking / Tokenization / Policy Block)
  4. Outbound tool wire packet inspection
  5. Simulated external tool response
  6. Response interception & token re-hydration
  7. Final verified safe result delivery to the AI agent
