# 🛡️ AI-Based Phishing URL Detection with Explainable Security Analysis

> **Information Security Project**  
> Machine Learning · SHAP Explainability · Flask Web App · PDF Reports

---

## Overview

This project builds an end-to-end AI system that detects phishing URLs and explains **why** each URL is flagged — making the security analysis transparent and auditable.

### Key Features

| Feature | Detail |
|---|---|
| **30 URL Features** | Length, entropy, subdomains, keywords, TLD, IP, special chars, and more |
| **Ensemble ML Model** | Soft-voting ensemble of Random Forest + XGBoost + Logistic Regression |
| **SHAP Explanations** | Per-prediction feature attribution using SHapley Additive exPlanations |
| **Security Flags** | Human-readable red-flag list for each scan |
| **PDF Report** | Downloadable professional security analysis report |
| **Web Interface** | Real-time dark-themed UI with probability gauge and charts |

---

## Project Structure

```
phishing-detector/
├── app.py                  # Flask web application
├── train.py                # One-click training entry point
├── requirements.txt        # Python dependencies
│
├── src/
│   ├── feature_extractor.py   # 30-feature URL parser
│   ├── dataset_generator.py   # Labelled dataset builder
│   ├── train_model.py         # RF + XGBoost + Ensemble trainer
│   ├── explainer.py           # SHAP explainer + charts
│   └── report_generator.py    # PDF report generator
│
├── templates/
│   └── index.html          # Main web UI
│
├── static/
│   ├── css/style.css       # Dark-theme stylesheet
│   └── js/main.js          # Frontend logic
│
├── models/                 # Saved .pkl models + metrics.json
├── data/                   # Generated CSV dataset
└── reports/                # Generated PDF reports
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Train the models

```bash
python train.py
```

This will:
- Generate a 1000-URL labelled dataset (`data/phishing_dataset.csv`)
- Train Random Forest, XGBoost, Logistic Regression, and an Ensemble
- Save models to `models/` and performance metrics to `models/metrics.json`

### 3. Start the web app

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

> **Note:** If models are missing on startup, the app will auto-train them.

---

## Extracted Features (30 total)

| # | Feature | Description |
|---|---|---|
| 1 | `url_length` | Total URL length |
| 2 | `domain_length` | Length of domain segment |
| 3 | `path_length` | Length of path segment |
| 4 | `num_dots` | Count of `.` characters |
| 5 | `num_hyphens` | Count of `-` characters |
| 6 | `num_underscores` | Count of `_` characters |
| 7 | `num_slashes` | Count of `/` characters |
| 8 | `num_at_symbols` | `@` symbols (credential injection) |
| 9 | `num_question_marks` | Count of `?` |
| 10 | `num_ampersands` | Count of `&` |
| 11 | `num_equals` | Count of `=` |
| 12 | `num_digits` | Digit character count |
| 13 | `num_special_chars` | Unusual special character count |
| 14 | `has_ip_address` | Domain is a raw IP |
| 15 | `has_https` | HTTPS scheme flag |
| 16 | `has_http` | HTTP scheme flag |
| 17 | `subdomain_count` | Number of subdomains |
| 18 | `is_shortener` | Known URL shortener domain |
| 19 | `has_phishing_keyword` | Phishing keyword present |
| 20 | `phishing_keyword_count` | Number of phishing keywords |
| 21 | `entropy` | Shannon entropy of URL string |
| 22 | `digit_ratio` | Proportion of digits |
| 23 | `letter_ratio` | Proportion of letters |
| 24 | `suspicious_tld` | TLD not in trusted set |
| 25 | `double_slash_redirect` | `//` in path (redirect trick) |
| 26 | `prefix_suffix_hyphen` | Domain starts/ends with `-` |
| 27 | `abnormal_url` | Hostname not found in URL body |
| 28 | `path_extension_suspicious` | Suspicious file extension |
| 29 | `query_param_count` | Number of query parameters |
| 30 | `has_port` | Explicit port in URL |

---

## ML Models

| Model | Role |
|---|---|
| **Random Forest** | High accuracy, robust to noise, provides feature importances |
| **XGBoost** | Gradient boosting, strong on tabular data |
| **Logistic Regression** | Linear baseline, fast and interpretable |
| **Ensemble (soft voting)** | Combines all three for best overall performance |

---

## Explainability — SHAP

SHAP (SHapley Additive exPlanations) assigns each feature a contribution score for every individual prediction:

- **Positive SHAP** → pushes the URL toward *phishing*
- **Negative SHAP** → pushes the URL toward *legitimate*

The SHAP chart is included in both the web UI and the downloadable PDF report.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web UI |
| `POST` | `/analyze` | Analyse a URL (JSON body: `{"url": "..."}`) |
| `POST` | `/report` | Generate + download PDF report |
| `GET` | `/metrics` | Model performance metrics |
| `GET` | `/global-importance` | Global feature importance chart |
| `GET` | `/health` | Health check |

### Example `/analyze` response

```json
{
  "url": "http://paypa1-secure-login.com/verify?user=victim",
  "label": 1,
  "verdict": "PHISHING",
  "probability": 97.3,
  "risk_level": "high",
  "features": { ... },
  "explanation": {
    "prediction_prob": 0.973,
    "top_contributors": [ ... ],
    "shap_values": [ ... ],
    "chart_b64": "..."
  },
  "flags": [
    { "severity": "high", "message": "URL contains 2 phishing-related keyword(s)" },
    ...
  ]
}
```

---

## Technologies Used

- **Python 3.10+**
- **scikit-learn** — Random Forest, Logistic Regression, VotingClassifier
- **XGBoost** — Gradient boosted trees
- **SHAP** — Model-agnostic explainability
- **Flask** — Web framework
- **fpdf2** — PDF generation
- **tldextract** — TLD / domain parsing
- **matplotlib** — Chart rendering

---

## Screenshots

| Screen | Description |
|---|---|
| Hero + Input | Clean dark UI for URL entry |
| Verdict Banner | Colour-coded PHISHING / SUSPICIOUS / LEGITIMATE |
| SHAP Chart | Visual breakdown of feature contributions |
| PDF Report | Professional downloadable analysis |

---

## Disclaimer

This tool is built for **educational purposes** as part of an information security project. It should not be used as the sole basis for production security decisions.
