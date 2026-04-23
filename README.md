# 🔰 ScamShield 2.0 — Intelligent Phishing Detection System

A 100% free and fully localized AI-powered browser extension that detects phishing websites entirely on your own machine. It utilizes Machine Learning (Random Forest) for structure analysis and NLP (TF-IDF + Heuristics) for advanced Social Engineering and Typosquatting verification. 

It runs locally with ZERO API costs and ZERO cloud subscriptions.

---

## 📁 Project Structure

```
ScamShield 2.0/
├── dataset/
│   ├── PhiUSIIL_Phishing_URL_Dataset.csv   ← ML training data (235k URLs)
│   └── phishing_nlp_dataset.xlsx           ← SE NLP training data (621 samples)
│
├── training/
│   ├── train_ml.py     ← Step 1: Train ML model
│   └── train_se.py     ← Step 2: Train SE NLP model
│
├── models/             ← All .pkl files saved here after training
│
├── flask_api.py        ← Step 3: Run this to start the API
├── social_engineering.py
├── requirements.txt
├── phishguard.db       ← Auto-generated SQLite Database containing local feedback
│
├── templates/          ← Dashboard UI HTML
├── static/             ← Dashboard CSS & JS
│ 
└── chrome_extension/   ← Step 4: Load this in Chrome
    ├── manifest.json
    ├── background.js
    ├── content.js
    ├── popup.html
    └── popup.js
```

---

## ⚙️ Setup — Run in this exact order

### Step 0 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 1 — Train ML Model
Place `PhiUSIIL_Phishing_URL_Dataset.csv` in the `dataset/` folder, then:
```bash
python training/train_ml.py
```

### Step 2 — Train SE NLP Model
Place `phishing_nlp_dataset.xlsx` in the `dataset/` folder, then:
```bash
python training/train_se.py
```

### Step 3 — Start Flask API
```bash
python flask_api.py
```
You should see:
```
✅ Layer 1 — ML Model : RandomForestClassifier (20 features)
✅ Layer 2 — SE NLP   : ready
✅ Layer 3 — Database : phishguard.db initialized
🚀 ScamShield 2.0 API running on http://localhost:5000
```

### Step 4 — Load Chrome Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `chrome_extension/` folder
5. ScamShield 2.0 icon appears in toolbar

---

## 🛡️ Core Features
1. **Machine Learning DOM/URL Analysis** (RandomForest)
2. **Dynamic Brand Impersonation NLP** (Typosquatting prevention & Logo/Brand Scraping)
3. **Interactive Local Dashboard** (Accessible via `http://localhost:5000/dashboard`)
4. **Post-Mortem Threat Intelligence** (View exactly *why* a site got blocked via Risk Factor calculations)
5. **Cookie Extractor** (Monitor background cookies placed on risky domains)
6. **Whitelist Configuration** (Reverse ML decisions locally bypassing all analysis natively)

---

## 🎯 Confidence Thresholds

| Score | Result | Badge |
|---|---|---|
| < 40% | ✅ Safe | Green ✓ |
| 40–84% | 🔶 Suspicious | Orange ? |
| ≥ 85% | ⚠️ Phishing | Red ! |

---

## 🛠️ Technologies

| Component | Technology |
|---|---|
| ML Training | Python, Scikit-learn |
| SE NLP | TF-IDF, Logistic Regression |
| Backend API | Flask, Flask-CORS |
| Database | SQLite |
| Brand Identity | Built-in regex heuristics + difflib |
| Browser Extension | JavaScript, Chrome MV3 |
