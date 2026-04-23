"""
ScamShield 2.0 - Flask Backend API
Layer 1: ML Model  (primary decision maker)
Layer 2: SE NLP    (bidirectional - boosts detection AND suppresses false positives)
Layer 3: Dashboard & Tracking
Run: python flask_api.py
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import pickle, os, pandas as pd, datetime
from social_engineering import analyze as se_analyze

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

DB_FILE = "phishguard.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    # Scans table
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            title TEXT,
            verdict TEXT,
            confidence REAL,
            ml_confidence REAL,
            se_score REAL,
            se_attack_type TEXT,
            se_suppressed INTEGER,
            se_boosted INTEGER,
            cookies_count INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            feature_json TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            url TEXT,
            user_verdict TEXT,
            feedback_type TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Simple migration to add SE columns if missing
    try:
        c.execute("ALTER TABLE scans ADD COLUMN se_tactics TEXT")
        c.execute("ALTER TABLE scans ADD COLUMN se_summary TEXT")
    except sqlite3.OperationalError:
        pass # Columns already exist

    conn.commit()
    conn.close()

init_db()

@app.after_request
def add_headers(response):
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    response.headers["Access-Control-Allow-Origin"]          = "*"
    response.headers["Access-Control-Allow-Headers"]         = "Content-Type"
    response.headers["Access-Control-Allow-Methods"]         = "GET, POST, OPTIONS"
    return response

@app.route("/predict", methods=["OPTIONS"])
@app.route("/",        methods=["OPTIONS"])
def handle_options():
    r = app.make_default_options_response()
    r.headers["Access-Control-Allow-Private-Network"] = "true"
    return r

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

with open(os.path.join(MODEL_DIR, "phishing_model.pkl"),    "rb") as f: MODEL    = pickle.load(f)
with open(os.path.join(MODEL_DIR, "scaler.pkl"),            "rb") as f: SCALER   = pickle.load(f)
with open(os.path.join(MODEL_DIR, "selected_features.pkl"), "rb") as f: FEATURES = pickle.load(f)

# Get feature importances for explainability
if hasattr(MODEL, 'feature_importances_'):
    FEATURE_IMPORTANCES = MODEL.feature_importances_
else:
    FEATURE_IMPORTANCES = [1.0 / len(FEATURES)] * len(FEATURES)

MODEL_NAME = type(MODEL).__name__
print(f"✅ Layer 1 — ML Model : {MODEL_NAME} ({len(FEATURES)} features)")
print(f"✅ Layer 2 — SE NLP   : bidirectional mode (boost + suppress)")
print(f"✅ Layer 3 — Database : {DB_FILE} initialized")


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "running", "model": MODEL_NAME})

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON payload"}), 400

        # Extract extra info
        cookies_count = data.get("cookies_count", 0)

        # ── Layer 1: ML Model (primary) ────────────────────
        feature_df = pd.DataFrame(
            [[data.get(f, 0) for f in FEATURES]], columns=FEATURES
        )
        scaled = feature_df if MODEL_NAME == "RandomForestClassifier" \
                 else SCALER.transform(feature_df)

        prediction  = MODEL.predict(scaled)[0]
        probability = MODEL.predict_proba(scaled)[0]
        ml_phishing = float(probability[0])

        # Feature Contributions for explainability
        # As surrogate, compute feature * importance
        contributions = {}
        for idx, feat in enumerate(FEATURES):
            val = float(data.get(feat, 0))
            imp = float(FEATURE_IMPORTANCES[idx])
            score = val * imp 
            # We scale it pseudo-linearly just for ranking
            contributions[feat] = {"value": val, "importanceScore": round(score, 4)}

        # Sort contributions from highest impact
        sorted_contribs = dict(sorted(contributions.items(), key=lambda item: item[1]["importanceScore"], reverse=True)[:5])

        from urllib.parse import urlparse
        domain = urlparse(data.get("url", "")).netloc
        
        # Check for user overrides in feedback table
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT user_verdict FROM feedback WHERE url LIKE ? ORDER BY timestamp DESC LIMIT 1", ('%' + domain + '%',))
        fb = c.fetchone()
        user_override = fb[0] if fb else None

        # ── Layer 2: SE NLP (bidirectional) ────────────────
        se = se_analyze(
            page_text = data.get("page_text",  ""),
            url       = data.get("url",        ""),
            title     = data.get("page_title", "")
        )

        se_attack    = se.get("attack_type", "NOT-Malicious General Class")
        se_known     = se_attack not in ["NOT-Malicious General Class", "Unknown", ""]
        se_no_threat = se_attack in  ["NOT-Malicious General Class", "Unknown", ""]
        se_conf      = se.get("attack_confidence", 0)
        word_count   = len(data.get("page_text", "").split())

        se_suppressed  = False
        se_boosted_now = False

        if user_override:
            if user_override == 'legitimate':
                is_phishing = False
                se_suppressed = True
                se_attack = "User Whitelisted"
            else:
                is_phishing = True
                se_boosted_now = True
                se_attack = "User Blacklisted"
        else:
            # Independent dynamic trigger for Brand Impersonation regardless of ML score
            if se_attack == "Brand Impersonation" and se_conf >= 70:
                is_phishing = True
                se_boosted_now = True
                # User requested pure ML score be untouched so they can see exact ML accuracy
                
            elif (se_no_threat      and
                se_conf   >= 70   and
                ml_phishing < 0.82 and
                word_count  >= 30):
                is_phishing   = False
                se_suppressed = True

            elif se_known and ml_phishing >= 0.45:
                if ml_phishing >= 0.60:
                    se_required = 40
                else:
                    se_required = 55

                if se_conf >= se_required:
                    is_phishing    = ml_phishing >= 0.50
                    se_boosted_now = True
                else:
                    is_phishing = ml_phishing >= 0.65
            else:
                is_phishing = ml_phishing >= 0.65
            
        verdict = "phishing" if is_phishing else "legitimate"

        # ── Layer 3: Store Scan locally ────────────────────
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO scans (url, title, verdict, confidence, ml_confidence, se_score, 
            se_attack_type, se_suppressed, se_boosted, cookies_count, feature_json, se_tactics, se_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get("url", ""), 
            data.get("page_title", ""),
            verdict,
            float(ml_phishing),
            float(ml_phishing),
            float(se["score"]),
            se_attack,
            int(se_suppressed),
            int(se_boosted_now),
            cookies_count,
            str(sorted_contribs),
            str(se["tactics_found"]),
            str(se["summary"])
        ))
        scan_id = c.lastrowid
        conn.commit()
        conn.close()

        return jsonify({
            "scan_id"        : scan_id,
            "prediction"     : verdict,
            "is_phishing"    : bool(is_phishing),
            "confidence"     : round(ml_phishing, 4),   # always show ML score
            "ml_confidence"  : round(ml_phishing, 4),
            "se_score"       : round(se["score"], 4),
            "se_risk"        : se["risk_level"],
            "se_attack_type" : se["attack_type"],
            "se_attack_conf" : se["attack_confidence"],
            "se_tactics"     : se["tactics_found"],
            "se_summary"     : se["summary"],
            "se_boosted"     : bool(se_boosted_now),
            "se_suppressed"  : bool(se_suppressed),
            "explainability" : sorted_contribs
        })

    except Exception as e:
        import traceback
        print("Error serving prediction:", traceback.format_exc())
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500

@app.route("/features", methods=["GET"])
def list_features():
    return jsonify({"total": len(FEATURES), "features": FEATURES})

# --- Dashboard API Endpoints ---
@app.route("/api/stats", methods=["GET"])
def api_stats():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM scans")
    total_scanned = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'phishing'")
    total_phishing = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'legitimate'")
    total_safe = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'legitimate' AND (confidence > 0.4)")
    total_suspicious = c.fetchone()[0]
    
    c.execute("SELECT SUM(cookies_count) FROM scans WHERE verdict = 'phishing'")
    cookies_detected_on_risky = c.fetchone()[0] or 0
    
    # False positives/negatives count from feedback
    c.execute("SELECT COUNT(*) FROM feedback WHERE feedback_type = 'false_positive'")
    false_positives = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM feedback WHERE feedback_type = 'false_negative'")
    false_negatives = c.fetchone()[0]
    
    # Whitelisted sites (from scans, or specifically from feedback)
    c.execute("SELECT COUNT(DISTINCT url) FROM feedback WHERE user_verdict = 'legitimate'")
    total_whitelisted = c.fetchone()[0]
    
    c.execute("SELECT se_attack_type, COUNT(*) as count FROM scans WHERE se_attack_type != 'NOT-Malicious General Class' GROUP BY se_attack_type ORDER BY count DESC LIMIT 1")
    most_common_attack_row = c.fetchone()
    most_common_attack = most_common_attack_row[0] if most_common_attack_row else "None"
    
    # Get last 7 days scans trend
    c.execute("""
        SELECT date(timestamp) as scan_date, verdict, COUNT(*) as count 
        FROM scans 
        WHERE timestamp >= date('now', '-7 days')
        GROUP BY scan_date, verdict
        ORDER BY scan_date ASC
    """)
    trend_data = c.fetchall()
    
    conn.close()
    
    daily_trend = {}
    for r in trend_data:
        d = r["scan_date"]
        v = r["verdict"]
        c_count = r["count"]
        if d not in daily_trend:
             daily_trend[d] = {"phishing": 0, "legitimate": 0}
        daily_trend[d][v] = c_count

    return jsonify({
        "totalScanned": total_scanned,
        "totalPhishing": total_phishing,
        "totalSafe": total_safe,
        "totalSuspicious": total_suspicious,
        "falsePositives": false_positives,
        "falseNegatives": false_negatives,
        "totalWhitelisted": total_whitelisted,
        "cookiesOnRisky": cookies_detected_on_risky,
        "mostCommonAttack": most_common_attack,
        "dailyTrend": daily_trend
    })

@app.route("/api/history", methods=["GET"])
def api_history():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    
    history = []
    for r in rows:
        history.append(dict(r))
    return jsonify({"history": history})

@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    data = request.json
    scan_id = data.get("scan_id")
    url = data.get("url")
    feedback_type = data.get("feedback_type")
    user_verdict = data.get("user_verdict")
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        INSERT INTO feedback (scan_id, url, user_verdict, feedback_type)
        VALUES (?, ?, ?, ?)
    ''', (scan_id, url, user_verdict, feedback_type))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/revoke_feedback", methods=["POST"])
def api_revoke_feedback():
    data = request.json
    url = data.get("url")
    if not url: return jsonify({"error": "No url"}), 400

    from urllib.parse import urlparse
    domain = urlparse(url).netloc
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('DELETE FROM feedback WHERE url LIKE ?', ('%' + domain + '%',))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})


@app.route("/api/whitelist", methods=["GET"])
def get_whitelist():
    conn = get_db_connection()
    c = conn.cursor()
    # Group by URL to remove duplicates, and only pick user_verdict = 'legitimate'
    c.execute("""
        SELECT MAX(id) as id, url, user_verdict, MAX(timestamp) as timestamp 
        FROM feedback 
        WHERE user_verdict = 'legitimate' 
        GROUP BY url 
        ORDER BY timestamp DESC
    """)
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/whitelist/delete/<int:feedback_id>", methods=["DELETE"])
def delete_whitelist_item(feedback_id):
    conn = get_db_connection()
    c = conn.cursor()
    # First, get the url for this ID
    c.execute("SELECT url FROM feedback WHERE id = ?", (feedback_id,))
    row = c.fetchone()
    if row:
        from urllib.parse import urlparse
        domain = urlparse(row["url"]).netloc
        # Delete all feedback related to this domain to clear it completely
        c.execute("DELETE FROM feedback WHERE url LIKE ?", ('%' + domain + '%',))
        conn.commit()
    conn.close()
    return jsonify({"status": "success"})


if __name__ == "__main__":
    print("\n🚀 ScamShield 2.0 API running on http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)