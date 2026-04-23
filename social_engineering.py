"""
=============================================================
  ScamShield 2.0 — Social Engineering Detector
  Loads models from models/ folder
  Called by flask_api.py
=============================================================
"""

import re, os, pickle

# ── Load models from models/ folder ──────────────────────
SE_MODEL      = None
SE_VECTORIZER = None
SE_CLASSES    = []

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

def load_models():
    global SE_MODEL, SE_VECTORIZER, SE_CLASSES
    try:
        with open(os.path.join(MODEL_DIR, "se_model.pkl"),      "rb") as f: SE_MODEL      = pickle.load(f)
        with open(os.path.join(MODEL_DIR, "se_vectorizer.pkl"), "rb") as f: SE_VECTORIZER = pickle.load(f)
        with open(os.path.join(MODEL_DIR, "se_classes.pkl"),    "rb") as f: SE_CLASSES    = pickle.load(f)
        print(f"✅ SE NLP loaded | Classes: {SE_CLASSES}")
    except Exception as e:
        print(f"⚠️  SE model not found: {e}")
        print("   Run: python training/train_se.py")

load_models()

# ── Attack type risk weights ──────────────────────────────
ATTACK_WEIGHTS = {
    "Phishing"                  : 0.90,
    "Scareware"                 : 0.85,
    "Malware"                   : 0.85,
    "Pretexting"                : 0.80,
    "Baiting"                   : 0.70,
    "NOT-Malicious General Class": 0.05,
}

# ── Keyword backup patterns ───────────────────────────────
KEYWORD_PATTERNS = {
    "urgency"   : [r"act\s+now", r"immediately", r"urgent", r"expires?\s+(today|soon)", r"limited\s+time"],
    "fear"      : [r"(account|device).{0,20}(suspended|blocked|compromised)", r"virus\s+detected", r"unauthorized\s+access"],
    "reward"    : [r"you\s+(have\s+)?won", r"congratulations", r"claim\s+your\s+(prize|reward)"],
    "credential": [r"(enter|verify).{0,20}(password|otp|pin|cvv)", r"bank\s+account\s+number"],
}

# ── Brand impersonation ───────────────────────────────────
BRANDS = {
    "paypal"   : "paypal.com",    "netflix"   : "netflix.com",
    "amazon"   : "amazon.com",    "sbi"       : "sbi.co.in",
    "hdfc"     : "hdfcbank.com",  "google"    : "google.com",
    "microsoft": "microsoft.com", "apple"     : "apple.com",
    "paycom"   : "paycom.com"
}


def analyze(page_text: str, url: str = "", title: str = "") -> dict:
    combined = re.sub(r'\s+', ' ', f"{title} {page_text}").strip()

    # ── NLP prediction ─────────────────────────────────────
    attack_type       = "NOT-Malicious General Class"
    attack_confidence = 0.0

    if SE_MODEL and SE_VECTORIZER and len(combined.split()) >= 3:
        try:
            vec   = SE_VECTORIZER.transform([combined[:1000]])
            probs = SE_MODEL.predict_proba(vec)[0]
            idx   = probs.argmax()
            attack_type       = SE_CLASSES[idx]
            attack_confidence = float(probs[idx]) * 100
        except: pass

    # ── Keyword patterns ───────────────────────────────────
    tactics_found = []
    for tactic, patterns in KEYWORD_PATTERNS.items():
        for pattern in patterns:
            try:
                if re.search(pattern, combined.lower(), re.IGNORECASE):
                    if tactic not in tactics_found:
                        tactics_found.append(tactic)
                    break
            except: continue

    # ── SE score ───────────────────────────────────────────
    if attack_type == "NOT-Malicious General Class":
        se_score = 0.05
    else:
        base     = ATTACK_WEIGHTS.get(attack_type, 0.5)
        se_score = base * (attack_confidence / 100)
        if tactics_found:
            se_score = min(1.0, se_score + 0.1 * len(tactics_found))

    # ── Dynamic Brand impersonation boost ──────────────────
    try:
        from urllib.parse import urlparse
        import difflib
        domain = urlparse(url).hostname or ""
        domain_body = domain.replace("www.", "").split('.')[0].lower() if domain else ""
        
        if domain_body:
            import collections
            # 1. Extract potential brands from Title
            words_in_title = re.findall(r'\b[a-zA-Z]{4,}\b', title)
            
            # 2. Extract potential brands from explicit claims
            claimed_entities = re.findall(r'(?:copyright|©|welcome to|sign in to|login to)\s*([A-Za-z]{4,})', combined, re.IGNORECASE)
            
            # 3. Extract frequent Title-Cased words (Proper Nouns) from the body
            proper_nouns = re.findall(r'\b[A-Z][a-z]{3,}\b', combined)
            common_nouns = [word[0].lower() for word in collections.Counter(proper_nouns).most_common(5)]
            
            potential_brands = set([w.lower() for w in words_in_title + claimed_entities + common_nouns])
            generic_ignore = {"login", "sign", "welcome", "home", "dashboard", "official", "page", "account", "client", "employee", "support", "about", "contact", "resources", "solution"}
            
            is_impersonating = False
            for brand in potential_brands:
                if brand in generic_ignore: continue
                
                # Check for dynamic typosquatting (e.g. 'paycom' vs 'paqcorn' -> similarity ~0.61)
                sim = difflib.SequenceMatcher(None, brand, domain_body).ratio()
                
                # Check if it claims a specific brand via explicit text (e.g. copyright) but the domain is totally different
                claimed_explicitly = (brand in [e.lower() for e in claimed_entities])
                
                is_typosquat = (0.55 < sim < 0.98) and (brand not in domain_body) and (domain_body not in brand)
                
                if is_typosquat or (claimed_explicitly and brand not in domain):
                    is_impersonating = True
                    break
            
            if is_impersonating:
                if "dynamic_impersonation" not in tactics_found:
                    tactics_found.append("dynamic_impersonation")
                
                # Forcefully overwrite attack logic if dynamic brand impersonation is found
                attack_type = "Brand Impersonation"
                attack_confidence = 95.0
                se_score = max(0.90, se_score + 0.4)
    except Exception as e: 
        print("SE Dynamic Brand Error: ", e)
        pass

    # ── Risk level ─────────────────────────────────────────
    if se_score >= 0.60:   risk = "high"
    elif se_score >= 0.30: risk = "medium"
    else:                  risk = "low"

    return {
        "score"            : round(se_score, 4),
        "risk_level"       : risk,
        "is_suspicious"    : se_score >= 0.30,
        "attack_type"      : attack_type,
        "attack_confidence": round(attack_confidence, 1),
        "tactics_found"    : tactics_found,
        "summary"          : f"{attack_type} ({round(attack_confidence,1)}% confident)"
    }
