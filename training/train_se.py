"""
=============================================================
  PhishGuard — Social Engineering NLP Training Script
  Dataset : phishing_nlp_dataset.xlsx (621 samples, 6 classes)
  Output  : ../models/se_model.pkl
            ../models/se_vectorizer.pkl
            ../models/se_classes.pkl
  Run     : python training/train_se.py
=============================================================
"""

import pandas as pd
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ── Paths ─────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET_PATH = os.path.join(DATASET_DIR, "phishing_nlp_dataset.xlsx")

# ── Step 1: Load & Parse Dataset ─────────────────────────
print("=" * 60)
print("STEP 1: Loading SE NLP Dataset")
print("=" * 60)

df = pd.read_excel(DATASET_PATH)
print(f"Raw shape: {df.shape}")

# Labels are embedded in Corpus text with \t separator
# e.g. "Your account is suspended\tPhishing"
rows = []
for text in df['Corpus']:
    text = str(text).strip()
    if '\t' in text:
        parts = text.rsplit('\t', 1)
        rows.append({
            'text' : parts[0].strip(),
            'label': parts[1].strip()
        })

df_clean = pd.DataFrame(rows)
print(f"Parsed: {len(df_clean)} samples")
print(f"\nClass distribution:")
print(df_clean['label'].value_counts().to_string())

# ── Step 2: Train/Test Split ──────────────────────────────
print("\n" + "=" * 60)
print("STEP 2: Train/Test Split (80/20)")
print("=" * 60)

X_train, X_test, y_train, y_test = train_test_split(
    df_clean['text'].tolist(),
    df_clean['label'].tolist(),
    test_size=0.2,
    random_state=42,
    stratify=df_clean['label'].tolist()
)
print(f"Train: {len(X_train)} | Test: {len(X_test)}")

# ── Step 3: TF-IDF Vectorizer ─────────────────────────────
print("\n" + "=" * 60)
print("STEP 3: TF-IDF Vectorization")
print("=" * 60)

vectorizer = TfidfVectorizer(
    ngram_range =(1, 2),
    max_features=1000,
    min_df      =1,
    stop_words  ='english',
    sublinear_tf=True
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec  = vectorizer.transform(X_test)
print(f"Vocabulary size: {len(vectorizer.vocabulary_)}")

# ── Step 4: Train Logistic Regression ────────────────────
print("\n" + "=" * 60)
print("STEP 4: Training Logistic Regression (Multi-class)")
print("=" * 60)

model = LogisticRegression(
    max_iter=1000, random_state=42,
    C=5.0, solver='lbfgs'
)
model.fit(X_train_vec, y_train)

# ── Step 5: Evaluate ──────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 5: Evaluation")
print("=" * 60)

y_pred = model.predict(X_test_vec)
acc    = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {acc*100:.2f}%\n")
print(classification_report(y_test, y_pred))

# Top words per attack type
print("Top indicator words per class:")
feature_names = vectorizer.get_feature_names_out()
for i, cls in enumerate(model.classes_):
    top_idx   = model.coef_[i].argsort()[-5:][::-1]
    top_words = [feature_names[j] for j in top_idx]
    print(f"  {cls:<30}: {', '.join(top_words)}")

# ── Step 6: Save Models ───────────────────────────────────
print("\n" + "=" * 60)
print("STEP 6: Saving SE Models to models/")
print("=" * 60)

model_path      = os.path.join(MODEL_DIR, "se_model.pkl")
vectorizer_path = os.path.join(MODEL_DIR, "se_vectorizer.pkl")
classes_path    = os.path.join(MODEL_DIR, "se_classes.pkl")

with open(model_path,      "wb") as f: pickle.dump(model,                   f)
with open(vectorizer_path, "wb") as f: pickle.dump(vectorizer,              f)
with open(classes_path,    "wb") as f: pickle.dump(model.classes_.tolist(), f)

print(f"✅ se_model.pkl      → {model_path}")
print(f"✅ se_vectorizer.pkl → {vectorizer_path}")
print(f"✅ se_classes.pkl    → {classes_path}")

print(f"""
=============================================================
  SE TRAINING COMPLETE
=============================================================
  Accuracy  : {acc*100:.2f}%
  Classes   : {model.classes_.tolist()}

  Next step : python flask_api.py
=============================================================
""")
