"""
=============================================================
  PhishGuard — ML Model Training Script
  Dataset : PhiUSIIL_Phishing_URL_Dataset.csv
  Output  : ../models/phishing_model.pkl
            ../models/scaler.pkl
            ../models/selected_features.pkl
  Run     : python training/train_ml.py
=============================================================
"""

import pandas as pd
import numpy as np
import pickle
import os
import warnings
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, learning_curve
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, roc_curve,
    classification_report, confusion_matrix
)
from sklearn.feature_selection import mutual_info_classif

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET_PATH = os.path.join(DATASET_DIR, "PhiUSIIL_Phishing_URL_Dataset.csv")

# ── Step 1: Load Dataset ──────────────────────────────────
print("=" * 60)
print("STEP 1: Loading Dataset")
print("=" * 60)

df = pd.read_csv(DATASET_PATH)
print(f"Shape        : {df.shape}")
print(f"Phishing (0) : {(df['label']==0).sum():,}")
print(f"Legitimate(1): {(df['label']==1).sum():,}")

# ── Step 2: Drop Non-Numeric Columns ──────────────────────
print("\n" + "=" * 60)
print("STEP 2: Dropping Metadata Columns")
print("=" * 60)

DROP_COLS = ['FILENAME', 'URL', 'Domain', 'TLD', 'Title']
df.drop(columns=[c for c in DROP_COLS if c in df.columns], inplace=True)
print(f"Remaining columns: {df.shape[1]}")

# ── Step 3: Data Cleaning ─────────────────────────────────
print("\n" + "=" * 60)
print("STEP 3: Data Cleaning")
print("=" * 60)

missing = df.isnull().sum().sum()
print(f"Missing values: {missing}")
if missing: df.dropna(inplace=True)

dupes = df.duplicated().sum()
print(f"Duplicate rows: {dupes:,}")
if dupes: df.drop_duplicates(inplace=True)

df = df.apply(pd.to_numeric, errors='coerce').dropna()
print(f"Clean shape: {df.shape}")

# ── Step 4: Feature Selection (Raw features only) ─────────
print("\n" + "=" * 60)
print("STEP 4: Feature Selection — Removing Leaky Features")
print("=" * 60)

# These are pre-computed score features — REMOVE to avoid data leakage
LEAKY_FEATURES = [
    'URLSimilarityIndex', 'TLDLegitimateProb',
    'URLCharProb', 'CharContinuationRate',
    'DomainTitleMatchScore', 'URLTitleMatchScore',
]
df.drop(columns=[c for c in LEAKY_FEATURES if c in df.columns], inplace=True)
print(f"Removed leaky features: {[c for c in LEAKY_FEATURES if c in df.columns]}")

X = df.drop('label', axis=1)
y = df['label']

# Mutual information feature selection on raw features
print("\nRunning mutual information feature selection...")
mi_scores  = mutual_info_classif(X, y, random_state=42)
mi_series  = pd.Series(mi_scores, index=X.columns).sort_values(ascending=False)

print("\nTop 20 features by MI score:")
print(mi_series.head(20).to_string())

TOP_FEATURES = mi_series.head(20).index.tolist()
X = X[TOP_FEATURES]
print(f"\nSelected {len(TOP_FEATURES)} features")

# ── Step 5: Train/Test Split ──────────────────────────────
print("\n" + "=" * 60)
print("STEP 5: Train/Test Split (80/20)")
print("=" * 60)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train: {X_train.shape[0]:,} | Test: {X_test.shape[0]:,}")

scaler         = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)

# ── Step 6: Train Models ──────────────────────────────────
print("\n" + "=" * 60)
print("STEP 6: Training Models")
print("=" * 60)

models = {
    "Logistic Regression": (LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1), True),
    "Random Forest"      : (RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1), False),
    "SVM"                : (SVC(kernel='rbf', probability=True, random_state=42), True),
}

results = {}
for name, (model, use_scaled) in models.items():
    print(f"  Training {name}...", end=" ", flush=True)
    Xtr = X_train_scaled if use_scaled else X_train
    Xte = X_test_scaled  if use_scaled else X_test
    model.fit(Xtr, y_train)
    y_pred = model.predict(Xte)
    y_prob = model.predict_proba(Xte)[:, 1]

    results[name] = {
        "model"     : model,
        "use_scaled": use_scaled,
        "y_pred"    : y_pred,
        "y_prob"    : y_prob,
        "Accuracy"  : round(accuracy_score (y_test, y_pred) * 100, 2),
        "Precision" : round(precision_score(y_test, y_pred) * 100, 2),
        "Recall"    : round(recall_score   (y_test, y_pred) * 100, 2),
        "F1-Score"  : round(f1_score       (y_test, y_pred) * 100, 2),
        "ROC-AUC"   : round(roc_auc_score  (y_test, y_prob) * 100, 2),
    }
    r = results[name]
    print(f"Done! Acc={r['Accuracy']}%  F1={r['F1-Score']}%")

# ── Step 7: Comparison ────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 7: Model Comparison")
print("=" * 60)

comp = pd.DataFrame({
    n: {k: v for k, v in info.items()
        if k not in ['model','y_pred','y_prob','use_scaled']}
    for n, info in results.items()
}).T
print(comp.to_string())

best_name = comp['F1-Score'].idxmax()
print(f"\n✅ Best Model: {best_name}")
print(f"\nClassification Report — {best_name}:")
print(classification_report(y_test, results[best_name]['y_pred'],
                             target_names=['Phishing','Legitimate']))

# ── Step 8: Learning Curve ────────────────────────────────
print("\n" + "=" * 60)
print("STEP 8: Learning Curve — Overfitting Check")
print("=" * 60)

rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
train_sizes, train_scores, val_scores = learning_curve(
    rf, X, y, cv=5,
    train_sizes=np.linspace(0.1, 1.0, 8),
    scoring='f1', n_jobs=-1
)

print(f"\n{'Train Size':>12} | {'Train F1':>10} | {'Val F1':>10} | {'Gap':>8}")
print("-" * 50)
for i in range(len(train_sizes)):
    gap  = train_scores.mean(axis=1)[i] - val_scores.mean(axis=1)[i]
    flag = " ← overfit?" if gap > 0.05 else ""
    print(f"{train_sizes[i]:>12,.0f} | "
          f"{train_scores.mean(axis=1)[i]*100:>9.2f}% | "
          f"{val_scores.mean(axis=1)[i]*100:>9.2f}% | "
          f"{gap*100:>7.2f}%{flag}")

# ── Step 9: Save Plots ────────────────────────────────────
fig, axes = plt.subplots(1, 3, figsize=(20, 6))
fig.suptitle("ScamShield 2.0 — Model Evaluation", fontsize=14, fontweight='bold')

# Metric comparison
metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC']
x = np.arange(len(metrics))
colors = ['#4e79a7', '#f28e2b', '#e15759']
for i, (name, info) in enumerate(results.items()):
    axes[0].bar(x + i*0.25, [info[m] for m in metrics], 0.25,
                label=name, color=colors[i], alpha=0.85)
axes[0].set_title("Metric Comparison")
axes[0].set_xticks(x + 0.25)
axes[0].set_xticklabels(metrics, rotation=15)
axes[0].set_ylim([85, 100])
axes[0].legend(fontsize=8)
axes[0].grid(axis='y', alpha=0.3)

# Confusion matrix
cm = confusion_matrix(y_test, results[best_name]['y_pred'])
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[1],
            xticklabels=['Phishing','Legitimate'],
            yticklabels=['Phishing','Legitimate'])
axes[1].set_title(f"Confusion Matrix — {best_name}")

# ROC curves
for name, info in results.items():
    fpr, tpr, _ = roc_curve(y_test, info['y_prob'])
    axes[2].plot(fpr, tpr, label=f"{name} ({info['ROC-AUC']}%)")
axes[2].plot([0,1],[0,1],'k--', alpha=0.4)
axes[2].set_title("ROC Curves")
axes[2].legend(fontsize=8)
axes[2].grid(alpha=0.3)

plt.tight_layout()
plot_path = os.path.join(MODEL_DIR, "model_evaluation.png")
plt.savefig(plot_path, dpi=150, bbox_inches='tight')
plt.close()
print(f"\nSaved → {plot_path}")

# Feature importance
if "Random Forest" in results:
    rf_model  = results["Random Forest"]["model"]
    feat_imp  = pd.Series(rf_model.feature_importances_, index=TOP_FEATURES).sort_values()
    plt.figure(figsize=(10, 8))
    feat_imp.plot(kind='barh', color='steelblue', alpha=0.85)
    plt.title("Feature Importances — Random Forest", fontweight='bold')
    plt.tight_layout()
    fi_path = os.path.join(MODEL_DIR, "feature_importance.png")
    plt.savefig(fi_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Saved → {fi_path}")

# ── Step 10: Save Best Model ──────────────────────────────
print("\n" + "=" * 60)
print("STEP 9: Saving Best Model to models/")
print("=" * 60)

best_model = results[best_name]['model']

model_path    = os.path.join(MODEL_DIR, "phishing_model.pkl")
scaler_path   = os.path.join(MODEL_DIR, "scaler.pkl")
features_path = os.path.join(MODEL_DIR, "selected_features.pkl")

with open(model_path,    "wb") as f: pickle.dump(best_model,   f)
with open(scaler_path,   "wb") as f: pickle.dump(scaler,       f)
with open(features_path, "wb") as f: pickle.dump(TOP_FEATURES, f)

print(f"✅ phishing_model.pkl   → {model_path}")
print(f"✅ scaler.pkl           → {scaler_path}")
print(f"✅ selected_features.pkl→ {features_path}")

print(f"""
=============================================================
  TRAINING COMPLETE
=============================================================
  Best Model : {best_name}
  Accuracy   : {results[best_name]['Accuracy']}%
  F1-Score   : {results[best_name]['F1-Score']}%

  Next step  : python training/train_se.py
=============================================================
""")
