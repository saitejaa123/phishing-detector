"""
Model Trainer
Trains Random Forest, XGBoost, and a soft-voting Ensemble classifier.
Saves models + metadata to /models directory.
"""

import json
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# Paths
ROOT      = Path(__file__).parent.parent
DATA_PATH = ROOT / "data" / "phishing_dataset.csv"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(Path(__file__).parent))
from feature_extractor import FEATURE_NAMES


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_data():
    if not DATA_PATH.exists():
        print("[*] Dataset not found — generating …")
        from dataset_generator import generate_dataset
        generate_dataset(500, 500, str(DATA_PATH))

    df = pd.read_csv(DATA_PATH)
    X  = df[FEATURE_NAMES].values
    y  = df["label"].values
    return X, y


def evaluate(name, model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    y_prob = (
        model.predict_proba(X_test)[:, 1]
        if hasattr(model, "predict_proba") else np.zeros(len(y_test))
    )
    acc  = accuracy_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_prob) if y_prob.any() else 0.0
    cm   = confusion_matrix(y_test, y_pred).tolist()
    rep  = classification_report(y_test, y_pred, output_dict=True)
    print(f"\n{'─'*50}")
    print(f"  {name}")
    print(f"  Accuracy : {acc:.4f}   AUC-ROC : {auc:.4f}")
    print(f"  Confusion Matrix:\n    {cm}")
    return {"accuracy": round(acc, 4), "auc_roc": round(auc, 4),
            "confusion_matrix": cm, "classification_report": rep}


# ── Training ──────────────────────────────────────────────────────────────────

def train():
    print("[+] Loading dataset …")
    X, y = load_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale for Logistic Regression inside ensemble
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    metrics = {}

    # ── Random Forest ─────────────────────────────────────────────────────────
    print("\n[+] Training Random Forest …")
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=12, min_samples_split=4,
        random_state=42, n_jobs=-1
    )
    rf.fit(X_train, y_train)
    metrics["random_forest"] = evaluate("Random Forest", rf, X_test, y_test)
    joblib.dump(rf, MODEL_DIR / "random_forest.pkl")
    print("    Saved → models/random_forest.pkl")

    # ── XGBoost ───────────────────────────────────────────────────────────────
    print("\n[+] Training XGBoost …")
    xgb = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42, n_jobs=-1
    )
    xgb.fit(X_train, y_train)
    metrics["xgboost"] = evaluate("XGBoost", xgb, X_test, y_test)
    joblib.dump(xgb, MODEL_DIR / "xgboost.pkl")
    print("    Saved → models/xgboost.pkl")

    # ── Logistic Regression ───────────────────────────────────────────────────
    print("\n[+] Training Logistic Regression …")
    lr = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    lr.fit(X_train_sc, y_train)
    metrics["logistic_regression"] = evaluate(
        "Logistic Regression", lr, X_test_sc, y_test
    )
    joblib.dump(lr,     MODEL_DIR / "logistic_regression.pkl")
    joblib.dump(scaler, MODEL_DIR / "scaler.pkl")
    print("    Saved → models/logistic_regression.pkl + scaler.pkl")

    # ── Ensemble (soft voting) ────────────────────────────────────────────────
    # Note: All sub-models use raw (unscaled) features here; LR gets its own
    # pipeline wrapper so the ensemble operates on the same X.
    from sklearn.pipeline import Pipeline
    lr_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("lr",     LogisticRegression(max_iter=1000, C=1.0, random_state=42)),
    ])
    ensemble = VotingClassifier(
        estimators=[
            ("rf",  RandomForestClassifier(n_estimators=200, max_depth=12,
                                           random_state=42, n_jobs=-1)),
            ("xgb", XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                                  subsample=0.8, colsample_bytree=0.8,
                                  eval_metric="logloss",
                                  random_state=42, n_jobs=-1)),
            ("lr",  lr_pipe),
        ],
        voting="soft",
    )
    print("\n[+] Training Ensemble (soft-voting RF + XGB + LR) …")
    ensemble.fit(X_train, y_train)
    metrics["ensemble"] = evaluate("Ensemble", ensemble, X_test, y_test)
    joblib.dump(ensemble, MODEL_DIR / "ensemble.pkl")
    print("    Saved → models/ensemble.pkl")

    # ── Cross-validation on best model ────────────────────────────────────────
    print("\n[+] 5-fold CV on Ensemble …")
    cv_scores = cross_val_score(
        ensemble, X, y,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
        scoring="accuracy", n_jobs=-1
    )
    metrics["ensemble"]["cv_mean"] = round(cv_scores.mean(), 4)
    metrics["ensemble"]["cv_std"]  = round(cv_scores.std(),  4)
    print(f"    CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # ── Feature importances (from RF) ─────────────────────────────────────────
    importances = dict(zip(FEATURE_NAMES, rf.feature_importances_.tolist()))
    metrics["feature_importances"] = importances

    # Save metadata
    with open(MODEL_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("\n[+] Metrics saved → models/metrics.json")
    print("\n✓ Training complete.")
    return metrics


if __name__ == "__main__":
    train()
