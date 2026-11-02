#!/usr/bin/env python3
"""
Wireless IDS - Model Training

Loads features.csv (produced by extract.py), trains a Decision Tree and a
Random Forest, and reports accuracy + a confusion matrix for each.
A simple random 80/20 row split is used - easy to explain, good enough
for a first working prototype.

Run with:
  python3 train.py
"""

from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib

DATA_DIR = Path("/home/james/wids/data")
FEATURES_CSV = DATA_DIR / "features.csv"
MODELS_DIR = Path("/home/james/wids/models")

# columns that are metadata, not features the model should learn from
NON_FEATURE_COLS = ["pcap", "window", "label"]


def load_data():
    df = pd.read_csv(FEATURES_CSV)
    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    X = df[feature_cols]
    y = df["label"]
    return X, y, feature_cols


def evaluate(name, model, X_test, y_test):
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    labels = sorted(y_test.unique())
    cm = confusion_matrix(y_test, preds, labels=labels)

    print(f"\n=== {name} ===")
    print(f"Accuracy: {acc:.4f}")
    print(f"Labels (row/col order): {labels}")
    print("Confusion matrix:")
    print(cm)
    print("\nPer-class report:")
    print(classification_report(y_test, preds, labels=labels))
    return acc


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    X, y, feature_cols = load_data()
    print(f"Loaded {len(X)} rows, {len(feature_cols)} features, classes: {sorted(y.unique())}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} rows, Test: {len(X_test)} rows")

    # --- Decision Tree ---
    dt = DecisionTreeClassifier(max_depth=6, random_state=42)
    dt.fit(X_train, y_train)
    dt_acc = evaluate("Decision Tree", dt, X_test, y_test)

    # --- Random Forest ---
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf.fit(X_train, y_train)
    rf_acc = evaluate("Random Forest", rf, X_test, y_test)

    # --- Feature importances (from the Random Forest) ---
    print("\n=== Feature importances (Random Forest) ===")
    importances = sorted(zip(feature_cols, rf.feature_importances_),
                          key=lambda x: x[1], reverse=True)
    for name, score in importances:
        print(f"  {name:35s} {score:.4f}")

    # --- Save both models ---
    joblib.dump(dt, MODELS_DIR / "decision_tree.joblib")
    joblib.dump(rf, MODELS_DIR / "random_forest.joblib")
    joblib.dump(feature_cols, MODELS_DIR / "feature_cols.joblib")
    print(f"\nSaved models to {MODELS_DIR}")
    print(f"Decision Tree accuracy: {dt_acc:.4f}")
    print(f"Random Forest accuracy: {rf_acc:.4f}")


if __name__ == "__main__":
    main()
