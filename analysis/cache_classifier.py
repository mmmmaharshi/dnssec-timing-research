#!/usr/bin/env python3
"""
cache_classifier.py - ML classifier for cache-based DNSSEC algorithm fingerprinting

This script trains and evaluates machine learning models to classify DNSSEC
signing algorithms based on cache timing vectors from Prime+Probe measurements.

Features:
- Load cache timing CSV from cache_probe.c
- Feature extraction (mean latency, miss count, histogram, PCA)
- Multiple classifiers (Random Forest, SVM, Gradient Boosting)
- Cross-validation and confusion matrix
- Feature importance analysis

Usage:
    # Train on labeled data
    python cache_classifier.py --train cache_timings.csv --model model.pkl

    # Evaluate on test data
    python cache_classifier.py --test cache_timings.csv --model model.pkl

    # Train and evaluate in one step
    python cache_classifier.py --input cache_timings.csv --output results/

Requirements:
    pip install numpy scipy scikit-learn pandas matplotlib

Author: DNSSEC Timing Research
"""

import argparse
import os
import sys
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.model_selection import (
    cross_val_score,
    StratifiedKFold,
    train_test_split,
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)


class CacheFeatureExtractor:
    """Extract features from raw cache timing vectors."""

    def __init__(self, threshold: int = 120, n_histogram_bins: int = 50):
        self.threshold = threshold
        self.n_histogram_bins = n_histogram_bins

    def extract(self, timing_vector: np.ndarray) -> np.ndarray:
        """
        Extract features from a single cache timing vector.

        Features:
        - Basic statistics (mean, std, min, max, median)
        - Percentiles (5th, 25th, 75th, 95th)
        - Miss count and ratio (above threshold)
        - Histogram of latencies
        - Autocorrelation (cache set patterns)
        - Entropy of miss distribution
        """
        features = []

        # Basic statistics
        features.append(np.mean(timing_vector))
        features.append(np.std(timing_vector))
        features.append(np.min(timing_vector))
        features.append(np.max(timing_vector))
        features.append(np.median(timing_vector))

        # Percentiles
        features.append(np.percentile(timing_vector, 5))
        features.append(np.percentile(timing_vector, 25))
        features.append(np.percentile(timing_vector, 75))
        features.append(np.percentile(timing_vector, 95))

        # Miss statistics
        misses = timing_vector[self.threshold < timing_vector]
        features.append(len(misses))
        features.append(len(misses) / len(timing_vector))

        # Histogram
        hist, _ = np.histogram(
            timing_vector,
            bins=self.n_histogram_bins,
            range=(0, max(self.threshold * 3, np.max(timing_vector))),
        )
        features.extend(hist / len(timing_vector))  # Normalize

        # Entropy of cache access pattern
        if len(misses) > 0:
            miss_indices = np.where(self.threshold < timing_vector)[0]
            if len(miss_indices) > 1:
                # Spatial distribution of misses
                diffs = np.diff(miss_indices)
                features.append(np.mean(diffs))
                features.append(np.std(diffs))
            else:
                features.append(0.0)
                features.append(0.0)
        else:
            features.append(0.0)
            features.append(0.0)

        # Entropy
        hist_nonzero = hist[hist > 0]
        if len(hist_nonzero) > 0:
            entropy = stats.entropy(hist_nonzero / hist_nonzero.sum())
            features.append(entropy)
        else:
            features.append(0.0)

        return np.array(features, dtype=np.float64)

    def extract_batch(self, timing_matrix: np.ndarray) -> np.ndarray:
        """Extract features from a batch of timing vectors."""
        return np.array([self.extract(row) for row in timing_matrix])

    def feature_names(self) -> List[str]:
        """Return list of feature names."""
        names = [
            "mean", "std", "min", "max", "median",
            "p5", "p25", "p75", "p95",
            "miss_count", "miss_ratio",
        ]
        names.extend([f"hist_{i}" for i in range(self.n_histogram_bins)])
        names.extend(["miss_spatial_mean", "miss_spatial_std", "entropy"])
        return names


class AlgorithmClassifier:
    """ML classifier for DNSSEC algorithm identification."""

    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_extractor = CacheFeatureExtractor()
        self.is_trained = False

    def load_data(self, csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load cache timing data from CSV.

        Expected CSV format:
        - First column: round number
        - Second column: label (algorithm name)
        - Remaining columns: cache timing values

        Returns:
            X: Feature matrix (n_samples, n_features)
            y: Label array (n_samples,)
        """
        print(f"[*] Loading data from {csv_path}")

        df = pd.read_csv(csv_path)
        print(f"[*] Loaded {len(df)} samples, {len(df.columns)} columns")

        # Extract labels
        if "label" in df.columns:
            labels = df["label"].values
            timing_data = df.drop(columns=["round", "label"], errors="ignore")
        else:
            raise ValueError("CSV must contain 'label' column")

        # Extract features from timing vectors
        print(f"[*] Extracting features...")
        X = self.feature_extractor.extract_batch(timing_data.values.astype(np.float64))
        y = labels

        print(f"[*] Feature matrix shape: {X.shape}")
        print(f"[*] Classes: {np.unique(y)}")

        return X, y

    def train(self, X: np.ndarray, y: np.ndarray) -> Dict:
        """
        Train the classifier.

        Returns:
            Dict with training results.
        """
        print(f"\n[*] Training random_forest classifier...")

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)

        self.is_trained = True

        results = {
            "accuracy": accuracy,
            "X_test": X_test_scaled,
            "y_test": y_test,
            "y_pred": y_pred,
            "classification_report": classification_report(
                y_test, y_pred,
                target_names=self.label_encoder.classes_,
            ),
            "confusion_matrix": confusion_matrix(y_test, y_pred),
        }

        print(f"[*] Test accuracy: {accuracy:.4f}")
        print(f"\n{results['classification_report']}")

        return results

    def cross_validate(
        self, X: np.ndarray, y: np.ndarray, cv: int = 5
    ) -> Dict:
        """
        Perform cross-validation.

        Returns:
            Dict with CV results.
        """
        print(f"\n[*] Running {cv}-fold cross-validation...")

        y_encoded = self.label_encoder.fit_transform(y)
        X_scaled = self.scaler.fit_transform(X)

        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
        )
        skf = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)

        scores = cross_val_score(model, X_scaled, y_encoded, cv=skf, scoring="accuracy")

        results = {
            "mean_accuracy": scores.mean(),
            "std_accuracy": scores.std(),
            "fold_scores": scores,
        }

        print(f"[*] CV Accuracy: {scores.mean():.4f} (+/- {scores.std():.4f})")
        print(f"[*] Fold scores: {scores}")

        return results

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict algorithm labels for new data."""
        if not self.is_trained:
            raise RuntimeError("Classifier not trained yet")

        X_scaled = self.scaler.transform(X)
        y_pred = self.model.predict(X_scaled)
        return self.label_encoder.inverse_transform(y_pred)

    def feature_importance(self) -> Optional[pd.DataFrame]:
        """Get feature importance (for tree-based models)."""
        if not self.is_trained:
            raise RuntimeError("Classifier not trained yet")

        if not hasattr(self.model, "feature_importances_"):
            print("[-] Model does not support feature importance")
            return None

        feature_names = self.feature_extractor.feature_names()
        importances = self.model.feature_importances_

        # Pad or truncate to match
        n_features = min(len(feature_names), len(importances))
        df = pd.DataFrame({
            "feature": feature_names[:n_features],
            "importance": importances[:n_features],
        })
        df = df.sort_values("importance", ascending=False)

        return df

    def save(self, path: str):
        """Save trained model to disk."""
        if not self.is_trained:
            raise RuntimeError("Classifier not trained yet")

        with open(path, "wb") as f:
            pickle.dump({
                "model": self.model,
                "scaler": self.scaler,
                "label_encoder": self.label_encoder,
                "model_type": "random_forest",
            }, f)

        print(f"[*] Model saved to {path}")

    def load(self, path: str):
        """Load trained model from disk."""
        with open(path, "rb") as f:
            data = pickle.load(f)

        self.model = data["model"]
        self.scaler = data["scaler"]
        self.label_encoder = data["label_encoder"]
        self.model_type = data["model_type"]
        self.is_trained = True

        print(f"[*] Model loaded from {path}")
        print(f"[*] Type: {self.model_type}")
        print(f"[*] Classes: {self.label_encoder.classes_}")


def run_full_pipeline(
    input_csv: str,
    output_dir: str = "results_cache",
    cv_folds: int = 5,
):
    """Run the full training and evaluation pipeline."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Initialize classifier
    clf = AlgorithmClassifier()

    # Load and prepare data
    X, y = clf.load_data(input_csv)

    # Cross-validation
    cv_results = clf.cross_validate(X, y, cv=cv_folds)

    # Train final model
    train_results = clf.train(X, y)

    # Feature importance
    importance_df = clf.feature_importance()
    if importance_df is not None:
        print("\n--- Top 20 Features ---")
        print(importance_df.head(20).to_string(index=False))

        # Save feature importance
        importance_csv = output_path / "feature_importance.csv"
        importance_df.to_csv(importance_csv, index=False)
        print(f"[*] Feature importance saved to {importance_csv}")

    # Save model
    model_path = output_path / "random_forest_model.pkl"
    clf.save(str(model_path))

    # Save results summary
    summary = {
        "model_type": "random_forest",
        "n_samples": len(X),
        "n_features": X.shape[1],
        "classes": list(clf.label_encoder.classes_),
        "cv_accuracy": cv_results["mean_accuracy"],
        "cv_std": cv_results["std_accuracy"],
        "test_accuracy": train_results["accuracy"],
    }

    summary_df = pd.DataFrame([summary])
    summary_csv = output_path / "classification_summary.csv"
    summary_df.to_csv(summary_csv, index=False)

    # Save classification report
    report_path = output_path / "classification_report.txt"
    with open(report_path, "w") as f:
        f.write("Cache-Based DNSSEC Algorithm Classification\n")
        f.write("=" * 60 + "\n\n")
        f.write("Model: random_forest\n")
        f.write(f"Samples: {len(X)}\n")
        f.write(f"Features: {X.shape[1]}\n")
        f.write(f"Classes: {clf.label_encoder.classes_}\n\n")
        f.write("Cross-Validation Results:\n")
        f.write(f"  Accuracy: {cv_results['mean_accuracy']:.4f} "
                f"(+/- {cv_results['std_accuracy']:.4f})\n\n")
        f.write("Classification Report:\n")
        f.write(train_results["classification_report"])
        f.write("\n\nConfusion Matrix:\n")
        f.write(str(train_results["confusion_matrix"]))

    print(f"\n[*] Results saved to {output_path}")

    return clf, summary


def main():
    parser = argparse.ArgumentParser(
        description="ML classifier for cache-based DNSSEC algorithm identification"
    )
    parser.add_argument(
        "--input", "-i",
        help="Input CSV file with cache timing data"
    )
    parser.add_argument(
        "--train",
        help="Training data CSV"
    )
    parser.add_argument(
        "--test",
        help="Test data CSV (requires --model)"
    )
    parser.add_argument(
        "--model", "-m",
        help="Path to trained model (for evaluation)"
    )
    parser.add_argument(
        "--output", "-o", default="results_cache",
        help="Output directory"
    )
    parser.add_argument(
        "--cv", type=int, default=5,
        help="Number of CV folds"
    )
    parser.add_argument(
        "--threshold", type=int, default=120,
        help="Cache hit/miss threshold (cycles)"
    )

    args = parser.parse_args()

    if args.input:
        # Full pipeline
        run_full_pipeline(
            input_csv=args.input,
            output_dir=args.output,
            cv_folds=args.cv,
        )

    elif args.train and not args.test:
        # Train only
        clf = AlgorithmClassifier()
        X, y = clf.load_data(args.train)
        clf.train(X, y)
        clf.save(args.model or "model.pkl")

    elif args.test and args.model:
        # Evaluate existing model
        clf = AlgorithmClassifier()
        clf.load(args.model)
        X, y = clf.load_data(args.test)
        y_pred = clf.predict(X)
        accuracy = accuracy_score(y, y_pred)
        print(f"Test accuracy: {accuracy:.4f}")
        print(classification_report(y, y_pred))

    elif args.train and args.test:
        # Train and evaluate
        clf = AlgorithmClassifier()
        X_train, y_train = clf.load_data(args.train)
        clf.train(X_train, y_train)

        X_test, y_test = clf.load_data(args.test)
        y_pred = clf.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Test accuracy: {accuracy:.4f}")
        print(classification_report(y_test, y_pred))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
