"""Logistic Regression and TF-IDF training pipeline for AI-WAF.

Trains character n-gram TF-IDF vectorizer and Logistic Regression classifier,
calibrates the classifier probabilities via CalibratedClassifierCV, and serializes
models with accompanying SHA-256 integrity checksums.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
from pathlib import Path
import pickle
from typing import Any, Dict, Iterable, Tuple, Union

import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

logger = logging.getLogger(__name__)

TFIDF_PARAMS: Dict[str, Any] = {
    "analyzer": "char",
    "ngram_range": (2, 5),
    "max_features": 200_000,
    "sublinear_tf": True,
}

LR_PARAMS: Dict[str, Any] = {
    "C": 1.0,
    "max_iter": 1000,
    "class_weight": "balanced",
    "random_state": 42,
}


def load_splits(splits_dir: Union[str, Path]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load train and validation partitions from the splits directory.

    Args:
        splits_dir: Directory containing train and val split files.

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: (train_df, val_df).
    """
    import json
    import hashlib

    root = Path(splits_dir)

    if not root.is_dir():
        raise FileNotFoundError(root)

    # Fail closed: raw staging is never accepted as training-ready.
    manifest_file = root / "canonical_manifest.json"

    if not manifest_file.is_file():
        raise RuntimeError(
            "CANONICAL_FEATURES_PENDING: "
            "Missing verified canonical feature manifest"
        )

    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

    required_flags = (
        "training_ready",
        "normalization_applied",
        "canonical_tfidf_generated",
    )

    if not all(manifest.get(key) is True for key in required_flags):
        raise RuntimeError(
            "CANONICAL_FEATURES_PENDING: "
            "Normalization or feature preparation is incomplete"
        )

    # Require the agreed training/serving representation.
    if (
        manifest.get("normalizer")
        != "waf.normalizer.normalize_context"
        or manifest.get("feature_extractor")
        != "waf.feature_extractor.extract_text_for_tfidf"
    ):
        raise RuntimeError(
            "CANONICAL_CONTRACT_MISMATCH: "
            "Training and WAF feature contracts differ"
        )

    datasets = {}

    for name in ("train", "val"):

        path = root / f"srbh_{name}.csv"

        if not path.is_file():
            raise FileNotFoundError(path)

        # Verify the file against its preparation manifest.
        expected_hash = (
            manifest.get("files", {})
            .get(name, {})
            .get("sha256")
        )

        if not isinstance(expected_hash, str):
            raise RuntimeError(
                f"Missing SHA-256 provenance for {name}"
            )

        digest = hashlib.sha256()

        with path.open("rb") as handle:
            for chunk in iter(
                lambda: handle.read(1024 * 1024),
                b""
            ):
                digest.update(chunk)

        if digest.hexdigest() != expected_hash:
            raise RuntimeError(
                f"Dataset checksum mismatch: {name}"
            )

        df = pd.read_csv(
            path,
            dtype=str,
            keep_default_na=False
        )

        required_columns = {
            "payload_tfidf",
            "label",
            "request_group_sha256",
        }

        if (
            df.empty
            or df.columns.duplicated().any()
            or not required_columns.issubset(df.columns)
        ):
            raise ValueError(
                f"Invalid canonical dataset schema: {name}"
            )

        if not df["label"].isin(["0", "1"]).all():
            raise ValueError(
                f"Invalid binary labels: {name}"
            )

        if set(df["label"]) != {"0", "1"}:
            raise ValueError(
                f"Both classes required: {name}"
            )

        if not df["request_group_sha256"].str.fullmatch(
            r"[0-9a-fA-F]{64}"
        ).all():
            raise ValueError(
                f"Invalid request group hashes: {name}"
            )

        if df["request_group_sha256"].duplicated().any():
            raise ValueError(
                f"Duplicate raw request groups: {name}"
            )

        if df["payload_tfidf"].str.strip().eq("").any():
            raise ValueError(
                f"Empty canonical text detected: {name}"
            )

        # Existing training main() expects a column named payload.
        # Replace its in-memory value with CANONICAL text only.
        # The original CSV on disk remains unchanged.
        df["payload"] = df["payload_tfidf"]

        df["label"] = df["label"].astype("int8")

        datasets[name] = df

    train_df = datasets["train"]
    val_df = datasets["val"]

    train_groups = set(train_df["request_group_sha256"])
    val_groups = set(val_df["request_group_sha256"])

    if train_groups & val_groups:
        raise ValueError(
            "DATA_LEAKAGE: Train/validation request groups overlap"
        )

    # Different raw requests may become identical after normalization.
    # Such collisions must be resolved before fitting TF-IDF.
    train_texts = set(train_df["payload_tfidf"])
    val_texts = set(val_df["payload_tfidf"])

    if train_texts & val_texts:
        raise ValueError(
            "DATA_LEAKAGE: Identical canonical text exists "
            "in train and validation"
        )

    return train_df, val_df


def train_tfidf(train_texts: Iterable[str]) -> TfidfVectorizer:
    """Fit character n-gram TF-IDF vectorizer on training text corpus.

    Args:
        train_texts: Collection of training payload strings.

    Returns:
        TfidfVectorizer: Fitted vectorizer configured with TFIDF_PARAMS.
    """
    if isinstance(train_texts, str):
        raise ValueError('Expected a collection of training texts')

    texts = list(train_texts)

    if not texts:
        raise ValueError('Training text collection is empty')

    if any(not isinstance(t, str) or not t.strip() for t in texts):
        raise ValueError('Training texts must be non-empty strings')

    vectorizer = TfidfVectorizer(**TFIDF_PARAMS)
    vectorizer.fit(texts)

    return vectorizer


def train_lr(X_train: Any, y_train: Any) -> LogisticRegression:
    """Train a Logistic Regression classifier on vectorized features.

    Args:
        X_train: Feature matrix of training payloads (sparse or dense).
        y_train: Target binary classification labels.

    Returns:
        LogisticRegression: Trained scikit-learn LogisticRegression model.
    """
    import numpy as np
    from scipy import sparse

    # Validate feature matrix.
    if not hasattr(X_train, "shape") or len(X_train.shape) != 2:
        raise ValueError("X_train must be a 2D feature matrix")

    n_samples, n_features = X_train.shape

    if n_samples < 2 or n_features < 1:
        raise ValueError("Training matrix is empty or invalid")

    # Validate labels.
    labels = np.asarray(y_train)

    if labels.ndim != 1:
        raise ValueError("y_train must be one-dimensional")

    if len(labels) != n_samples:
        raise ValueError("Features and labels have different lengths")

    if not np.isin(labels, [0, 1]).all():
        raise ValueError("Labels must contain only binary values 0 and 1")

    if set(labels.tolist()) != {0, 1}:
        raise ValueError("Both benign and attack classes are required")

    # Reject NaN and infinite feature values.
    if sparse.issparse(X_train):
        finite = np.isfinite(X_train.data).all()
    else:
        finite = np.isfinite(np.asarray(X_train, dtype=float)).all()

    if not finite:
        raise ValueError("Training features contain NaN or infinity")

    # Use the existing project configuration.
    model = LogisticRegression(**LR_PARAMS)

    # Fit on training data only.
    model.fit(X_train, labels.astype(int))

    return model


def calibrate(model: LogisticRegression, X_val: Any, y_val: Any) -> CalibratedClassifierCV:
    """Calibrate model probability estimates on validation data using isotonic or sigmoid calibration.

    Args:
        model: Pre-fitted Logistic Regression model.
        X_val: Feature matrix of validation payloads.
        y_val: Target binary validation labels.

    Returns:
        CalibratedClassifierCV: Calibrated classifier wrapper.
    """
    import numpy as np
    from scipy import sparse
    from sklearn.frozen import FrozenEstimator

    # Validate the fitted Logistic Regression model.
    if not isinstance(model, LogisticRegression):
        raise TypeError("Expected a LogisticRegression model")

    if not hasattr(model, "coef_") or not hasattr(model, "classes_"):
        raise ValueError("Model must be fitted before calibration")

    if not np.array_equal(model.classes_, [0, 1]):
        raise ValueError("Model must contain binary classes 0 and 1")

    # Validate the validation feature matrix.
    if not hasattr(X_val, "shape") or len(X_val.shape) != 2:
        raise ValueError("X_val must be a 2D feature matrix")

    n_samples, n_features = X_val.shape

    if n_samples < 2 or n_features < 1:
        raise ValueError("Validation matrix is empty or invalid")

    if n_features != model.n_features_in_:
        raise ValueError("Validation feature count does not match the model")

    if sparse.issparse(X_val):
        finite = np.isfinite(X_val.data).all()
    else:
        finite = np.isfinite(np.asarray(X_val, dtype=float)).all()

    if not finite:
        raise ValueError("Validation features contain NaN or infinity")

    # Validate binary labels.
    labels = np.asarray(y_val)

    if labels.ndim != 1:
        raise ValueError("y_val must be one-dimensional")

    if len(labels) != n_samples:
        raise ValueError("Features and labels have different lengths")

    if not np.isin(labels, [0, 1]).all():
        raise ValueError("Labels must contain only 0 and 1")

    if set(labels.tolist()) != {0, 1}:
        raise ValueError("Both classes are required for calibration")

    # FrozenEstimator keeps the already-trained model fixed.
    # Fit only the sigmoid probability calibration on validation data.
    calibrator = CalibratedClassifierCV(
        estimator=FrozenEstimator(model),
        method="sigmoid"
    )

    calibrator.fit(X_val, labels.astype(int))

    return calibrator


def save_models(
    vectorizer: TfidfVectorizer,
    model: LogisticRegression,
    calibrator: CalibratedClassifierCV,
    output_dir: Union[str, Path],
) -> None:
    """Save trained vectorizer, model, and calibrator as pickle files with SHA-256 checksums.

    Creates artifacts in output_dir:
    - vectorizer.pkl
    - model.pkl
    - calibrator.pkl
    - checksums.sha256

    Args:
        vectorizer: Fitted TF-IDF vectorizer.
        model: Trained Logistic Regression model.
        calibrator: Calibrated model instance.
        output_dir: Destination directory for serialized model files.
    """
    import tempfile
    import shutil

    if not isinstance(vectorizer, TfidfVectorizer):
        raise TypeError("Expected TfidfVectorizer")

    if not isinstance(model, LogisticRegression):
        raise TypeError("Expected LogisticRegression")

    if not isinstance(calibrator, CalibratedClassifierCV):
        raise TypeError("Expected CalibratedClassifierCV")

    if not hasattr(vectorizer, "vocabulary_"):
        raise ValueError("Vectorizer is not fitted")

    if not hasattr(model, "coef_"):
        raise ValueError("Logistic Regression is not fitted")

    if not hasattr(calibrator, "calibrated_classifiers_"):
        raise ValueError("Calibrator is not fitted")

    destination = Path(output_dir)

    if destination.exists() or destination.is_symlink():
        raise FileExistsError(
            f"Model directory already exists: {destination}"
        )

    destination.parent.mkdir(parents=True, exist_ok=True)

    objects = {
        "vectorizer.pkl": vectorizer,
        "model.pkl": model,
        "calibrator.pkl": calibrator,
    }

    stage = Path(
        tempfile.mkdtemp(
            prefix=".model_stage_",
            dir=destination.parent
        )
    )

    try:
        checksums = []

        for filename, obj in objects.items():

            path = stage / filename

            with path.open("xb") as f:
                pickle.dump(
                    obj,
                    f,
                    protocol=pickle.HIGHEST_PROTOCOL
                )

            digest = hashlib.sha256()

            with path.open("rb") as f:
                for block in iter(
                    lambda: f.read(1024 * 1024),
                    b""
                ):
                    digest.update(block)

            checksums.append(
                f"{digest.hexdigest()}  {filename}"
            )

        checksum_file = stage / "checksums.sha256"

        checksum_file.write_text(
            "\n".join(checksums) + "\n",
            encoding="utf-8"
        )

        # Verify all files before publishing.
        for line in checksum_file.read_text(
            encoding="utf-8"
        ).splitlines():

            expected, filename = line.split("  ", 1)

            actual = hashlib.sha256(
                (stage / filename).read_bytes()
            ).hexdigest()

            if actual != expected:
                raise RuntimeError(
                    f"SHA-256 mismatch: {filename}"
                )

        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)

        stage.rename(destination)

    finally:
        if stage.exists():
            shutil.rmtree(stage)

    return None


def main() -> None:
    """Parse command line arguments and execute the Logistic Regression training pipeline."""
    parser = argparse.ArgumentParser(description="AI-WAF Logistic Regression Training Pipeline")
    parser.add_argument(
        "--splits-dir",
        type=str,
        default="data/splits",
        help="Directory containing train.parquet and val.parquet",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models/lr",
        help="Directory to save trained models and checksums",
    )
    args = parser.parse_args()

    train_df, val_df = load_splits(args.splits_dir)
    vectorizer = train_tfidf(train_df["payload"])
    X_train = vectorizer.transform(train_df["payload"])
    y_train = train_df["label"]

    model = train_lr(X_train, y_train)

    X_val = vectorizer.transform(val_df["payload"])
    y_val = val_df["label"]
    calibrator = calibrate(model, X_val, y_val)

    save_models(vectorizer, model, calibrator, args.output_dir)


if __name__ == "__main__":
    main()
