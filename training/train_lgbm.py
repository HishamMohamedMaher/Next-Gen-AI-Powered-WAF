"""LightGBM feature-based training pipeline for AI-WAF.

Extracts domain-engineered structural and statistical features from HTTP payloads using
the AI-WAF feature_extractor module and trains a LightGBM classifier.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import pickle
import sys
from typing import Any, Dict, Tuple, Union

import numpy as np
import pandas as pd

# Path hack to ensure waf modules can be imported directly when running as a standalone script
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from lightgbm import LGBMClassifier
except ImportError:
    LGBMClassifier = None  # type: ignore[assignment, misc]

from waf import feature_extractor  # noqa: E402

logger = logging.getLogger(__name__)

LGBM_PARAMS: Dict[str, Any] = {
    "n_estimators": 300,
    "max_depth": 6,
    "class_weight": "balanced",
    "random_state": 42,
}


def load_splits(splits_dir: Union[str, Path]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load verified canonical train and validation splits.

    Args:
        splits_dir: Directory containing the canonical manifest and train/val CSVs.

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: (train_df, val_df).
    """
    from training.train_lr import load_splits as load_canonical_splits

    train_df, val_df = load_canonical_splits(splits_dir)
    logger.warning(
        "STRUCTURAL_FEATURES_PENDING: canonical text rows are validated, but "
        "they do not provide the normalized RequestContext required by "
        "waf.feature_extractor.extract"
    )
    return train_df, val_df


def extract_features(df: pd.DataFrame, text_column: str = "payload") -> np.ndarray:
    """Extract domain-engineered features from payload strings using waf.feature_extractor.

    Args:
        df: Input DataFrame containing payload column.
        text_column: Column name containing payload strings.

    Returns:
        np.ndarray: 2D numpy array containing extracted numerical feature vectors.
    """
    pass


def train_lgbm(X_train: np.ndarray, y_train: Any) -> Any:
    """Train a LightGBM classifier on extracted numerical features.

    Args:
        X_train: Matrix of numerical features for training samples.
        y_train: Ground truth target labels.

    Returns:
        LGBMClassifier: Trained LightGBM model.
    """
    if not hasattr(X_train, "shape") or len(X_train.shape) != 2:
        raise ValueError("X_train must be a 2D feature matrix")

    n_samples, n_features = X_train.shape
    if n_samples < 2 or n_features < 1:
        raise ValueError("Training matrix is empty or invalid")

    labels = np.asarray(y_train)
    if labels.ndim != 1:
        raise ValueError("y_train must be one-dimensional")
    if len(labels) != n_samples:
        raise ValueError("Features and labels have different lengths")
    if not np.isin(labels, [0, 1]).all():
        raise ValueError("Labels must contain only binary values 0 and 1")
    if set(labels.tolist()) != {0, 1}:
        raise ValueError("Both benign and attack classes are required")

    try:
        finite = np.isfinite(np.asarray(X_train, dtype=float)).all()
    except (TypeError, ValueError) as exc:
        raise ValueError("Training features must be numeric") from exc
    if not finite:
        raise ValueError("Training features contain NaN or infinity")

    if LGBMClassifier is None:
        raise ImportError(
            "LightGBM is required to train this model; install the project-pinned "
            "lightgbm dependency"
        )

    model = LGBMClassifier(**LGBM_PARAMS)
    model.fit(X_train, labels.astype(int))
    return model


def save_model(model: Any, output_dir: Union[str, Path]) -> None:
    """Validate and save a trained LightGBM model when checksum format is defined.

    Args:
        model: Trained LightGBM model instance.
        output_dir: Destination directory for the model and its integrity metadata.

    Raises:
        RuntimeError: If model validation or the checksum metadata contract blocks saving.
    """
    if LGBMClassifier is None:
        raise RuntimeError(
            "LightGBM is unavailable, so the model type and fitted state "
            "cannot be validated"
        )
    if not isinstance(model, LGBMClassifier):
        raise TypeError("Expected a LightGBM LGBMClassifier model")
    if (
        not hasattr(model, "booster_")
        or not callable(getattr(model, "predict", None))
        or not callable(getattr(model, "predict_proba", None))
    ):
        raise ValueError("LightGBM model is not fitted or lacks prediction methods")

    destination = Path(output_dir)
    artifact = destination / "model_lgbm.pkl"
    checksum_sidecar = destination / "model_lgbm.pkl.sha256"
    if (
        artifact.exists()
        or artifact.is_symlink()
        or checksum_sidecar.exists()
        or checksum_sidecar.is_symlink()
    ):
        raise FileExistsError(
            f"LightGBM artifact or checksum already exists in {destination}"
        )

    raise RuntimeError(
        "LIGHTGBM_CHECKSUM_CONTRACT_PENDING: the LR consumer requires exactly "
        "three entries in checksums.sha256, while the LightGBM consumer only "
        "documents an adjacent .sha256 file without defining its format; "
        "refusing to serialize an artifact with incompatible or ambiguous metadata"
    )


def main() -> None:
    """Parse command line arguments and execute the LightGBM training pipeline."""
    parser = argparse.ArgumentParser(description="AI-WAF LightGBM Training Pipeline")
    parser.add_argument(
        "--splits-dir",
        type=str,
        default="data/splits",
        help="Directory containing train.parquet and val.parquet splits",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models/lgbm",
        help="Directory to save the trained LightGBM model",
    )
    args = parser.parse_args()

    train_df, val_df = load_splits(args.splits_dir)
    X_train = extract_features(train_df)
    y_train = train_df["label"]

    model = train_lgbm(X_train, y_train)
    save_model(model, args.output_dir)


if __name__ == "__main__":
    main()
