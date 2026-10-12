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
    """Load train and validation splits from disk.

    Args:
        splits_dir: Directory containing train.parquet and val.parquet splits.

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: (train_df, val_df).
    """
    pass


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
    pass


def save_model(model: Any, output_dir: Union[str, Path]) -> None:
    """Serialize and save the trained LightGBM model to disk.

    Args:
        model: Trained LightGBM model instance.
        output_dir: Destination directory where model will be saved.
    """
    pass


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
