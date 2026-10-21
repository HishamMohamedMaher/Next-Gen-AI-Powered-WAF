"""Probability calibration utilities and error metrics for AI-WAF.

Provides functions to calibrate machine learning models (isotonic or sigmoid scaling),
calculate calibration quality metrics (Expected Calibration Error, Maximum Calibration Error, Brier Score),
and render reliability diagrams.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Union

import matplotlib.pyplot as plt
import numpy as np
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import brier_score_loss

logger = logging.getLogger(__name__)


def calibrate_model(
    model: Any,
    X_val: Any,
    y_val: Any,
    method: str = "isotonic",
) -> CalibratedClassifierCV:
    """Calibrate probabilities of an existing trained model using validation data.

    Args:
        model: Base classifier instance (scikit-learn compatible).
        X_val: Validation feature matrix.
        y_val: Validation ground truth target labels.
        method: Calibration technique ('isotonic' or 'sigmoid').

    Returns:
        CalibratedClassifierCV: Calibrated classifier model fitted on validation data.
    """
    from sklearn.frozen import FrozenEstimator
    from sklearn.utils.validation import check_is_fitted
    from scipy import sparse

    if method not in ("isotonic", "sigmoid"):
        raise ValueError(
            "Calibration method must be isotonic or sigmoid"
        )

    if not hasattr(model, "fit") or not hasattr(model, "predict_proba"):
        raise TypeError(
            "Model must be a scikit-learn compatible classifier"
        )

    if not hasattr(model, "classes_"):
        raise ValueError("Base model must be fitted")

    check_is_fitted(model)

    if set(model.classes_) != {0, 1}:
        raise ValueError(
            "Base model must have binary classes 0 and 1"
        )

    if not hasattr(X_val, "shape") or len(X_val.shape) != 2:
        raise ValueError("X_val must be a 2D feature matrix")

    n_samples, n_features = X_val.shape

    if n_samples < 2 or n_features < 1:
        raise ValueError("Invalid validation matrix")

    if (
        hasattr(model, "n_features_in_")
        and n_features != model.n_features_in_
    ):
        raise ValueError("Validation feature count mismatch")

    if sparse.issparse(X_val):
        finite = np.isfinite(X_val.data).all()
    else:
        finite = np.isfinite(
            np.asarray(X_val, dtype=float)
        ).all()

    if not finite:
        raise ValueError(
            "Validation features contain NaN or infinity"
        )

    labels = np.asarray(y_val)

    if labels.ndim != 1:
        raise ValueError("y_val must be one-dimensional")

    if len(labels) != n_samples:
        raise ValueError("Features and labels length mismatch")

    if not np.isin(labels, [0, 1]).all():
        raise ValueError("Labels must be binary 0 and 1")

    if set(labels.tolist()) != {0, 1}:
        raise ValueError(
            "Both classes are required for calibration"
        )

    # Freeze the pretrained model.
    # Only the probability mapping is fitted on validation data.
    calibrator = CalibratedClassifierCV(
        estimator=FrozenEstimator(model),
        method=method
    )

    calibrator.fit(X_val, labels.astype(int))

    return calibrator


def evaluate_calibration(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    n_bins: int = 10,
) -> Dict[str, float]:
    """Compute probability calibration error metrics: ECE, MCE, and Brier Score.

    Args:
        y_true: True binary target labels (0 or 1).
        y_proba: Predicted probability of positive class (values in [0, 1]).
        n_bins: Number of confidence bins to evaluate.

    Returns:
        Dict[str, float]: Dictionary containing:
            - 'ece': Expected Calibration Error
            - 'mce': Maximum Calibration Error
            - 'brier_score': Mean squared difference between predicted probabilities and outcomes
    """
    # Validate number of bins.
    if (
        isinstance(n_bins, bool)
        or not isinstance(n_bins, (int, np.integer))
        or n_bins < 1
    ):
        raise ValueError("n_bins must be a positive integer")

    # Convert inputs to NumPy arrays.
    labels = np.asarray(y_true)

    try:
        probabilities = np.asarray(
            y_proba,
            dtype=np.float64
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Probabilities must be numeric"
        ) from exc

    # Validate input dimensions.
    if labels.ndim != 1 or probabilities.ndim != 1:
        raise ValueError(
            "Labels and probabilities must be 1D arrays"
        )

    if len(labels) == 0:
        raise ValueError("Evaluation data cannot be empty")

    if len(labels) != len(probabilities):
        raise ValueError(
            "Labels and probabilities length mismatch"
        )

    # Validate binary labels.
    if not np.isin(labels, [0, 1]).all():
        raise ValueError(
            "Labels must contain only 0 and 1"
        )

    # Validate predicted probabilities.
    if not np.isfinite(probabilities).all():
        raise ValueError(
            "Probabilities contain NaN or infinity"
        )

    if (
        (probabilities < 0).any()
        or (probabilities > 1).any()
    ):
        raise ValueError(
            "Probabilities must be between 0 and 1"
        )

    labels = labels.astype(np.float64)

    # ============================================================
    # ECE AND MCE
    # Equal-width probability bins in [0, 1].
    # A probability of exactly 1 belongs to the last bin.
    # ============================================================

    bin_indices = np.minimum(
        (probabilities * n_bins).astype(np.int64),
        n_bins - 1
    )

    counts = np.bincount(
        bin_indices,
        minlength=n_bins
    ).astype(np.float64)

    positive_sums = np.bincount(
        bin_indices,
        weights=labels,
        minlength=n_bins
    )

    confidence_sums = np.bincount(
        bin_indices,
        weights=probabilities,
        minlength=n_bins
    )

    # Ignore empty bins.
    valid_bins = counts > 0

    bin_accuracy = (
        positive_sums[valid_bins]
        / counts[valid_bins]
    )

    bin_confidence = (
        confidence_sums[valid_bins]
        / counts[valid_bins]
    )

    bin_errors = np.abs(
        bin_accuracy - bin_confidence
    )

    # Expected Calibration Error.
    bin_weights = (
        counts[valid_bins] / len(labels)
    )

    ece = np.sum(
        bin_weights * bin_errors
    )

    # Maximum Calibration Error.
    mce = np.max(bin_errors)

    # Brier Score.
    brier = brier_score_loss(
        labels,
        probabilities
    )

    return {
        "ece": float(ece),
        "mce": float(mce),
        "brier_score": float(brier)
    }


def plot_reliability_diagram(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    output_path: Union[str, Path],
    n_bins: int = 10,
    title: str = "Reliability Diagram",
) -> None:
    """Generate and save a reliability diagram showing empirical accuracy per probability bin.

    Args:
        y_true: Ground truth binary target labels.
        y_proba: Predicted confidence scores for positive class.
        output_path: Destination file path for the plot.
        n_bins: Discretization bin count.
        title: Plot title.
    """
    # Validate bin count.
    if (
        isinstance(n_bins, bool)
        or not isinstance(n_bins, (int, np.integer))
        or not 1 <= n_bins <= 10000
    ):
        raise ValueError(
            "n_bins must be an integer between 1 and 10000"
        )

    if not isinstance(title, str) or not title.strip():
        raise ValueError("title must be nonempty text")

    # Validate evaluation arrays.
    labels = np.asarray(y_true)

    try:
        probabilities = np.asarray(
            y_proba,
            dtype=np.float64
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "y_proba must contain numeric probabilities"
        ) from exc

    if (
        labels.ndim != 1
        or probabilities.ndim != 1
        or len(labels) == 0
    ):
        raise ValueError(
            "Expected nonempty one-dimensional input arrays"
        )

    if len(labels) != len(probabilities):
        raise ValueError(
            "Labels/probabilities length mismatch"
        )

    if not np.isin(labels, [0, 1]).all():
        raise ValueError(
            "Labels must be binary: 0 or 1"
        )

    if (
        not np.isfinite(probabilities).all()
        or ((probabilities < 0) | (probabilities > 1)).any()
    ):
        raise ValueError(
            "Probabilities must be finite and between 0 and 1"
        )

    # Validate output destination.
    path = Path(output_path)

    if path.suffix.lower() != ".png":
        raise ValueError("Expected a .png output_path")

    if path.exists() or path.is_symlink():
        raise FileExistsError(
            f"Refusing to overwrite existing diagram: {path}"
        )

    # ============================================================
    # CALCULATE RELIABILITY BINS
    # Use the same binning convention as evaluate_calibration().
    # ============================================================

    indices = np.minimum(
        (probabilities * n_bins).astype(np.int64),
        n_bins - 1
    )

    counts = np.bincount(
        indices,
        minlength=n_bins
    )

    positive = np.bincount(
        indices,
        weights=labels.astype(float),
        minlength=n_bins
    )

    confidence = np.bincount(
        indices,
        weights=probabilities,
        minlength=n_bins
    )

    nonempty = counts > 0

    mean_true = (
        positive[nonempty]
        / counts[nonempty]
    )

    mean_predicted = (
        confidence[nonempty]
        / counts[nonempty]
    )

    # ============================================================
    # CREATE RELIABILITY DIAGRAM
    # ============================================================

    # This helper saves a file and is also used in headless CLI runs.
    plt.switch_backend("Agg")
    fig, ax = plt.subplots(
        figsize=(6.5, 5.5)
    )

    try:

        # Ideal calibration reference.
        ax.plot(
            [0, 1],
            [0, 1],
            "--",
            label="Perfect calibration"
        )

        # Actual observed calibration.
        ax.plot(
            mean_predicted,
            mean_true,
            marker="o",
            label="Observed calibration"
        )

        ax.set(
            xlabel="Mean predicted attack probability",
            ylabel="Observed attack fraction",
            title=title,
            xlim=(0, 1),
            ylim=(0, 1)
        )

        ax.grid(
            True,
            alpha=0.25
        )

        ax.legend()

        fig.tight_layout()

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        # Exclusive creation: existing images are never overwritten.
        with path.open("xb") as file:
            fig.savefig(
                file,
                format="png",
                dpi=160,
                bbox_inches="tight"
            )

    finally:
        plt.close(fig)

    return None
