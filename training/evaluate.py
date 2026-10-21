"""Model evaluation and benchmarking suite for AI-WAF classifiers.

Provides utilities for evaluating classification metrics (precision, recall, F1, ROC-AUC),
generating confusion matrix plots, reliability/calibration curves, and rendering markdown reports.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any, Dict, Union

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score

logger = logging.getLogger(__name__)


def load_test_data(splits_dir: Union[str, Path]) -> pd.DataFrame:
    """Load test dataset partition from disk.

    Args:
        splits_dir: Directory containing test split file (e.g. test.parquet or test.csv).

    Returns:
        pd.DataFrame: DataFrame containing test payloads and ground-truth labels.
    """
    import json, hashlib
    root=Path(splits_dir)
    manifest_path=root/'canonical_manifest.json'
    if not manifest_path.is_file():
        raise RuntimeError('FINAL_TEST_LOCKED: missing verified canonical manifest')
    manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
    if not all(manifest.get(flag) is True for flag in ('training_ready','normalization_applied','canonical_tfidf_generated','final_evaluation_authorized')):
        raise RuntimeError('FINAL_TEST_LOCKED: final canonical evaluation not authorized')
    if (manifest.get('normalizer')!='waf.normalizer.normalize_context' or
        manifest.get('feature_extractor')!='waf.feature_extractor.extract_text_for_tfidf'):
        raise RuntimeError('FINAL_TEST_LOCKED: text feature contract mismatch')
    p=root/'srbh_test.csv'
    if not p.is_file():raise FileNotFoundError(p)
    expected=manifest.get('files',{}).get('test',{}).get('sha256')
    if not isinstance(expected,str) or len(expected)!=64:
        raise RuntimeError('FINAL_TEST_LOCKED: missing test checksum')
    hash_=hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): hash_.update(chunk)
    if hash_.hexdigest()!=expected:raise RuntimeError('Test checksum mismatch')
    df=pd.read_csv(p,dtype=str,keep_default_na=False)
    cols={'payload_tfidf','label','request_group_sha256'}
    if df.empty or df.columns.duplicated().any() or not cols.issubset(df.columns):raise ValueError('Invalid test schema')
    if not df['label'].isin(['0','1']).all() or set(df['label'])!={'0','1'}:raise ValueError('Invalid test labels')
    if not df['request_group_sha256'].str.fullmatch(r'[0-9a-fA-F]{64}').all():raise ValueError('Invalid test group hash')
    if df['request_group_sha256'].duplicated().any():raise ValueError('Duplicate test groups')
    if df['payload_tfidf'].str.strip().eq('').any():raise ValueError('Empty canonical test text')
    df['payload']=df['payload_tfidf']
    df['label']=df['label'].astype('int8')
    return df


def load_models(models_dir: Union[str, Path]) -> Dict[str, Any]:
    """Load trained models and vectorizers from model directory.

    Args:
        models_dir: Directory containing serialized model artifacts.

    Returns:
        Dict[str, Any]: Dictionary mapping model identifiers to loaded model objects.
    """
    import hashlib,pickle
    root=Path(models_dir)
    if not root.is_dir():raise FileNotFoundError(root)
    required={'vectorizer.pkl','model.pkl','calibrator.pkl'}
    check=root/'checksums.sha256'
    if not check.is_file():raise RuntimeError('Missing model checksums')
    checks={}
    for line in check.read_text(encoding='utf-8').splitlines():
        sha,sep,name=line.partition('  ')
        if not sep or len(sha)!=64 or any(ch not in '0123456789abcdef' for ch in sha.lower()):
            raise ValueError('Invalid checksum format')
        if name in checks:raise ValueError('Duplicate checksum entry')
        checks[name]=sha.lower()
    if set(checks)!=required:raise ValueError('Unexpected or missing artifact checksums')
    for name in sorted(required):
        p=root/name
        if not p.is_file() or p.is_symlink():raise FileNotFoundError(p)
        digest=hashlib.sha256()
        with p.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
        if digest.hexdigest()!=checks[name]:raise RuntimeError('Model checksum mismatch: '+name)
    # IMPORTANT: Only load trusted artifacts created by this team. A matching SHA alone is NOT proof of authenticity.
    objects={}
    for name,key in [('vectorizer.pkl','vectorizer'),('model.pkl','model'),('calibrator.pkl','calibrator')]:
        with (root/name).open('rb') as f:objects[key]=pickle.load(f)
    if not hasattr(objects['vectorizer'],'transform') or not hasattr(objects['calibrator'],'predict_proba'):
        raise TypeError('Invalid trained artifact interface')
    return objects


def evaluate_model(
    model_name: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
) -> Dict[str, Any]:
    """Calculate and display evaluation metrics for a given model.

    Computes classification report, confusion matrix, macro F1 score, and returns metric summary.

    Args:
        model_name: Identifier name of the evaluated model.
        y_true: Ground truth binary labels.
        y_pred: Predicted class labels.
        y_proba: Predicted class probability scores.

    Returns:
        Dict[str, Any]: Summary dictionary containing evaluation metric values.
    """
    from sklearn.metrics import accuracy_score,precision_score,recall_score,roc_auc_score
    if not isinstance(model_name,str) or not model_name.strip():raise ValueError('Invalid model name')
    y=np.asarray(y_true); p=np.asarray(y_pred); prob=np.asarray(y_proba,dtype=float)
    if any(a.ndim!=1 for a in (y,p,prob)) or len(y)==0 or len(y)!=len(p) or len(y)!=len(prob):
        raise ValueError('Labels, predictions, probabilities must be equal-length 1D arrays')
    if not np.isin(y,[0,1]).all() or not np.isin(p,[0,1]).all():raise ValueError('Binary labels required')
    if not np.isfinite(prob).all() or (prob<0).any() or (prob>1).any():raise ValueError('Invalid probabilities')
    cm=confusion_matrix(y,p,labels=[0,1])
    return {
        'model_name':model_name,
        'accuracy':float(accuracy_score(y,p)),
        'precision_macro':float(precision_score(y,p,average='macro',zero_division=0)),
        'recall_macro':float(recall_score(y,p,average='macro',zero_division=0)),
        'f1_macro':float(f1_score(y,p,average='macro',zero_division=0)),
        'roc_auc':float(roc_auc_score(y,prob)) if len(np.unique(y))==2 else None,
        'confusion_matrix':cm.tolist(),
        'classification_report':classification_report(y,p,labels=[0,1],target_names=['benign','attack'],zero_division=0,output_dict=True),
        'support':int(len(y)),
    }


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    output_path: Union[str, Path],
    labels: Union[list[str], None] = None,
) -> None:
    """Render and save a confusion matrix plot to an image file.

    Args:
        y_true: Ground truth binary labels.
        y_pred: Predicted class labels.
        output_path: Destination file path for the rendered image.
        labels: Optional class label names for axis display.
    """
    import tempfile
    true=np.asarray(y_true);pred=np.asarray(y_pred)
    if true.ndim!=1 or pred.ndim!=1 or len(true)==0 or len(true)!=len(pred):raise ValueError('Invalid confusion matrix inputs')
    if not np.isin(true,[0,1]).all() or not np.isin(pred,[0,1]).all():raise ValueError('Binary labels required')
    if labels is not None and (len(labels)!=2 or not all(isinstance(v,str) for v in labels)):
        raise ValueError('Expected two label names')
    display_names=labels if labels is not None else ['Benign','Attack']
    p=Path(output_path)
    if p.suffix.lower()!='.png':raise ValueError('PNG required')
    if p.exists() or p.is_symlink():raise FileExistsError(p)
    cm=confusion_matrix(true,pred,labels=[0,1]);fig,ax=plt.subplots(figsize=(5.5,4.5))
    try:
        ax.imshow(cm)
        ax.set_xticks([0,1],labels=display_names)
        ax.set_yticks([0,1],labels=display_names)
        ax.set(xlabel='Predicted',ylabel='Actual',title='Confusion Matrix')
        for i in (0,1):
            for j in (0,1):ax.text(j,i,str(cm[i,j]),ha='center',va='center')
        fig.tight_layout();p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('xb') as f:fig.savefig(f,format='png',dpi=150)
    finally:plt.close(fig)
    return None


def plot_calibration_curve(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    output_path: Union[str, Path],
    n_bins: int = 10,
) -> None:
    """Compute and plot a calibration reliability curve comparing confidence to accuracy.

    Args:
        y_true: Ground truth binary labels.
        y_proba: Predicted probability scores for the positive class.
        output_path: Destination file path for the plot image.
        n_bins: Number of discretization bins for probability partitioning.
    """
    from training.calibrate import plot_reliability_diagram
    return plot_reliability_diagram(y_true,y_proba,output_path,n_bins=n_bins,title='Model Calibration Curve')


def generate_report(results: Dict[str, Any], output_path: Union[str, Path]) -> None:
    """Generate and write a comprehensive markdown evaluation report.

    Args:
        results: Dictionary containing metric summaries for evaluated models.
        output_path: Destination file path for the generated markdown report.
    """
    import json
    if not isinstance(results,dict) or not results:raise ValueError('Expected nonempty results dictionary')
    p=Path(output_path)
    if p.suffix.lower()!='.md':raise ValueError('Expected Markdown output')
    if p.exists() or p.is_symlink():raise FileExistsError(p)
    def clean(s):return str(s).replace('|','/').replace('\n',' ')
    lines=['# WAF Model Evaluation','', '**Note:** Include provenance, dataset version, evaluation date and locked-test policy before academic submission.','','| Model | Samples | Accuracy | Macro F1 | ROC-AUC |','|---|---:|---:|---:|---:|']
    for key,res in sorted(results.items()):
        if not isinstance(res,dict) or not {'accuracy','f1_macro','support'}.issubset(res):raise ValueError('Invalid evaluation result entry')
        auc=res.get('roc_auc')
        auc_text=f"{float(auc):.4f}" if auc is not None else "N/A"
        lines.append(f"| {clean(key)} | {int(res['support'])} | {float(res['accuracy']):.4f} | {float(res['f1_macro']):.4f} | {auc_text} |")
    lines.extend(['','## Full JSON metrics','```json',json.dumps(results,indent=2,ensure_ascii=False,default=str),'```',''])
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('x',encoding='utf-8') as f:f.write('\n'.join(lines))
    return None


def main() -> None:
    """Parse command line arguments and execute the evaluation suite."""
    parser = argparse.ArgumentParser(description="AI-WAF Model Evaluation & Reporting Suite")
    parser.add_argument(
        "--splits-dir",
        type=str,
        default="data/splits",
        help="Directory containing test dataset split",
    )
    parser.add_argument(
        "--models-dir",
        type=str,
        default="models",
        help="Directory containing trained model artifacts",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Directory to save evaluation reports and plots",
    )
    args = parser.parse_args()

    models = load_models(args.models_dir)
    if not {"vectorizer", "model", "calibrator"}.issubset(models):
        raise RuntimeError("Verified LR model artifacts are incomplete")

    # The decision threshold is frozen in the project configuration. Do not
    # derive or tune it from the held-out evaluation partition.
    import yaml
    config_path = Path("config.yaml")
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeError(
            "EVALUATION_THRESHOLD_LOCKED: cannot read frozen config.yaml threshold"
        ) from exc

    ai_config = config.get("ai") if isinstance(config, dict) else None
    threshold = ai_config.get("threshold_block") if isinstance(ai_config, dict) else None
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not np.isfinite(threshold)
        or not 0.0 <= threshold <= 1.0
    ):
        raise RuntimeError(
            "EVALUATION_THRESHOLD_LOCKED: config.yaml must define ai.threshold_block in [0, 1]"
        )
    threshold = float(threshold)

    # load_test_data enforces the final_evaluation_authorized manifest gate
    # before it opens the held-out split.
    test_df = load_test_data(args.splits_dir)
    vectorizer = models["vectorizer"]
    calibrator = models["calibrator"]
    if not callable(getattr(vectorizer, "transform", None)):
        raise TypeError("Verified vectorizer does not support transform")
    if not callable(getattr(calibrator, "predict_proba", None)):
        raise TypeError("Verified calibrator does not support predict_proba")

    classes = np.asarray(getattr(calibrator, "classes_", []))
    positive_class = np.flatnonzero(classes == 1)
    if classes.shape != (2,) or set(classes.tolist()) != {0, 1} or len(positive_class) != 1:
        raise ValueError("Calibrator must expose fitted binary classes [0, 1]")

    X_test = vectorizer.transform(test_df["payload"])
    probabilities = np.asarray(calibrator.predict_proba(X_test), dtype=float)
    if probabilities.shape != (len(test_df), 2):
        raise ValueError("Calibrator returned an invalid probability matrix")
    if (
        not np.isfinite(probabilities).all()
        or (probabilities < 0.0).any()
        or (probabilities > 1.0).any()
        or not np.allclose(probabilities.sum(axis=1), 1.0, atol=1e-6)
    ):
        raise ValueError("Calibrator returned invalid class probabilities")

    y_true = test_df["label"].to_numpy(dtype=int)
    y_proba = probabilities[:, positive_class[0]]
    y_pred = (y_proba >= threshold).astype(int)

    results = evaluate_model(
        "calibrated_logistic_regression",
        y_true,
        y_pred,
        y_proba,
    )
    from training.calibrate import evaluate_calibration
    results["threshold"] = threshold
    results["calibration"] = evaluate_calibration(y_true, y_proba)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Evaluation runs in CLI/headless environments; neither plot is displayed.
    plt.switch_backend("Agg")
    plot_confusion_matrix(
        y_true,
        y_pred,
        output_dir / "confusion_matrix.png",
        labels=["Benign", "Attack"],
    )
    plot_calibration_curve(
        y_true,
        y_proba,
        output_dir / "reliability_diagram.png",
    )

    import json
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
