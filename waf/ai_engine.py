"""Machine Learning Inference Engine for Threat Detection."""

from __future__ import annotations

import hashlib
import logging
import pickle
from pathlib import Path
from typing import Any, Optional
import numpy as np

from waf.feature_extractor import extract, extract_text_for_tfidf
from waf.models import RequestContext

logger = logging.getLogger("ai_waf.ai_engine")

MODELS_DIR: Path = Path(__file__).resolve().parent.parent / "models"

_vectorizer: Optional[Any] = None
_model_lr: Optional[Any] = None
_calibrator: Optional[Any] = None
_model_lgbm: Optional[Any] = None

def verify_checksum(filepath: Path | str, expected_checksum: Optional[str] = None) -> bool:
    """Verify the SHA-256 integrity checksum of a model file."""
    filepath = Path(filepath)
    if not filepath.exists():
        return False
        
    if not expected_checksum:
        checksum_file = filepath.with_suffix(filepath.suffix + ".sha256")
        if not checksum_file.exists():
            logger.warning(f"No checksum file found for {filepath.name}, skipping verification.")
            return True
        expected_checksum = checksum_file.read_text().strip()

    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            
    return sha256_hash.hexdigest() == expected_checksum

def load_models(models_dir: Optional[Path | str] = None) -> bool:
    """Load serialized model artifacts from disk and verify file integrity."""
    global _vectorizer, _model_lr, _calibrator, _model_lgbm
    
    m_dir = Path(models_dir) if models_dir else MODELS_DIR
    
    models_to_load = {
        "vectorizer": m_dir / "vectorizer.pkl",
        "lr_model": m_dir / "model_lr.pkl",
        "calibrator": m_dir / "calibrator.pkl"
    }

    try:
        for name, path in models_to_load.items():
            if not path.exists():
                logger.warning(f"{path.name} not found. AI detection will fallback to default.")
                continue
                
            if not verify_checksum(path):
                raise RuntimeError(f"Checksum validation failed for {path.name}")
                
            with open(path, "rb") as f:
                model_obj = pickle.load(f)
                
            if name == "vectorizer": _vectorizer = model_obj
            elif name == "lr_model": _model_lr = model_obj
            elif name == "calibrator": _calibrator = model_obj
            
        return _vectorizer is not None and _model_lr is not None
    except Exception as e:
        logger.error(f"Failed to load models: {e}")
        return False

def predict(ctx: RequestContext) -> float:
    """Compute malicious probability score for a request context."""
    if not _vectorizer or not _model_lr:
        return 0.0 # Fail-open if models aren't loaded
        
    try:
        text_data = extract_text_for_tfidf(ctx)
        features = _vectorizer.transform([text_data])
        
        # Linear decision score via _model_lr
        score = _model_lr.predict_proba(features)[0][1]
        
        if _calibrator:
            score = _calibrator.predict_proba(features)[0][1]
            
        return float(score)
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return 0.0

def warmup() -> None:
    """Perform a dry-run inference pass to prime caches and JIT compilers."""
    logger.info("Starting AI Engine warmup...")
    dummy_ctx = RequestContext(
        client_ip="127.0.0.1",
        method="GET",
        path="/warmup",
        query_string="test=1",
        headers={"host": "localhost"},
        body_raw=b"",
        body_fields={}
    )
    predict(dummy_ctx)
    logger.info("AI Engine warmup complete.")