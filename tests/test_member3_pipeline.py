import asyncio
from collections import OrderedDict
import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZipFile

import numpy as np
import pandas as pd
import pytest
from fastapi import Request

from training.clean_data import _normalized_request, scan_mislabeled
from training.evaluate import _evaluate_partition, load_models, load_test_data
from training.prepare_features import save_splits
from training.train_lr import calibrate, load_splits, save_models, train_lr, train_tfidf
from training.week1_staging import prepare_canonical_if_ready, prepare_raw_staging
from waf import ai_engine, detector, signatures
from waf.context import build_context
from waf.feature_extractor import FEATURE_NAMES, _shannon_entropy, extract, extract_text_for_tfidf
from waf.models import Layer, RequestContext
from waf.normalizer import normalize_context


def _records(rows):
    return pd.DataFrame([
        {"payload": payload, "label": label, "content_type": content_type,
         "request_group_sha256": hashlib.sha256(payload.encode()).hexdigest()}
        for payload, label, content_type in rows
    ])


def test_raw_staging_keeps_conflicting_records_and_verifies_sources(tmp_path):
    rows = [
        {"request_http_method": "GET", "request_http_request": f"/sample/{label}/{n}",
         "request_body": "", "000 - Normal": 1 - label, "11 - Test label": label}
        for label in (0, 1) for n in range(30)
    ]
    rows.extend([
        {"request_http_method": "GET", "request_http_request": "/needs-review",
         "request_body": "", "000 - Normal": 1 - label, "11 - Test label": label}
        for label in (0, 1)
    ])
    source = tmp_path / "srbh.csv"
    pd.DataFrame(rows).to_csv(source, index=False)
    archive = tmp_path / "http.zip"
    with ZipFile(archive, "w") as zipped:
        zipped.writestr("payload_train.csv", "payload,label\nplain,norm\n")
    stage = tmp_path / "stage"
    report = prepare_raw_staging(source, archive, stage)
    assert report["quarantined_original_rows"] == 2
    assert report["unique_safe_srbh_rows"] == 60
    assert report["sha256_input"]["srbh_csv"] == hashlib.sha256(source.read_bytes()).hexdigest()
    file = stage / "quarantined_raw_records.csv"
    assert report["sha256_output"][file.name] == hashlib.sha256(file.read_bytes()).hexdigest()
    assert set(pd.read_csv(file)["label"]) == {0, 1}


def test_context_and_features_match_runtime():
    async def receive():
        return {"type": "http.request", "body": b'a=1&a=2&b=hello', "more_body": False}

    request = Request(
        {"type": "http", "method": "POST", "path": "/Fruits Shelf", "query_string": b"q=A%20B",
         "headers": [(b"content-type", b"application/x-www-form-urlencoded"), (b"cookie", b"secret")]},
        receive,
    )

    async def compare():
        runtime = normalize_context(await build_context(request))
        candidate = await _normalized_request(
            "POST /Fruits%20Shelf?q=A%20B HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\nCookie: secret\r\n\r\na=1&a=2&b=hello"
        )
        assert candidate.body_fields == {"a": "1,2", "b": "hello"}
        text = extract_text_for_tfidf(candidate)
        assert text == extract_text_for_tfidf(runtime)
        assert "secret" not in text
        features = extract(candidate)
        assert features.shape == (len(FEATURE_NAMES),) == (12,)
        assert np.isfinite(features).all()
        assert _shannon_entropy("aabb") == pytest.approx(1.0)

    asyncio.run(compare())


def test_signature_review_uses_normalized_context(monkeypatch):
    def scan(ctx):
        assert isinstance(ctx, RequestContext)
        assert ctx.path_normalized == "/review"
        return SimpleNamespace(rule_id="test-rule")

    monkeypatch.setattr(signatures, "scan", scan)
    frame = pd.DataFrame({"payload": ["GET /Review", "GET /other"], "label": [0, 1]}, index=[7, 7])
    usable, review = scan_mislabeled(frame)
    assert usable.label.tolist() == [1]
    assert review.label.tolist() == [0]


def test_canonical_quarantine_and_held_out_access_guard(tmp_path, monkeypatch):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "week1_manifest.json").write_text(json.dumps({"stage": "RAW_PRENORMALIZATION_ONLY"}))
    train = _records([("GET /friendly", 0, ""), ("GET /train", 1, ""),
                      ("GET /Friendly", 0, ""), ("GET /shared", 1, ""),
                      ("POST /unknown\nfield=value", 0, ""), ("GET /review", 0, "")])
    val = _records([("GET /garden", 0, ""), ("GET /val", 1, ""), ("GET /Shared", 1, "")])
    dummy = _records([("GET /fixture-one", 0, ""), ("GET /fixture-two", 1, "")])
    save_splits(train, val, dummy, raw / "splits")
    open_file = Path.open

    def guarded_open(path, *args, **kwargs):
        assert "test" not in path.name, "Held-out file was opened"
        return open_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr(signatures, "scan", lambda ctx: SimpleNamespace(rule_id="review")
                        if ctx.path_normalized == "/review" else None)
    output = tmp_path / "canonical"
    prepare_canonical_if_ready(raw, output)
    manifest = json.loads((output / "canonical_manifest.json").read_text())
    assert not manifest["training_ready"] and not manifest["normalization_approved"]
    assert not manifest["final_evaluation_authorized"]
    assert set(manifest["files"]) == {"train", "val", "quarantine"}
    assert manifest["quarantine_counts"] == {
        "benign_signature_match:review": 1, "cross_partition_canonical_collision": 2,
        "duplicate_canonical_text": 1, "unrepresentable_request": 1,
    }
    for name in ("train", "val", "quarantine"):
        item = manifest["files"][name]
        assert item["sha256"] == hashlib.sha256((output / item["path"]).read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="CANONICAL_FEATURES_PENDING"):
        load_splits(output)
    with pytest.raises(RuntimeError, match="FINAL_TEST_LOCKED"):
        load_test_data(output)
    (raw / "splits" / "srbh_train_raw.csv").write_text("corrupt")
    with pytest.raises(ValueError, match="Raw split checksum mismatch"):
        prepare_canonical_if_ready(raw, tmp_path / "other")


def test_model_integrity_calibration_inference_and_diagnostic_figures(tmp_path, monkeypatch):
    def context(path):
        return normalize_context(RequestContext(path=path))

    train = [context(f"/orchard/item/{i}") for i in range(4)]
    train += [context(f"/warehouse/product/{i}") for i in range(4)]
    train_texts = [extract_text_for_tfidf(ctx) for ctx in train]
    labels = np.array([0] * 4 + [1] * 4)
    val_texts = [extract_text_for_tfidf(context(path)) for path in
                 ["/orchard/shop", "/orchard/fruit", "/warehouse/desk", "/warehouse/stock"]]
    val_labels = np.array([0, 0, 1, 1])
    vectorizer = train_tfidf(train_texts)
    assert vectorizer.analyzer == "char"
    assert vectorizer.ngram_range == (2, 5) and vectorizer.max_features == 200_000
    assert vectorizer.sublinear_tf
    model = train_lr(vectorizer.transform(train_texts), labels)
    assert model.class_weight == "balanced"
    val_features = vectorizer.transform(val_texts)
    with pytest.raises(ValueError, match="Both classes"):
        calibrate(model, val_features, np.zeros(len(val_texts)))
    coefficients = model.coef_.copy()
    calibrator = calibrate(model, val_features, val_labels)
    np.testing.assert_array_equal(model.coef_, coefficients)
    output = tmp_path / "export"
    save_models(vectorizer, model, calibrator, output)
    models = load_models(output)
    expected = calibrator.predict_proba(val_features)
    np.testing.assert_allclose(models["calibrator"].predict_proba(val_features), expected)
    np.testing.assert_allclose(expected.sum(axis=1), 1.0)

    frame = pd.DataFrame({"payload": val_texts, "label": val_labels})
    reports = tmp_path / "reports"
    result = _evaluate_partition(models, frame, 0.5, reports, "calibration_validation_diagnostics")
    assert result["evaluation_kind"] == "calibration_validation_diagnostics"
    assert result["support"] == 4 and result["roc_auc"] == pytest.approx(1.0)
    assert result["false_positive_rate"] == 0 and result["false_negative_rate"] == 0
    assert 0 <= result["calibration"]["brier_score"] <= 1
    assert result["inference_latency"]["samples"] == 4
    assert {path.name for path in reports.iterdir()} == {
        "evaluation.md", "roc_curve.png", "confusion_matrix.png", "reliability_diagram.png",
    }

    for name in ("_vectorizer", "_model_lr", "_calibrator"):
        monkeypatch.setattr(ai_engine, name, None)
    for line in (output / "checksums.sha256").read_text().splitlines():
        digest, filename = line.split("  ")
        (output / f"{filename}.sha256").write_text(digest)
    assert not ai_engine.load_models(output)  # The exporter uses model.pkl.
    shutil.move(output / "model.pkl", output / "model_lr.pkl")
    shutil.move(output / "model.pkl.sha256", output / "model_lr.pkl.sha256")
    assert ai_engine.load_models(output)
    assert ai_engine.predict(context("/orchard/shop")) == pytest.approx(expected[0, 1])
    monkeypatch.setattr(detector, "_ai_cache", OrderedDict())
    decision = detector.detect(RequestContext(client_ip="8.8.4.4", path="/orchard/shop"))
    assert decision.layer == Layer.AI
    assert decision.confidence == pytest.approx(expected[0, 1])

    (output / "vectorizer.pkl").write_bytes(b"tampered")
    shutil.move(output / "model_lr.pkl", output / "model.pkl")
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        load_models(output)
