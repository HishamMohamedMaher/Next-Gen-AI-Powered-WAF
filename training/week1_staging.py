"""Member 3 week-1 auditable raw data preparation. NOT training-ready.

No leakage-prone heuristic relabels, no automatic use of held-out test, and
no replacement of shared team normalizer/signature functions.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import tempfile
import re

import pandas as pd

from training.clean_data import load_srbh, load_httpparams, load_baseline, deduplicate
from training.prepare_features import split_data, save_splits


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def prepare_raw_staging(srbh_csv: Path, httpparams_zip: Path,
                        output_dir: Path, baseline_file: Path | None = None) -> dict:
    """Quarantine label-ambiguous groups, dedup and split original SRBH.

    Returns a report and writes auditable pre-normalization CSVs. ZERO synthetic
    accuracy and no training-ready assertion. HTTPParams held-out test is not read.
    """
    srbh_csv = Path(srbh_csv)
    httpparams_zip = Path(httpparams_zip)
    dest = Path(output_dir)
    if not srbh_csv.is_file() or not httpparams_zip.is_file():
        raise FileNotFoundError('Both original SRBH CSV and HTTPParams ZIP are required')
    if dest.exists() or dest.is_symlink():
        raise FileExistsError(f'Refusing overwrite: {dest}')

    # Distinct request_group_sha256 defined by EXACT raw loader payload.
    sr = load_srbh(srbh_csv)
    http_train = load_httpparams(httpparams_zip)
    sr['request_group_sha256'] = sr['payload'].map(
        lambda x: hashlib.sha256(x.encode('utf-8')).hexdigest()
    )

    labels_per_group = sr.groupby('request_group_sha256', sort=False)['label'].nunique()
    conflict_keys = set(labels_per_group.index[labels_per_group.gt(1)])
    ambiguous = sr[sr['request_group_sha256'].isin(conflict_keys)]
    usable = sr[~sr['request_group_sha256'].isin(conflict_keys)]
    clean = deduplicate(usable)
    if clean['request_group_sha256'].nunique() != len(clean):
        raise AssertionError('Deduplication did not produce independent groups')
    train, val, test = split_data(clean, test_size=.15, val_size=.15, random_state=42)

    # Early manual-review hints are advisory, NOT authoritative signature matches.
    benign = clean[clean['label'].eq(0)]
    expression = re.compile(
        r'(?:\.\./|%2e%2e|<script\b|%3cscript|\bunion\s+(?:all\s+)?select\b|'
        r'\b(?:select|insert|delete)\s+.+\bfrom\b|/etc/passwd|/bin/sh)',
        re.IGNORECASE,
    )
    review = benign[benign['payload'].str.contains(expression, na=False)]
    # No unverified row is ever relabelled, dropped based solely on regex, or
    # passed off as inspected by the shared signature engine.

    baseline = None
    if baseline_file is not None:
        baseline = load_baseline(baseline_file)

    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.week1_stage_', dir=dest.parent) as tmp:
        stage = Path(tmp)
        raw_splits = stage / 'splits'
        save_splits(train, val, test, raw_splits)
        quarantined = (ambiguous.groupby('request_group_sha256')
                       .agg(rows=('label','size'), benign=('label',lambda s: int(s.eq(0).sum())),
                            attack=('label',lambda s: int(s.eq(1).sum())))
                       .reset_index())
        quarantine_file = stage / 'conflicting_groups_quarantine.csv'
        quarantined.to_csv(quarantine_file, index=False)
        review_file = stage / 'benign_regex_review_ONLY.csv'
        review[['request_group_sha256','payload','label','attack_type']].to_csv(review_file,index=False)
        httpparams_file = stage / 'httpparams_train_ONLY.csv'
        http_train.to_csv(httpparams_file,index=False)
        if baseline is not None:
            baseline.to_csv(stage/'baseline_benign_verified_NOT_MERGED.csv',index=False)
        report = {
            'stage':'RAW_PRENORMALIZATION_ONLY',
            'training_ready':False, 'normalization_applied':False,
            'signature_scan_completed':False, 'benign_review_is_heuristic_only':True,
            'baseline_merged':False, 'baseline_status': 'VERIFIED_NOT_MERGED' if baseline is not None else 'WAITING_FOR_MEMBER_5',
            'test_used_for_model_selection':False,
            'full_srbh_rows':int(len(sr)),
            'original_srbh_class_counts':{str(k):int(v) for k,v in sr.label.value_counts().sort_index().items()},
            'conflicting_request_groups':int(len(conflict_keys)),
            'quarantined_original_rows':int(len(ambiguous)),
            'unique_safe_srbh_rows':int(len(clean)),
            'benign_regex_review_count':int(len(review)),
            'httpparams_train_rows':int(len(http_train)),
            'httpparams_train_class_counts':{str(k):int(v) for k,v in http_train.label.value_counts().sort_index().items()},
            'splits':{'train':int(len(train)), 'val':int(len(val)), 'test_holdout':int(len(test))},
            'split_class_counts':{name:{str(k):int(v) for k,v in part.label.value_counts().sort_index().items()}
                 for name,part in [('train',train),('val',val),('test_holdout',test)]},
            'sha256_input':{'srbh_csv':_sha256(srbh_csv),'httpparams_zip':_sha256(httpparams_zip)},
            'notes':[
                'Original SRBH CAPEC labels preserved: ambiguous exact-request groups excluded entirely.',
                'Raw CSVs are not canonical WAF TF-IDF inputs. No training until parity with shared serving normalizer.',
                'Do not inspect or train on test_holdout_raw.csv before final locked evaluation.',
                'HTTPParams held-out partitions in ZIP were not loaded.',
                'Member5 benign baseline needs approval and canonical representation before merging.',
            ]
        }
        (stage / 'week1_manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        # Check files exist & manifest agrees; no original file mutation.
        assert all((raw_splits/f'srbh_{kind}_raw.csv').is_file() for kind in ['train','val','test'])
        if _sha256(srbh_csv) != report['sha256_input']['srbh_csv']:
            raise RuntimeError('SRBH source changed during staging')
        if _sha256(httpparams_zip) != report['sha256_input']['httpparams_zip']:
            raise RuntimeError('HTTPParams source changed during staging')
        if dest.exists():
            raise FileExistsError(dest)
        stage.rename(dest)
    return report


def prepare_canonical_if_ready(raw_dir: Path, output_dir: Path) -> None:
    """Explicit gate for production-ready pipeline.

    A canonical feature contract must be agreed with Members 1 and 2 and must
    reproduce WAF runtime context assembly exactly. Never train on METHOD+URL
    raw loader staging text or silently skip shared normalization/signatures.
    """
    raise RuntimeError(
        'BLOCKED_FOR_REAL_TRAINING: Waiting for Member 2 shared normalizer and signature engine '
        'plus Member 1 training/serving context contract. Use prepare_raw_staging() for safe Week1 outputs.'
    )
