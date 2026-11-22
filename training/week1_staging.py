"""Member 3 week-1 auditable raw data preparation. NOT training-ready.

No leakage-prone heuristic relabels, no automatic use of held-out test, and
no replacement of shared team normalizer/signature functions.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import hashlib
import json
import tempfile
import re

import pandas as pd
from fastapi import HTTPException

from training.clean_data import (
    PROJECT_ROOT, _load_srbh, _normalized_request, deduplicate, load_baseline, load_httpparams,
)
from waf import signatures
from waf.feature_extractor import extract_text_for_tfidf
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

    source_hashes = {'srbh_csv': _sha256(srbh_csv), 'httpparams_zip': _sha256(httpparams_zip)}
    if baseline_file is not None:
        source_hashes['baseline'] = _sha256(Path(baseline_file))

    # Distinct request_group_sha256 defined by EXACT raw loader payload.
    sr = _load_srbh(srbh_csv, include_content_type=True)
    http_train = load_httpparams(httpparams_zip)
    sr['request_group_sha256'] = sr['payload'].map(
        lambda x: hashlib.sha256(x.encode('utf-8')).hexdigest()
    )

    labels_per_group = sr.groupby('request_group_sha256', sort=False)['label'].nunique()
    conflict_keys = set(labels_per_group.index[labels_per_group.gt(1)])
    metadata_keys = set()
    if 'content_type' in sr:
        media_types = sr['content_type'].str.strip().str.lower()
        counts = media_types.groupby(sr['request_group_sha256']).nunique()
        metadata_keys = set(counts.index[counts.gt(1)])
    ambiguous = sr[sr['request_group_sha256'].isin(conflict_keys | metadata_keys)].copy()
    ambiguous['quarantine_reason'] = ambiguous['request_group_sha256'].map(
        lambda key: 'conflicting_labels' if key in conflict_keys else 'conflicting_content_types'
    )
    usable = sr[~sr['request_group_sha256'].isin(conflict_keys | metadata_keys)]
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
        ambiguous.to_csv(stage / 'quarantined_raw_records.csv', index=False)
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
            'conflicting_content_type_groups': int(len(metadata_keys)),
            'quarantined_original_rows':int(len(ambiguous)),
            'unique_safe_srbh_rows':int(len(clean)),
            'benign_regex_review_count':int(len(review)),
            'httpparams_train_rows':int(len(http_train)),
            'httpparams_train_class_counts':{str(k):int(v) for k,v in http_train.label.value_counts().sort_index().items()},
            'splits':{'train':int(len(train)), 'val':int(len(val)), 'test_holdout':int(len(test))},
            'split_class_counts':{name:{str(k):int(v) for k,v in part.label.value_counts().sort_index().items()}
                 for name,part in [('train',train),('val',val),('test_holdout',test)]},
            'sha256_input': source_hashes,
            'sha256_output': {
                path.relative_to(stage).as_posix(): _sha256(path)
                for path in sorted(stage.iterdir()) if path.is_file()
            } | {'splits/split_manifest.json': _sha256(raw_splits / 'split_manifest.json')},
            'notes':[
                'Original SRBH CAPEC labels preserved in the raw quarantine.',
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
        if _sha256(httpparams_zip) != source_hashes['httpparams_zip']:
            raise RuntimeError('HTTPParams source changed during staging')
        if baseline_file is not None and _sha256(Path(baseline_file)) != source_hashes['baseline']:
            raise RuntimeError('Baseline source changed during staging')
        if dest.exists():
            raise FileExistsError(dest)
        stage.rename(dest)
    return report


async def _canonical_rows(rows: pd.DataFrame) -> pd.DataFrame:
    features = []
    reasons = []
    for row in rows.itertuples(index=False):
        try:
            ctx = await _normalized_request(row.payload, getattr(row, 'content_type', ''))
        except (ValueError, HTTPException):
            features.append('')
            reasons.append('unrepresentable_request')
            continue
        hit = signatures.scan(ctx) if row.label == 0 else None
        try:
            text = extract_text_for_tfidf(ctx)
        except ValueError:
            text = ''
        features.append(text)
        if hit is not None:
            reasons.append(f'benign_signature_match:{hit.rule_id}')
        else:
            reasons.append('' if text else 'unrepresentable_request')
    return rows.assign(payload_tfidf=features, quarantine_reason=reasons)


def prepare_canonical_if_ready(raw_dir: Path, output_dir: Path) -> None:
    """Write runtime-parity train/validation candidates and quarantine for review.

    The source is a prepare_raw_staging directory. The existing held-out split
    stays in that directory and is neither opened nor copied.
    """
    from training.prepare_features import load_cleaned_data

    root = Path(raw_dir)
    dest = Path(output_dir)
    manifest_path = root / 'week1_manifest.json'
    if not manifest_path.is_file():
        raise RuntimeError('BLOCKED_FOR_REAL_TRAINING: missing raw staging manifest')
    raw_manifest_sha = _sha256(manifest_path)
    raw_manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if raw_manifest.get('stage') != 'RAW_PRENORMALIZATION_ONLY':
        raise ValueError('Expected raw staging provenance')
    split_path = root / 'splits' / 'split_manifest.json'
    split_sha = _sha256(split_path)
    expected_split_sha = raw_manifest.get('sha256_output', {}).get('splits/split_manifest.json')
    if expected_split_sha is not None and split_sha != expected_split_sha:
        raise ValueError('Raw split manifest checksum mismatch')
    splits = json.loads(split_path.read_text(encoding='utf-8'))['subsets']
    if dest.exists() or dest.is_symlink():
        raise FileExistsError(dest)

    inputs = {}
    partitions = []
    for name in ('train', 'val'):
        path = root / 'splits' / f'srbh_{name}_raw.csv'
        expected = splits[name]['sha256']
        if _sha256(path) != expected:
            raise ValueError(f'Raw split checksum mismatch: {name}')
        data = load_cleaned_data(path)
        actual_groups = data['payload'].map(lambda value: hashlib.sha256(value.encode('utf-8')).hexdigest())
        groups = data['request_group_sha256']
        class_counts = {str(label): int(count) for label, count in data.label.value_counts().items()}
        if (groups.duplicated().any() or not groups.eq(actual_groups).all()
                or len(data) != splits[name]['rows'] or class_counts != splits[name]['classes']):
            raise ValueError(f'Invalid raw split provenance: {name}')
        inputs[path] = expected
        partitions.append(data.assign(partition=name))

    rows = pd.concat(partitions, ignore_index=True)
    if rows['request_group_sha256'].duplicated().any():
        raise ValueError('Raw train and validation groups overlap')

    rules_path = PROJECT_ROOT / 'rules' / 'rules.json'
    rules_sha = _sha256(rules_path)
    if signatures.load_rules(str(rules_path)) < 1:
        raise RuntimeError('No official signature rules loaded')
    rows = asyncio.run(_canonical_rows(rows))
    represented = rows.loc[rows['payload_tfidf'].ne('')]
    grouped = represented.groupby('payload_tfidf', sort=False)
    conflicting = grouped['label'].transform('nunique').gt(1)
    overlapping = grouped['partition'].transform('nunique').gt(1)
    for mask, reason in ((conflicting, 'conflicting_canonical_labels'),
                         (overlapping, 'cross_partition_canonical_collision')):
        indexes = mask.index[mask & rows.loc[mask.index, 'quarantine_reason'].eq('')]
        rows.loc[indexes, 'quarantine_reason'] = reason

    eligible = rows.loc[rows['quarantine_reason'].eq('')]
    duplicates = eligible.duplicated(['partition', 'payload_tfidf'])
    rows.loc[duplicates.index[duplicates], 'quarantine_reason'] = 'duplicate_canonical_text'
    eligible = rows.loc[rows['quarantine_reason'].eq('')]
    quarantine = rows.loc[rows['quarantine_reason'].ne('')]
    sources = inputs | {manifest_path: raw_manifest_sha, split_path: split_sha, rules_path: rules_sha}
    if any(_sha256(path) != expected for path, expected in sources.items()):
        raise ValueError('Preparation source changed during canonical processing')

    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.canonical_', dir=dest.parent) as tmp:
        stage = Path(tmp)
        files = {}
        validation_issues = []
        for name in ('train', 'val', 'quarantine'):
            part = quarantine if name == 'quarantine' else eligible.loc[eligible['partition'].eq(name)]
            if name != 'quarantine' and set(part.label) != {0, 1}:
                validation_issues.append(f'Both classes required after canonical quarantine: {name}')
            filename = 'canonical_quarantine.csv' if name == 'quarantine' else f'srbh_{name}.csv'
            path = stage / filename
            part.to_csv(path, index=False)
            files[name] = {
                'path': filename,
                'sha256': _sha256(path),
                'rows': len(part),
                'classes': {str(label): int(count) for label, count in part.label.value_counts().sort_index().items()},
            }

        manifest = {
            'stage': 'CANONICAL_CANDIDATE', 'normalization_applied': True,
            'canonical_tfidf_generated': True, 'signature_scan_completed': True,
            'normalization_approved': False, 'training_ready': False,
            'final_evaluation_authorized': False,
            'normalizer': 'waf.normalizer.normalize_context',
            'feature_extractor': 'waf.feature_extractor.extract_text_for_tfidf',
            'signature_engine': 'waf.signatures.scan',
            'signature_rules_sha256': rules_sha,
            'raw_manifest_sha256': raw_manifest_sha,
            'raw_split_manifest_sha256': split_sha,
            'source_sha256': {path.relative_to(root).as_posix(): digest for path, digest in inputs.items()},
            'files': files,
            'held_out_status': 'UNCHANGED_UNVERIFIED',
            'baseline_merged': False,
            'httpparams_merged': False,
            'validation_issues': validation_issues,
            'quarantine_counts': quarantine['quarantine_reason'].value_counts().sort_index().to_dict(),
        }
        (stage / 'canonical_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        if dest.exists() or dest.is_symlink():
            raise FileExistsError(dest)
        stage.rename(dest)
