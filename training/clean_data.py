"""Data cleaning and pre-processing pipeline for AI-WAF datasets.

Handles raw dataset ingestion (SRBH, HTTPParams, Baseline), deduplication using SHA-256 hashes,
HTTP header stripping, mislabel scanning via signature detection, and text normalization.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
from pathlib import Path
import sys
from typing import Tuple, Union

import pandas as pd

# Path hack to ensure waf modules can be imported directly when running as a standalone script
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from waf.normalizer import normalize_text  # noqa: E402

logger = logging.getLogger(__name__)


def load_srbh(path: Union[str, Path]) -> pd.DataFrame:
    """Load SR-BH2020 CSV; raw staging text, NOT normalized TF-IDF text.
    Returns payload, binary label, attack_type without headers/IPs or responses.
    """
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    request_cols = ['request_http_method', 'request_http_request', 'request_body']
    normal_col = '000 - Normal'
    cols = pd.read_csv(source, nrows=0, encoding='utf-8-sig').columns.tolist()
    attack_cols = [c for c in cols if c != normal_col and c.split(' - ', 1)[0].isdigit()]
    missing = [c for c in request_cols + [normal_col] if c not in cols]
    if missing or not attack_cols:
        raise ValueError(f'Invalid SR-BH columns; missing={missing}, attack_columns={len(attack_cols)}')
    yes = {'1', '1.0', 'true', 't', 'yes'}
    no = {'0', '0.0', 'false', 'f', 'no', ''}
    chunks, n = [], 0
    for chunk in pd.read_csv(source, usecols=request_cols + [normal_col] + attack_cols,
                             dtype=str, keep_default_na=False, chunksize=25000,
                             encoding='utf-8-sig'):
        flags = chunk[[normal_col] + attack_cols].apply(lambda col: col.str.strip().str.lower())
        if not flags.isin(yes | no).all().all():
            raise ValueError(f'Unexpected SR-BH CAPEC flags around row {n}')
        positive = flags.isin(yes)
        malicious = positive[attack_cols].any(axis=1)
        if positive[normal_col].eq(malicious).any():
            raise ValueError(f'Conflicting/missing SR-BH labels around row {n}')
        method = chunk['request_http_method'].str.strip()
        body = chunk['request_body']
        payload = method + ' ' + chunk['request_http_request']
        payload = payload.where(body.eq(''), payload + '\n' + body)
        kinds = positive[attack_cols].apply(
            lambda row: ';'.join(col for col in attack_cols if row[col]), axis=1
        )
        chunks.append(pd.DataFrame({
            'payload': payload.to_numpy(),
            'label': malicious.astype('int8').to_numpy(),
            'attack_type': kinds.where(malicious, 'benign').to_numpy(),
        }))
        n += len(chunk)
    if not chunks:
        raise ValueError('Empty SR-BH dataset')
    return pd.concat(chunks, ignore_index=True)



def load_httpparams(path: Union[str, Path]) -> pd.DataFrame:
    """Load only HttpParams payload_train.csv from ZIP; never read held-out test/full.
    Standalone CSV accepted when supplied explicitly. Raw text, no normalization.
    """
    from zipfile import ZipFile
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(source)
    if source.suffix.lower() == '.zip':
        with ZipFile(source) as archive:
            candidates = [n for n in archive.namelist()
                          if Path(n).name == 'payload_train.csv' and not n.endswith('/')]
            if len(candidates) != 1:
                raise ValueError('HTTPParams ZIP must contain exactly one payload_train.csv')
            with archive.open(candidates[0]) as f:
                df = pd.read_csv(f, dtype=str, keep_default_na=False, encoding='utf-8-sig')
    elif source.suffix.lower() == '.csv':
        df = pd.read_csv(source, dtype=str, keep_default_na=False, encoding='utf-8-sig')
    else:
        raise ValueError('Expected a CSV or ZIP file')
    df.columns = df.columns.str.strip().str.lower()
    if df.columns.duplicated().any() or not {'payload', 'label'}.issubset(df.columns):
        raise ValueError(f'Invalid HTTPParams headers: {list(df.columns)}')
    if df.empty:
        raise ValueError('Empty HTTPParams dataset')
    labels = df['label'].str.strip().str.lower()
    mapping = {'norm': 0, 'normal': 0, 'benign': 0, '0': 0,
               'anom': 1, 'anomaly': 1, 'attack': 1, 'malicious': 1, '1': 1}
    if not labels.isin(mapping).all():
        raise ValueError(f'Unknown HTTPParams labels: {sorted(set(labels) - set(mapping))}')
    binary = labels.map(mapping).astype('int8')
    types = (df['attack_type'].str.strip() if 'attack_type' in df
             else pd.Series([''] * len(df), index=df.index))
    types = types.where(binary.eq(1), 'benign').replace('', 'unknown')
    result = pd.DataFrame({'payload': df['payload'].astype(str),
                           'label': binary, 'attack_type': types})
    if result['payload'].str.len().eq(0).any():
        raise ValueError('HTTPParams contains empty payloads; review required')
    return result.reset_index(drop=True)



def load_baseline(path: Union[str, Path]) -> pd.DataFrame:
    """Load verified benign Juice Shop baseline samples from CSV/JSONL.

    Each record MUST explicitly carry benign label (0, 'benign', etc.) or
    is_benign=True. Unverified logs are never silently labelled benign.
    """
    import json
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(src)
    if src.suffix.lower() == '.csv':
        frame = pd.read_csv(src, dtype=str, keep_default_na=False)
    elif src.suffix.lower() in {'.jsonl', '.ndjson'}:
        rows = []
        with src.open(encoding='utf-8-sig') as fh:
            for n, line in enumerate(fh, 1):
                if line.strip():
                    item = json.loads(line)
                    if not isinstance(item, dict):
                        raise ValueError(f'Invalid baseline object at line {n}')
                    rows.append(item)
        frame = pd.DataFrame(rows)
    else:
        raise ValueError('Baseline requires CSV or JSONL')
    if frame.empty:
        raise ValueError('Empty baseline file')
    if 'label' in frame:
        if not frame['label'].astype(str).str.strip().str.lower().isin({'0', '0.0', 'benign', 'norm', 'normal'}).all():
            raise ValueError('Baseline has non-benign/unknown labels')
    elif 'is_benign' in frame:
        if not frame['is_benign'].astype(str).str.strip().str.lower().isin({'true', '1', 'yes'}).all():
            raise ValueError('Baseline has unverified/non-benign rows')
    else:
        raise ValueError('Baseline records must explicitly verify benign label or is_benign')
    if 'payload' in frame:
        payload = frame['payload'].fillna('').astype(str)
    else:
        method = frame.get('method', frame.get('request_http_method'))
        target = frame.get('path', frame.get('request_http_request'))
        if method is None or target is None:
            raise ValueError('Baseline needs payload OR method+path')
        method = method.fillna('').astype(str).str.strip()
        target = target.fillna('').astype(str)
        body = frame.get('body', frame.get('request_body'))
        if body is None:
            body = pd.Series([''] * len(frame), index=frame.index)
        else:
            body = body.fillna('').astype(str)
        payload = method + ' ' + target
        payload = payload.where(body.eq(''), payload + '\n' + body)
    if payload.str.strip().eq('').any():
        raise ValueError('Baseline contains empty payloads')
    return pd.DataFrame({'payload': payload.to_numpy(), 'label': 0,
                         'attack_type': 'benign'}).reset_index(drop=True)



def deduplicate(df: pd.DataFrame, text_column: str = 'payload') -> pd.DataFrame:
    """SHA-256 exact-text deduplication, rejecting conflicting hash labels.

    Keeps a request_group_sha256 key for group-safe splitting; NEVER resolves a
    conflicting label by first-row selection or majority vote.
    """
    if not {text_column, 'label'}.issubset(df.columns):
        raise ValueError('Missing payload/label columns')
    result = df.copy()
    if result[text_column].isna().any():
        raise ValueError('Null payload must be reviewed before deduplication')
    if not result['label'].isin([0, 1]).all():
        raise ValueError('Only binary labels 0/1 accepted')
    result['request_group_sha256'] = result[text_column].astype(str).map(
        lambda value: hashlib.sha256(value.encode('utf-8')).hexdigest())
    if result.groupby('request_group_sha256')['label'].nunique().gt(1).any():
        raise ValueError('Conflicting request groups require quarantine BEFORE deduplicate')
    return result.drop_duplicates('request_group_sha256', keep='first').reset_index(drop=True)



def scan_mislabeled(df: pd.DataFrame, text_column: str = 'payload',
                    label_column: str = 'label') -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Quarantine benign-labelled rows flagged by the TEAM signature engine.

    Fails closed when the shared normalizer/signature engine is still stubbed.
    Never relabels a row automatically. This is NOT a heuristic substitute.
    """
    import ast
    import inspect
    from urllib.parse import urlsplit
    from waf.models import RequestContext
    from waf import normalizer, signatures
    def not_stub(fn):
        tree = ast.parse(inspect.getsource(fn))
        node = next((n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)), None)
        core = [x for x in node.body if not (isinstance(x, ast.Expr) and isinstance(x.value, ast.Constant)
                 and isinstance(x.value.value, str))]
        return bool(core) and not (len(core) == 1 and isinstance(core[0], ast.Pass))
    if not not_stub(normalizer.normalize_context) or not not_stub(signatures.scan):
        raise RuntimeError('WAITING_ON_MEMBER_2: shared normalizer and signature scan not implemented')
    if not {text_column, label_column}.issubset(df):
        raise ValueError('Missing payload/label columns')
    suspicious = []
    for idx, row in df[df[label_column].eq(0)].iterrows():
        raw = str(row[text_column])
        request_line, sep, body = raw.partition('\n')
        try:
            method, target = request_line.split(' ', 1)
        except ValueError as error:
            raise ValueError('Non-HTTP payload cannot be signature-scanned as RequestContext') from error
        target = target.strip()
        parsed = urlsplit(target)
        path = parsed.path or '/'
        ctx = RequestContext(method=method, path=path,
                             query_string=parsed.query, body_raw=body.encode('utf-8'),
                             body_fields={'__raw_body__': body} if sep else {})
        normalized_ctx = normalizer.normalize_context(ctx)
        if normalized_ctx is None:
            raise RuntimeError('Shared normalizer returned None')
        if signatures.scan(normalized_ctx) is not None:
            suspicious.append(idx)
    return df.drop(index=suspicious).copy(), df.loc[suspicious].copy()



def remove_headers(text: str) -> str:
    """Extract the request target and body without user-agent/host/cookie headers.

    Handles full HTTP request lines, a raw METHOD+target staging string, or
    standalone parameter values without interpreting them as HTTP headers.
    """
    import re
    if not isinstance(text, str):
        raise TypeError('Request text must be a string')
    raw = text.replace('\r\n', '\n')
    lines = raw.split('\n')
    first = lines[0]
    match = re.fullmatch(r'[A-Z]+\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?', first.strip())
    if not match:
        return text
    target = match.group(1)
    remaining = lines[1:]
    sep = next((i for i, l in enumerate(remaining) if l == ''), None)
    if sep is not None:
        # Headers are present only if at least one valid-looking field follows
        # and all nonblank lines before the blank separator are header lines.
        head = remaining[:sep]
        if head and all(re.fullmatch(r'[A-Za-z0-9-]+:\s*.*', l) for l in head):
            body = '\n'.join(remaining[sep+1:])
            return target + ('\n' + body if body else '')
    # Day1 SRBH representation: METHOD + target + optional raw body on next line.
    body = '\n'.join(remaining)
    return target + ('\n' + body if body else '')



def normalize_all(df: pd.DataFrame, text_column: str = 'payload') -> pd.DataFrame:
    """Apply Member 2's shared normalizer without replacing original text.

    This is an auditable low-level text utility, NOT the canonical
    RequestContext-to-TF-IDF feature builder used at inference time.
    """
    if text_column not in df:
        raise ValueError(f'Missing text column: {text_column}')
    probe = normalize_text('Test%2520Value')
    if probe is None or not isinstance(getattr(probe, 'normalized', None), str):
        raise RuntimeError('WAITING_ON_MEMBER_2: normalize_text not implemented')
    result = df.copy()
    def convert(value):
        normalized = normalize_text(str(value))
        if not isinstance(getattr(normalized, 'normalized', None), str):
            raise RuntimeError('Normalizer returned invalid NormalizedResult')
        return normalized.normalized
    result[f'{text_column}_normalized'] = result[text_column].map(convert)
    return result



def clean_pipeline(raw_dir: Union[str, Path], output_dir: Union[str, Path]) -> None:
    """Final week-1 normalized preparation; fail closed if teammates are pending.

    Produces canonical payloads only after shared normalizer, signature scan,
    and feature extractor are ready. Never emits 'training-ready' from raw text.
    Run prepare_raw_staging() to make auditable raw splits meanwhile.
    """
    from training.week1_staging import prepare_canonical_if_ready
    prepare_canonical_if_ready(Path(raw_dir), Path(output_dir))



def main() -> None:
    """Parse command line arguments and execute the data cleaning pipeline."""
    parser = argparse.ArgumentParser(description="AI-WAF Dataset Cleaning Pipeline")
    parser.add_argument(
        "--raw-dir",
        type=str,
        default="data/raw",
        help="Path to directory containing raw dataset files",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/processed",
        help="Path to directory where cleaned datasets will be saved",
    )
    args = parser.parse_args()
    clean_pipeline(raw_dir=args.raw_dir, output_dir=args.output_dir)


if __name__ == "__main__":
    main()
