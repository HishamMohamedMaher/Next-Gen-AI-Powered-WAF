"""Data cleaning and pre-processing pipeline for AI-WAF datasets.

Handles raw dataset ingestion (SRBH, HTTPParams, Baseline), deduplication using SHA-256 hashes,
HTTP header stripping, mislabel scanning via signature detection, and text normalization.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import re
from pathlib import Path
import sys
from typing import Tuple, Union
from urllib.parse import unquote

import pandas as pd

# Path hack to ensure waf modules can be imported directly when running as a standalone script
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import Request
from waf import normalizer, signatures
from waf.context import build_context
from waf.models import RequestContext
from waf.normalizer import normalize_text  # noqa: E402

_REQUEST_LINE = re.compile(r"([A-Z]+)[ \t]+(\S+)(?:[ \t]+HTTP/\d(?:\.\d)?)?")
_HEADER = re.compile(r"([A-Za-z0-9-]+):[ \t]*(.*)")

logger = logging.getLogger(__name__)


def load_srbh(path: Union[str, Path]) -> pd.DataFrame:
    """Load SR-BH2020 CSV; raw staging text, NOT normalized TF-IDF text.
    Returns payload, binary label, attack_type without headers/IPs or responses.
    """
    return _load_srbh(path, include_content_type=False)


def _load_srbh(path: Union[str, Path], *, include_content_type: bool) -> pd.DataFrame:
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
    content_type_column = 'request_content_type'
    metadata = [content_type_column] if include_content_type and content_type_column in cols else []
    yes = {'1', '1.0', 'true', 't', 'yes'}
    no = {'0', '0.0', 'false', 'f', 'no', ''}
    chunks, n = [], 0
    for chunk in pd.read_csv(source, usecols=request_cols + [normal_col] + attack_cols + metadata,
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
        if metadata:
            chunks[-1]['content_type'] = chunk[content_type_column].to_numpy()
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
        if 'query_string' in frame:
            query = frame['query_string'].fillna('').astype(str)
            if (query.ne('') & target.str.contains('?', regex=False)).any():
                raise ValueError('Baseline contains conflicting query representations')
            target = target.where(query.eq(''), target + '?' + query)
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



def _parse_request(text: str) -> tuple[str, str, dict[str, str], str] | None:
    request_line, _, remainder = text.partition('\n')
    match = _REQUEST_LINE.fullmatch(request_line.rstrip('\r').strip())
    if not match:
        return None

    method, target = match.groups()
    # Inspect only the prefix. Preserve the body verbatim for the runtime parser.
    header_block, separator, body = remainder.partition('\r\n\r\n')
    if not separator:
        header_block, separator, body = remainder.partition('\n\n')
    lines = header_block.splitlines()
    if separator and lines and all(_HEADER.fullmatch(line) for line in lines):
        headers = dict(_HEADER.fullmatch(line).groups() for line in lines)
        return method, target, {key.lower(): value for key, value in headers.items()}, body
    return method, target, {}, remainder


async def _normalized_request(payload: str, content_type: str = '') -> RequestContext:
    parts = _parse_request(payload)
    if parts is None:
        raise ValueError('Non-HTTP payload cannot be mapped to RequestContext')
    method, target, headers, body = parts
    if not target.startswith('/') or '#' in target:
        raise ValueError('Expected an origin-form HTTP request target')
    path, _, query = target.partition('?')
    media_type = headers.get('content-type') or content_type
    if body and not media_type:
        raise ValueError('Body content type is missing')
    raw_body = body.encode('utf-8')

    async def receive():
        return {'type': 'http.request', 'body': raw_body, 'more_body': False}

    request = Request({
        'type': 'http',
        'method': method,
        'path': unquote(path),
        'query_string': query.encode('utf-8'),
        'headers': [(b'content-type', media_type.encode('latin-1'))] if media_type else [],
    }, receive)
    ctx = normalizer.normalize_context(await build_context(request))
    if not isinstance(ctx, RequestContext):
        raise RuntimeError('Shared normalizer returned an invalid RequestContext')
    return ctx


def scan_mislabeled(df: pd.DataFrame, text_column: str = 'payload',
                    label_column: str = 'label') -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Quarantine benign-labelled rows flagged by the shared signature engine."""
    if not {text_column, label_column}.issubset(df):
        raise ValueError('Missing payload/label columns')
    if signatures.load_rules(str(PROJECT_ROOT / 'rules' / 'rules.json')) < 1:
        raise RuntimeError('No official signature rules loaded')

    async def flagged_rows():
        flagged = []
        for _, row in df.iterrows():
            if row[label_column] != 0:
                flagged.append(False)
                continue
            ctx = await _normalized_request(str(row[text_column]), str(row.get('content_type', '')))
            flagged.append(signatures.scan(ctx) is not None)
        return flagged

    suspicious = pd.Series(asyncio.run(flagged_rows()), dtype=bool).to_numpy()
    return df.iloc[~suspicious].copy(), df.iloc[suspicious].copy()


def remove_headers(text: str) -> str:
    """Extract the request target and body, omitting HTTP headers."""
    if not isinstance(text, str):
        raise TypeError('Request text must be a string')
    parts = _parse_request(text)
    if parts is None:
        return text
    _, target, _, body = parts
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
    """Prepare reviewable canonical candidates from verified raw staging."""
    from training.week1_staging import prepare_canonical_if_ready
    prepare_canonical_if_ready(Path(raw_dir), Path(output_dir))



def main() -> None:
    """Parse command line arguments and execute the data cleaning pipeline."""
    parser = argparse.ArgumentParser(description="AI-WAF Dataset Cleaning Pipeline")
    parser.add_argument(
        "--raw-dir",
        type=str,
        default="data/staging",
        help="Directory created by prepare_raw_staging",
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
