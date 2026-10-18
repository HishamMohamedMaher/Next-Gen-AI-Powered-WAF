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
    """Load baseline benign HTTP traffic samples.

    Args:
        path: File path to baseline benign payload logs or dataset.

    Returns:
        pd.DataFrame: Structured DataFrame with standard columns ['payload', 'label', 'attack_type'].
    """
    pass


def deduplicate(df: pd.DataFrame, text_column: str = "payload") -> pd.DataFrame:
    """Deduplicate records based on SHA-256 hashes of the payload text.

    Args:
        df: Input DataFrame containing payload text.
        text_column: Name of the column containing the raw payload text.

    Returns:
        pd.DataFrame: Deduplicated DataFrame with unique payload entries.
    """
    pass


def scan_mislabeled(
    df: pd.DataFrame,
    text_column: str = "payload",
    label_column: str = "label",
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Scan for mislabeled entries where attacks might be labeled as benign using known attack signatures.

    Args:
        df: Input DataFrame with payloads and labels.
        text_column: Column name holding payload text.
        label_column: Column name holding ground-truth binary label (0 for benign, 1 for attack).

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]: (clean_df, suspicious_df) where clean_df contains validated samples
        and suspicious_df contains benign samples flagged for signature hits.
    """
    pass


def remove_headers(text: str) -> str:
    """Strip HTTP header lines and preserve only the query parameters and request payload body.

    Args:
        text: Raw HTTP request or payload string with possible headers.

    Returns:
        str: Cleaned payload with headers stripped out.
    """
    pass


def normalize_all(df: pd.DataFrame, text_column: str = "payload") -> pd.DataFrame:
    """Apply the standard AI-WAF normalizer to every row in the dataset.

    Args:
        df: Input DataFrame containing payload strings.
        text_column: Target column to normalize.

    Returns:
        pd.DataFrame: DataFrame with normalized payload text column updated or added.
    """
    pass


def clean_pipeline(raw_dir: Union[str, Path], output_dir: Union[str, Path]) -> None:
    """Orchestrate the end-to-end data cleaning, sanitization, and normalization pipeline.

    Args:
        raw_dir: Directory containing raw data files.
        output_dir: Target directory to persist cleaned data files.
    """
    pass


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
