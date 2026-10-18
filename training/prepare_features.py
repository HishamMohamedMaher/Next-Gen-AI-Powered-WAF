"""Dataset splitting and feature preparation utilities for AI-WAF.

Handles loading cleaned dataset records, performing stratified train/validation/test splits,
and saving split partitions for reproducible model training and evaluation.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Tuple, Union

import pandas as pd
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)


def load_cleaned_data(path: Union[str, Path]) -> pd.DataFrame:
    """Read a previously prepared CSV/parquet with labels and group identifiers.

    The caller remains responsible for verifying the normalization manifest
    before using any data for model training.
    """
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(src)
    if src.suffix.lower() == '.csv':
        df = pd.read_csv(src, dtype={'request_group_sha256': str},
                         keep_default_na=False)
    elif src.suffix.lower() in {'.parquet', '.pq'}:
        df = pd.read_parquet(src)
    else:
        raise ValueError('Expected CSV or parquet')
    if df.empty or not {'payload', 'label', 'request_group_sha256'}.issubset(df):
        raise ValueError('Missing payload, label, or request_group_sha256')
    if not df['label'].isin([0, 1]).all():
        raise ValueError('Invalid label values')
    if not df['request_group_sha256'].astype(str).str.fullmatch(r'[0-9a-fA-F]{64}').all():
        raise ValueError('Invalid request group hashes')
    return df



def split_data(df: pd.DataFrame, test_size: float = 0.15,
               val_size: float = 0.15, random_state: int = 42,
               stratify_col: str = 'label') -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Deterministic group-disjoint stratified train/val/test split.

    Fractions refer to the FULL dataset. Conflicting labels within a request
    group are rejected, never arbitrarily resolved.
    """
    from sklearn.model_selection import train_test_split
    group_col = 'request_group_sha256'
    if not {group_col, stratify_col}.issubset(df):
        raise ValueError('Missing group hash or stratification column')
    if not (0 < test_size < 1 and 0 < val_size < 1 and test_size + val_size < 1):
        raise ValueError('Invalid validation/test sizes')
    if df.empty or not df[stratify_col].isin([0, 1]).all():
        raise ValueError('Expected nonempty binary labelled data')
    if df.groupby(group_col)[stratify_col].nunique().gt(1).any():
        raise ValueError('Conflicting label group must be quarantined first')
    groups = df.groupby(group_col, sort=True)[stratify_col].first()
    if (groups.value_counts() < 3).any() or set(groups.unique()) != {0, 1}:
        raise ValueError('Not enough independent groups in each class')
    group_train_val, group_test = train_test_split(
        groups.index.to_numpy(), test_size=test_size, random_state=random_state,
        stratify=groups.values)
    remaining = groups.loc[group_train_val]
    group_train, group_val = train_test_split(
        remaining.index.to_numpy(),
        test_size=val_size / (1 - test_size), random_state=random_state,
        stratify=remaining.values)
    ids = (set(group_train), set(group_val), set(group_test))
    if ids[0] & ids[1] or ids[0] & ids[2] or ids[1] & ids[2]:
        raise AssertionError('Group overlap')
    parts = [df.loc[df[group_col].isin(ids[i])].copy().reset_index(drop=True)
             for i in range(3)]
    if sum(len(p) for p in parts) != len(df):
        raise AssertionError('Lost or duplicated records')
    if any(set(p[stratify_col]) != {0, 1} for p in parts):
        raise ValueError('One split has only one class')
    return tuple(parts)



def save_splits(train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame,
                output_dir: Union[str, Path]) -> None:
    """Safely save disjoint CSV partitions and a source-agnostic SHA256 manifest.

    A pre-existing output directory is NEVER overwritten; held-out test remains
    a separate file. The manifest explicitly labels these partitions raw-only.
    """
    import hashlib
    import json
    import tempfile
    from pathlib import Path
    for name, df in [('train', train), ('val', val), ('test', test)]:
        if not {'payload', 'label', 'request_group_sha256'}.issubset(df):
            raise ValueError(f'{name}: missing required columns')
        if set(df['label']) != {0, 1}:
            raise ValueError(f'{name}: both classes required')
    col = 'request_group_sha256'
    groups = [set(part[col]) for part in (train, val, test)]
    if groups[0] & groups[1] or groups[0] & groups[2] or groups[1] & groups[2]:
        raise ValueError('Leakage detected between split groups')
    dest = Path(output_dir)
    if dest.exists() or dest.is_symlink():
        raise FileExistsError(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent, prefix='.week1split_') as tmp:
        staged = Path(tmp)
        manifest = {'normalization_applied': False, 'training_ready': False,
                    'split_strategy': 'stratified_sha256_request_group',
                    'subsets': {}}
        for name, part in [('train',train),('val',val),('test',test)]:
            file = staged / f'srbh_{name}_raw.csv'
            part.to_csv(file, index=False)
            digest = hashlib.sha256(file.read_bytes()).hexdigest()
            manifest['subsets'][name] = {'rows': int(len(part)), 'sha256': digest,
                'classes': {str(k): int(v) for k,v in part.label.value_counts().sort_index().items()}}
        (staged / 'split_manifest.json').write_text(json.dumps(manifest, indent=2),encoding='utf-8')
        if dest.exists():
            raise FileExistsError(dest)
        staged.rename(dest)



def main() -> None:
    """Parse command line arguments and execute dataset splitting."""
    parser = argparse.ArgumentParser(description="AI-WAF Dataset Feature & Split Preparation")
    parser.add_argument(
        "--input-file",
        type=str,
        default="data/processed/cleaned_dataset.parquet",
        help="Path to cleaned dataset file",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/splits",
        help="Directory to store dataset splits (train, val, test)",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.15,
        help="Proportion of dataset reserved for testing",
    )
    parser.add_argument(
        "--val-size",
        type=float,
        default=0.15,
        help="Proportion of dataset reserved for validation",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducible stratified splitting",
    )
    args = parser.parse_args()

    df = load_cleaned_data(args.input_file)
    train_df, val_df, test_df = split_data(
        df,
        test_size=args.test_size,
        val_size=args.val_size,
        random_state=args.random_state,
    )
    save_splits(train_df, val_df, test_df, args.output_dir)


if __name__ == "__main__":
    main()
