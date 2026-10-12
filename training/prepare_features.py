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
    """Load cleaned and normalized dataset from parquet or CSV file.

    Args:
        path: Path to the cleaned data file.

    Returns:
        pd.DataFrame: Cleaned dataset containing payloads and labels.
    """
    pass


def split_data(
    df: pd.DataFrame,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
    stratify_col: str = "label",
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Perform a stratified split into training, validation, and test datasets.

    Args:
        df: Input DataFrame to split.
        test_size: Proportion of the dataset to include in the test split.
        val_size: Proportion of the dataset to include in the validation split.
        random_state: Seed used by the random number generator.
        stratify_col: Column name on which to perform stratified sampling.

    Returns:
        Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]: (train_df, val_df, test_df).
    """
    pass


def save_splits(
    train: pd.DataFrame,
    val: pd.DataFrame,
    test: pd.DataFrame,
    output_dir: Union[str, Path],
) -> None:
    """Persist train, validation, and test partitions to disk in parquet or CSV format.

    Args:
        train: Training partition DataFrame.
        val: Validation partition DataFrame.
        test: Test partition DataFrame.
        output_dir: Directory where the split files will be stored.
    """
    pass


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
