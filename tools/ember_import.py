#!/usr/bin/env python3
"""Import the official EMBER vectorized PE dataset into a portable NPZ bundle.

This intentionally does NOT convert EMBER's 2,381-dimensional feature space
into LULZ's unrelated 28-feature schema. The resulting bundle is for the
separate EMBER-compatible training/inference path.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def split_validation(x, y, fraction: float, seed: int):
    import numpy as np

    rng = np.random.default_rng(seed)
    train_indices = []
    validation_indices = []
    for label in (0, 1):
        indices = np.flatnonzero(y == label)
        rng.shuffle(indices)
        if len(indices) < 2:
            raise ValueError(
                f"Not enough labeled samples for class {label}: {len(indices)}"
            )
        count = max(1, int(round(len(indices) * fraction)))
        count = min(count, len(indices) - 1)
        validation_indices.extend(indices[:count].tolist())
        train_indices.extend(indices[count:].tolist())
    rng.shuffle(train_indices)
    rng.shuffle(validation_indices)
    return (
        x[train_indices],
        y[train_indices],
        x[validation_indices],
        y[validation_indices],
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import official EMBER vectors without mixing feature schemas."
    )
    parser.add_argument("ember_dir", type=Path, help="Directory containing EMBER dataset files")
    parser.add_argument("output_npz", type=Path, help="Output .npz bundle")
    parser.add_argument("--validation-fraction", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=20261115)
    args = parser.parse_args()

    if not 0.05 <= args.validation_fraction <= 0.4:
        parser.error("--validation-fraction must be between 0.05 and 0.4")
    if not args.ember_dir.is_dir():
        print(f"ERROR: EMBER directory does not exist: {args.ember_dir}", file=sys.stderr)
        return 2

    try:
        import numpy as np
        import ember
    except ImportError as exc:
        print(
            "ERROR: EMBER dependencies are missing. Install the official package "
            "in a dedicated Python virtual environment first.\n"
            f"Details: {exc}",
            file=sys.stderr,
        )
        return 2

    try:
        print("[1/4] Creating EMBER vectorized features when needed...")
        ember.create_vectorized_features(str(args.ember_dir))
        print("[2/4] Loading official train/test vectors...")
        x_train, y_train, x_test, y_test = ember.read_vectorized_features(
            str(args.ember_dir)
        )

        x_train = np.asarray(x_train, dtype=np.float32)
        y_train = np.asarray(y_train, dtype=np.int32).reshape(-1)
        x_test = np.asarray(x_test, dtype=np.float32)
        y_test = np.asarray(y_test, dtype=np.int32).reshape(-1)

        if x_train.ndim != 2 or x_test.ndim != 2:
            raise ValueError("EMBER feature arrays must be two-dimensional")
        if x_train.shape[1] != x_test.shape[1]:
            raise ValueError("Train/test feature dimensions do not match")
        if x_train.shape[1] != 2381:
            raise ValueError(
                f"Expected EMBER2018 v2 feature width 2381, got {x_train.shape[1]}. "
                "Check the dataset/feature version."
            )
        if len(x_train) != len(y_train) or len(x_test) != len(y_test):
            raise ValueError("Feature and label counts do not match")

        # EMBER labels: 0=benign, 1=malicious, -1=unlabeled.
        train_mask = np.isin(y_train, (0, 1))
        test_mask = np.isin(y_test, (0, 1))
        x_train, y_train = x_train[train_mask], y_train[train_mask]
        x_test, y_test = x_test[test_mask], y_test[test_mask]
        if not len(y_train) or not len(y_test):
            raise ValueError("No labeled samples remain after removing label -1")
        if not np.isfinite(x_train).all() or not np.isfinite(x_test).all():
            raise ValueError("EMBER vectors contain NaN or infinite values")

        print("[3/4] Creating a stratified validation split from EMBER train data...")
        x_fit, y_fit, x_val, y_val = split_validation(
            x_train, y_train, args.validation_fraction, args.seed
        )

        args.output_npz.parent.mkdir(parents=True, exist_ok=True)
        print("[4/4] Saving portable NPZ bundle...")
        np.savez_compressed(
            args.output_npz,
            x_train=x_fit,
            y_train=y_fit,
            x_validation=x_val,
            y_validation=y_val,
            x_test=x_test,
            y_test=y_test,
            feature_schema=np.asarray(["EMBER2018-v2-2381"]),
            label_schema=np.asarray(["0=benign", "1=malicious"]),
            seed=np.asarray([args.seed], dtype=np.int64),
        )

        summary = {
            "feature_schema": "EMBER2018-v2",
            "feature_count": int(x_train.shape[1]),
            "train": {
                "samples": int(len(y_fit)),
                "benign": int(np.sum(y_fit == 0)),
                "malicious": int(np.sum(y_fit == 1)),
            },
            "validation": {
                "samples": int(len(y_val)),
                "benign": int(np.sum(y_val == 0)),
                "malicious": int(np.sum(y_val == 1)),
            },
            "test": {
                "samples": int(len(y_test)),
                "benign": int(np.sum(y_test == 0)),
                "malicious": int(np.sum(y_test == 1)),
            },
            "output": str(args.output_npz),
            "note": (
                "This bundle is NOT compatible with lulz_trainer's 28-feature CSV "
                "or the current AIEngine inference schema."
            ),
        }
        print(json.dumps(summary, indent=2))
        return 0
    except Exception as exc:
        print(f"ERROR: EMBER import failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
