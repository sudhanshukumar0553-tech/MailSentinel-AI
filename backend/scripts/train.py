"""
MailSentinel AI - Command-Line Model Training Script

Usage:
    python backend/scripts/train.py [--samples 5000]
"""

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.ml.trainer import run_full_training


def main():
    parser = argparse.ArgumentParser(description="Train MailSentinel AI Dual ML Models.")
    parser.add_argument(
        "--samples",
        type=int,
        default=5000,
        help="Max samples per dataset for training (default: 5000; use 0 or -1 for full dataset)"
    )
    args = parser.parse_args()

    max_samples = None if args.samples <= 0 else args.samples
    print(f"[*] Starting MailSentinel AI training (max samples: {max_samples or 'FULL'})...")
    report = run_full_training(max_samples=max_samples)
    print("\n[+] Training Complete! Results:")
    for model_key, res in report.get("models", {}).items():
        print(f"  - {model_key}: Accuracy={res.get('accuracy')}, F1={res.get('f1_score')}, Precision={res.get('precision')}, Recall={res.get('recall')}")


if __name__ == "__main__":
    main()

