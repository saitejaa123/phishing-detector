"""
Entry-point script to generate the dataset and train all models.
Run this once before starting the web app.

    python train.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from dataset_generator import generate_dataset
from train_model import train

DATA_PATH = Path(__file__).parent / "data" / "phishing_dataset.csv"

if __name__ == "__main__":
    print("=" * 60)
    print("  AI Phishing URL Detector — Model Training")
    print("=" * 60)

    if not DATA_PATH.exists():
        print("\n[Step 1/2] Generating dataset …")
        generate_dataset(
            n_legit=500,
            n_phish=500,
            output_path=str(DATA_PATH),
        )
    else:
        print(f"\n[Step 1/2] Dataset already exists at {DATA_PATH}")

    print("\n[Step 2/2] Training models …\n")
    metrics = train()

    print("\n" + "=" * 60)
    print("  Training complete. You can now start the app:")
    print("  python app.py")
    print("=" * 60)
