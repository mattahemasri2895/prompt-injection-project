import sys
from pathlib import Path

import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

# ============================================================
# PROJECT PATH
# ============================================================

# Find project root:
# D:\prompt-injection-project
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Add project root to Python path
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# IMPORT RULE-BASED DETECTOR
# ============================================================

from src.rules.rules import predict, detect_injection


# ============================================================
# DATASET PATH
# ============================================================

VALIDATION_PATH = PROJECT_ROOT / "data" / "processed" / "validation_processed.csv"


# ============================================================
# MAIN EVALUATION
# ============================================================

def main():

    print("=" * 70)
    print("RULE-BASED PROMPT INJECTION DETECTOR EVALUATION")
    print("=" * 70)

    # --------------------------------------------------------
    # Check dataset
    # --------------------------------------------------------

    if not VALIDATION_PATH.exists():
        print("\nERROR: Validation dataset not found.")
        print("Expected location:")
        print(VALIDATION_PATH)
        return

    # --------------------------------------------------------
    # Load validation dataset
    # --------------------------------------------------------

    print("\nLoading validation dataset...")

    df = pd.read_csv(VALIDATION_PATH)

    print(f"Validation samples: {len(df)}")

    print("\nColumns:")
    print(df.columns.tolist())

    # --------------------------------------------------------
    # Check required columns
    # --------------------------------------------------------

    required_columns = [
        "text",
        "label",
        "is_injection"
    ]

    for column in required_columns:

        if column not in df.columns:
            print(f"\nERROR: Missing column: {column}")
            return

    # --------------------------------------------------------
    # Generate predictions
    # --------------------------------------------------------

    print("\nRunning rule-based detector...")

    predictions = []

    for text in df["text"]:

        prediction = predict(text)

        predictions.append(prediction)

    df["prediction"] = predictions

    # --------------------------------------------------------
    # Actual and predicted labels
    # --------------------------------------------------------

    y_true = df["is_injection"].astype(int)
    y_pred = df["prediction"].astype(int)

    # --------------------------------------------------------
    # Calculate metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_true,
        y_pred
    )

    # --------------------------------------------------------
    # Print results
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("RULE-BASED DETECTOR RESULTS")
    print("=" * 70)

    print(f"\nAccuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    print("\n                 Predicted")
    print("                 Benign  Injection")
    print(
        f"Actual Benign    {cm[0][0]:6d}  {cm[0][1]:9d}"
    )
    print(
        f"Actual Injection {cm[1][0]:6d}  {cm[1][1]:9d}"
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("CLASSIFICATION REPORT")
    print("=" * 70)

    print(
        classification_report(
            y_true,
            y_pred,
            target_names=[
                "BENIGN",
                "INJECTION"
            ],
            zero_division=0
        )
    )

    # --------------------------------------------------------
    # Count predictions
    # --------------------------------------------------------

    benign_predictions = (y_pred == 0).sum()
    injection_predictions = (y_pred == 1).sum()

    print("=" * 70)
    print("PREDICTION DISTRIBUTION")
    print("=" * 70)

    print(f"\nPredicted BENIGN    : {benign_predictions}")
    print(f"Predicted INJECTION : {injection_predictions}")

    # --------------------------------------------------------
    # Compare actual distribution
    # --------------------------------------------------------

    actual_benign = (y_true == 0).sum()
    actual_injection = (y_true == 1).sum()

    print("\nActual BENIGN       :", actual_benign)
    print("Actual INJECTION    :", actual_injection)

    # --------------------------------------------------------
    # Error analysis
    # --------------------------------------------------------

    false_positives = df[
        (df["is_injection"] == 0) &
        (df["prediction"] == 1)
    ]

    false_negatives = df[
        (df["is_injection"] == 1) &
        (df["prediction"] == 0)
    ]

    print("\n" + "=" * 70)
    print("ERROR ANALYSIS")
    print("=" * 70)

    print(
        f"\nFalse Positives: {len(false_positives)}"
    )

    print(
        f"False Negatives: {len(false_negatives)}"
    )

    # --------------------------------------------------------
    # Show some false negatives
    # --------------------------------------------------------

    if len(false_negatives) > 0:

        print("\n" + "-" * 70)
        print("EXAMPLE FALSE NEGATIVES")
        print("-" * 70)

        for _, row in false_negatives.head(10).iterrows():

            print("\nPrompt:")
            print(row["text"])

            print("\nActual label:")
            print(row["label"])

            print("-" * 70)

    # --------------------------------------------------------
    # Show some false positives
    # --------------------------------------------------------

    if len(false_positives) > 0:

        print("\n" + "-" * 70)
        print("EXAMPLE FALSE POSITIVES")
        print("-" * 70)

        for _, row in false_positives.head(10).iterrows():

            print("\nPrompt:")
            print(row["text"])

            print("\nActual label:")
            print(row["label"])

            print("-" * 70)

    # --------------------------------------------------------
    # Save evaluation results
    # --------------------------------------------------------

    output_path = PROJECT_ROOT / "data" / "processed" / "rule_evaluation_results.csv"

    df.to_csv(
        output_path,
        index=False
    )

    print("\n" + "=" * 70)
    print("EVALUATION COMPLETE")
    print("=" * 70)

    print("\nResults saved to:")
    print(output_path)


# ============================================================
# RUN PROGRAM
# ============================================================

if __name__ == "__main__":
    main()