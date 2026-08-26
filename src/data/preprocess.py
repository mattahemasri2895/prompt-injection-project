import pandas as pd
import numpy as np


TRAIN_PATH = "data/raw/train.parquet"
VALIDATION_PATH = "data/raw/validation.parquet"

TRAIN_OUTPUT = "data/processed/train_processed.csv"
VALIDATION_OUTPUT = "data/processed/validation_processed.csv"


def clean_label(label_array):
    """
    Convert numpy array labels into a simple string.

    Examples:
    ['BENIGN'] -> BENIGN
    ['JAILBREAK', 'INSTRUCTION_OVERRIDE']
        -> JAILBREAK|INSTRUCTION_OVERRIDE
    """

    labels = list(label_array)

    if "BENIGN" in labels:
        return "BENIGN"

    return "|".join(labels)


def preprocess_dataset(input_path, output_path):

    print(f"Loading: {input_path}")

    df = pd.read_parquet(input_path)

    print("Original shape:", df.shape)

    # Remove missing prompts
    df = df.dropna(subset=["text"])

    # Convert prompts to string
    df["text"] = df["text"].astype(str)

    # Convert numpy-array labels to strings
    df["label"] = df["labels"].apply(clean_label)

    # Binary classification target
    # 0 = benign
    # 1 = prompt injection
    df["is_injection"] = (df["label"] != "BENIGN").astype(int)

    # Keep only required columns
    df = df[["text", "label", "is_injection"]]

    print("Processed shape:", df.shape)

    print("\nLabel distribution:")
    print(df["label"].value_counts())

    print("\nBinary distribution:")
    print(df["is_injection"].value_counts())

    # Save
    df.to_csv(output_path, index=False)

    print(f"\nSaved to: {output_path}")


if __name__ == "__main__":

    preprocess_dataset(
        TRAIN_PATH,
        TRAIN_OUTPUT
    )

    preprocess_dataset(
        VALIDATION_PATH,
        VALIDATION_OUTPUT
    )

    print("\nPreprocessing completed successfully!")