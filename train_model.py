import os
import re
import pickle
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


DATASET = "email.csv"
MODEL_DIR = "model"

MODEL_FILE = os.path.join(MODEL_DIR, "model.pkl")
VECTORIZER_FILE = os.path.join(MODEL_DIR, "vectorizer.pkl")
METRICS_FILE = os.path.join(MODEL_DIR, "metrics.pkl")


def clean_text(text):
    """Basic text normalization."""

    text = str(text)

    text = text.lower()

    # Replace URLs with a common token
    text = re.sub(
        r"https?://\S+|www\.\S+",
        " URL ",
        text
    )

    # Replace email addresses
    text = re.sub(
        r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
        " EMAIL ",
        text
    )

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def main():

    print("=" * 60)
    print("PHISHING EMAIL DETECTOR - MODEL TRAINING")
    print("=" * 60)

    if not os.path.exists(DATASET):
        print("ERROR: email.csv was not found.")
        return

    # ---------------------------------------------------------
    # LOAD DATA
    # ---------------------------------------------------------

    df = pd.read_csv(DATASET)

    required_columns = ["text", "label"]

    for column in required_columns:
        if column not in df.columns:
            print(f"ERROR: Missing column: {column}")
            return

    df = df[["text", "label"]].dropna()

    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.strip()

    # Keep only valid labels
    df = df[df["label"].isin(["Phishing", "Safe"])]

    # Remove duplicate emails
    df = df.drop_duplicates(subset=["text"])

    if len(df) < 10:
        print("ERROR: Dataset is too small.")
        return

    print("\nDataset information")
    print("-" * 40)

    print("Total emails:", len(df))
    print("Phishing emails:", (df["label"] == "Phishing").sum())
    print("Safe emails:", (df["label"] == "Safe").sum())

    print("\nLabel distribution:")
    print(df["label"].value_counts())

    # ---------------------------------------------------------
    # CLEAN TEXT
    # ---------------------------------------------------------

    X = df["text"].apply(clean_text)
    y = df["label"]

    # ---------------------------------------------------------
    # TRAIN / TEST SPLIT
    # ---------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\nTraining emails:", len(X_train))
    print("Testing emails:", len(X_test))

    # ---------------------------------------------------------
    # TF-IDF
    # ---------------------------------------------------------

    word_vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        min_df=1,
        max_df=0.98,
        sublinear_tf=True,
        max_features=20000
    )

    char_vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=1,
        max_features=30000,
        sublinear_tf=True
    )

    vectorizer = FeatureUnion([
        ("word", word_vectorizer),
        ("char", char_vectorizer)
    ])

    X_train_vectorized = vectorizer.fit_transform(X_train)
    X_test_vectorized = vectorizer.transform(X_test)

    print("\nTF-IDF features:", X_train_vectorized.shape[1])

    # ---------------------------------------------------------
    # MODEL
    # ---------------------------------------------------------

    model = LogisticRegression(
        max_iter=3000,
        class_weight="balanced",
        random_state=42
    )

    model.fit(X_train_vectorized, y_train)

    # ---------------------------------------------------------
    # PREDICTION
    # ---------------------------------------------------------

    y_pred = model.predict(X_test_vectorized)

    # ---------------------------------------------------------
    # METRICS
    # ---------------------------------------------------------

    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test,
        y_pred,
        pos_label="Phishing",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        pos_label="Phishing",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        pos_label="Phishing",
        zero_division=0
    )

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=["Safe", "Phishing"]
    )

    # ---------------------------------------------------------
    # PRINT RESULTS
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("MODEL PERFORMANCE")
    print("=" * 60)

    print(f"Accuracy : {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall   : {recall * 100:.2f}%")
    print(f"F1 Score : {f1 * 100:.2f}%")

    print("\nConfusion Matrix")
    print("Rows = Actual")
    print("Columns = Predicted")
    print()
    print("              Safe  Phishing")
    print(f"Safe          {cm[0][0]:4d}    {cm[0][1]:4d}")
    print(f"Phishing      {cm[1][0]:4d}    {cm[1][1]:4d}")

    print("\nClassification Report")
    print(
        classification_report(
            y_test,
            y_pred,
            labels=["Safe", "Phishing"],
            zero_division=0
        )
    )

    # ---------------------------------------------------------
    # SAVE MODEL
    # ---------------------------------------------------------

    os.makedirs(MODEL_DIR, exist_ok=True)

    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)

    with open(VECTORIZER_FILE, "wb") as f:
        pickle.dump(vectorizer, f)

    metrics = {
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1 * 100, 2),
        "confusion_matrix": cm.tolist(),
        "total_emails": int(len(df)),
        "phishing_count": int((df["label"] == "Phishing").sum()),
        "safe_count": int((df["label"] == "Safe").sum()),
        "training_count": int(len(X_train)),
        "testing_count": int(len(X_test))
    }

    with open(METRICS_FILE, "wb") as f:
        pickle.dump(metrics, f)

    print("\n" + "=" * 60)
    print("TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 60)

    print("\nCreated files:")
    print("model/model.pkl")
    print("model/vectorizer.pkl")
    print("model/metrics.pkl")


if __name__ == "__main__":
    main()