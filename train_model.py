import os
import re
import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# SETTINGS
# ============================================================

DATASET = "email.csv"
MODEL_DIR = "model"

os.makedirs(MODEL_DIR, exist_ok=True)


print("=" * 70)
print("          PHISHING EMAIL DETECTOR - MODEL TRAINING")
print("=" * 70)


# ============================================================
# LOAD DATA
# ============================================================

try:
    df = pd.read_csv(DATASET)
except Exception as e:
    print("\nERROR reading email.csv:")
    print(e)
    exit()


if "text" not in df.columns or "label" not in df.columns:
    print("\nERROR: email.csv must contain:")
    print("text,label")
    exit()


# ============================================================
# CLEAN DATA
# ============================================================

df = df.dropna(subset=["text", "label"])

df["text"] = df["text"].astype(str).str.strip()

df["label"] = df["label"].astype(str).str.strip().str.lower()

df["label"] = df["label"].replace({
    "phishing": "Phishing",
    "safe": "Safe",
    "legitimate": "Safe",
    "legit": "Safe"
})

df = df[df["label"].isin(["Phishing", "Safe"])]

df = df.drop_duplicates(subset=["text"])

print("\nDataset information")
print("-" * 70)
print("Total emails:", len(df))
print("\nClass distribution:")
print(df["label"].value_counts())


# ============================================================
# SECURITY FEATURE EXTRACTION
# ============================================================

def security_features(text):

    text = str(text)

    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        text,
        flags=re.IGNORECASE
    )

    url_count = len(urls)

    suspicious_url_count = 0

    for url in urls:

        suspicious_words = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "confirm",
            "password",
            "bank",
            "payment",
            "wallet",
            "reward",
            "claim",
            "security"
        ]

        if any(word in url.lower() for word in suspicious_words):
            suspicious_url_count += 1

    ip_url_count = 0

    for url in urls:

        if re.search(
            r'https?://(?:\d{1,3}\.){3}\d{1,3}',
            url
        ):
            ip_url_count += 1

    length = len(text)

    exclamation_count = text.count("!")

    digit_count = sum(
        character.isdigit()
        for character in text
    )

    special_count = len(
        re.findall(
            r'[^a-zA-Z0-9\s]',
            text
        )
    )

    uppercase_count = sum(
        1 for word in text.split()
        if len(word) > 2 and word.isupper()
    )

    suspicious_keyword_count = sum(
        text.lower().count(keyword)
        for keyword in [
            "urgent",
            "immediately",
            "verify",
            "suspended",
            "password",
            "account",
            "click",
            "winner",
            "prize",
            "claim",
            "security",
            "blocked",
            "limited",
            "confirm",
            "payment",
            "refund"
        ]
    )

    return [
        url_count,
        suspicious_url_count,
        ip_url_count,
        length,
        exclamation_count,
        digit_count,
        special_count,
        uppercase_count,
        suspicious_keyword_count
    ]


print("\nExtracting security features...")

security_matrix = [
    security_features(text)
    for text in df["text"]
]

security_matrix = csr_matrix(security_matrix)


# ============================================================
# TRAIN TEST SPLIT
# ============================================================

X_train_text, X_test_text, y_train, y_test, \
X_train_sec, X_test_sec = train_test_split(

    df["text"],
    df["label"],
    security_matrix,

    test_size=0.20,

    random_state=42,

    stratify=df["label"]
)


print("\nTraining emails:", len(X_train_text))
print("Testing emails :", len(X_test_text))


# ============================================================
# WORD TF-IDF
# ============================================================

print("\nCreating WORD TF-IDF features...")

word_vectorizer = TfidfVectorizer(

    lowercase=True,

    stop_words="english",

    ngram_range=(1, 2),

    sublinear_tf=True,

    min_df=1,

    max_features=50000
)


X_train_word = word_vectorizer.fit_transform(
    X_train_text
)

X_test_word = word_vectorizer.transform(
    X_test_text
)


# ============================================================
# CHARACTER TF-IDF
# ============================================================

print("Creating CHARACTER TF-IDF features...")

char_vectorizer = TfidfVectorizer(

    analyzer="char",

    ngram_range=(3, 5),

    sublinear_tf=True,

    min_df=1,

    max_features=50000
)


X_train_char = char_vectorizer.fit_transform(
    X_train_text
)

X_test_char = char_vectorizer.transform(
    X_test_text
)


# ============================================================
# COMBINE ALL FEATURES
# ============================================================

X_train = hstack([
    X_train_word,
    X_train_char,
    X_train_sec
])

X_test = hstack([
    X_test_word,
    X_test_char,
    X_test_sec
])


print("\nFinal training feature shape:")
print(X_train.shape)


# ============================================================
# BASE MODEL
# ============================================================

print("\nTraining Logistic Regression...")

base_model = LogisticRegression(

    max_iter=5000,

    C=5.0,

    class_weight="balanced",

    solver="liblinear"
)


# ============================================================
# CALIBRATED MODEL
# ============================================================

print("Calibrating prediction probabilities...")

model = CalibratedClassifierCV(

    estimator=base_model,

    method="sigmoid",

    cv=3
)


model.fit(
    X_train,
    y_train
)


# ============================================================
# EVALUATION
# ============================================================

y_pred = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    y_pred
)

matrix = confusion_matrix(

    y_test,

    y_pred,

    labels=[
        "Phishing",
        "Safe"
    ]
)


print("\n")
print("=" * 70)
print("                    MODEL PERFORMANCE")
print("=" * 70)

print(
    f"\nAccuracy: {accuracy * 100:.2f}%"
)

print("\nConfusion Matrix:")
print(matrix)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        labels=[
            "Phishing",
            "Safe"
        ],
        zero_division=0
    )
)


# ============================================================
# SAVE EVERYTHING
# ============================================================

model_data = {

    "model": model,

    "word_vectorizer": word_vectorizer,

    "char_vectorizer": char_vectorizer
}


joblib.dump(
    model_data,
    os.path.join(
        MODEL_DIR,
        "model.pkl"
    )
)


metrics = {

    "accuracy": float(accuracy),

    "confusion_matrix":
        matrix.tolist(),

    "total_emails":
        int(len(df)),

    "phishing_count":
        int(
            (df["label"] == "Phishing").sum()
        ),

    "safe_count":
        int(
            (df["label"] == "Safe").sum()
        ),

    "feature_type":
        "Word TF-IDF + Character TF-IDF + Security Features",

    "probability_calibration":
        "Sigmoid"
}


joblib.dump(
    metrics,
    os.path.join(
        MODEL_DIR,
        "metrics.pkl"
    )
)


# Save security feature information separately

joblib.dump(
    security_features,
    os.path.join(
        MODEL_DIR,
        "security_features.pkl"
    )
)


print("\n")
print("=" * 70)
print("                    TRAINING COMPLETE")
print("=" * 70)

print("\nCreated:")

print("model/model.pkl")
print("model/metrics.pkl")
print("model/security_features.pkl")

print(
    f"\nFinal model accuracy: "
    f"{accuracy * 100:.2f}%"
)

print("\nIMPORTANT:")
print("The displayed confidence will come from the trained model.")
print("It is NOT hard-coded to 99%.")

print("=" * 70)