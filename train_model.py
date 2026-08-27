import os
import re
import joblib
import pandas as pd

from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion
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
print("       PHISHING EMAIL DETECTOR - MODEL TRAINING")
print("=" * 70)


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_csv(DATASET)

print("\nDataset information")
print("-" * 70)

print("Total emails:", len(df))


# ============================================================
# CLEAN DATA
# ============================================================

df = df.dropna(
    subset=["text", "label"]
)

df["text"] = (
    df["text"]
    .astype(str)
    .str.strip()
)

df["label"] = (
    df["label"]
    .astype(str)
    .str.strip()
    .str.lower()
)

df["label"] = df["label"].replace({

    "phishing": "Phishing",

    "safe": "Safe",

    "legitimate": "Safe",

    "legit": "Safe"

})


df = df[
    df["label"].isin(
        ["Phishing", "Safe"]
    )
]


df = df.drop_duplicates(
    subset=["text"]
)


print("\nAfter cleaning:")
print("Total emails:", len(df))

print("\nClass distribution:")
print(
    df["label"].value_counts()
)


# ============================================================
# SECURITY FEATURE EXTRACTION
# ============================================================

def security_features(text):

    text = str(text)

    lower = text.lower()

    # URLs
    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        text,
        flags=re.IGNORECASE
    )

    url_count = len(urls)

    # Suspicious URLs
    suspicious_words = [

        "login",
        "verify",
        "verification",
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
        "security",
        "unlock",
        "signin"

    ]

    suspicious_url_count = 0

    for url in urls:

        if any(
            word in url.lower()
            for word in suspicious_words
        ):

            suspicious_url_count += 1


    # IP URL
    ip_url_count = 0

    for url in urls:

        if re.search(
            r'https?://(?:\d{1,3}\.){3}\d{1,3}',
            url
        ):

            ip_url_count += 1


    # Length
    email_length = len(text)


    # Exclamation
    exclamation_count = text.count("!")


    # Question marks
    question_count = text.count("?")


    # Digits
    digit_count = sum(
        c.isdigit()
        for c in text
    )


    # Special characters
    special_count = len(
        re.findall(
            r'[^a-zA-Z0-9\s]',
            text
        )
    )


    # Uppercase words
    uppercase_words = sum(

        1

        for word in text.split()

        if len(word) >= 3
        and word.isupper()

    )


    # Phishing keywords
    phishing_keywords = [

        "urgent",
        "immediately",
        "action required",
        "final warning",
        "verify",
        "verification",
        "suspended",
        "suspension",
        "password",
        "account",
        "click",
        "winner",
        "prize",
        "claim",
        "security alert",
        "unauthorized",
        "transaction",
        "blocked",
        "limited",
        "confirm",
        "payment",
        "refund",
        "bank",
        "login",
        "sign in",
        "unlock",
        "expire",
        "expired",
        "24 hours",
        "kyc",
        "credit card",
        "billing",
        "credentials"

    ]

    keyword_count = sum(

        lower.count(keyword)

        for keyword in phishing_keywords

    )


    # Sensitive information
    sensitive_words = [

        "enter your password",
        "enter your username",
        "provide your password",
        "bank details",
        "credit card details",
        "card number",
        "login credentials",
        "verify your identity",
        "confirm your account",
        "update your payment",
        "submit your information"

    ]

    sensitive_count = sum(

        lower.count(word)

        for word in sensitive_words

    )


    # Urgency
    urgency_words = [

        "urgent",
        "immediately",
        "now",
        "as soon as possible",
        "within 24 hours",
        "final warning",
        "last chance",
        "action required"

    ]

    urgency_count = sum(

        lower.count(word)

        for word in urgency_words

    )


    return [

        url_count,

        suspicious_url_count,

        ip_url_count,

        email_length,

        exclamation_count,

        question_count,

        digit_count,

        special_count,

        uppercase_words,

        keyword_count,

        sensitive_count,

        urgency_count

    ]


# ============================================================
# CREATE SECURITY FEATURES
# ============================================================

print("\nExtracting security features...")

security_matrix = [

    security_features(text)

    for text in df["text"]

]

security_matrix = csr_matrix(
    security_matrix
)


# ============================================================
# TRAIN TEST SPLIT
# ============================================================

X_train_text, X_test_text, \
y_train, y_test, \
X_train_sec, X_test_sec = train_test_split(

    df["text"],

    df["label"],

    security_matrix,

    test_size=0.20,

    random_state=42,

    stratify=df["label"]

)


print("\nTraining emails:", len(X_train_text))

print(
    "Testing emails :",
    len(X_test_text)
)


# ============================================================
# WORD TF-IDF
# ============================================================

print("\nCreating WORD TF-IDF...")

word_vectorizer = TfidfVectorizer(

    lowercase=True,

    stop_words="english",

    ngram_range=(1, 3),

    sublinear_tf=True,

    min_df=1,

    max_features=100000

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

print("Creating CHARACTER TF-IDF...")

char_vectorizer = TfidfVectorizer(

    analyzer="char",

    ngram_range=(2, 6),

    sublinear_tf=True,

    min_df=1,

    max_features=100000

)


X_train_char = char_vectorizer.fit_transform(
    X_train_text
)

X_test_char = char_vectorizer.transform(
    X_test_text
)


# ============================================================
# COMBINE FEATURES
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


print("\nFinal feature shape:")

print(
    X_train.shape
)


# ============================================================
# TRAIN MODEL
# ============================================================

print("\nTraining Logistic Regression...")

model = LogisticRegression(

    max_iter=5000,

    C=10,

    class_weight="balanced",

    solver="liblinear"

)


model.fit(

    X_train,

    y_train

)


# ============================================================
# TEST
# ============================================================

y_pred = model.predict(
    X_test
)


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
# SAVE MODEL
# ============================================================

model_data = {

    "model": model,

    "word_vectorizer":
        word_vectorizer,

    "char_vectorizer":
        char_vectorizer

}


joblib.dump(

    model_data,

    os.path.join(
        MODEL_DIR,
        "model.pkl"
    )

)


# ============================================================
# SAVE METRICS
# ============================================================

metrics = {

    "accuracy":
        float(accuracy),

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
        "Word TF-IDF + Character TF-IDF + Security Features"

}


joblib.dump(

    metrics,

    os.path.join(
        MODEL_DIR,
        "metrics.pkl"
    )

)


# ============================================================
# SAVE SECURITY FUNCTION
# ============================================================

joblib.dump(

    security_features,

    os.path.join(
        MODEL_DIR,
        "security_features.pkl"
    )

)


# ============================================================
# COMPLETE
# ============================================================

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

print("=" * 70)