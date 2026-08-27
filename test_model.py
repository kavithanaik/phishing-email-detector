import re
import joblib
from scipy.sparse import hstack, csr_matrix


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = "model/model.pkl"


# ============================================================
# LOAD MODEL
# ============================================================

data = joblib.load(MODEL_PATH)

model = data["model"]

word_vectorizer = data["word_vectorizer"]

char_vectorizer = data["char_vectorizer"]


print("=" * 70)
print("        PHISHING EMAIL DETECTOR - MODEL TEST")
print("=" * 70)


# ============================================================
# SECURITY FEATURES
# MUST MATCH train_model.py EXACTLY
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

    for url in urls:

        if any(
            word in url.lower()
            for word in suspicious_words
        ):
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
        1
        for word in text.split()
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


# ============================================================
# PREDICT EMAIL
# ============================================================

def predict_email(email):

    # Word TF-IDF
    word_features = word_vectorizer.transform(
        [email]
    )

    # Character TF-IDF
    char_features = char_vectorizer.transform(
        [email]
    )

    # Security features
    security = csr_matrix([
        security_features(email)
    ])

    # Combine EXACTLY like train_model.py
    features = hstack([
        word_features,
        char_features,
        security
    ]).tocsr()

    print("\nFeature count:", features.shape[1])

    # Model expected features
    expected_features = model.calibrated_classifiers_[0].estimator.n_features_in_

    print(
        "Model expected:",
        expected_features
    )

    # Safety check
    if features.shape[1] != expected_features:

        raise ValueError(
            f"Feature mismatch! "
            f"Test created {features.shape[1]} "
            f"features but model expects "
            f"{expected_features}."
        )

    # Prediction
    prediction = model.predict(
        features
    )[0]

    probabilities = model.predict_proba(
        features
    )[0]

    classes = model.classes_

    probability_data = {}

    for class_name, probability in zip(
        classes,
        probabilities
    ):

        probability_data[
            class_name
        ] = float(probability) * 100

    phishing = probability_data.get(
        "Phishing",
        0
    )

    safe = probability_data.get(
        "Safe",
        0
    )

    confidence = max(
        phishing,
        safe
    )

    return (
        prediction,
        phishing,
        safe,
        confidence
    )


# ============================================================
# TEST 1 - PHISHING
# ============================================================

phishing_email = """
URGENT SECURITY ALERT!

Your bank account has been temporarily suspended
due to suspicious activity.

Verify your account immediately by clicking:

http://secure-bank-verification.com/login

Enter your username and password to restore access.

Failure to verify within 24 hours will result in
permanent account closure.

Bank Security Team
"""


print("\n")
print("=" * 70)
print("PHISHING EMAIL")
print("=" * 70)

print(phishing_email)

prediction, phishing, safe, confidence = predict_email(
    phishing_email
)

print("-" * 70)

print(
    "\nPrediction:",
    prediction
)

print(
    f"Phishing:   {phishing:.2f}%"
)

print(
    f"Safe:       {safe:.2f}%"
)

print(
    f"Confidence: {confidence:.2f}%"
)

print("-" * 70)


# ============================================================
# TEST 2 - SAFE
# ============================================================

safe_email = """
Subject: Project Meeting Reminder

Hello Team,

This is a reminder that our project meeting is scheduled
for Monday at 10:00 AM in the seminar hall.

Please bring your project progress and presentation materials.

Thank you,
Project Coordinator
"""


print("\n")
print("=" * 70)
print("SAFE EMAIL")
print("=" * 70)

print(safe_email)

prediction, phishing, safe, confidence = predict_email(
    safe_email
)

print("-" * 70)

print(
    "\nPrediction:",
    prediction
)

print(
    f"Phishing:   {phishing:.2f}%"
)

print(
    f"Safe:       {safe:.2f}%"
)

print(
    f"Confidence: {confidence:.2f}%"
)

print("-" * 70)