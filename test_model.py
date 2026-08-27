import re
import joblib

from scipy.sparse import hstack, csr_matrix


# ============================================================
# LOAD MODEL
# ============================================================

MODEL_PATH = "model/model.pkl"

data = joblib.load(MODEL_PATH)

model = data["model"]

word_vectorizer = data["word_vectorizer"]

char_vectorizer = data["char_vectorizer"]


# ============================================================
# SECURITY FEATURES
# ============================================================

def security_features(text):

    text = str(text)

    lower = text.lower()

    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        text,
        flags=re.IGNORECASE
    )

    url_count = len(urls)

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

    ip_url_count = 0

    for url in urls:

        if re.search(
            r'https?://(?:\d{1,3}\.){3}\d{1,3}',
            url
        ):
            ip_url_count += 1

    email_length = len(text)

    exclamation_count = text.count("!")

    question_count = text.count("?")

    digit_count = sum(
        c.isdigit()
        for c in text
    )

    special_count = len(
        re.findall(
            r'[^a-zA-Z0-9\s]',
            text
        )
    )

    uppercase_words = sum(

        1

        for word in text.split()

        if len(word) >= 3
        and word.isupper()

    )

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
# PREDICT FUNCTION
# ============================================================

def predict_email(email):

    # Word features
    word_features = word_vectorizer.transform(
        [email]
    )

    # Character features
    char_features = char_vectorizer.transform(
        [email]
    )

    # Security features
    sec = security_features(email)

    security_matrix = csr_matrix(
        [sec]
    )

    # Combine
    features = hstack([

        word_features,

        char_features,

        security_matrix

    ])

    # Prediction
    prediction = model.predict(
        features
    )[0]

    probabilities = model.predict_proba(
        features
    )[0]

    classes = model.classes_

    probability_dict = {

        cls: float(prob)

        for cls, prob in zip(
            classes,
            probabilities
        )

    }

    phishing = (
        probability_dict.get(
            "Phishing",
            0
        ) * 100
    )

    safe = (
        probability_dict.get(
            "Safe",
            0
        ) * 100
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


print()
print("=" * 70)
print("PHISHING EMAIL")
print("=" * 70)

print()
print(phishing_email)

prediction, phishing, safe, confidence = predict_email(
    phishing_email
)

print("-" * 70)

print(
    "Prediction:",
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


print()
print("=" * 70)
print("SAFE EMAIL")
print("=" * 70)

print()
print(safe_email)

prediction, phishing, safe, confidence = predict_email(
    safe_email
)

print("-" * 70)

print(
    "Prediction:",
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