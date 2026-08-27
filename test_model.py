import os
import re
import joblib

from scipy.sparse import hstack, csr_matrix


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = os.path.join(
    "model",
    "model.pkl"
)


# ============================================================
# SECURITY FEATURE EXTRACTION
# ============================================================

def extract_security_features(text):

    text = str(text)
    lower = text.lower()

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        text,
        flags=re.IGNORECASE
    )

    url_count = len(urls)

    # --------------------------------------------------------
    # Suspicious URLs
    # --------------------------------------------------------

    suspicious_url_words = [
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
            for word in suspicious_url_words
        ):
            suspicious_url_count += 1

    # --------------------------------------------------------
    # IP-based URLs
    # --------------------------------------------------------

    ip_url_count = 0

    for url in urls:

        if re.search(
            r'https?://(?:\d{1,3}\.){3}\d{1,3}',
            url
        ):
            ip_url_count += 1

    # --------------------------------------------------------
    # Basic email statistics
    # --------------------------------------------------------

    email_length = len(text)

    exclamation_count = text.count("!")

    question_count = text.count("?")

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

    # --------------------------------------------------------
    # Uppercase words
    # --------------------------------------------------------

    uppercase_words = sum(
        1
        for word in text.split()
        if len(word) >= 3 and word.isupper()
    )

    # --------------------------------------------------------
    # Phishing keywords
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Sensitive information requests
    # --------------------------------------------------------

    sensitive_requests = [
        "enter your password",
        "enter your username",
        "provide your password",
        "provide your bank",
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
        for word in sensitive_requests
    )

    # --------------------------------------------------------
    # Urgency indicators
    # --------------------------------------------------------

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
# LOAD MODEL
# ============================================================

print("\n")
print("=" * 70)
print("              PHISHING EMAIL DETECTOR")
print("=" * 70)

try:

    data = joblib.load(
        MODEL_PATH
    )

    model = data["model"]

    word_vectorizer = data[
        "word_vectorizer"
    ]

    char_vectorizer = data[
        "char_vectorizer"
    ]

    print("\nMachine learning model loaded successfully.")

except Exception as e:

    print("\nERROR: Could not load the model.")
    print("Reason:", e)
    exit()


# ============================================================
# PREDICTION FUNCTION
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
    security = extract_security_features(
        email
    )

    security_features = csr_matrix(
        [security]
    )

    # Combine all features
    features = hstack([
        word_features,
        char_features,
        security_features
    ])

    # Prediction
    prediction = model.predict(
        features
    )[0]

    # Probabilities
    probabilities = model.predict_proba(
        features
    )[0]

    classes = model.classes_

    probability_data = {}

    for class_name, probability in zip(
        classes,
        probabilities
    ):

        probability_data[class_name] = (
            float(probability) * 100
        )

    phishing_probability = probability_data.get(
        "Phishing",
        0.0
    )

    safe_probability = probability_data.get(
        "Safe",
        0.0
    )

    confidence = max(
        phishing_probability,
        safe_probability
    )

    return (
        prediction,
        phishing_probability,
        safe_probability,
        confidence
    )


# ============================================================
# PHISHING EMAIL
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

print()

# Print complete phishing email
print(phishing_email.strip())

print()
print("-" * 70)

# Predict phishing email
prediction, phishing, safe, confidence = predict_email(
    phishing_email
)

print()
print("Prediction:", prediction)
print(f"Phishing:   {phishing:.2f}%")
print(f"Safe:       {safe:.2f}%")
print(f"Confidence: {confidence:.2f}%")

print("-" * 70)


# ============================================================
# SAFE EMAIL
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

print()

# Print complete safe email
print(safe_email.strip())

print()
print("-" * 70)

# Predict safe email
prediction, phishing, safe, confidence = predict_email(
    safe_email
)

print()
print("Prediction:", prediction)
print(f"Phishing:   {phishing:.2f}%")
print(f"Safe:       {safe:.2f}%")
print(f"Confidence: {confidence:.2f}%")

print("-" * 70)


# ============================================================
# END
# ============================================================

print("\n")
print("=" * 70)
print("                    TEST COMPLETE")
print("=" * 70)