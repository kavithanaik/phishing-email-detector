from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

import os
import re
import joblib

from scipy.sparse import hstack, csr_matrix


app = Flask(__name__)
CORS(app)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "model"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "model.pkl"
)

METRICS_PATH = os.path.join(
    MODEL_DIR,
    "metrics.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

model_data = None
metrics = {}


try:

    model_data = joblib.load(
        MODEL_PATH
    )

    if os.path.exists(
        METRICS_PATH
    ):

        metrics = joblib.load(
            METRICS_PATH
        )

    print(
        "\nMachine learning model loaded successfully."
    )

    print(
        "Model classes:",
        model_data["model"].classes_
    )

except Exception as e:

    print(
        "\nWARNING: Machine learning model not loaded."
    )

    print(
        "ERROR:",
        e
    )


# ============================================================
# SECURITY ANALYSIS
# ============================================================

SUSPICIOUS_URL_WORDS = [

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
    "security",
    "suspended",
    "blocked",
    "unlock"

]


SUSPICIOUS_KEYWORDS = [

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
    "refund",
    "bank",
    "login",
    "credential",
    "credentials",
    "expire",
    "expired",
    "action required",
    "final warning",
    "unauthorized",
    "transaction",
    "kyc"

]


def analyze_email_security(text):

    text = str(text)

    lower_text = text.lower()


    urls = re.findall(

        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',

        text,

        flags=re.IGNORECASE

    )


    suspicious_urls = []

    ip_urls = []


    total_url_length = 0


    for url in urls:

        clean_url = url.rstrip(
            ".,!?;:)"
        )

        lower_url = clean_url.lower()

        total_url_length += len(
            clean_url
        )


        if any(

            word in lower_url

            for word in SUSPICIOUS_URL_WORDS

        ):

            suspicious_urls.append(
                clean_url
            )


        if re.search(

            r'https?://(?:\d{1,3}\.){3}\d{1,3}',

            clean_url

        ):

            ip_urls.append(
                clean_url
            )


    if urls:

        average_url_length = (

            total_url_length
            /
            len(urls)

        )

    else:

        average_url_length = 0.0


    email_length = len(text)

    exclamation_count = text.count("!")

    question_count = text.count("?")

    digit_count = sum(

        c.isdigit()

        for c in text

    )


    special_character_count = len(

        re.findall(

            r'[^a-zA-Z0-9\s]',

            text

        )

    )


    uppercase_count = sum(

        1

        for word in text.split()

        if len(word) > 2
        and word.isupper()

    )


    suspicious_keyword_count = sum(

        lower_text.count(keyword)

        for keyword in SUSPICIOUS_KEYWORDS

    )


    sensitive_phrases = [

        "password",
        "bank details",
        "credit card",
        "card details",
        "login information",
        "login credentials",
        "personal information",
        "verify your account",
        "confirm your identity",
        "security code",
        "one time password",
        "otp"

    ]


    sensitive_count = sum(

        1

        for phrase in sensitive_phrases

        if phrase in lower_text

    )


    urgency_phrases = [

        "urgent",
        "immediately",
        "within 24 hours",
        "final warning",
        "action required",
        "expires today",
        "account will be closed",
        "account will be suspended"

    ]


    urgency_count = sum(

        1

        for phrase in urgency_phrases

        if phrase in lower_text

    )


    return {

        "urls_found":
            len(urls),

        "suspicious_urls":
            len(suspicious_urls),

        "ip_urls":
            len(ip_urls),

        "email_length":
            email_length,

        "avg_url_length":
            round(
                average_url_length,
                2
            ),

        "exclamation_marks":
            exclamation_count,

        "question_marks":
            question_count,

        "special_characters":
            special_character_count,

        "digits":
            digit_count,

        "uppercase_words":
            uppercase_count,

        "suspicious_keywords":
            suspicious_keyword_count,

        "sensitive_requests":
            sensitive_count,

        "urgency_indicators":
            urgency_count,

        "urls":
            urls,

        "suspicious_url_list":
            suspicious_urls,

        "ip_url_list":
            ip_urls

    }


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# PREDICT
# ============================================================

@app.route(
    "/predict",
    methods=["POST"]
)
def predict():

    if model_data is None:

        return jsonify({

            "success": False,

            "error":
                "Machine learning model is not loaded."

        }), 500


    data = request.get_json(
        silent=True
    )


    if not data:

        return jsonify({

            "success": False,

            "error":
                "No email data received."

        }), 400


    email_text = str(

        data.get(
            "email",
            ""
        )

    ).strip()


    if not email_text:

        return jsonify({

            "success": False,

            "error":
                "Please enter an email."

        }), 400


    try:

        model = model_data[
            "model"
        ]

        word_vectorizer = (
            model_data[
                "word_vectorizer"
            ]
        )

        char_vectorizer = (
            model_data[
                "char_vectorizer"
            ]
        )

        security_scaler = (
            model_data[
                "security_scaler"
            ]
        )


    except Exception as e:

        return jsonify({

            "success": False,

            "error":
                f"Model components missing: {str(e)}"

        }), 500


    # ========================================================
    # TEXT FEATURES
    # ========================================================

    word_features = (

        word_vectorizer.transform(

            [email_text]

        )

    )


    char_features = (

        char_vectorizer.transform(

            [email_text]

        )

    )


    # ========================================================
    # SECURITY
    # ========================================================

    security = analyze_email_security(
        email_text
    )


    security_values = [[

        security["urls_found"],

        security["suspicious_urls"],

        security["ip_urls"],

        security["email_length"],

        security["exclamation_marks"],

        security["question_marks"],

        security["digits"],

        security["special_characters"],

        security["uppercase_words"],

        security["suspicious_keywords"],

        security["sensitive_requests"],

        security["urgency_indicators"],

        security["avg_url_length"]

    ]]


    security_features = csr_matrix(
        security_values
    )


    security_features = (
        security_scaler.transform(
            security_features
        )
    )


    # ========================================================
    # COMBINE
    # ========================================================

    features = hstack([

        word_features,

        char_features,

        security_features

    ]).tocsr()


    # ========================================================
    # PREDICTION
    # ========================================================

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
            str(class_name)
        ] = round(

            float(probability) * 100,

            2

        )


    phishing_probability = (

        probability_data.get(
            "Phishing",
            0.0
        )

    )


    safe_probability = (

        probability_data.get(
            "Safe",
            0.0
        )

    )


    confidence = max(

        phishing_probability,

        safe_probability

    )


    # ========================================================
    # REASONS
    # ========================================================

    reasons = []


    if security[
        "suspicious_urls"
    ] > 0:

        reasons.append(
            "Suspicious URL detected."
        )


    if security[
        "ip_urls"
    ] > 0:

        reasons.append(
            "IP-based URL detected."
        )


    if security[
        "exclamation_marks"
    ] >= 2:

        reasons.append(
            "Multiple exclamation marks detected."
        )


    if security[
        "sensitive_requests"
    ] > 0:

        reasons.append(
            "Request for sensitive information detected."
        )


    if security[
        "urgency_indicators"
    ] > 0:

        reasons.append(
            "Urgency indicators detected."
        )


    if security[
        "suspicious_keywords"
    ] > 0:

        reasons.append(
            "Suspicious security-related keywords detected."
        )


    if not reasons:

        if prediction == "Safe":

            reasons.append(
                "No major phishing indicators detected."
            )

        else:

            reasons.append(
                "The machine-learning model detected suspicious textual patterns."
            )


    # ========================================================
    # RESPONSE
    # ========================================================

    return jsonify({

        "success":
            True,

        "prediction":
            str(prediction),

        "confidence":
            round(
                confidence,
                2
            ),

        "phishing_probability":
            phishing_probability,

        "safe_probability":
            safe_probability,

        "security":
            security,

        "reasons":
            reasons,

        "metrics":
            metrics

    })


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 70)
    print("             PHISHING EMAIL DETECTOR")
    print("=" * 70)

    print(
        "\nOpen:"
    )

    print(
        "http://127.0.0.1:5000/"
    )

    print(
        "\nPress CTRL+C to stop."
    )


    app.run(

        host="0.0.0.0",

        port=5000,

        debug=False

    )