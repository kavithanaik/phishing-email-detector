from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

import os
import re
import joblib


app = Flask(__name__)
CORS(app)


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = os.path.join(
    "model",
    "model.pkl"
)

METRICS_PATH = os.path.join(
    "model",
    "metrics.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

model_data = None
metrics = None

try:

    model_data = joblib.load(MODEL_PATH)

    metrics = joblib.load(METRICS_PATH)

    print("\nMachine learning model loaded successfully.")

except Exception as e:

    print("\nWARNING: Machine learning model not loaded.")
    print("ERROR:", e)


# ============================================================
# SECURITY FEATURE ANALYSIS
# ============================================================

def analyze_email_security(text):

    text = str(text)

    # Find URLs
    urls = re.findall(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        text,
        flags=re.IGNORECASE
    )

    suspicious_urls = []

    ip_urls = []

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

        lower_url = url.lower()

        if any(
            word in lower_url
            for word in suspicious_words
        ):
            suspicious_urls.append(url)

        if re.search(
            r'https?://(?:\d{1,3}\.){3}\d{1,3}',
            url
        ):
            ip_urls.append(url)

    # Email statistics

    email_length = len(text)

    exclamation_marks = text.count("!")

    special_characters = len(
        re.findall(
            r'[^a-zA-Z0-9\s]',
            text
        )
    )

    digits = sum(
        character.isdigit()
        for character in text
    )

    # Average URL length

    if urls:

        avg_url_length = sum(
            len(url)
            for url in urls
        ) / len(urls)

    else:

        avg_url_length = 0.0

    return {

        "urls_found": len(urls),

        "suspicious_urls": len(
            suspicious_urls
        ),

        "ip_urls": len(ip_urls),

        "email_length": email_length,

        "avg_url_length": round(
            avg_url_length,
            2
        ),

        "exclamation_marks":
            exclamation_marks,

        "special_characters":
            special_characters,

        "digits":
            digits,

        "urls":
            urls,

        "suspicious_url_list":
            suspicious_urls,

        "ip_url_list":
            ip_urls
    }


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# PREDICTION API
# ============================================================

@app.route(
    "/predict",
    methods=["POST"]
)
def predict():

    # Check model

    if model_data is None:

        return jsonify({
            "success": False,
            "error":
                "Machine learning model is not loaded."
        }), 500


    # Get request data

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify({
            "success": False,
            "error":
                "No email data received."
        }), 400


    email_text = data.get(
        "email",
        ""
    )


    # Validate email

    if not email_text.strip():

        return jsonify({
            "success": False,
            "error":
                "Please enter an email."
        }), 400


    # ========================================================
    # GET MODEL COMPONENTS
    # ========================================================

    model = model_data["model"]

    word_vectorizer = model_data[
        "word_vectorizer"
    ]

    char_vectorizer = model_data[
        "char_vectorizer"
    ]


    # ========================================================
    # TEXT FEATURES
    # ========================================================

    word_features = word_vectorizer.transform(
        [email_text]
    )

    char_features = char_vectorizer.transform(
        [email_text]
    )


    # ========================================================
    # SECURITY FEATURES
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

        security["digits"],

        security["special_characters"],

        0,

        sum(
            email_text.lower().count(keyword)
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

    ]]


    from scipy.sparse import csr_matrix

    security_features = csr_matrix(
        security_values
    )


    # ========================================================
    # COMBINE FEATURES
    # ========================================================

    from scipy.sparse import hstack

    features = hstack([

        word_features,

        char_features,

        security_features

    ])


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
            class_name
        ] = round(
            float(probability) * 100,
            2
        )


    # Make sure both labels exist

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


    # ========================================================
    # REASONS
    # ========================================================

    reasons = []


    if security["suspicious_urls"] > 0:

        reasons.append(
            "Suspicious URL detected."
        )


    if security["ip_urls"] > 0:

        reasons.append(
            "IP-based URL detected."
        )


    if security["exclamation_marks"] >= 2:

        reasons.append(
            "Multiple exclamation marks detected."
        )


    lower_email = email_text.lower()


    urgent_words = [
        "urgent",
        "immediately",
        "final warning",
        "action required"
    ]


    for word in urgent_words:

        if word in lower_email:

            reasons.append(
                f"Urgency indicator detected: '{word}'."
            )

            break


    sensitive_words = [
        "password",
        "bank details",
        "credit card",
        "verify your account",
        "login"
    ]


    for word in sensitive_words:

        if word in lower_email:

            reasons.append(
                f"Sensitive information request detected: '{word}'."
            )

            break


    if not reasons:

        if prediction == "Safe":

            reasons.append(
                "No major phishing indicators detected."
            )

        else:

            reasons.append(
                "The machine learning model detected suspicious textual patterns."
            )


    # ========================================================
    # RESPONSE
    # ========================================================

    return jsonify({

        "success": True,

        "prediction":
            prediction,

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
    print("=" * 60)
    print("        PHISHING EMAIL DETECTOR")
    print("=" * 60)

    print(
        "\nOpen your browser:"
    )

    print(
        "http://127.0.0.1:5000/"
    )

    print(
        "\nPress CTRL+C to stop the server."
    )

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )