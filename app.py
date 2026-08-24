from flask import Flask, render_template, request, jsonify
import pickle
import os
import re


app = Flask(__name__)


MODEL_FILE = "model/model.pkl"
VECTORIZER_FILE = "model/vectorizer.pkl"
METRICS_FILE = "model/metrics.pkl"


# ---------------------------------------------------------
# LOAD MODEL
# ---------------------------------------------------------

try:

    with open(MODEL_FILE, "rb") as f:
        model = pickle.load(f)

    with open(VECTORIZER_FILE, "rb") as f:
        vectorizer = pickle.load(f)

    with open(METRICS_FILE, "rb") as f:
        metrics = pickle.load(f)

    MODEL_LOADED = True

except Exception as e:

    print("Model loading error:", e)

    model = None
    vectorizer = None
    metrics = {}

    MODEL_LOADED = False


# ---------------------------------------------------------
# SUSPICIOUS KEYWORDS
# ---------------------------------------------------------

PHISHING_KEYWORDS = [
    "verify your account",
    "verify your identity",
    "verify your password",
    "confirm your password",
    "confirm your identity",
    "account suspended",
    "account will be suspended",
    "account has been suspended",
    "account will be closed",
    "account has been compromised",
    "unusual activity",
    "suspicious activity",
    "security alert",
    "urgent action",
    "immediate action",
    "act immediately",
    "click here immediately",
    "click the link",
    "reset your password",
    "update your payment",
    "update billing information",
    "claim your reward",
    "claim your prize",
    "you have won",
    "lottery winner",
    "cash reward",
    "provide your credentials",
    "confirm your credentials",
    "bank information",
    "password immediately"
]


# ---------------------------------------------------------
# TEXT CLEANING
# ---------------------------------------------------------

def clean_text(text):

    text = str(text).lower()

    text = re.sub(
        r"https?://\S+|www\.\S+",
        " URL ",
        text
    )

    text = re.sub(
        r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
        " EMAIL ",
        text
    )

    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ---------------------------------------------------------
# URL ANALYSIS
# ---------------------------------------------------------

def analyze_urls(text):

    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text,
        flags=re.IGNORECASE
    )

    suspicious_urls = []

    suspicious_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly"
    ]

    for url in urls:

        url_lower = url.lower()

        for domain in suspicious_domains:

            if domain in url_lower:

                suspicious_urls.append(url)
                break

    return urls, suspicious_urls


# ---------------------------------------------------------
# KEYWORD ANALYSIS
# ---------------------------------------------------------

def analyze_keywords(text):

    text_lower = text.lower()

    found = []

    for keyword in PHISHING_KEYWORDS:

        if keyword in text_lower:

            found.append(keyword)

    return list(dict.fromkeys(found))


# ---------------------------------------------------------
# MAIN ANALYSIS
# ---------------------------------------------------------

def analyze_email(email):

    if not MODEL_LOADED:

        return {
            "success": False,
            "error": "Model is not loaded. Run train_model.py first."
        }

    if not email or not email.strip():

        return {
            "success": False,
            "error": "Please enter an email."
        }

    cleaned = clean_text(email)

    # -----------------------------------------------
    # ML MODEL
    # -----------------------------------------------

    vectorized = vectorizer.transform([cleaned])

    prediction = model.predict(vectorized)[0]

    probabilities = model.predict_proba(vectorized)[0]

    classes = list(model.classes_)

    probability_map = {
        classes[i]: float(probabilities[i])
        for i in range(len(classes))
    }

    ml_phishing_probability = probability_map.get(
        "Phishing",
        0
    )

    ml_safe_probability = probability_map.get(
        "Safe",
        0
    )

    # -----------------------------------------------
    # ADDITIONAL ANALYSIS
    # -----------------------------------------------

    urls, suspicious_urls = analyze_urls(email)

    keywords = analyze_keywords(email)

    # -----------------------------------------------
    # FINAL DECISION
    #
    # ML remains the main classifier.
    # Additional indicators are used only when
    # the ML result is uncertain.
    # -----------------------------------------------

    final_prediction = prediction

    reasons = []

    # Strong phishing signals
    strong_phishing = (
        len(suspicious_urls) > 0
        or len(keywords) >= 2
    )

    # If model is uncertain and there are strong
    # phishing indicators, classify as phishing.
    if (
        prediction == "Safe"
        and ml_phishing_probability >= 0.40
        and strong_phishing
    ):
        final_prediction = "Phishing"

    # If the ML model is strongly confident that
    # the email is safe, do not override it merely
    # because one common word appears.
    elif (
        prediction == "Phishing"
        and ml_phishing_probability < 0.60
        and not strong_phishing
    ):
        final_prediction = "Safe"

    # -----------------------------------------------
    # REASONS
    # -----------------------------------------------

    if suspicious_urls:

        reasons.append(
            "Suspicious shortened URL detected."
        )

    if urls and not suspicious_urls:

        reasons.append(
            f"{len(urls)} URL(s) detected in the email."
        )

    if keywords:

        if len(keywords) == 1:

            reasons.append(
                f"Suspicious phrase detected: '{keywords[0]}'."
            )

        else:

            reasons.append(
                f"{len(keywords)} suspicious phrases detected."
            )

    if final_prediction == "Phishing":

        if not reasons:

            reasons.append(
                "The machine-learning model detected phishing-like language patterns."
            )

    else:

        if not reasons:

            reasons.append(
                "No strong phishing indicators were detected."
            )

    # -----------------------------------------------
    # CONFIDENCE
    # -----------------------------------------------

    confidence = max(
        ml_phishing_probability,
        ml_safe_probability
    ) * 100

    return {

        "success": True,

        "prediction": final_prediction,

        "confidence": round(confidence, 2),

        "phishing_probability": round(
            ml_phishing_probability * 100,
            2
        ),

        "safe_probability": round(
            ml_safe_probability * 100,
            2
        ),

        "urls_found": len(urls),

        "suspicious_urls": suspicious_urls,

        "suspicious_keywords": keywords,

        "reasons": reasons
    }


# ---------------------------------------------------------
# HOME PAGE
# ---------------------------------------------------------

@app.route("/")
def home():

    return render_template("index.html")


# ---------------------------------------------------------
# ANALYZE API
# ---------------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "success": False,
                "error": "No data received."
            }), 400

        email = data.get("email", "")

        result = analyze_email(email)

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# METRICS API
# ---------------------------------------------------------

@app.route("/metrics")
def get_metrics():

    if not MODEL_LOADED:

        return jsonify({
            "success": False,
            "error": "Model is not trained."
        }), 500

    return jsonify({
        "success": True,
        "metrics": metrics
    })


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.route("/health")
def health():

    return jsonify({
        "status": "running",
        "model_loaded": MODEL_LOADED
    })


# ---------------------------------------------------------
# RUN
# ---------------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )