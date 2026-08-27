from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

import os
import re
import joblib

from scipy.sparse import hstack, csr_matrix


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)
CORS(app)


# ============================================================
# BASE DIRECTORY
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


# ============================================================
# MODEL PATHS
# ============================================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model",
    "model.pkl"
)

METRICS_PATH = os.path.join(
    BASE_DIR,
    "model",
    "metrics.pkl"
)


# ============================================================
# LOAD MODEL
# ============================================================

model_data = None
metrics = None

try:

    model_data = joblib.load(
        MODEL_PATH
    )

    metrics = joblib.load(
        METRICS_PATH
    )

    print()
    print("=" * 70)
    print("       PHISHING EMAIL DETECTOR")
    print("=" * 70)

    print()
    print("Machine learning model loaded successfully.")

except Exception as e:

    print()
    print("WARNING: Machine learning model not loaded.")
    print("ERROR:", e)


# ============================================================
# SECURITY FEATURE EXTRACTION
# ============================================================

def security_features(text):

    text = str(text)

    lower = text.lower()


    # --------------------------------------------------------
    # URL DETECTION
    # --------------------------------------------------------

    urls = re.findall(

        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',

        text,

        flags=re.IGNORECASE

    )

    url_count = len(urls)


    # --------------------------------------------------------
    # SUSPICIOUS URL
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # IP URL
    # --------------------------------------------------------

    ip_url_count = 0

    for url in urls:

        if re.search(

            r'https?://(?:\d{1,3}\.){3}\d{1,3}',

            url

        ):

            ip_url_count += 1


    # --------------------------------------------------------
    # EMAIL LENGTH
    # --------------------------------------------------------

    length = len(text)


    # --------------------------------------------------------
    # EXCLAMATION MARKS
    # --------------------------------------------------------

    exclamation_count = text.count("!")


    # --------------------------------------------------------
    # DIGITS
    # --------------------------------------------------------

    digit_count = sum(

        character.isdigit()

        for character in text

    )


    # --------------------------------------------------------
    # SPECIAL CHARACTERS
    # --------------------------------------------------------

    special_count = len(

        re.findall(

            r'[^a-zA-Z0-9\s]',

            text

        )

    )


    # --------------------------------------------------------
    # UPPERCASE WORDS
    # --------------------------------------------------------

    uppercase_count = sum(

        1

        for word in text.split()

        if len(word) > 2

        and word.isupper()

    )


    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
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
        "security",
        "blocked",
        "limited",
        "confirm",
        "payment",
        "refund",
        "bank",
        "login",
        "unlock",
        "expired",
        "24 hours",
        "kyc",
        "credit card",
        "billing",
        "credentials"

    ]

    suspicious_keyword_count = sum(

        lower.count(keyword)

        for keyword in phishing_keywords

    )


    # ========================================================
    # EXACT SAME 9 FEATURES AS train_model.py
    # ========================================================

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
# EMAIL SECURITY DISPLAY INFORMATION
# ============================================================

def analyze_email_security(text):

    text = str(text)

    urls = re.findall(

        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',

        text,

        flags=re.IGNORECASE

    )

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
        "security",
        "unlock",
        "signin"

    ]

    suspicious_urls = []

    ip_urls = []

    for url in urls:

        if any(

            word in url.lower()

            for word in suspicious_words

        ):

            suspicious_urls.append(url)


        if re.search(

            r'https?://(?:\d{1,3}\.){3}\d{1,3}',

            url

        ):

            ip_urls.append(url)


    if urls:

        avg_url_length = (

            sum(
                len(url)
                for url in urls
            )
            / len(urls)

        )

    else:

        avg_url_length = 0.0


    return {

        "urls_found":
            len(urls),

        "suspicious_urls":
            len(suspicious_urls),

        "ip_urls":
            len(ip_urls),

        "email_length":
            len(text),

        "avg_url_length":
            round(
                avg_url_length,
                2
            ),

        "exclamation_marks":
            text.count("!"),

        "special_characters":
            len(
                re.findall(
                    r'[^a-zA-Z0-9\s]',
                    text
                )
            ),

        "digits":
            sum(
                character.isdigit()
                for character in text
            ),

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

    if model_data is None:

        return jsonify({

            "success": False,

            "error":
                "Machine learning model is not loaded."

        }), 500


    try:

        # ----------------------------------------------------
        # GET JSON
        # ----------------------------------------------------

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


        if not isinstance(
            email_text,
            str
        ):

            email_text = str(
                email_text
            )


        if not email_text.strip():

            return jsonify({

                "success": False,

                "error":
                    "Please enter an email."

            }), 400


        # ----------------------------------------------------
        # LOAD MODEL COMPONENTS
        # ----------------------------------------------------

        model = model_data[
            "model"
        ]

        word_vectorizer = model_data[
            "word_vectorizer"
        ]

        char_vectorizer = model_data[
            "char_vectorizer"
        ]


        # ----------------------------------------------------
        # WORD TF-IDF
        # ----------------------------------------------------

        word_features = (

            word_vectorizer.transform(

                [email_text]

            )

        )


        # ----------------------------------------------------
        # CHARACTER TF-IDF
        # ----------------------------------------------------

        char_features = (

            char_vectorizer.transform(

                [email_text]

            )

        )


        # ----------------------------------------------------
        # SECURITY FEATURES
        # ----------------------------------------------------

        security_values = security_features(
            email_text
        )


        security_matrix = csr_matrix(

            [security_values]

        )


        # ----------------------------------------------------
        # COMBINE FEATURES
        # ----------------------------------------------------

        features = hstack([

            word_features,

            char_features,

            security_matrix

        ])


        # ----------------------------------------------------
        # CHECK FEATURE COUNT
        # ----------------------------------------------------

        expected_features = (

            getattr(
                model,
                "n_features_in_",
                None
            )

        )

        actual_features = (
            features.shape[1]
        )


        print()
        print(
            "Expected features:",
            expected_features
        )

        print(
            "Actual features:",
            actual_features
        )


        # ----------------------------------------------------
        # PREDICTION
        # ----------------------------------------------------

        prediction = model.predict(

            features

        )[0]


        probabilities = model.predict_proba(

            features

        )[0]


        classes = model.classes_


        # ----------------------------------------------------
        # PROBABILITIES
        # ----------------------------------------------------

        probability_data = {}


        for class_name, probability in zip(

            classes,

            probabilities

        ):

            probability_data[
                class_name
            ] = (

                float(probability)
                * 100

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


        # ----------------------------------------------------
        # SECURITY ANALYSIS
        # ----------------------------------------------------

        security = (

            analyze_email_security(

                email_text

            )

        )


        # ----------------------------------------------------
        # REASONS
        # ----------------------------------------------------

        reasons = []

        lower_email = (
            email_text.lower()
        )


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


        urgency_words = [

            "urgent",
            "immediately",
            "final warning",
            "action required",
            "within 24 hours"

        ]


        for word in urgency_words:

            if word in lower_email:

                reasons.append(

                    "Urgency indicator detected: "
                    + word

                )

                break


        sensitive_words = [

            "password",
            "bank details",
            "credit card",
            "verify your account",
            "login credentials",
            "enter your username"

        ]


        for word in sensitive_words:

            if word in lower_email:

                reasons.append(

                    "Sensitive information request detected: "
                    + word

                )

                break


        if not reasons:

            if prediction == "Safe":

                reasons.append(

                    "No major phishing indicators detected."

                )

            else:

                reasons.append(

                    "Suspicious textual patterns detected."

                )


        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return jsonify({

            "success":
                True,

            "prediction":
                prediction,

            "confidence":
                round(
                    confidence,
                    2
                ),

            "phishing_probability":
                round(
                    phishing_probability,
                    2
                ),

            "safe_probability":
                round(
                    safe_probability,
                    2
                ),

            "security":
                security,

            "reasons":
                reasons,

            "metrics":
                metrics

        })


    except Exception as e:

        print()
        print("=" * 70)
        print("PREDICTION ERROR")
        print("=" * 70)
        print(e)

        return jsonify({

            "success":
                False,

            "error":
                str(e)

        }), 500


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("          PHISHING EMAIL DETECTOR")
    print("=" * 70)

    print()
    print(
        "Open browser:"
    )

    print(
        "http://127.0.0.1:5000/"
    )

    print()

    app.run(

        host="0.0.0.0",

        port=5000,

        debug=False

    )