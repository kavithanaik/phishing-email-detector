from flask import Flask, request, render_template_string
import joblib
import re
import os


# ==========================================
# CREATE FLASK APPLICATION
# ==========================================

app = Flask(__name__)


# ==========================================
# FIND PROJECT FOLDER
# ==========================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


# ==========================================
# LOAD MACHINE LEARNING MODEL
# ==========================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model.pkl"
)


model, vectorizer = joblib.load(
    MODEL_PATH
)


# ==========================================
# SUSPICIOUS KEYWORDS
# ==========================================

suspicious_keywords = [
    "urgent",
    "verify",
    "password",
    "account",
    "suspended",
    "click",
    "login",
    "winner",
    "prize",
    "bank",
    "security",
    "confirm",
    "update",
    "blocked",
    "expire"
]


# ==========================================
# WEBSITE HTML + CSS
# ==========================================

HTML = """

<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>
        Phishing Email Detector
    </title>


    <style>

        * {
            box-sizing: border-box;
        }


        body {

            margin: 0;

            font-family: Arial, sans-serif;

            background: #f1f5f9;

            color: #1e293b;

        }


        /* =========================
           NAVIGATION
        ========================= */

        nav {

            background: #172554;

            color: white;

            padding: 20px 8%;

            display: flex;

            justify-content: space-between;

            align-items: center;

        }


        nav h2 {

            margin: 0;

        }


        nav span {

            font-size: 14px;

            opacity: 0.9;

        }


        /* =========================
           MAIN CONTAINER
        ========================= */

        .container {

            max-width: 900px;

            margin: 50px auto;

            padding: 20px;

        }


        /* =========================
           CARD
        ========================= */

        .card {

            background: white;

            padding: 35px;

            border-radius: 15px;

            box-shadow:
                0 5px 20px
                rgba(0, 0, 0, 0.10);

        }


        /* =========================
           HEADING
        ========================= */

        h1 {

            text-align: center;

            color: #172554;

            margin-bottom: 10px;

        }


        .description {

            text-align: center;

            color: #64748b;

            margin-bottom: 30px;

        }


        /* =========================
           TEXT AREA
        ========================= */

        textarea {

            width: 100%;

            height: 250px;

            padding: 15px;

            border: 1px solid #cbd5e1;

            border-radius: 10px;

            font-size: 16px;

            resize: vertical;

            outline: none;

        }


        textarea:focus {

            border-color: #2563eb;

        }


        /* =========================
           BUTTON
        ========================= */

        button {

            width: 100%;

            margin-top: 20px;

            padding: 15px;

            border: none;

            border-radius: 10px;

            background: #2563eb;

            color: white;

            font-size: 18px;

            cursor: pointer;

        }


        button:hover {

            background: #1d4ed8;

        }


        /* =========================
           RESULT
        ========================= */

        .result {

            margin-top: 30px;

            padding: 25px;

            border-radius: 12px;

        }


        .phishing {

            background: #fee2e2;

            border-left: 6px solid #dc2626;

        }


        .safe {

            background: #dcfce7;

            border-left: 6px solid #16a34a;

        }


        .phishing h2 {

            color: #dc2626;

        }


        .safe h2 {

            color: #16a34a;

        }


        .section {

            margin-top: 25px;

        }


        .section h3 {

            margin-bottom: 10px;

        }


        li {

            margin: 8px 0;

            word-break: break-word;

        }


        .confidence {

            font-size: 18px;

            font-weight: bold;

        }


        /* =========================
           FOOTER
        ========================= */

        footer {

            text-align: center;

            margin-top: 30px;

            color: #64748b;

            font-size: 14px;

        }


        /* =========================
           MOBILE
        ========================= */

        @media (max-width: 600px) {

            nav {

                padding: 18px;

            }


            nav h2 {

                font-size: 18px;

            }


            .container {

                margin: 20px auto;

                padding: 15px;

            }


            .card {

                padding: 20px;

            }


            h1 {

                font-size: 28px;

            }

        }

    </style>

</head>


<body>


    <!-- =========================
         NAVIGATION
    ========================= -->

    <nav>

        <h2>
            🛡️ Phishing Detector
        </h2>

        <span>
            Machine Learning
        </span>

    </nav>


    <!-- =========================
         MAIN CONTENT
    ========================= -->

    <div class="container">

        <div class="card">


            <h1>
                📧 Phishing Email Detection
            </h1>


            <p class="description">

                Paste an email below and our
                machine learning model will
                classify it as Phishing or Safe.

            </p>


            <!-- =====================
                 EMAIL FORM
            ====================== -->

            <form method="POST">


                <textarea
                    name="email"
                    placeholder="Paste email content here..."
                    required>{{ email }}</textarea>


                <button type="submit">

                    🔍 Analyze Email

                </button>


            </form>


            <!-- =====================
                 RESULT
            ====================== -->

            {% if result %}


            <div class="result

                {% if result == 'Phishing' %}

                    phishing

                {% else %}

                    safe

                {% endif %}

            ">


                <!-- Prediction -->

                {% if result == "Phishing" %}

                    <h2>
                        🔴 PHISHING EMAIL
                    </h2>

                {% else %}

                    <h2>
                        🟢 SAFE EMAIL
                    </h2>

                {% endif %}


                <p>

                    <strong>
                        Prediction:
                    </strong>

                    {{ result }}

                </p>


                <p class="confidence">

                    Confidence:
                    {{ confidence }}%

                </p>


                <!-- =====================
                     URL SECTION
                ====================== -->

                <div class="section">

                    <h3>
                        🔗 URLs Detected
                    </h3>


                    {% if urls %}

                        <ul>

                        {% for url in urls %}

                            <li>
                                {{ url }}
                            </li>

                        {% endfor %}

                        </ul>

                    {% else %}

                        <p>
                            No URLs detected.
                        </p>

                    {% endif %}

                </div>


                <!-- =====================
                     KEYWORDS
                ====================== -->

                <div class="section">

                    <h3>
                        ⚠️ Suspicious Keywords
                    </h3>


                    {% if keywords %}

                        <ul>

                        {% for word in keywords %}

                            <li>
                                {{ word }}
                            </li>

                        {% endfor %}

                        </ul>

                    {% else %}

                        <p>
                            No suspicious keywords detected.
                        </p>

                    {% endif %}

                </div>


            </div>


            {% endif %}


        </div>


        <footer>

            Phishing Email Detection System
            using Machine Learning

        </footer>


    </div>


</body>

</html>

"""


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    confidence = None

    urls = []

    keywords = []

    email = ""


    # ======================================
    # WHEN USER SUBMITS EMAIL
    # ======================================

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        )


        # ----------------------------------
        # CHECK EMPTY EMAIL
        # ----------------------------------

        if not email.strip():

            return render_template_string(
                HTML,
                result=None,
                confidence=None,
                urls=[],
                keywords=[],
                email=""
            )


        # ----------------------------------
        # CONVERT EMAIL TO TF-IDF
        # ----------------------------------

        email_vector = vectorizer.transform(
            [email]
        )


        # ----------------------------------
        # MACHINE LEARNING PREDICTION
        # ----------------------------------

        result = model.predict(
            email_vector
        )[0]


        # ----------------------------------
        # CONFIDENCE
        # ----------------------------------

        probabilities = model.predict_proba(
            email_vector
        )[0]


        confidence = round(
            max(probabilities) * 100,
            2
        )


        # ----------------------------------
        # FIND URLs
        # ----------------------------------

        urls = re.findall(
            r'https?://\S+|www\.\S+',
            email
        )


        # ----------------------------------
        # FIND SUSPICIOUS KEYWORDS
        # ----------------------------------

        email_lower = email.lower()


        for word in suspicious_keywords:

            if word in email_lower:

                keywords.append(word)


    # ======================================
    # DISPLAY WEBSITE
    # ======================================

    return render_template_string(

        HTML,

        result=result,

        confidence=confidence,

        urls=urls,

        keywords=keywords,

        email=email

    )


# ==========================================
# START FLASK SERVER
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )