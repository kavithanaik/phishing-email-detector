import joblib


model = joblib.load("model/model.pkl")

vectorizer = joblib.load(
    "model/vectorizer.pkl"
)


emails = [

    """
    URGENT! Your bank account has been suspended.
    Click http://secure-bank-login.com immediately
    to verify your password.
    Failure to verify your account within 24 hours
    will result in permanent account closure.
    """,

    """
    Hello team,

    This is a reminder that our project meeting
    is scheduled for tomorrow at 10 AM.

    Please bring the project report.

    Thank you.
    """

]


for email in emails:

    features = vectorizer.transform([email])

    prediction = model.predict(features)[0]

    probabilities = model.predict_proba(features)[0]

    classes = model.classes_

    print("\n" + "=" * 60)

    print("Prediction:", prediction)

    for class_name, probability in zip(
        classes,
        probabilities
    ):

        print(
            f"{class_name}: "
            f"{probability * 100:.2f}%"
        )

    print(
        "Confidence:",
        f"{max(probabilities) * 100:.2f}%"
    )