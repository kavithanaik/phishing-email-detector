import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix


# Load dataset
data = pd.read_csv("emails.csv")

print("Dataset loaded successfully!")
print("Total emails:", len(data))


# Separate text and labels
X = data["text"]
y = data["label"]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# Convert text into numbers
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english"
)

X_train = vectorizer.fit_transform(X_train)
X_test = vectorizer.transform(X_test)


# Train model
model = LogisticRegression()

model.fit(X_train, y_train)


# Test model
prediction = model.predict(X_test)


# Accuracy
accuracy = accuracy_score(y_test, prediction)

print("\nAccuracy:", round(accuracy * 100, 2), "%")


# Confusion Matrix
matrix = confusion_matrix(
    y_test,
    prediction,
    labels=["Safe", "Phishing"]
)

print("\nConfusion Matrix:")
print(matrix)


# Save model and vectorizer together
joblib.dump(
    (model, vectorizer),
    "model.pkl"
)

print("\nModel saved successfully as model.pkl")