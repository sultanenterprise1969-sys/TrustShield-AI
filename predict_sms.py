
from pathlib import Path
import sys
import joblib

# =====================================================
# SULTAN AI | TRUSTSHIELD
# SMS SPAM MODEL TESTING
# =====================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "sms_spam_model.joblib"
VECTORIZER_PATH = BASE_DIR / "models" / "sms_vectorizer.joblib"


def load_model():
    """Load the trained model and TF-IDF vectorizer."""

    if not MODEL_PATH.exists():
        print("ERROR: Trained model not found.")
        print(f"Expected location: {MODEL_PATH}")
        print("Run: py train_model.py")
        sys.exit(1)

    if not VECTORIZER_PATH.exists():
        print("ERROR: TF-IDF vectorizer not found.")
        print(f"Expected location: {VECTORIZER_PATH}")
        print("Run: py train_model.py")
        sys.exit(1)

    try:
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        return model, vectorizer

    except Exception as error:
        print(f"Failed to load model: {error}")
        sys.exit(1)


def get_risk_level(score):
    """Convert spam probability into a demo risk category."""

    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"


def test_messages(model, vectorizer):
    """Predict labels and spam probabilities for test messages."""

    test_messages = [
        "Congratulations! You won a free ticket. Claim your prize now!",
        "Hey bro, are we meeting today?",
        "URGENT! Verify your bank account immediately.",
        "Your appointment is confirmed for tomorrow at 10 AM.",
        "You have won a cash prize. Send your OTP to claim it."
    ]

    X_test = vectorizer.transform(test_messages)
    predictions = model.predict(X_test)

    # Get probability of the spam class when supported.
    spam_index = None
    if hasattr(model, "predict_proba"):
        classes = list(model.classes_)
        if "spam" in classes:
            spam_index = classes.index("spam")

    probabilities = None
    if spam_index is not None:
        probabilities = model.predict_proba(X_test)[:, spam_index]

    print("\n" + "=" * 65)
    print("          SULTAN AI | TRUSTSHIELD")
    print("          MESSAGE DETECTION REPORT")
    print("=" * 65)

    for index, (message, prediction) in enumerate(
        zip(test_messages, predictions), start=1
    ):
        label = str(prediction).lower()

        if label == "spam":
            status = "POTENTIAL SPAM"
        elif label == "ham":
            status = "NOT FLAGGED"
        else:
            status = f"MODEL LABEL: {label.upper()}"

        print(f"\n[{index}] {message}")
        print(f"    Prediction : {status}")

        if probabilities is not None:
            score = float(probabilities[index - 1]) * 100
            print(f"    Spam score : {score:.2f}%")
            print(f"    Risk level : {get_risk_level(score)}")
        else:
            print("    Spam score : Not available")

    print("\n" + "=" * 65)
    print("Testing completed.")
    print("Note: Spam probability is not a guarantee of fraud.")
    print("=" * 65)


if __name__ == "__main__":
    trained_model, trained_vectorizer = load_model()
    test_messages(trained_model, trained_vectorizer)
