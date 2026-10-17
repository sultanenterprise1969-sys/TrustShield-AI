
from pathlib import Path
import json
import warnings

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    average_precision_score
)

warnings.filterwarnings("ignore", category=UserWarning)

# =========================================================
# SULTAN AI | TRUSTSHIELD
# SMS / MESSAGE SPAM DETECTION TRAINING PIPELINE
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "SMSSpamCollection"
MODEL_DIR = BASE_DIR / "models"

MODEL_PATH = MODEL_DIR / "sms_spam_model.joblib"
VECTORIZER_PATH = MODEL_DIR / "sms_vectorizer.joblib"
METRICS_PATH = MODEL_DIR / "training_metrics.json"

RANDOM_STATE = 42
TEST_SIZE = 0.20

# =========================================================
# 1. LOAD DATASET
# =========================================================

def load_dataset():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}\n"
            "Place SMSSpamCollection in your project folder."
        )

    print("\n" + "=" * 60)
    print(" SULTAN AI | TRUSTSHIELD MODEL TRAINING")
    print("=" * 60)

    df = pd.read_csv(
        DATASET_PATH,
        sep="\t",
        header=None,
        names=["label", "message"],
        usecols=[0, 1],
        on_bad_lines="skip",
        encoding="utf-8"
    )

    # Clean labels and text
    df = df.dropna(subset=["label", "message"]).copy()

    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df["message"] = df["message"].astype(str).str.strip()

    # Keep only valid classes
    df = df[df["label"].isin(["ham", "spam"])]

    # Remove empty messages and duplicate rows
    df = df[df["message"].str.len() > 0]
    df = df.drop_duplicates(subset=["label", "message"])

    if df.empty:
        raise ValueError(
            "No valid ham/spam messages found in the dataset."
        )

    if df["label"].nunique() != 2:
        raise ValueError(
            "Dataset must contain both 'ham' and 'spam' labels."
        )

    print(f"\nDataset: {DATASET_PATH.name}")
    print(f"Valid unique messages: {len(df):,}")

    print("\nClass distribution:")
    print(df["label"].value_counts().to_string())

    return df


# =========================================================
# 2. SPLIT DATA BEFORE FITTING VECTORIZER
# =========================================================

def prepare_data(df):
    X = df["message"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print(f"\nTraining samples: {len(X_train):,}")
    print(f"Testing samples:  {len(X_test):,}")

    # Learn vocabulary ONLY from training data.
    vectorizer = TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        stop_words="english",
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.98,
        sublinear_tf=True,
        max_features=50000,
        dtype="float64"
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print(f"TF-IDF features: {X_train_vec.shape[1]:,}")

    return (
        X_train_vec,
        X_test_vec,
        y_train,
        y_test,
        vectorizer
    )


# =========================================================
# 3. TRAIN MODEL
# =========================================================

def train_model(X_train, y_train):
    print("\nTraining Logistic Regression...")

    model = LogisticRegression(
        C=2.0,
        max_iter=2000,
        class_weight="balanced",
        solver="liblinear",
        random_state=RANDOM_STATE
    )

    model.fit(X_train, y_train)

    print("Training completed successfully.")

    return model


# =========================================================
# 4. EVALUATE ON UNSEEN TEST DATA
# =========================================================

def evaluate_model(model, X_test, y_test):
    predictions = model.predict(X_test)

    # Spam is the positive class.
    spam_probabilities = model.predict_proba(X_test)[
        :, list(model.classes_).index("spam")
    ]

    accuracy = accuracy_score(y_test, predictions)

    precision = precision_score(
        y_test, predictions,
        pos_label="spam",
        zero_division=0
    )

    recall = recall_score(
        y_test, predictions,
        pos_label="spam",
        zero_division=0
    )

    f1 = f1_score(
        y_test, predictions,
        pos_label="spam",
        zero_division=0
    )

    # Binary ranking metrics
    y_test_binary = (y_test == "spam").astype(int)

    roc_auc = roc_auc_score(
        y_test_binary,
        spam_probabilities
    )

    average_precision = average_precision_score(
        y_test_binary,
        spam_probabilities
    )

    # Explicit order: ham first, spam second
    cm = confusion_matrix(
        y_test,
        predictions,
        labels=["ham", "spam"]
    )

    tn, fp, fn, tp = cm.ravel()

    specificity = tn / (tn + fp) if (tn + fp) else 0.0

    print("\n" + "=" * 60)
    print(" MODEL EVALUATION REPORT")
    print("=" * 60)

    print(f"Accuracy:            {accuracy:.4f}")
    print(f"Spam Precision:      {precision:.4f}")
    print(f"Spam Recall:         {recall:.4f}")
    print(f"Spam F1-score:       {f1:.4f}")
    print(f"Specificity:         {specificity:.4f}")
    print(f"ROC-AUC:             {roc_auc:.4f}")
    print(f"Average Precision:   {average_precision:.4f}")

    print("\nConfusion Matrix")
    print("Rows = Actual; Columns = Predicted")
    print("                 Predicted Ham   Predicted Spam")
    print(f"Actual Ham       {tn:>13}   {fp:>14}")
    print(f"Actual Spam      {fn:>13}   {tp:>14}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=["ham", "spam"],
            target_names=["Ham (Legitimate)", "Spam (Suspicious)"],
            digits=4,
            zero_division=0
        )
    )

    metrics = {
        "dataset": DATASET_PATH.name,
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "training_samples": int(len(y_test) / TEST_SIZE * (1 - TEST_SIZE)),
        "test_samples": int(len(y_test)),
        "accuracy": float(accuracy),
        "spam_precision": float(precision),
        "spam_recall": float(recall),
        "spam_f1_score": float(f1),
        "specificity": float(specificity),
        "roc_auc": float(roc_auc),
        "average_precision": float(average_precision),
        "confusion_matrix": {
            "true_ham": int(tn),
            "false_spam": int(fp),
            "missed_spam": int(fn),
            "detected_spam": int(tp)
        }
    }

    return metrics


# =========================================================
# 5. SAVE ARTIFACTS
# =========================================================

def save_artifacts(model, vectorizer, metrics):
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH, compress=3)
    joblib.dump(vectorizer, VECTORIZER_PATH, compress=3)

    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=4)

    print("\n" + "=" * 60)
    print(" MODEL ARTIFACTS SAVED")
    print("=" * 60)

    print(f"Model:     {MODEL_PATH}")
    print(f"Vectorizer:{VECTORIZER_PATH}")
    print(f"Metrics:   {METRICS_PATH}")


# =========================================================
# 6. TEST SAVED MODEL
# =========================================================

def test_saved_model():
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

    samples = [
        "Congratulations! You have won a free prize. Call now!",
        "Hey, are we still meeting for lunch today?",
        "URGENT! Verify your account immediately to avoid suspension."
    ]

    print("\n" + "=" * 60)
    print(" QUICK MODEL DEMONSTRATION")
    print("=" * 60)

    for message in samples:
        features = vectorizer.transform([message])
        prediction = model.predict(features)[0]

        probabilities = model.predict_proba(features)[0]
        spam_index = list(model.classes_).index("spam")
        spam_probability = probabilities[spam_index]

        print(f"\nMessage: {message}")
        print(f"Prediction: {prediction.upper()}")
        print(f"Spam probability: {spam_probability:.2%}")


# =========================================================
# MAIN
# =========================================================

def main():
    df = load_dataset()

    X_train, X_test, y_train, y_test, vectorizer = (
        prepare_data(df)
    )

    model = train_model(X_train, y_train)

    metrics = evaluate_model(model, X_test, y_test)

    save_artifacts(model, vectorizer, metrics)

    test_saved_model()

    print("\nTraining pipeline finished successfully.")
    print("Next step: run your Streamlit app.")


if __name__ == "__main__":
    main()
