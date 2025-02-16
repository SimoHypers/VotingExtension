from flask import Flask, request, jsonify
import joblib
import os
import pandas as pd
import re
import nltk
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from collections import Counter

nltk.download("stopwords")
from nltk.corpus import stopwords

app = Flask(__name__)

# Paths for model, vectorizer, and dataset
BASE_DIR = os.getcwd()
MODEL_PATH = os.path.join(BASE_DIR, "scam_detection_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")
DATASET_PATH = os.path.join(BASE_DIR, "junkmail_dataset.csv")  # Uses uploaded dataset

# Load dataset and check columns
df = pd.read_csv(DATASET_PATH)
print("🔍 Columns found in dataset:", df.columns)

# Ensure dataset contains the expected columns
if "text" not in df.columns or "is_spam" not in df.columns:
    raise ValueError("❌ Required columns 'text' or 'is_spam' not found in dataset. Check CSV format.")

# Convert labels: 0 = safe, 1 = scam
df["label"] = df["is_spam"].astype(int)

# Train vectorizer & model
vectorizer = TfidfVectorizer(max_features=5000)
X = vectorizer.fit_transform(df["text"])
model = LogisticRegression()
model.fit(X, df["label"])

# Save trained model
joblib.dump(model, MODEL_PATH)
joblib.dump(vectorizer, VECTORIZER_PATH)

# Scam keywords for extra scoring
SCAM_KEYWORDS = {
    "link in bio", "bio", "giveaway", "airdrop", "win", "prize", "free", "click here",
    "claim now", "bitcoin", "binance", "eth", "doge", "roobet", "lottery", "bonus",
    "btc", "investment", "fast money", "double your money", "instant profit", "stake"
}

# Track repeat scam content
scam_counts = Counter()


def preprocess_text(text):
    """Cleans text by removing links, special characters, and stopwords."""
    text = re.sub(r"http\S+|www\S+", "", text)  # Remove URLs
    text = re.sub(r"[^a-zA-Z0-9\s]", "", text)  # Remove special characters
    words = text.lower().split()
    words = [word for word in words if word not in stopwords.words("english")]
    return " ".join(words)


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        if not data or "postDescription" not in data or "imageText" not in data:
            return jsonify({"error": "Provide 'postDescription' and 'imageText'"}), 400

        text = f"{data['imageText']} {data['postDescription']}"
        cleaned_text = preprocess_text(text)
        transformed_text = vectorizer.transform([cleaned_text])

        # Predict scam probability
        prob = model.predict_proba(transformed_text)[0]
        risk_score = prob[1] if len(prob) > 1 else prob[0]

        # Scam keyword detection
        scam_keywords_found = [word for word in SCAM_KEYWORDS if word in cleaned_text]
        scam_likelihood = "High" if risk_score > 0.7 else "Medium" if risk_score > 0.4 else "Low"

        # Track repeat scam patterns
        if scam_likelihood == "High":
            scam_counts[text] += 1

        return jsonify({
            "risk_score": round(risk_score * 100, 2),
            "scam_keywords": scam_keywords_found,
            "scam_likelihood": scam_likelihood,
            "repeat_scam_count": scam_counts[text]
        })

    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


@app.route("/flag", methods=["POST"])
def flag():
    """Adds flagged content to the dataset and retrains the model."""
    try:
        data = request.get_json()
        if not data or "postDescription" not in data or "imageText" not in data:
            return jsonify({"error": "Provide 'postDescription' and 'imageText'"}), 400

        text = f"{data['imageText']} {data['postDescription']}"
        cleaned_text = preprocess_text(text)

        # Append to dataset
        global df
        new_entry = pd.DataFrame([[cleaned_text, 1]], columns=["text", "label"])
        df = pd.concat([df, new_entry], ignore_index=True)

        # Ensure dataset has both scam (1) and non-scam (0) data
        if df["label"].nunique() < 2:
            print("⚠️ Not enough class diversity. Adding sample non-scam data.")
            df = pd.concat([df, pd.DataFrame([
                ["Genuine tech discussion on AI", 0],
                ["Football match highlights", 0],
                ["Latest iPhone features", 0],
                ["Stock market analysis", 0]
            ], columns=["text", "label"])], ignore_index=True)

        # Save updated dataset
        df.to_csv(DATASET_PATH, index=False)

        # Retrain model
        retrain_model()

        return jsonify({"message": "Post flagged and added to dataset. Model updated."})

    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"})


def retrain_model():
    """Retrains the model with the updated dataset."""
    try:
        global df
        if df.empty:
            print("⚠️ Dataset is empty, skipping retraining.")
            return

        texts = df["text"].values
        labels = df["label"].values

        # Refit vectorizer with the entire dataset
        global vectorizer
        vectorizer = TfidfVectorizer(max_features=5000)
        X = vectorizer.fit_transform(texts)

        # Train new model
        global model
        model = LogisticRegression()
        model.fit(X, labels)

        # Save updated model and vectorizer
        joblib.dump(model, MODEL_PATH)
        joblib.dump(vectorizer, VECTORIZER_PATH)

        print("✅ Model retrained successfully.")

    except Exception as e:
        print(f"⚠️ Retraining failed: {str(e)}")


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5030,
        ssl_context=(
            "/etc/letsencrypt/live/192.71.151.167/cert.pem",
            "/etc/letsencrypt/live/192.71.151.167/privkey.pem"
        )
    )
