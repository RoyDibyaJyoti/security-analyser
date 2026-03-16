"""
Simple ML-based phishing classifier using scikit-learn
"""
import joblib
import os
import re
from typing import List, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

class PhishingMLModel:
    """Lightweight ML model for phishing detection"""
    MODEL_PATH = "models/phishing_classifier.pkl"

    def __init__(self):
        self.pipeline: Optional[Pipeline] = None
        self.is_trained = False
        
        # Sample training data
        self._training_data = {
            "phishing": [
                "urgent verify your account now click here",
                "your paypal account has been limited update immediately",
                "winner notification claim your prize bitcoin payment",
                "suspicious login detected confirm your identity",
                "irs tax refund wire transfer required",
            ],
            "legitimate": [
                "your order has shipped tracking number included",
                "meeting reminder tomorrow at 3pm conference room",
                "newsletter subscription confirmed welcome aboard",
                "password reset requested if not you ignore this",
                "invoice attached please review and approve",
            ]
        }

    def _preprocess(self, text: str) -> str:
        """Basic text preprocessing"""
        if not text:
            return ""
        text = text.lower()
        text = re.sub(r'http\S+|www\S+|https\S+', '', text)
        text = re.sub(r'\S+@\S+', '', text)
        text = re.sub(r'[^a-z\s]', '', text)
        return ' '.join(text.split())

    def train(self):
        """Train the model on sample data"""
        texts = []
        labels = []
        
        for label, samples in self._training_data.items():
            for sample in samples:
                texts.append(self._preprocess(sample))
                labels.append(1 if label == "phishing" else 0)
        
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=1000, ngram_range=(1, 2))),
            ('clf', MultinomialNB(alpha=0.1))
        ])
        
        self.pipeline.fit(texts, labels)
        self.is_trained = True
        
        os.makedirs("models", exist_ok=True)
        joblib.dump(self.pipeline, self.MODEL_PATH)
        print(f"✓ Model trained and saved to {self.MODEL_PATH}")

    def load(self):
        """Load pre-trained model"""
        if os.path.exists(self.MODEL_PATH):
            self.pipeline = joblib.load(self.MODEL_PATH)
            self.is_trained = True
            print(f"✓ Model loaded from {self.MODEL_PATH}")
            return True
        return False

    def predict(self, text: str) -> dict:
        """Predict if text is phishing"""
        if not self.is_trained:
            if not self.load():
                self.train()
        
        processed = self._preprocess(text)
        if not processed:
            return {"is_phishing": False, "confidence": 0.0, "phishing_probability": 0.0, "legitimate_probability": 1.0}

        prediction = self.pipeline.predict([processed])[0]
        probabilities = self.pipeline.predict_proba([processed])[0]
        
        return {
            "is_phishing": bool(prediction),
            "confidence": float(max(probabilities)),
            "phishing_probability": float(probabilities[1]),
            "legitimate_probability": float(probabilities[0])
        }

ml_model = PhishingMLModel()