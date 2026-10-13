"""
server.py - a tiny local web service around model.pkl

Run:  python server.py

Then send it a URL, for example:
    curl -s -X POST http://127.0.0.1:5050/predict \
         -H "Content-Type: application/json" \
         -d '{"url": "http://paypa1-login.xyz/verify"}'

The service only reads the URL as TEXT. It never connects to it.
It listens on 127.0.0.1 only, so other computers cannot reach it.
"""
import os

import joblib
import numpy as np
from flask import Flask, jsonify, request

from features import FEATURE_NAMES, extract_features, to_vector

HERE = os.path.dirname(os.path.abspath(__file__))
# Only load a model.pkl that YOU trained: pickle files can run code when loaded.
bundle = joblib.load(os.path.join(HERE, "model.pkl"))
model = bundle["model"]
baseline = np.array(bundle["baseline"], dtype=float)
safe_below = bundle["bands"]["safe_below"]
phish_above = bundle["bands"]["phish_above"]

if bundle["feature_names"] != FEATURE_NAMES:
    raise SystemExit("model.pkl was trained with different features. Run train.py again.")

app = Flask(__name__)


def explain(x, phishing_prob, top_n=3):
    """Which features pushed the score towards 'phishing'?

    For each feature, replace its value with what a typical legitimate URL
    has, and see how much the phishing probability drops. A big drop means
    that feature was pushing the score up."""
    variants = np.tile(x, (len(x), 1))
    for i in range(len(x)):
        variants[i, i] = baseline[i]
    drops = phishing_prob - model.predict_proba(variants)[:, 1]
    signals = []
    for i in np.argsort(drops)[::-1][:top_n]:
        if drops[i] > 0.02:
            value = x[i]
            value = int(value) if float(value).is_integer() else round(float(value), 2)
            signals.append(f"{FEATURE_NAMES[i]} = {value}")
    return signals


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("url"), str):
        return jsonify(error='send JSON like {"url": "http://example.com"}'), 400
    url = data["url"].strip()
    if not url or len(url) > 2048:
        return jsonify(error="url must be 1-2048 characters"), 400

    x = np.array(to_vector(extract_features(url)), dtype=float)
    phishing_prob = float(model.predict_proba(x.reshape(1, -1))[0, 1])
    is_phishing = phishing_prob >= 0.5

    # band = how sure the model is, using the cut-offs train.py chose on
    # validation data: "legit" / "unsure" / "phish"
    if phishing_prob <= safe_below:
        band = "legit"
    elif phishing_prob >= phish_above:
        band = "phish"
    else:
        band = "unsure"

    return jsonify(
        prediction="phishing" if is_phishing else "legitimate",
        probability=round(phishing_prob if is_phishing else 1 - phishing_prob, 4),
        phishing_probability=round(phishing_prob, 4),
        band=band,
        top_signals=explain(x, phishing_prob),
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050)
