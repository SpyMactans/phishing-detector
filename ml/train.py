"""
train.py - trains a Random Forest on dataset.csv and saves it to model.pkl

Run:  python train.py

dataset.csv needs two columns:  url,label     (label: 1 = phishing, 0 = legitimate)
"""
import numpy as np
import pandas as pd
import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)

from features import (FEATURE_NAMES, extract_features, parse_url,
                      registered_domain, rule_flags, to_vector)

SEED = 42
TARGET_PRECISION = 0.90   # URLs in the "phish" band should be phishing at least 90% of the time
TARGET_NPV = 0.95         # URLs in the "legit" band should be legitimate at least 95% of the time

# ---------------------------------------------------------------- 1. load
df = pd.read_csv("dataset.csv")
df = df.dropna(subset=["url", "label"])
df["url"] = df["url"].astype(str).str.strip()
df["label"] = df["label"].astype(int)
df = df[df["url"] != ""]
print(f"Loaded {len(df)} rows")

# ------------------------------------------------- 2. leakage guard: duplicates
# The same URL must never appear twice (or the model could be tested on
# something it already memorised). We ignore http/https, case and a trailing "/".
key = df["url"].str.lower().str.replace(r"^[a-z]+://", "", regex=True).str.rstrip("/")
conflicting = key[df.groupby(key)["label"].transform("nunique") > 1]
df = df[~key.isin(conflicting)]             # same URL labelled both ways -> unusable
key = key[df.index]
df = df[~key.duplicated()].reset_index(drop=True)
print(f"After removing duplicates/conflicts: {len(df)} rows")

# ------------------------------------------------------------ 3. features
X = np.array([to_vector(extract_features(u)) for u in df["url"]], dtype=float)
y = df["label"].to_numpy()
groups = df["url"].map(lambda u: registered_domain(parse_url(u)["host"])).to_numpy()

print(f"Class balance: {int((y == 0).sum())} legitimate, {int((y == 1).sum())} phishing "
      f"({100 * y.mean():.1f}% phishing)")

# ----------------------------------------- 4. leakage guard: split BY WEBSITE
# Phishing campaigns put hundreds of URLs on the same site. A normal random
# split would put some of them in training and some in testing, and the model
# would look brilliant just by recognising the site. GroupShuffleSplit keeps
# every URL of a website on ONE side only.
#
# Three parts:  train (fit the model) / validation (choose the confidence
# bands) / test (final exam, looked at once, never used to make decisions).
def split_by_site(idx, test_size):
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=SEED)
    a, b = next(splitter.split(X[idx], y[idx], groups[idx]))
    return idx[a], idx[b]

trainval_idx, test_idx = split_by_site(np.arange(len(y)), 0.20)
train_idx, val_idx = split_by_site(trainval_idx, 0.25)
for name_a, a, name_b, b in [("train", train_idx, "validation", val_idx),
                             ("train", train_idx, "test", test_idx),
                             ("validation", val_idx, "test", test_idx)]:
    assert not (set(groups[a]) & set(groups[b])), f"{name_a} and {name_b} share a website!"
print(f"Train: {len(train_idx)}   Validation: {len(val_idx)}   Test: {len(test_idx)}   "
      f"(no website appears in two of them)")

# ---------------------------------------------- 5. train (class imbalance)
# class_weight makes mistakes on the rarer class cost more, so the forest
# does not just learn to say "legitimate" every time.
model = RandomForestClassifier(
    n_estimators=200,
    min_samples_leaf=5,
    class_weight="balanced_subsample",
    n_jobs=-1,
    random_state=SEED,
)
model.fit(X[train_idx], y[train_idx])

# --------------------------------------- 6. choose the confidence bands
# Instead of guessing "0.3 and 0.7", look at the VALIDATION data:
#   phish band : lowest score from which 90% of the URLs really are phishing
#   legit band : highest score up to which 95% of the URLs really are legitimate
# Anything in between is "unsure".
val_prob = model.predict_proba(X[val_idx])[:, 1]
val_y = y[val_idx]
grid = np.round(np.arange(0.05, 0.96, 0.01), 2)

phish_above = 0.70            # fallback if the target cannot be reached
for t in grid:
    sel = val_prob >= t
    if sel.sum() >= 50 and val_y[sel].mean() >= TARGET_PRECISION:
        phish_above = float(t)
        break

safe_below = 0.30
for t in grid[::-1]:
    sel = val_prob <= t
    if sel.sum() >= 50 and (1 - val_y[sel].mean()) >= TARGET_NPV:
        safe_below = float(t)
        break
safe_below = min(safe_below, phish_above - 0.05)
print(f"\nConfidence bands chosen on the validation set: "
      f"legit if P(phishing) <= {safe_below:.2f}, phish if >= {phish_above:.2f}, otherwise unsure")

# ---------------------------------------------------------- 7. evaluate
Xt, yt = X[test_idx], y[test_idx]
test_prob = model.predict_proba(Xt)[:, 1]
pred = (test_prob >= 0.5).astype(int)

acc = accuracy_score(yt, pred)
prec = precision_score(yt, pred)
rec = recall_score(yt, pred)
f1 = f1_score(yt, pred)
auc = roc_auc_score(yt, test_prob)
tn, fp, fn, tp = confusion_matrix(yt, pred).ravel()
majority = max(yt.mean(), 1 - yt.mean())

print("\n=== Results on the TEST set (websites the model never saw) ===")
print(f"Accuracy : {acc:.3f}   (a model that always says the majority class scores {majority:.3f})")
print(f"Precision: {prec:.3f}   of URLs flagged phishing, this share really were")
print(f"Recall   : {rec:.3f}   of real phishing URLs, this share was caught")
print(f"F1-score : {f1:.3f}   balance of precision and recall")
print(f"ROC-AUC  : {auc:.3f}   (0.5 = coin flip, 1.0 = perfect ranking)")
print("\nConfusion matrix (rows = truth, columns = prediction)")
print("                    pred legit   pred phishing")
print(f"  truly legit     {tn:10d}   {fp:13d}   <- false alarms")
print(f"  truly phishing  {fn:10d}   {tp:13d}   <- missed phishing")

band = np.where(test_prob <= safe_below, "legit", np.where(test_prob >= phish_above, "phish", "unsure"))
print("\nConfidence bands on the TEST set")
print("  band     URLs   share that is truly phishing")
for b in ("legit", "unsure", "phish"):
    m = band == b
    print(f"  {b:7s} {m.sum():5d}   {100 * yt[m].mean():5.1f}%" if m.sum() else f"  {b:7s}     0")

# Does the model punish legitimate sites just for containing rule words?
flags = [rule_flags(u) for u in df["url"].iloc[test_idx]]
has_kw = np.array([f["has_keyword"] for f in flags])
risky_tld = np.array([f["risky_tld"] for f in flags])
legit = yt == 0
print("\nFalse-alarm rate on LEGITIMATE test URLs (flagged phishing at 0.5):")
print(f"  all legitimate URLs                     {100 * pred[legit].mean():5.1f}%  (n={legit.sum()})")
print(f"  ... containing login/verify/... words   {100 * pred[legit & has_kw].mean():5.1f}%  (n={(legit & has_kw).sum()})")
print(f"  ... on a risky TLD (.xyz, .top, ...)    {100 * pred[legit & risky_tld].mean():5.1f}%  (n={(legit & risky_tld).sum()})")

print("\n=== What the forest relies on (feature importance) ===")
order = np.argsort(model.feature_importances_)[::-1]
for i in order[:8]:
    print(f"  {FEATURE_NAMES[i]:24s} {model.feature_importances_[i]:.3f}")
if model.feature_importances_.max() > 0.5:
    print("WARNING: one feature dominates. Check it is not a quirk of the dataset.")

# ------------------------------------------------------------- 8. save
# "baseline" = what a typical legitimate URL looks like (median of each
# feature in the training data). server.py uses it to explain predictions.
baseline = np.median(X[train_idx][y[train_idx] == 0], axis=0)

joblib.dump({
    "model": model,
    "feature_names": FEATURE_NAMES,
    "baseline": baseline.tolist(),
    "bands": {"safe_below": safe_below, "phish_above": phish_above},
    "metrics": {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "roc_auc": auc},
    "sklearn_version": sklearn.__version__,
}, "model.pkl", compress=3)
print("\nSaved model.pkl")
