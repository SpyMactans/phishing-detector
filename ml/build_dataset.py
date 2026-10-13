"""
build_dataset.py - downloads two public URL lists and writes dataset.csv

    label 1 = phishing    (Phishing.Database "ACTIVE" list, real phishing URLs)
    label 0 = legitimate  (a) the "good" rows of a public good/bad URL dataset
                              (ordinary pages with paths)
                          (b) homepages of sites from a public top-1-million
                              domain list (so legitimate sites on .xyz, .top,
                              .tk ... exist in the data, and the model cannot
                              learn "this TLD = phishing")
                          (c) top-1-million domains + an ordinary page such as
                              /login, /account, /about. Without these the
                              model learns "short path like /login = phishing",
                              because the other legitimate rows have none.
                              NOTE: these URLs are constructed, not crawled.

Run:  python build_dataset.py

The URLs are only treated as TEXT. Nothing here ever visits them.

IMPORTANT - read this before you trust any accuracy number:
The two classes come from two different places and different years, so the
model can partly learn "which list did this URL come from" instead of
"is this phishing". That is a limitation of almost every public dataset.
For a stronger project, collect both classes the same way, or compare
results on a second, independent dataset.
"""
import csv
import io
import json
import random
import time
import urllib.request

import re

from features import RISKY_TLDS, parse_url, registered_domain

PHISH_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
LEGIT_URL = "https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv"

TOP_URL = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains"

N_PHISHING = 20000        # phishing URLs to keep
N_LEGIT_PAGES = 25000     # legitimate pages with paths
N_LEGIT_HOMES = 15000     # legitimate homepages, picked at random from the top-1M list
N_PER_RISKY_TLD = 100     # extra legitimate homepages for each TLD in RISKY_TLDS
N_LEGIT_GENERIC = 8000    # legitimate domain + ordinary page (constructed)
GENERIC_PATHS = [
    "/login", "/signin", "/sign-in", "/account", "/my-account", "/about",
    "/contact", "/help", "/support", "/pricing", "/blog", "/news", "/careers",
    "/privacy", "/terms", "/store", "/user/login", "/account/login",
    "/en/login", "/search?q=test",
]
# Sites used as examples in README.md. They are removed from the dataset so
# the examples are tested on sites the model has never seen.
DEMO_DOMAINS = {"github.com", "paypal.com", "google.com", "wikipedia.org", "medium.com",
                "amazon.com", "abc.xyz", "microsoft.com", "apple.com", "example.com"}
# Total legitimate is roughly twice the phishing count: a mild imbalance on purpose.
MAX_PER_DOMAIN = 20    # no single website may dominate a class
SEED = 42


def download(url):
    print("downloading", url)
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read().decode("utf-8", errors="ignore")


def clean(urls):
    """Keep sane-looking http(s) / scheme-less URLs, drop duplicates."""
    seen, out = set(), []
    for u in urls:
        u = u.strip()
        if not u or len(u) > 300 or any(c.isspace() for c in u):
            continue
        low = u.lower()
        if "://" in low and not low.startswith(("http://", "https://")):
            continue                       # skip ftp:// and similar
        key = low.split("://", 1)[-1].rstrip("/")
        host = parse_url(u)["host"]
        if "." not in host or key in seen:
            continue
        seen.add(key)
        out.append(u)
    return out


def cap_per_domain(urls, rng):
    rng.shuffle(urls)
    count, out = {}, []
    for u in urls:
        d = registered_domain(parse_url(u)["host"])
        if count.get(d, 0) < MAX_PER_DOMAIN:
            count[d] = count.get(d, 0) + 1
            out.append(u)
    return out


def top_domain_urls(text, rng):
    """Legitimate URLs built from the top-1M domain list: (homepages, ordinary pages)."""
    domains = []
    for line in text.splitlines():
        d = line.strip().lower().split(",")[-1]
        if re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,98}\.[a-z]{2,}", d) and registered_domain(d) not in DEMO_DOMAINS:
            domains.append(d)
    rng.shuffle(domains)
    homes = domains[:N_LEGIT_HOMES]
    generic = domains[N_LEGIT_HOMES:N_LEGIT_HOMES + N_LEGIT_GENERIC]
    rest = domains[N_LEGIT_HOMES + N_LEGIT_GENERIC:]
    for tld in RISKY_TLDS:
        homes += [d for d in rest if d.endswith(tld)][:N_PER_RISKY_TLD]
    home_urls = ["https://" + d for d in homes]
    page_urls = ["https://" + d + rng.choice(GENERIC_PATHS) for d in generic]
    return home_urls, page_urls


def main():
    rng = random.Random(SEED)

    phish_raw = download(PHISH_URL).splitlines()
    legit_rows = csv.reader(io.StringIO(download(LEGIT_URL)))
    next(legit_rows)                                    # header: url,label
    legit_raw = [row[0] for row in legit_rows if len(row) >= 2 and row[-1] == "good"]

    phish = cap_per_domain(clean(phish_raw), rng)[:N_PHISHING]
    not_demo = lambda urls: [u for u in urls if registered_domain(parse_url(u)["host"]) not in DEMO_DOMAINS]
    phish = not_demo(phish)
    legit_pages = not_demo(cap_per_domain(clean(legit_raw), rng))[:N_LEGIT_PAGES]
    legit_homes, legit_generic = top_domain_urls(download(TOP_URL), rng)
    legit = legit_pages + legit_homes + legit_generic

    rows = [(u, 1) for u in phish] + [(u, 0) for u in legit]
    rng.shuffle(rows)

    with open("dataset.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        w.writerows(rows)

    info = {
        "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "phishing_source": PHISH_URL, "legit_pages_source": LEGIT_URL,
        "legit_homepages_source": TOP_URL,
        "phishing_rows": len(phish), "legit_page_rows": len(legit_pages),
        "legit_homepage_rows": len(legit_homes),
        "legit_constructed_page_rows": len(legit_generic),
        "max_per_domain": MAX_PER_DOMAIN, "seed": SEED,
    }
    with open("dataset_info.json", "w") as f:
        json.dump(info, f, indent=2)
    print(json.dumps(info, indent=2))
    print("wrote dataset.csv")


if __name__ == "__main__":
    main()
