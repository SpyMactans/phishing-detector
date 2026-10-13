"""
features.py - turns a URL string into a fixed list of numbers.

train.py and server.py both import this file, so the model sees features
computed in exactly the same way when it learns and when it predicts.
(If the two used different code, the model would be fed numbers it never
trained on - a classic ML bug called "training/serving skew".)

The features are the same kinds of measurements your C++ analyzer already
makes (lengths, dots, hyphens, digits, IP host, '@', port, % signs ...).
We pass the model raw measurements and let it learn how much each one
matters. We do NOT pass it your hand-picked weights or verdicts.

The rule LISTS (keywords such as "login", risky TLDs such as ".xyz", URL
shorteners, popular brands for typosquatting) are deliberately NOT model
inputs. They stay in the C++ heuristic engine. Reasons:
  1. The public datasets contain very few legitimate URLs with such words,
     so a model fed them just learns "login => phishing" and flags real
     login pages (we measured this - see README).
  2. If both engines used the same signals, the final risk would count the
     same evidence twice.
The lists below are only used to REPORT how the model behaves on those
cases (see train.py).
"""

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "banking", "password", "billing", "webscr", "suspend", "unlock",
    "invoice", "wallet", "recover", "support", "helpdesk", "security-alert",
]

RISKY_TLDS = [
    ".zip", ".mov", ".xyz", ".top", ".click", ".work", ".gq", ".tk",
    ".ml", ".cf", ".loan", ".men", ".review", ".country",
]

# The order of this list is the order of the numbers fed to the model.
FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "path_depth",
    "query_params",
    "host_is_ip",
    "has_at_sign",
    "dots_in_host",
    "hyphens_in_host",
    "digits_in_host",
    "nonstandard_port",
    "percent_count",
    "double_slash_in_path",
]


def parse_url(raw):
    """Same idea as parseUrl() in main.cpp: split into scheme/host/port/path/query."""
    url = raw.strip()
    scheme = ""
    if "://" in url:
        scheme, url = url.split("://", 1)
        scheme = scheme.lower()
    url_no_scheme = url

    # The host ends at the first / ? or #. Only look for '@' inside that
    # part, so  https://medium.com/@user  is not mistaken for user@host.
    cut = len(url)
    for ch in "/?#":
        i = url.find(ch)
        if i != -1 and i < cut:
            cut = i
    authority, rest = url[:cut], url[cut:]

    has_at = "@" in authority
    if has_at:
        authority = authority.rsplit("@", 1)[1]

    host, port = authority, ""
    if ":" in authority:
        host, port = authority.split(":", 1)
    host = host.lower()

    path, query = rest, ""
    if "?" in rest:
        path, query = rest.split("?", 1)

    return {
        "scheme": scheme, "host": host, "port": port, "path": path,
        "query": query, "has_at": has_at, "url_no_scheme": url_no_scheme,
    }


def is_ipv4(host):
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or len(p) > 3 or int(p) > 255:
            return False
    return True


def registered_domain(host):
    """Rough 'main domain' of a host, e.g. mail.google.com -> google.com.
    Used to group URLs so the same site never lands in both train and test.
    (Approximation: handles co.uk-style endings but is not a full public-suffix list.)"""
    if is_ipv4(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def rule_flags(raw_url):
    """Only used by train.py to measure how the model treats URLs that contain
    rule-list words. NOT a model input."""
    p = parse_url(raw_url)
    text = (p["host"] + p["path"] + p["query"]).lower()
    return {
        "has_keyword": any(k in text for k in SUSPICIOUS_KEYWORDS),
        "risky_tld": any(p["host"].endswith(t) for t in RISKY_TLDS),
    }


def extract_features(raw_url):
    """Return a dict {feature_name: number} for one URL."""
    p = parse_url(raw_url)
    host, path, query = p["host"], p["path"], p["query"]

    # "www." says nothing about a site's honesty, but some datasets keep it
    # and some strip it. Remove it so the model cannot learn that quirk.
    url_length = len(p["url_no_scheme"])
    if host.startswith("www."):
        host = host[4:]
        if p["url_no_scheme"].lower().startswith("www."):
            url_length -= 4

    return {
        # Lengths are measured WITHOUT the "http://" part, because some
        # datasets store URLs with it and some without - we don't want the
        # model to learn that quirk of the dataset.
        "url_length": url_length,
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "path_depth": path.count("/"),
        "query_params": 0 if not query else query.count("&") + 1,
        "host_is_ip": 1 if is_ipv4(host) else 0,
        "has_at_sign": 1 if p["has_at"] else 0,
        "dots_in_host": host.count("."),
        "hyphens_in_host": host.count("-"),
        "digits_in_host": sum(c.isdigit() for c in host),
        "nonstandard_port": 1 if p["port"] not in ("", "80", "443") else 0,
        "percent_count": raw_url.count("%"),
        "double_slash_in_path": 1 if "//" in path else 0,
    }


def to_vector(features):
    return [features[name] for name in FEATURE_NAMES]
