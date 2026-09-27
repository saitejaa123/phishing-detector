"""
Dataset Generator
Creates a labelled CSV dataset of phishing (1) and legitimate (0) URLs
with extracted features. Used to train the ML models.
"""

import random
import pandas as pd
from pathlib import Path
from feature_extractor import extract_features, FEATURE_NAMES

random.seed(42)

# ── Sample URL pools ──────────────────────────────────────────────────────────

LEGIT_URLS = [
    "https://www.google.com",
    "https://www.github.com/trending",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.wikipedia.org/wiki/Machine_learning",
    "https://www.amazon.com/s?k=laptop",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.linkedin.com/feed",
    "https://www.reddit.com/r/netsec",
    "https://docs.python.org/3/library/re.html",
    "https://www.bbc.com/news/technology",
    "https://www.apple.com/iphone",
    "https://www.microsoft.com/en-us/windows",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.netflix.com/browse",
    "https://www.ebay.com/sch/i.html?_nkw=phone",
    "https://www.paypal.com/us/home",
    "https://www.dropbox.com/login",
    "https://www.salesforce.com",
    "https://www.adobe.com/products/photoshop.html",
    "https://www.cloudflare.com",
    "https://www.mozilla.org/en-US/firefox",
    "https://www.oracle.com/java",
    "https://www.ibm.com/cloud",
    "https://www.cisco.com/c/en/us/products",
    "https://www.intel.com/content/www/us/en/homepage.html",
    "https://www.samsung.com/us",
    "https://www.hp.com/us-en/home.html",
    "https://www.dell.com/en-us",
]

PHISHING_URLS = [
    "http://paypa1-secure-login.com/verify?user=victim",
    "http://192.168.1.1/login/account-update.php",
    "http://apple-id-verify.support/unlock?token=abc123",
    "http://secure-banking-update.tk/login",
    "http://bit.ly/3xPhish1ng",
    "http://amazon-account-suspended.ml/signin",
    "http://login.microsoft-support-alert.com/password-reset",
    "http://facebook-security.cf/confirm-identity",
    "http://netflix-billing-update.xyz/account/update",
    "http://ebay-account-verify.ga/ebayisapi.dll",
    "http://google-account-locked.tk/signin/verify",
    "http://paypal.com.malicious-domain.ru/wallet",
    "http://www.secure-login-update.info/bank/signin",
    "http://credential-verify.win/login.php",
    "http://update-your-password.xyz/microsoft/login",
    "http://confirm-your-account.ml/amazon/signin",
    "http://support-apple-id.com/account/validate",
    "http://instagram-verify.tk/account-confirm",
    "http://www-paypal-com.phishingsite.com/webscr",
    "http://twitter-login-verify.ml/account",
    "http://12.34.56.78/login/banking",
    "http://secure.update-account.ga/signin",
    "http://dropbox-phish.tk/files/share?token=abc",
    "http://chase-bank-login.xyz/online/banking/signin",
    "http://steam-free-items.gq/login?redirect=steampowered",
    "http://fake-antivirus-alert.ml/download/security.exe",
    "http://prize-winner-confirm.win/claim?id=99999",
    "http://login-support.amazon.com.evil-domain.com/signin",
    "http://secure.paypal.account-verify.club/wallet",
    "http://microsoft-alert.support/windows/security/update",
]


def _augment_url(url: str, phishing: bool) -> str:
    """Slightly mutate a URL to expand the dataset with variation."""
    mutations = []
    if phishing:
        mutations = [
            lambda u: u.replace("http://", "http://") + "&session=" + str(random.randint(1000, 9999)),
            lambda u: u + "?id=" + str(random.randint(100000, 999999)),
            lambda u: u.replace(".com", [".ml", ".tk", ".cf", ".ga", ".xyz"][random.randint(0, 4)]),
            lambda u: "http://www." + u.split("//")[-1],
        ]
    else:
        mutations = [
            lambda u: u + "/page/" + str(random.randint(1, 50)),
            lambda u: u + "?lang=en",
            lambda u: u + "#section-" + str(random.randint(1, 10)),
            lambda u: u,
        ]
    if mutations:
        fn = random.choice(mutations)
        try:
            return fn(url)
        except Exception:
            return url
    return url


def generate_dataset(n_legit: int = 500, n_phish: int = 500,
                     output_path: str = None) -> pd.DataFrame:
    """
    Generate a labelled dataset.
    Each URL is augmented to reach n_legit / n_phish samples.
    Returns a DataFrame and optionally saves it as CSV.
    """
    rows = []

    # Legitimate URLs (label = 0)
    for i in range(n_legit):
        base = LEGIT_URLS[i % len(LEGIT_URLS)]
        url  = _augment_url(base, phishing=False)
        feats = extract_features(url)
        row   = {name: feats[name] for name in FEATURE_NAMES}
        row["label"] = 0
        row["url"]   = url
        rows.append(row)

    # Phishing URLs (label = 1)
    for i in range(n_phish):
        base = PHISHING_URLS[i % len(PHISHING_URLS)]
        url  = _augment_url(base, phishing=True)
        feats = extract_features(url)
        row   = {name: feats[name] for name in FEATURE_NAMES}
        row["label"] = 1
        row["url"]   = url
        rows.append(row)

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"[+] Dataset saved → {output_path}  ({len(df)} rows)")

    return df


if __name__ == "__main__":
    generate_dataset(
        n_legit=500,
        n_phish=500,
        output_path=str(Path(__file__).parent.parent / "data" / "phishing_dataset.csv"),
    )
