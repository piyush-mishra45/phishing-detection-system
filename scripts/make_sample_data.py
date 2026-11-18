"""Generates SMALL SYNTHETIC demo datasets so the training pipeline and app can run out-of-the-box.

!!  These are template-generated and NOT real phishing/legitimate data.  Metrics computed on them say
!!  NOTHING about real-world accuracy.  Replace with real datasets (see datasets/README.md) and retrain.
"""
import csv
import random
from pathlib import Path

random.seed(7)
OUT = Path(__file__).resolve().parent.parent / "datasets"

brands = ["PayPal", "Microsoft", "Apple", "Amazon", "Netflix", "your bank", "DHL", "Google", "Facebook", "DocuSign"]
phish_open = ["Dear customer,", "Dear user,", "Attention account holder,", "URGENT NOTICE:", "Security Alert:", "Final warning:", "Hello,"]
phish_body = [
    "We detected unusual sign-in activity on your {b} account. Verify your account immediately or it will be suspended within 24 hours: {u}",
    "Your {b} payment failed. Update your billing information now to avoid account closure. Click here: {u}",
    "Congratulations! You have won a free gift card. Claim your prize before it expires today: {u}",
    "Your password will expire in 24 hours. Confirm your password and login to your account to keep access: {u}",
    "Invoice attached. A wire transfer is pending, please confirm your bank account details urgently: {u}",
    "Your {b} account has been locked due to suspicious activity. Restore access by verifying your identity: {u}",
    "You are selected for a tax refund. Submit your credit card and personal details to receive the refund: {u}",
]
legit_open = ["Hi team,", "Hello Sam,", "Hi all,", "Good morning,", "Dear colleagues,", "Hi Priya,", "Thanks everyone,"]
legit_body = [
    "Just a reminder that our weekly project sync is tomorrow at 10am in the main meeting room. Agenda is attached in the calendar invite.",
    "Please find the meeting notes from Monday below. Let me know if I missed any action items and I will update the document.",
    "The quarterly report draft is ready for review. Could you share your comments by Friday so we can finalise it next week?",
    "Thanks for your order. Your package shipped today and should arrive in three to five business days. Tracking is available on our website.",
    "Our team lunch is on Thursday at noon. Let me know about dietary preferences and I will book the restaurant.",
    "Here is the monthly newsletter with updates on new features, upcoming events and community highlights. Enjoy the read!",
    "I reviewed your pull request and left a few small suggestions. Overall it looks great, happy to merge once the tests pass.",
]
subj_p = ["Verify your account now", "URGENT: account suspended", "You have won!", "Payment failed - action required", "Security alert", "Confirm your password"]
subj_l = ["Weekly sync", "Meeting notes", "Q3 report draft", "Order shipped", "Team lunch", "Newsletter", "Code review"]
tlds = ["tk", "xyz", "top", "click", "ml", "ga"]
legit_domains = ["google.com", "wikipedia.org", "github.com", "stackoverflow.com", "python.org", "mozilla.org", "bbc.co.uk", "nytimes.com", "apple.com", "microsoft.com", "amazon.com",
                 "reddit.com", "linkedin.com", "cloudflare.com", "nasa.gov", "mit.edu", "harvard.edu", "who.int", "paypal.com", "dropbox.com", "netflix.com", "ibm.com", "oracle.com", "adobe.com"]
legit_paths = ["", "/", "/about", "/products/overview", "/docs/getting-started", "/blog/2024/update", "/search?q=news", "/en/support", "/careers"]
kw = ["login", "verify", "secure", "update", "account", "confirm", "signin", "banking"]


def emails(n=300):
    rows = []
    for _ in range(n):
        b = random.choice(brands)
        url = f"http://{random.choice(['secure', 'login', 'verify'])}-{b.split()[0].lower()}.{random.choice(tlds)}/{random.choice(kw)}"
        rows.append((f"{random.choice(subj_p)}\n{random.choice(phish_open)} {random.choice(phish_body).format(b=b, u=url)}", 1))
        rows.append((f"{random.choice(subj_l)}\n{random.choice(legit_open)} {random.choice(legit_body)} Regards, {random.choice(['Alex', 'Jordan', 'Sam', 'Taylor'])}", 0))
    return rows


def urls(n=400):
    rows = set()
    while len(rows) < n:
        d = random.choice(legit_domains)
        rows.add((f"{random.choice(['https', 'https', 'http'])}://{random.choice(['', 'www.', 'docs.'])}{d}{random.choice(legit_paths)}", 0))
    pk = set()
    while len(pk) < n:
        b = random.choice(["paypal", "apple", "microsoft", "amazon", "netflix", "google", "hdfc", "sbi"])
        style = random.randint(0, 4)
        k1, k2 = random.sample(kw, 2)
        if style == 0:
            u = f"http://{b}-{k1}-{random.randint(10, 999)}.{random.choice(tlds)}/{k2}/index.php?id={random.randint(1000, 99999)}"
        elif style == 1:
            u = f"http://{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}/{b}/{k1}.html"
        elif style == 2:
            u = f"https://{b}.com.{k1}-{k2}.{random.choice(tlds)}/signin?session={random.randint(10**6, 10**9)}"
        elif style == 3:
            u = f"http://{k1}.{k2}.{b}.account-{random.randint(1, 99)}.{random.choice(tlds)}/wp-content/{k1}"
        else:
            u = f"http://user@{b}{random.randint(1, 9)}.{random.choice(tlds)}:{random.choice([8080, 8888, 2083])}/{k1}"
        pk.add((u, 1))
    return list(rows) + list(pk)


for name, header, data in (("sample_phishing_emails.csv", ["text", "label"], emails()), ("sample_phishing_urls.csv", ["url", "label"], urls())):
    random.shuffle(data)
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(data)
    print("wrote", OUT / name, len(data), "rows (SYNTHETIC)")
