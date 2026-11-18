# Datasets

`sample_phishing_emails.csv` and `sample_phishing_urls.csv` are **synthetic, template-generated demo files**
(`scripts/make_sample_data.py`). They exist only so the pipeline runs out of the box. Because they are
trivially separable, models reach ~100% on them. **That says nothing about real-world accuracy.**

## Use real data (recommended)
Place these files here, then run `python train_email_model.py` and `python train_website_model.py` from `backend/`:

| File | Columns | Suggested sources (check each licence) |
|---|---|---|
| `phishing_emails.csv` | `text,label` (also accepts Kaggle's `Email Text,Email Type`) | Kaggle "Phishing Email Dataset" (Naser Abdullah Alam); Nazario phishing corpus; Enron (legitimate); SpamAssassin public corpus |
| `phishing_urls.csv` | `url,label` (also accepts `URL,Label` with `bad/good`) | PhishTank or OpenPhish feeds (phishing); Tranco list or Common Crawl (legitimate); Kaggle "Phishing Site URLs"; UCI Phishing Websites |

Label values understood: `1/phishing/bad/malicious/spam` = phishing, `0/legitimate/safe/good/ham` = legitimate.

## Pitfalls that inflate metrics
* **Source bias** - phishing URLs (full paths) vs. top-site domains (no paths): the model may learn "has a path". Build legit URLs with realistic paths too.
* **Time leakage** - phishing campaigns repeat; split by time/campaign if you can.
* **Duplicates** - removed by the training scripts, but near-duplicates remain.
* **Stale data** - phishing URLs die in hours; retrain regularly.
