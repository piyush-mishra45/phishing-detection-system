"""Model smoke tests. Require trained models in /models (run backend/train_*.py first)."""
import pytest

from app.ml import predictor

pytestmark = pytest.mark.skipif(not (predictor.email_ready() and predictor.website_ready()), reason="models not trained")


def test_probabilities_in_range():
    assert 0 <= predictor.predict_email_prob("Verify your account immediately") <= 1
    assert 0 <= predictor.predict_url_prob("http://paypal-login.tk/verify") <= 1


def test_models_rank_obvious_cases_sensibly():
    assert predictor.predict_url_prob("http://paypal-secure-login-48.tk/verify/index.php?id=123") > predictor.predict_url_prob("https://www.python.org/downloads/")
    assert predictor.predict_email_prob("URGENT verify your account password suspended click here") > predictor.predict_email_prob("Hi team, notes from the project meeting attached")
