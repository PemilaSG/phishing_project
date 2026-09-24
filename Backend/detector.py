import re
from pathlib import Path
import joblib
import pandas as pd
from urllib.parse import urlparse


# -----------------------------------
# Load trained model
# -----------------------------------

BASE_DIR = Path(__file__).resolve().parent
model_data = joblib.load(BASE_DIR / "model.pkl")

model = model_data["model"]

features = model_data["features"]


# -----------------------------------
# Extract features from URL
# -----------------------------------

def extract_features(url):
    # Remove trailing slash if present for standard parsing
    raw_url = url.strip()
    if raw_url.endswith("/") and len(raw_url) > 8:
        raw_url = raw_url[:-1]

    if "://" not in raw_url:
        url_for_parsing = "http://" + raw_url
    else:
        url_for_parsing = raw_url

    parsed_url = urlparse(url_for_parsing)
    domain = parsed_url.netloc.split(":")[0]
    domain_parts = domain.split(".")

    url_length = len(raw_url)
    domain_length = len(domain)

    # TLD Length
    if len(domain_parts) > 1:
        tld = domain_parts[-1]
    else:
        tld = ""
    tld_length = len(tld)

    # Subdomain count
    if len(domain_parts) > 2:
        no_of_subdomain = len(domain_parts) - 2
    else:
        no_of_subdomain = 0

    # IP check
    is_domain_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0

    # Obfuscation
    suspicious_characters = ["@", "%", "&"]
    no_of_obfuscated_char = sum(raw_url.count(c) for c in suspicious_characters)
    has_obfuscation = 1 if no_of_obfuscated_char > 0 else 0
    obfuscation_ratio = round(no_of_obfuscated_char / url_length, 3) if url_length > 0 else 0.0

    # Letters in URL (Main domain body + path letters, matching PhiUSIIL dataset logic)
    if len(domain_parts) >= 2:
        main_domain = domain_parts[-2]
    else:
        main_domain = domain
    
    path_and_query = parsed_url.path + parsed_url.query
    no_of_letters = sum(c.isalpha() for c in main_domain) + sum(c.isalpha() for c in path_and_query)
    letter_ratio = round(no_of_letters / url_length, 3) if url_length > 0 else 0.0

    # Digits in URL
    no_of_digits = sum(c.isdigit() for c in raw_url)
    digit_ratio = round(no_of_digits / url_length, 3) if url_length > 0 else 0.0

    # Special characters
    no_of_equals = raw_url.count("=")
    no_of_question_marks = raw_url.count("?")
    no_of_ampersand = raw_url.count("&")

    # Non-alphanumeric special characters
    no_of_other_special_chars = sum(
        1 for c in raw_url if not c.isalnum() and c not in [".", "/", ":", "?", "="]
    )
    special_char_ratio = round(no_of_other_special_chars / url_length, 3) if url_length > 0 else 0.0

    # HTTPS check
    is_https = 1 if parsed_url.scheme == "https" else 0

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_of_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_of_obfuscated_char,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": no_of_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_of_digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": no_of_equals,
        "NoOfQMarkInURL": no_of_question_marks,
        "NoOfAmpersandInURL": no_of_ampersand,
        "NoOfOtherSpecialCharsInURL": no_of_other_special_chars,
        "SpacialCharRatioInURL": special_char_ratio,
        "IsHTTPS": is_https
    }


# -----------------------------------
# Predict URL
# -----------------------------------

def predict_url(url):
    # Extract features
    feature_values = extract_features(url)

    # Create DataFrame
    input_data = pd.DataFrame(
        [
            [
                feature_values[feature]
                for feature in features
            ]
        ],
        columns=features
    )

    # Make prediction
    prediction = model.predict(input_data)[0]

    # Calculate confidence / probability
    probabilities = model.predict_proba(input_data)[0]
    classes = list(model.classes_)
    
    # Class index for prediction
    pred_idx = classes.index(prediction)
    confidence = round(float(probabilities[pred_idx]) * 100, 1)

    # Determine if phishing or legitimate
    # Note: In PhiUSIIL dataset, label 1 is Legitimate, 0 is Phishing
    if prediction == 1:
        result_label = "Legitimate"
        is_phishing = False
    else:
        result_label = "Phishing"
        is_phishing = True

    # Generate reasons breakdown
    reasons = []

    if is_phishing:
        if feature_values["IsHTTPS"] == 0:
            reasons.append("URL does not use secure HTTPS encryption")
        if feature_values["URLLength"] > 54:
            reasons.append(f"Unusually long URL length ({feature_values['URLLength']} characters)")
        if feature_values["NoOfSubDomain"] > 1:
            reasons.append(f"Contains multiple subdomains ({feature_values['NoOfSubDomain']} subdomains)")
        if feature_values["IsDomainIP"] == 1:
            reasons.append("Uses an IP address instead of a domain name")
        if feature_values["HasObfuscation"] == 1:
            reasons.append("Contains suspicious obfuscated characters (@, %, &)")
        if feature_values["DegitRatioInURL"] > 0.15:
            reasons.append("High proportion of numeric digits in the URL")
        if feature_values["SpacialCharRatioInURL"] > 0.08:
            reasons.append("High count of special characters in the URL path")

        if not reasons:
            reasons.append("URL matches suspicious structural patterns detected by AI model")
    else:
        if feature_values["IsHTTPS"] == 1:
            reasons.append("Uses secure HTTPS encryption protocol")
        if feature_values["URLLength"] <= 54:
            reasons.append(f"Standard URL length ({feature_values['URLLength']} characters)")
        if feature_values["NoOfSubDomain"] <= 1:
            reasons.append("Clean domain structure without excessive subdomains")
        if feature_values["HasObfuscation"] == 0:
            reasons.append("No suspicious obfuscated characters found")

        if not reasons:
            reasons.append("URL passes standard domain safety and structural checks")

    return {
        "label": result_label,
        "is_phishing": is_phishing,
        "confidence": confidence,
        "reasons": reasons,
        "features": feature_values
    }