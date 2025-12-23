"""
Phishing Email Detection Script
Use trained model to detect phishing emails
"""

import joblib
import pandas as pd
import sys
import os
from typing import Dict
from phishing_detector import PhishingDetector

def detect_email(email_content: str, email_subject: str = "", 
                from_address: str = "", to_address: str = "", 
                model_path: str = 'phishing_model.pkl') -> Dict:
    """
    Detect if an email is phishing
    
    Args:
        email_content: Email body content
        email_subject: Email subject line
        from_address: Sender email address
        to_address: Recipient email address
        model_path: Path to trained model
        
    Returns:
        Dictionary with prediction results
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at {model_path}. Please train the model first using train_model.py"
        )
    
    # Load model
    model = joblib.load(model_path)
    
    # Initialize detector and extract features
    detector = PhishingDetector()
    features = detector.extract_features(
        email_content=email_content,
        email_subject=email_subject,
        from_address=from_address,
        to_address=to_address
    )
    
    # Convert to DataFrame with correct feature order
    try:
        feature_names_path = 'feature_names.pkl'
        if os.path.exists(feature_names_path):
            feature_names = joblib.load(feature_names_path)
            features_df = pd.DataFrame([features])[feature_names]
        else:
            features_df = pd.DataFrame([features])
    except:
        features_df = pd.DataFrame([features])
    
    # Make prediction
    prediction = model.predict(features_df)[0]
    probability = model.predict_proba(features_df)[0]
    
    result = {
        'is_phishing': bool(prediction == 1),
        'phishing_probability': float(probability[1]),
        'legitimate_probability': float(probability[0]),
        'confidence': float(max(probability)),
        'features': features
    }
    
    return result

def detect_from_file(email_file_path: str, model_path: str = 'phishing_model.pkl') -> Dict:
    """Detect phishing from email file"""
    detector = PhishingDetector()
    
    # Parse email file
    features = detector.parse_email_file(email_file_path)
    
    if not features:
        return {'error': 'Failed to parse email file'}
    
    # Load model
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at {model_path}. Please train the model first using train_model.py"
        )
    
    model = joblib.load(model_path)
    
    # Convert to DataFrame
    try:
        feature_names_path = 'feature_names.pkl'
        if os.path.exists(feature_names_path):
            feature_names = joblib.load(feature_names_path)
            features_df = pd.DataFrame([features])[feature_names]
        else:
            features_df = pd.DataFrame([features])
    except:
        features_df = pd.DataFrame([features])
    
    # Make prediction
    prediction = model.predict(features_df)[0]
    probability = model.predict_proba(features_df)[0]
    
    result = {
        'is_phishing': bool(prediction == 1),
        'phishing_probability': float(probability[1]),
        'legitimate_probability': float(probability[0]),
        'confidence': float(max(probability)),
        'features': features
    }
    
    return result

def print_results(result):
    """Print detection results in a formatted way"""
    print("\n" + "=" * 60)
    print("PHISHING EMAIL DETECTION RESULTS")
    print("=" * 60)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        return
    
    print(f"\nPrediction: {'⚠️  PHISHING EMAIL DETECTED' if result['is_phishing'] else '✅ Legitimate Email'}")
    print(f"\nConfidence: {result['confidence']*100:.2f}%")
    print(f"Phishing Probability: {result['phishing_probability']*100:.2f}%")
    print(f"Legitimate Probability: {result['legitimate_probability']*100:.2f}%")
    
    print("\nKey Features Detected:")
    features = result['features']
    print(f"  - Suspicious Keywords: {features.get('suspicious_keywords_count', 0)}")
    print(f"  - URLs Found: {features.get('url_count', 0)}")
    print(f"  - Suspicious URLs: {features.get('suspicious_urls', 0)}")
    print(f"  - Urgent Language: {'Yes' if features.get('urgent_language', 0) else 'No'}")
    print(f"  - IP in URL: {'Yes' if features.get('ip_in_url', 0) else 'No'}")
    print(f"  - Spam Score: {features.get('spam_score', 0):.2f}")
    
    print("\n" + "=" * 60)
    
    # Recommendation
    if result['is_phishing']:
        print("\n⚠️  WARNING: This email is likely a phishing attempt!")
        print("Recommendations:")
        print("  - Do not click any links")
        print("  - Do not download attachments")
        print("  - Do not provide personal information")
        print("  - Delete the email")
        print("  - Report to your IT security team")
    else:
        print("\n✅ This email appears to be legitimate.")
        print("However, always exercise caution with emails requesting sensitive information.")

def main():
    """Command-line interface"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python detect_phishing.py <email_file_path>")
        print("  python detect_phishing.py --interactive")
        print("\nExample:")
        print("  python detect_phishing.py email.txt")
        return
    
    if sys.argv[1] == '--interactive':
        print("Interactive Phishing Email Detection")
        print("-" * 40)
        
        subject = input("Enter email subject (or press Enter to skip): ").strip()
        content = input("Enter email content: ").strip()
        from_addr = input("Enter sender email (or press Enter to skip): ").strip()
        
        if not content:
            print("Error: Email content is required")
            return
        
        result = detect_email(content, subject, from_addr)
        print_results(result)
    else:
        email_file = sys.argv[1]
        if not os.path.exists(email_file):
            print(f"Error: File not found: {email_file}")
            return
        
        result = detect_from_file(email_file)
        print_results(result)

if __name__ == "__main__":
    main()

