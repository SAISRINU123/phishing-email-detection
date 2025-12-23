"""
Train phishing email detection model
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
from phishing_detector import PhishingDetector

def create_sample_data():
    """Create sample training data if no dataset exists"""
    print("Creating sample training data...")
    
    # Sample phishing emails
    phishing_samples = [
        {
            'subject': 'URGENT: Verify Your Account Immediately!',
            'content': 'Dear Customer, Your account has been suspended. Click here to verify: http://bit.ly/suspicious-link. Act now or your account will be deleted!',
            'from': 'support@suspicious-domain.com',
            'to': 'user@email.com',
            'label': 1
        },
        {
            'subject': 'You Won a Prize! Claim Now!',
            'content': 'Congratulations! You have won $1000. Click below to claim your prize: http://tinyurl.com/fake-prize. Limited time offer!',
            'from': 'noreply@fake-lottery.com',
            'to': 'user@email.com',
            'label': 1
        },
        {
            'subject': 'Password Reset Required',
            'content': 'We detected unusual activity on your account. Please verify your identity by clicking here: http://192.168.1.1/fake-login. Your password will expire in 24 hours!',
            'from': 'security@phishing-site.com',
            'to': 'user@email.com',
            'label': 1
        },
        {
            'subject': 'Update Your Payment Information',
            'content': 'Your payment method expired. Update now: <a href="http://fake-payment-site.com">Click Here</a>. Your account will be locked if not updated immediately!',
            'from': 'billing@scam-service.com',
            'to': 'user@email.com',
            'label': 1
        },
        {
            'subject': 'Urgent: Account Verification Needed',
            'content': 'Your account requires immediate verification. Please confirm your details at: http://bit.ly/verify-now. Failure to verify will result in account suspension.',
            'from': 'admin@suspicious-service.com',
            'to': 'user@email.com',
            'label': 1
        },
    ]
    
    # Sample legitimate emails
    legitimate_samples = [
        {
            'subject': 'Meeting scheduled for tomorrow',
            'content': 'Hi, just confirming our meeting tomorrow at 2 PM. See you then. Best regards.',
            'from': 'colleague@company.com',
            'to': 'user@email.com',
            'label': 0
        },
        {
            'subject': 'Monthly Report',
            'content': 'Please find attached the monthly report. Let me know if you have any questions.',
            'from': 'manager@company.com',
            'to': 'user@email.com',
            'label': 0
        },
        {
            'subject': 'Newsletter - January 2024',
            'content': 'Here is your monthly newsletter with company updates and news. Visit our website for more information.',
            'from': 'newsletter@company.com',
            'to': 'user@email.com',
            'label': 0
        },
        {
            'subject': 'Project Update',
            'content': 'The project is progressing well. We have completed phase 1. Next steps are outlined in the attached document.',
            'from': 'team@company.com',
            'to': 'user@email.com',
            'label': 0
        },
        {
            'subject': 'Thank you for your inquiry',
            'content': 'Thank you for contacting us. We have received your message and will respond within 24 hours.',
            'from': 'support@company.com',
            'to': 'user@email.com',
            'label': 0
        },
    ]
    
    # Expand dataset by creating variations
    all_samples = phishing_samples * 10 + legitimate_samples * 10
    
    return all_samples

def load_or_create_dataset(csv_path='phishing_dataset.csv'):
    """Load dataset from CSV or create sample data"""
    if os.path.exists(csv_path):
        print(f"Loading dataset from {csv_path}...")
        df = pd.read_csv(csv_path)
        return df
    else:
        print(f"Dataset not found at {csv_path}. Creating sample dataset...")
        samples = create_sample_data()
        df = pd.DataFrame(samples)
        df.to_csv(csv_path, index=False)
        print(f"Sample dataset saved to {csv_path}")
        return df

def prepare_features(df, detector):
    """Extract features from dataset"""
    print("Extracting features...")
    features_list = []
    
    for _, row in df.iterrows():
        features = detector.extract_features(
            email_content=row['content'],
            email_subject=row['subject'],
            from_address=row['from'],
            to_address=row['to']
        )
        features_list.append(features)
    
    features_df = pd.DataFrame(features_list)
    return features_df

def train_phishing_model():
    """Main training function"""
    print("=" * 50)
    print("Phishing Email Detection Model Training")
    print("=" * 50)
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Load or create dataset
    df = load_or_create_dataset()
    
    print(f"\nDataset loaded: {len(df)} samples")
    print(f"Phishing emails: {df['label'].sum()}")
    print(f"Legitimate emails: {len(df) - df['label'].sum()}")
    
    # Extract features
    X = prepare_features(df, detector)
    y = df['label'].values
    
    print(f"\nExtracted {X.shape[1]} features")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Train Random Forest model
    print("\nTraining Random Forest model...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = rf_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print("\n" + "=" * 50)
    print("Model Evaluation Results")
    print("=" * 50)
    print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Save model
    model_path = 'phishing_model.pkl'
    joblib.dump(rf_model, model_path)
    print(f"\nModel saved to {model_path}")
    
    # Save feature names for later use
    feature_names_path = 'feature_names.pkl'
    joblib.dump(list(X.columns), feature_names_path)
    print(f"Feature names saved to {feature_names_path}")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    print(feature_importance.head(10).to_string(index=False))
    
    return rf_model

if __name__ == "__main__":
    train_phishing_model()

