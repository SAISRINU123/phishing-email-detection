"""
Example usage of the phishing detection system
"""

from detect_phishing import detect_email, print_results

def example_1_phishing_email():
    """Example: Detecting a phishing email"""
    print("=" * 60)
    print("Example 1: Phishing Email Detection")
    print("=" * 60)
    
    email_subject = "URGENT: Verify Your Account Immediately!"
    email_content = """
    Dear Customer,
    
    We have detected unusual activity on your account. Your account has been 
    temporarily suspended for security reasons.
    
    Please verify your account by clicking the link below:
    http://bit.ly/verify-account-now
    
    You must verify within 24 hours or your account will be permanently deleted.
    
    This is urgent! Click here now: http://192.168.1.100/fake-login
    
    Thank you,
    Account Security Team
    """
    from_address = "security@suspicious-bank.com"
    
    result = detect_email(
        email_content=email_content,
        email_subject=email_subject,
        from_address=from_address
    )
    
    print_results(result)

def example_2_legitimate_email():
    """Example: Detecting a legitimate email"""
    print("\n" + "=" * 60)
    print("Example 2: Legitimate Email Detection")
    print("=" * 60)
    
    email_subject = "Meeting scheduled for tomorrow"
    email_content = """
    Hi,
    
    Just confirming our meeting tomorrow at 2 PM in the conference room.
    
    Please bring the quarterly report. Let me know if you have any questions.
    
    Best regards,
    John
    """
    from_address = "john@company.com"
    
    result = detect_email(
        email_content=email_content,
        email_subject=email_subject,
        from_address=from_address
    )
    
    print_results(result)

def example_3_suspicious_email():
    """Example: Detecting a suspicious but not clear phishing email"""
    print("\n" + "=" * 60)
    print("Example 3: Suspicious Email Detection")
    print("=" * 60)
    
    email_subject = "You have won a prize!"
    email_content = """
    Congratulations! You have been selected to win $1000!
    
    Click here to claim your prize: http://tinyurl.com/claim-prize
    
    Limited time offer! Act now!
    """
    from_address = "noreply@lottery-winner.com"
    
    result = detect_email(
        email_content=email_content,
        email_subject=email_subject,
        from_address=from_address
    )
    
    print_results(result)

if __name__ == "__main__":
    try:
        example_1_phishing_email()
        example_2_legitimate_email()
        example_3_suspicious_email()
    except FileNotFoundError as e:
        print(f"\nError: {e}")
        print("\nPlease train the model first by running:")
        print("  python train_model.py")
    except Exception as e:
        print(f"\nUnexpected error: {e}")

