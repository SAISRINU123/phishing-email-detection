"""
Phishing Email Detection System
Feature extraction and ML-based phishing detection
"""

import re
import urllib.parse
from typing import Dict, List
import email
from email.header import decode_header


class PhishingDetector:
    """Feature extractor for phishing email detection"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'password', 'click here',
            'verify your account', 'confirm your account', 'update account',
            'win', 'prize', 'free', 'limited time', 'act now', 'expires',
            'click below', 'secure your account', 'unauthorized login attempt',
            'verify identity', 'account verification required'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'tiny.cc',
            'is.gd', 'buff.ly', 'ow.ly'
        ]
    
    def extract_features(self, email_content: str, email_subject: str = "", 
                        from_address: str = "", to_address: str = "") -> Dict:
        """
        Extract features from email for phishing detection
        
        Args:
            email_content: Email body content
            email_subject: Email subject line
            from_address: Sender email address
            to_address: Recipient email address
            
        Returns:
            Dictionary of extracted features
        """
        # Combine all text for analysis
        full_text = f"{email_subject} {email_content}".lower()
        
        features = {}
        
        # 1. Suspicious keywords count
        features['suspicious_keywords_count'] = sum(
            1 for keyword in self.suspicious_keywords 
            if keyword in full_text
        )
        
        # 2. Presence of urgent language
        urgent_words = ['urgent', 'immediately', 'asap', 'critical', 'important']
        features['urgent_language'] = 1 if any(word in full_text for word in urgent_words) else 0
        
        # 3. URL count
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, full_text)
        features['url_count'] = len(urls)
        
        # 4. Suspicious URL shortening services
        features['suspicious_urls'] = sum(
            1 for url in urls 
            if any(domain in url for domain in self.suspicious_domains)
        )
        
        # 5. Email contains HTML
        features['has_html'] = 1 if '<html' in email_content.lower() or '<body' in email_content.lower() else 0
        
        # 6. Number of links
        link_pattern = r'<a\s+href=["\']([^"\']+)["\']'
        links = re.findall(link_pattern, email_content, re.IGNORECASE)
        features['link_count'] = len(links)
        
        # 7. URL length (average if multiple)
        if urls:
            avg_url_length = sum(len(url) for url in urls) / len(urls)
            features['avg_url_length'] = avg_url_length
        else:
            features['avg_url_length'] = 0
        
        # 8. Presence of IP address in URL
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['ip_in_url'] = 1 if any(re.search(ip_pattern, url) for url in urls) else 0
        
        # 9. Subject length
        features['subject_length'] = len(email_subject)
        
        # 10. Content length
        features['content_length'] = len(email_content)
        
        # 11. Ratio of uppercase letters
        if email_content:
            uppercase_count = sum(1 for c in email_content if c.isupper())
            features['uppercase_ratio'] = uppercase_count / len(email_content)
        else:
            features['uppercase_ratio'] = 0
        
        # 12. Presence of attachments mentioned
        attachment_keywords = ['attachment', 'attached', 'download', 'file attached']
        features['attachment_mention'] = 1 if any(keyword in full_text for keyword in attachment_keywords) else 0
        
        # 13. Mismatch between link text and URL
        if links and email_content:
            # Check if link text differs significantly from URL
            mismatches = 0
            for link in links:
                # Simple heuristic: if URL domain not in visible text near link
                try:
                    parsed = urllib.parse.urlparse(link)
                    domain = parsed.netloc
                    if domain and domain.lower() not in full_text:
                        mismatches += 1
                except:
                    pass
            features['link_mismatch'] = min(mismatches, 5)  # Cap at 5
        else:
            features['link_mismatch'] = 0
        
        # 14. Number of exclamation marks (urgency indicator)
        features['exclamation_count'] = email_content.count('!') + email_subject.count('!')
        
        # 15. Domain age/trust indicators (simplified - checking for common patterns)
        if from_address:
            domain = from_address.split('@')[-1] if '@' in from_address else ''
            features['is_common_domain'] = 1 if domain in ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com'] else 0
        else:
            features['is_common_domain'] = 0
        
        # 16. Email contains form/input fields (often phishing attempts)
        form_indicators = ['<input', '<form', 'type="password"', 'type="text"']
        features['has_form'] = 1 if any(indicator in email_content.lower() for indicator in form_indicators) else 0
        
        # 17. Number of images
        img_pattern = r'<img[^>]+>'
        images = re.findall(img_pattern, email_content, re.IGNORECASE)
        features['image_count'] = len(images)
        
        # 18. Spam score (simple heuristic)
        spam_score = 0
        spam_score += features['suspicious_keywords_count'] * 2
        spam_score += features['url_count'] * 1.5
        spam_score += features['suspicious_urls'] * 3
        spam_score += features['exclamation_count'] * 0.5
        spam_score += features['urgent_language'] * 2
        features['spam_score'] = min(spam_score, 50)  # Cap at 50
        
        return features
    
    def parse_email_file(self, email_file_path: str) -> Dict:
        """Parse an email file and extract features"""
        try:
            with open(email_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                msg = email.message_from_file(f)
            
            # Extract email components
            subject = ""
            if msg['Subject']:
                subject = str(decode_header(msg['Subject'])[0][0])
            
            from_addr = msg['From'] or ""
            to_addr = msg['To'] or ""
            
            # Extract body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain" or content_type == "text/html":
                        try:
                            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except:
                            pass
            else:
                try:
                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    body = str(msg.get_payload())
            
            return self.extract_features(body, subject, from_addr, to_addr)
        except Exception as e:
            print(f"Error parsing email: {e}")
            return {}
    
    def extract_from_text(self, email_text: str, subject: str = "", 
                         from_addr: str = "", to_addr: str = "") -> Dict:
        """Extract features from plain text email"""
        return self.extract_features(email_text, subject, from_addr, to_addr)

