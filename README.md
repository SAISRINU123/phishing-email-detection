# Phishing Email Detection System

A machine learning-based cybersecurity project for detecting phishing emails. This system uses feature extraction and Random Forest classification to identify suspicious emails.

## Features

- **18+ Feature Extraction**: Analyzes emails for various phishing indicators including:
  - Suspicious keywords
  - URL analysis (count, shortening services, IP addresses)
  - Urgent language detection
  - HTML/form elements
  - Text characteristics (uppercase ratio, length, etc.)
  - Link-text mismatches

- **Machine Learning Model**: Uses Random Forest classifier for accurate detection

- **Easy-to-use Interface**: Command-line tools for training and detection

- **Comprehensive Analysis**: Provides confidence scores and detailed feature breakdown

## Project Structure

```
phishing/
├── phishing_detector.py    # Feature extraction module
├── train_model.py          # Model training script
├── detect_phishing.py      # Phishing detection script
├── app.py                  # Flask web application
├── templates/
│   └── index.html         # Web interface (HTML/CSS/JS)
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Installation

1. **Clone or download this repository**

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Step 1: Train the Model

First, train the phishing detection model:

```bash
python train_model.py
```

This will:
- Create a sample dataset if one doesn't exist
- Extract features from emails
- Train a Random Forest classifier
- Save the model to `phishing_model.pkl`
- Display model evaluation metrics

**Note**: The script creates a sample dataset by default. For production use, replace `phishing_dataset.csv` with your own labeled dataset.

### Step 2: Detect Phishing Emails

#### Option A: Web Interface (Recommended)

Start the web server:

```bash
python app.py
```

Then open your browser and navigate to:
```
http://localhost:5000
```

You'll see a user-friendly web interface where you can:
- Enter email subject, content, and sender information
- Click "Detect Phishing" to analyze the email
- View detailed results with confidence scores and recommendations

#### Option B: Detect from Email File

```bash
python detect_phishing.py email.txt
```

Where `email.txt` is a file containing the email content.

#### Option C: Interactive Mode

```bash
python detect_phishing.py --interactive
```

This will prompt you to enter:
- Email subject
- Email content
- Sender email address

#### Option D: Use as Python Module

```python
from detect_phishing import detect_email

result = detect_email(
    email_content="Your account has been suspended. Click here to verify: http://bit.ly/suspicious",
    email_subject="URGENT: Verify Your Account",
    from_address="support@suspicious-domain.com"
)

print(f"Is Phishing: {result['is_phishing']}")
print(f"Confidence: {result['confidence']*100:.2f}%")
```

## Dataset Format

To use your own dataset, create a CSV file (`phishing_dataset.csv`) with the following columns:

- `subject`: Email subject line
- `content`: Email body content
- `from`: Sender email address
- `to`: Recipient email address
- `label`: 1 for phishing, 0 for legitimate

Example:
```csv
subject,content,from,to,label
"Verify Your Account","Click here to verify: http://bit.ly/suspicious",support@fake.com,user@email.com,1
"Meeting Tomorrow","Hi, meeting at 2 PM",colleague@company.com,user@email.com,0
```

## Features Analyzed

The system extracts the following features from emails:

1. **Suspicious Keywords Count**: Number of common phishing keywords
2. **Urgent Language**: Presence of urgent language indicators
3. **URL Count**: Total number of URLs in email
4. **Suspicious URLs**: URLs from known shortening services
5. **HTML Content**: Presence of HTML tags
6. **Link Count**: Number of hyperlinks
7. **Average URL Length**: Average length of URLs
8. **IP in URL**: Presence of IP addresses in URLs
9. **Subject Length**: Length of subject line
10. **Content Length**: Length of email body
11. **Uppercase Ratio**: Ratio of uppercase letters
12. **Attachment Mentions**: References to attachments
13. **Link Mismatch**: Mismatch between link text and URL
14. **Exclamation Count**: Number of exclamation marks
15. **Common Domain**: Whether sender uses common email domain
16. **Form Elements**: Presence of form/input fields
17. **Image Count**: Number of images
18. **Spam Score**: Composite spam score

## Model Performance

The trained model typically achieves:
- **Accuracy**: 85-95% (depending on dataset)
- **Precision**: High precision for phishing detection
- **Recall**: Good recall to catch phishing attempts

## Example Output

```
============================================================
PHISHING EMAIL DETECTION RESULTS
============================================================

Prediction: ⚠️  PHISHING EMAIL DETECTED

Confidence: 92.45%
Phishing Probability: 92.45%
Legitimate Probability: 7.55%

Key Features Detected:
  - Suspicious Keywords: 5
  - URLs Found: 2
  - Suspicious URLs: 1
  - Urgent Language: Yes
  - IP in URL: No
  - Spam Score: 15.50

============================================================

⚠️  WARNING: This email is likely a phishing attempt!
Recommendations:
  - Do not click any links
  - Do not download attachments
  - Do not provide personal information
  - Delete the email
  - Report to your IT security team
```

## Limitations

1. **Training Data**: Model performance depends on quality and diversity of training data
2. **Feature-Based**: Detection relies on extracted features, may miss sophisticated attacks
3. **False Positives**: Legitimate emails with phishing-like characteristics may be flagged
4. **Evolution**: Phishing techniques evolve; model may need retraining

## Best Practices

1. **Regular Retraining**: Retrain model periodically with new phishing samples
2. **Feature Updates**: Update feature extraction as new attack vectors emerge
3. **Human Review**: Use as one layer of defense, not sole decision maker
4. **Combine Methods**: Use alongside other security measures (SPF, DKIM, etc.)

## Security Considerations

- This tool is for **educational and research purposes**
- In production environments, use established email security solutions
- Always verify suspicious emails through separate channels
- Keep the model and training data secure

## Contributing

To improve the detection system:

1. Add more features to `phishing_detector.py`
2. Experiment with different ML models in `train_model.py`
3. Collect and label more diverse training data
4. Implement additional email parsing capabilities

## License

This project is provided as-is for educational purposes.

## Acknowledgments

- Machine learning: scikit-learn
- Feature engineering based on common phishing indicators
- Model uses Random Forest for robust classification

## Troubleshooting

**Error: Model not found**
- Solution: Run `python train_model.py` first to train the model

**Error: Module not found**
- Solution: Install dependencies with `pip install -r requirements.txt`

**Low accuracy**
- Solution: Use a larger, more diverse training dataset

**False positives/negatives**
- Solution: Adjust feature thresholds or retrain with more examples

