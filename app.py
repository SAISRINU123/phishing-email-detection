"""
Flask web application for phishing email detection
"""

from flask import Flask, render_template, request, jsonify
from detect_phishing import detect_email
import os

app = Flask(__name__)

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/detect', methods=['POST'])
def detect():
    """API endpoint for phishing detection"""
    try:
        data = request.get_json()
        
        email_content = data.get('email_content', '')
        email_subject = data.get('email_subject', '')
        from_address = data.get('from_address', '')
        to_address = data.get('to_address', '')
        
        if not email_content:
            return jsonify({
                'error': 'Email content is required'
            }), 400
        
        # Check if model exists
        model_path = 'phishing_model.pkl'
        if not os.path.exists(model_path):
            return jsonify({
                'error': 'Model not found. Please train the model first by running: python train_model.py'
            }), 500
        
        # Detect phishing
        result = detect_email(
            email_content=email_content,
            email_subject=email_subject,
            from_address=from_address,
            to_address=to_address,
            model_path=model_path
        )
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    model_exists = os.path.exists('phishing_model.pkl')
    return jsonify({
        'status': 'ok',
        'model_loaded': model_exists
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

