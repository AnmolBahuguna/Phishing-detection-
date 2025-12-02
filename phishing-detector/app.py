from flask import Flask, render_template, request, jsonify
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime
import ssl
import socket

app = Flask(__name__)

def check_url_pattern(url):
    suspicious_keywords = ['login', 'signin', 'account', 'bank', 'secure', 'update', 'verify']
    score = 0
    reasons = []
    
    if len(url) > 75:
        score += 1
        reasons.append("Long URL")
    
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            score += 0.5
            reasons.append(f"Suspicious keyword: {keyword}")
    
    return {
        'score': min(score, 3),
        'reasons': reasons if reasons else ["No suspicious patterns found"],
        'is_suspicious': score > 0
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Check URL pattern
        url_check = check_url_pattern(url)
        
        # Prepare response
        response = {
            'url': url,
            'checks': {
                'url_pattern': url_check
            },
            'risk_score': min(10, int((url_check['score'] / 3) * 10)),
            'is_phishing': url_check['score'] >= 1.5
        }
        
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)