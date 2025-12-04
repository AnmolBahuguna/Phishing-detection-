from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import re
import os
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 16KB max request size

# Enable CORS for production
CORS(app, resources={r"/scan": {"origins": "*"}})

# Configure logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/phishing_detector.log', 
                                       maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Phishing Detector startup')

# Constants
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'account', 'verify', 'secure', 'update', 
    'confirm', 'bank', 'paypal', 'amazon', 'apple', 'microsoft', 
    'google', 'password', 'credential', 'suspended', 'locked'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.club', '.online', '.site', '.website', '.space', '.tech'
]

POPULAR_BRANDS = [
    'google', 'facebook', 'amazon', 'paypal', 'microsoft', 
    'apple', 'netflix', 'instagram', 'twitter', 'linkedin',
    'ebay', 'yahoo', 'wells-fargo', 'chase', 'bankofamerica'
]

def validate_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def analyze_protocol(url):
    """Check if URL uses HTTPS"""
    parsed = urlparse(url)
    score = 0
    reasons = []
    
    if parsed.scheme != 'https':
        score += 2
        reasons.append('Not using secure HTTPS protocol')
    else:
        reasons.append('Using secure HTTPS protocol')
    
    return score, reasons

def analyze_domain(domain):
    """Analyze domain for suspicious patterns"""
    score = 0
    reasons = []
    
    # Check for suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.lower().endswith(tld):
            score += 3
            reasons.append(f'Uses suspicious top-level domain: {tld}')
            break
    
    # Check for IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain):
        score += 3
        reasons.append('Uses IP address instead of domain name')
    
    # Check subdomain count
    subdomain_count = domain.count('.') - 1
    if subdomain_count > 2:
        score += 2
        reasons.append(f'Excessive subdomains detected ({subdomain_count})')
    
    # Check for special characters
    special_char_count = len(re.findall(r'[-_@]', domain))
    if special_char_count > 3:
        score += 2
        reasons.append(f'Excessive special characters in domain ({special_char_count})')
    
    # Check for homograph attacks (Cyrillic characters)
    if re.search(r'[а-яА-Я]', domain):
        score += 4
        reasons.append('Potential homograph attack detected')
    
    return score, reasons

def analyze_typosquatting(domain):
    """Detect typosquatting attempts"""
    score = 0
    reasons = []
    
    domain_lower = domain.lower()
    for brand in POPULAR_BRANDS:
        if brand in domain_lower:
            # Check if it's not the legitimate domain
            if not (domain_lower == f'{brand}.com' or 
                    domain_lower.endswith(f'.{brand}.com') or
                    domain_lower == f'{brand}.org' or
                    domain_lower.endswith(f'.{brand}.org')):
                score += 3
                reasons.append(f'Possible typosquatting of "{brand}"')
                break
    
    return score, reasons

def analyze_url_structure(url):
    """Analyze URL structure and content"""
    score = 0
    reasons = []
    
    # Check URL length
    if len(url) > 100:
        score += 1
        reasons.append('Unusually long URL')
    
    # Check for suspicious keywords
    keyword_count = sum(1 for keyword in SUSPICIOUS_KEYWORDS 
                       if keyword in url.lower())
    
    if keyword_count >= 3:
        score += 3
        reasons.append(f'Multiple suspicious keywords found ({keyword_count})')
    elif keyword_count == 2:
        score += 2
        reasons.append('Two suspicious keywords detected')
    elif keyword_count == 1:
        score += 1
        reasons.append('Suspicious keyword detected')
    
    # Check for @ symbol (redirects)
    if '@' in url:
        score += 3
        reasons.append('Contains @ symbol (potential redirect)')
    
    # Check for double slashes in path
    if '//' in url[8:]:  # Skip the protocol part
        score += 2
        reasons.append('Contains double slashes in path')
    
    return score, reasons

def analyze_port(parsed_url):
    """Check for unusual port numbers"""
    score = 0
    reasons = []
    
    if parsed_url.port and str(parsed_url.port) not in ['80', '443']:
        score += 2
        reasons.append(f'Using unusual port number: {parsed_url.port}')
    
    return score, reasons

def comprehensive_url_analysis(url):
    """Perform comprehensive phishing analysis"""
    try:
        # Validate URL
        if not validate_url(url):
            return {
                'url': url,
                'risk_score': 10,
                'is_phishing': True,
                'checks': {
                    'url_pattern': {
                        'passed': False,
                        'reasons': ['Invalid URL format']
                    }
                }
            }
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        total_score = 0
        all_reasons = []
        
        # Run all checks
        protocol_score, protocol_reasons = analyze_protocol(url)
        total_score += protocol_score
        all_reasons.extend(protocol_reasons)
        
        domain_score, domain_reasons = analyze_domain(domain)
        total_score += domain_score
        all_reasons.extend(domain_reasons)
        
        typo_score, typo_reasons = analyze_typosquatting(domain)
        total_score += typo_score
        all_reasons.extend(typo_reasons)
        
        structure_score, structure_reasons = analyze_url_structure(url)
        total_score += structure_score
        all_reasons.extend(structure_reasons)
        
        port_score, port_reasons = analyze_port(parsed_url)
        total_score += port_score
        all_reasons.extend(port_reasons)
        
        # Cap the risk score at 10
        risk_score = min(total_score, 10)
        
        # Determine if phishing (threshold: 5)
        is_phishing = risk_score >= 5
        
        # If no issues found, add positive message
        if not all_reasons:
            all_reasons.append('No obvious security concerns detected')
        
        return {
            'url': url,
            'risk_score': risk_score,
            'is_phishing': is_phishing,
            'checks': {
                'url_pattern': {
                    'passed': not is_phishing,
                    'reasons': all_reasons
                }
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        app.logger.error(f'Analysis error for URL {url}: {str(e)}')
        return {
            'url': url,
            'risk_score': 10,
            'is_phishing': True,
            'checks': {
                'url_pattern': {
                    'passed': False,
                    'reasons': ['Error analyzing URL']
                }
            }
        }

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Scan URL endpoint"""
    try:
        # Get JSON data
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid request format'}), 400
        
        url = data.get('url', '').strip()
        
        # Validate input
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        if len(url) > 2048:  # Max URL length
            return jsonify({'error': 'URL too long'}), 400
        
        # Log the scan request
        app.logger.info(f'Scanning URL: {url}')
        
        # Perform analysis
        result = comprehensive_url_analysis(url)
        
        # Log the result
        app.logger.info(f'Scan result for {url}: Risk={result["risk_score"]}, Phishing={result["is_phishing"]}')
        
        return jsonify(result), 200
        
    except Exception as e:
        app.logger.error(f'Scan endpoint error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health')
def health():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    app.logger.error(f'Internal error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Get port from environment variable (for Render)
    port = int(os.environ.get('PORT', 5000))
    
    # Run the app
    # In production, use gunicorn instead of Flask's built-in server
    app.run(host='0.0.0.0', port=port, debug=False)