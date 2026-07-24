import os
import re
import json
import hashlib
import requests
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email
from dotenv import load_dotenv
from urllib.parse import urlparse
import dns.resolver
import email
from email.policy import default
import hashlib
import re
from collections import Counter
import joblib

# Machine Learning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Security configurations
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///email_security.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# API Keys (set in .env)
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')

# ============= DATABASE MODELS =============

class EmailLog(db.Model):
    """Store analyzed emails"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    sender = db.Column(db.String(255), nullable=False)
    recipient = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(500), nullable=True)
    body_preview = db.Column(db.Text, nullable=True)
    full_body = db.Column(db.Text, nullable=True)
    headers = db.Column(db.Text, nullable=True)
    
    # Security flags
    spf_pass = db.Column(db.Boolean, default=False)
    dkim_pass = db.Column(db.Boolean, default=False)
    dmarc_pass = db.Column(db.Boolean, default=False)
    
    # Analysis results
    phishing_score = db.Column(db.Float, default=0.0)
    is_phishing = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float, default=0.0)
    
    # URL analysis
    urls_found = db.Column(db.Text, nullable=True)
    suspicious_urls = db.Column(db.Text, nullable=True)
    malicious_urls = db.Column(db.Text, nullable=True)
    
    # Threat details
    threat_type = db.Column(db.String(50), nullable=True)
    threat_details = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='low')
    
    # Action taken
    action_taken = db.Column(db.String(50), default='delivered')
    is_quarantined = db.Column(db.Boolean, default=False)

class SecurityAlert(db.Model):
    """Store security alerts"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email_log.id'), nullable=True)
    severity = db.Column(db.String(20), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    sender = db.Column(db.String(255), nullable=True)
    is_resolved = db.Column(db.Boolean, default=False)

class ThreatIntelligence(db.Model):
    """Store threat intelligence data"""
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(500), unique=True, nullable=False)
    indicator_type = db.Column(db.String(50), nullable=False)  # domain, ip, url, email
    threat_type = db.Column(db.String(50), nullable=True)
    confidence = db.Column(db.Float, default=0.0)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(100), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

# ============= EMAIL SECURITY ENGINE =============

class EmailSecurityEngine:
    """Email security analysis engine"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        self.threat_indicators = []
        self.phishing_keywords = [
            'urgent', 'verify', 'account', 'password', 'confirm', 'update',
            'security', 'alert', 'suspended', 'limited', 'unauthorized',
            'login', 'click', 'link', 'attachment', 'invoice', 'payment',
            'verify your account', 'security alert', 'unusual activity',
            'suspicious login', 'reset your password', 'confirm your identity'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.club', '.online', '.site', '.work', '.date']
        
        # Load or train model
        self._load_or_train_model()
        
        # Load threat intelligence
        self._load_threat_intelligence()
    
    def _load_or_train_model(self):
        """Load existing model or train a new one"""
        model_path = 'models/phishing_model.pkl'
        vectorizer_path = 'models/vectorizer.pkl'
        
        try:
            if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                self.is_trained = True
                print("✅ Model loaded successfully")
            else:
                self._train_model()
        except Exception as e:
            print(f"⚠️ Error loading model: {str(e)}")
            self._train_model()
    
    def _train_model(self):
        """Train the phishing detection model"""
        print("🔄 Training phishing detection model...")
        
        # Sample training data (expand this for better accuracy)
        phishing_emails = [
            "URGENT: Your account has been compromised. Click here to verify",
            "Your PayPal account has been suspended. Verify your identity now",
            "Security alert: Someone tried to login to your account",
            "Confirm your email address to avoid account suspension",
            "Your credit card has been charged. View invoice here",
            "You have won a lottery. Claim your prize now",
            "Update your banking information to avoid service interruption",
            "Your password needs to be reset. Click the link below",
            "Account verification required within 24 hours",
            "Suspicious activity detected on your account"
        ]
        
        legitimate_emails = [
            "Meeting schedule for next week",
            "Project update and progress report",
            "Team lunch tomorrow at 12 PM",
            "Monthly newsletter - company updates",
            "Your order has been shipped",
            "Welcome to the team!",
            "Performance review schedule",
            "Office holiday schedule announced",
            "New feature release notes",
            "Weekly team meeting agenda"
        ]
        
        # Combine and label data
        all_emails = phishing_emails + legitimate_emails
        labels = [1] * len(phishing_emails) + [0] * len(legitimate_emails)
        
        # Create features
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        X = self.vectorizer.fit_transform(all_emails)
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, labels)
        self.is_trained = True
        
        # Save model
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.model, 'models/phishing_model.pkl')
        joblib.dump(self.vectorizer, 'models/vectorizer.pkl')
        
        # Test accuracy
        y_pred = self.model.predict(X)
        accuracy = accuracy_score(labels, y_pred)
        print(f"✅ Model trained with {accuracy*100:.2f}% accuracy")
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data"""
        try:
            # Load from database
            with app.app_context():
                threats = ThreatIntelligence.query.filter_by(is_active=True).all()
                self.threat_indicators = [t.indicator for t in threats]
        except:
            self.threat_indicators = []
    
    def analyze_headers(self, headers):
        """Analyze email headers for SPF, DKIM, DMARC"""
        results = {
            'spf_pass': False,
            'dkim_pass': False,
            'dmarc_pass': False,
            'details': {}
        }
        
        if not headers:
            return results
        
        # Parse headers
        header_text = str(headers).lower()
        
        # Check SPF
        if 'spf=pass' in header_text or 'spf pass' in header_text:
            results['spf_pass'] = True
        elif 'spf=fail' in header_text or 'spf fail' in header_text:
            results['spf_pass'] = False
        
        # Check DKIM
        if 'dkim=pass' in header_text or 'dkim pass' in header_text:
            results['dkim_pass'] = True
        elif 'dkim=fail' in header_text or 'dkim fail' in header_text:
            results['dkim_pass'] = False
        
        # Check DMARC
        if 'dmarc=pass' in header_text or 'dmarc pass' in header_text:
            results['dmarc_pass'] = True
        elif 'dmarc=fail' in header_text or 'dmarc fail' in header_text:
            results['dmarc_pass'] = False
        
        return results
    
    def extract_urls(self, text):
        """Extract URLs from email body"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        urls = re.findall(url_pattern, text)
        return list(set(urls))
    
    def analyze_urls(self, urls):
        """Analyze URLs for malicious content"""
        suspicious = []
        malicious = []
        
        for url in urls:
            # Check for suspicious patterns
            is_suspicious = False
            is_malicious = False
            
            # Check for suspicious TLDs
            for tld in self.suspicious_tlds:
                if tld in url:
                    is_suspicious = True
                    suspicious.append(url)
                    break
            
            # Check for IP addresses instead of domain
            if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url):
                is_suspicious = True
                suspicious.append(url)
            
            # Check for URL shortening services
            if any(service in url for service in ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co']):
                is_suspicious = True
                suspicious.append(url)
            
            # Check against threat intelligence
            domain = urlparse(url).netloc
            if domain in self.threat_indicators:
                is_malicious = True
                malicious.append(url)
            
            # VirusTotal API check
            if VIRUSTOTAL_API_KEY and not is_malicious:
                vt_result = self._check_virustotal(url)
                if vt_result and vt_result.get('malicious', 0) > 0:
                    is_malicious = True
                    malicious.append(url)
        
        return {
            'suspicious': list(set(suspicious)),
            'malicious': list(set(malicious))
        }
    
    def _check_virustotal(self, url):
        """Check URL with VirusTotal API"""
        try:
            headers = {
                'x-apikey': VIRUSTOTAL_API_KEY
            }
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{hashlib.md5(url.encode()).hexdigest()}',
                headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        except:
            pass
        return None
    
    def analyze_sender(self, sender_email):
        """Analyze sender email address"""
        suspicious = False
        details = []
        
        if not sender_email:
            return {'suspicious': True, 'details': ['No sender found']}
        
        # Check for suspicious patterns in sender
        patterns = [
            ('@', 'Missing @ symbol'),
            ('.', 'Missing domain'),
            (' ', 'Contains spaces'),
            ('_', 'Contains underscore'),
            ('-', 'Contains hyphen'),
            ('.tk', 'Suspicious TLD'),
            ('.ml', 'Suspicious TLD'),
            ('.ga', 'Suspicious TLD'),
            ('.cf', 'Suspicious TLD'),
            ('.top', 'Suspicious TLD'),
            ('.xyz', 'Suspicious TLD'),
        ]
        
        # Check if sender is in threat intelligence
        if sender_email in self.threat_indicators:
            suspicious = True
            details.append('Sender in threat intelligence database')
        
        # Check for common phishing patterns
        phishing_domains = ['gmaill.com', 'yahooo.com', 'hotmaill.com', 'paypa1.com', 'amaz0n.com']
        for domain in phishing_domains:
            if domain in sender_email:
                suspicious = True
                details.append(f'Domain spoofing: {domain}')
                break
        
        # Check for domain mismatch (common in phishing)
        if '@' in sender_email:
            domain = sender_email.split('@')[1]
            if len(domain) > 30:
                suspicious = True
                details.append('Unusually long domain name')
        
        return {
            'suspicious': suspicious,
            'details': details if details else ['Sender appears legitimate']
        }
    
    def analyze_content(self, content):
        """Analyze email content for phishing indicators"""
        if not content:
            return {'score': 0, 'keywords': [], 'suspicious': False}
        
        content_lower = content.lower()
        found_keywords = []
        
        # Check for phishing keywords
        for keyword in self.phishing_keywords:
            if keyword in content_lower:
                found_keywords.append(keyword)
        
        # Calculate score
        score = len(found_keywords) / len(self.phishing_keywords) * 100
        
        # Check for urgency language
        urgency_words = ['urgent', 'immediate', 'now', 'immediately', 'asap']
        if any(word in content_lower for word in urgency_words):
            score += 20
        
        # Check for suspicious phrases
        suspicious_phrases = [
            'verify your account',
            'confirm your identity',
            'security alert',
            'unusual activity',
            'suspicious login',
            'reset your password',
            'account suspended',
            'click here',
            'click the link',
            'log in now'
        ]
        
        for phrase in suspicious_phrases:
            if phrase in content_lower:
                score += 15
        
        # Check for grammar issues (simplified)
        if re.search(r'\b\w{20,}\b', content):
            score += 10
        
        # Cap score at 100
        score = min(score, 100)
        
        return {
            'score': score,
            'keywords': list(set(found_keywords)),
            'suspicious': score > 50
        }
    
    def analyze_email(self, email_data):
        """Complete email analysis"""
        results = {
            'phishing_score': 0.0,
            'is_phishing': False,
            'confidence': 0.0,
            'spf_pass': False,
            'dkim_pass': False,
            'dmarc_pass': False,
            'urls_found': [],
            'suspicious_urls': [],
            'malicious_urls': [],
            'threat_type': None,
            'threat_details': None,
            'severity': 'low'
        }
        
        # Extract components
        sender = email_data.get('sender', '')
        recipient = email_data.get('recipient', '')
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        headers = email_data.get('headers', '')
        
        # Analyze headers
        header_results = self.analyze_headers(headers)
        results.update(header_results)
        
        # Extract and analyze URLs
        urls = self.extract_urls(body)
        results['urls_found'] = urls
        if urls:
            url_results = self.analyze_urls(urls)
            results['suspicious_urls'] = url_results['suspicious']
            results['malicious_urls'] = url_results['malicious']
        
        # Analyze sender
        sender_analysis = self.analyze_sender(sender)
        
        # Analyze content
        content_analysis = self.analyze_content(body)
        
        # Calculate overall phishing score
        total_score = 0
        total_factors = 0
        
        # Content score (40% weight)
        total_score += content_analysis['score'] * 0.4
        total_factors += 40
        
        # Header score (20% weight)
        header_score = 0
        if not results['spf_pass']:
            header_score += 30
        if not results['dkim_pass']:
            header_score += 30
        if not results['dmarc_pass']:
            header_score += 40
        total_score += header_score * 0.2
        total_factors += 20
        
        # URL score (20% weight)
        url_score = 0
        if results['malicious_urls']:
            url_score = 100
        elif results['suspicious_urls']:
            url_score = 60
        total_score += url_score * 0.2
        total_factors += 20
        
        # Sender score (20% weight)
        sender_score = 100 if sender_analysis['suspicious'] else 0
        total_score += sender_score * 0.2
        total_factors += 20
        
        # Normalize score
        final_score = total_score / (total_factors / 100)
        final_score = min(final_score, 100)
        
        results['phishing_score'] = final_score
        
        # Determine if phishing
        if final_score > 70:
            results['is_phishing'] = True
            results['severity'] = 'critical' if final_score > 90 else 'high'
            results['threat_type'] = 'phishing'
            results['threat_details'] = f'Phishing detected with {final_score:.1f}% confidence'
        elif final_score > 50:
            results['is_phishing'] = True
            results['severity'] = 'medium'
            results['threat_type'] = 'suspicious'
            results['threat_details'] = f'Suspicious email with {final_score:.1f}% confidence'
        else:
            results['is_phishing'] = False
            results['severity'] = 'low'
            results['threat_details'] = 'Email appears legitimate'
        
        results['confidence'] = final_score
        
        # Check for specific threat types
        if results['malicious_urls']:
            results['threat_type'] = 'malicious_urls'
            results['threat_details'] = f'Contains malicious URLs: {", ".join(results["malicious_urls"][:3])}'
        
        if sender_analysis['suspicious'] and final_score > 60:
            results['threat_type'] = 'sender_spoofing'
            results['threat_details'] = f'Suspicious sender: {sender}'
        
        # ML classification
        if self.is_trained and body:
            try:
                features = self.vectorizer.transform([body])
                ml_prediction = self.model.predict_proba(features)[0]
                ml_score = ml_prediction[1] * 100  # Probability of phishing
                
                # Weighted combination with rule-based score
                final_score = (final_score * 0.6) + (ml_score * 0.4)
                results['phishing_score'] = final_score
                results['confidence'] = final_score
                
                if final_score > 70:
                    results['is_phishing'] = True
                    results['severity'] = 'critical' if final_score > 90 else 'high'
            except:
                pass
        
        return results
    
    def generate_alert(self, email_id, results):
        """Generate security alert if needed"""
        if not results['is_phishing'] and not results['malicious_urls']:
            return None
        
        alert = SecurityAlert(
            email_id=email_id,
            severity=results['severity'],
            alert_type=results['threat_type'] or 'suspicious_activity',
            description=results['threat_details'] or 'Suspicious email detected'
        )
        return alert

# ============= GLOBAL SECURITY ENGINE =============

security_engine = EmailSecurityEngine()

# ============= ROUTES =============

@app.route('/')
def index():
    """Home page with real stats"""
    # Get real stats from database
    total_emails = EmailLog.query.count()
    phishing_emails = EmailLog.query.filter_by(is_phishing=True).count()
    quarantined_emails = EmailLog.query.filter_by(is_quarantined=True).count()
    alerts = SecurityAlert.query.filter_by(is_resolved=False).count()
    
    return render_template('index.html',
                         total_emails=total_emails,
                         phishing_emails=phishing_emails,
                         quarantined_emails=quarantined_emails,
                         alerts=alerts)

@app.route('/dashboard')
def dashboard():
    """Dashboard with statistics"""
    # Get statistics
    total_emails = EmailLog.query.count()
    phishing_emails = EmailLog.query.filter_by(is_phishing=True).count()
    quarantined_emails = EmailLog.query.filter_by(is_quarantined=True).count()
    alerts = SecurityAlert.query.filter_by(is_resolved=False).count()
    
    # Recent emails
    recent_emails = EmailLog.query.order_by(EmailLog.timestamp.desc()).limit(20).all()
    
    # Recent alerts
    recent_alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).limit(10).all()
    
    return render_template('dashboard.html',
                         total_emails=total_emails,
                         phishing_emails=phishing_emails,
                         quarantined_emails=quarantined_emails,
                         alerts=alerts,
                         recent_emails=recent_emails,
                         recent_alerts=recent_alerts)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """Analyze email for phishing"""
    if request.method == 'POST':
        try:
            # Get email data
            sender = request.form.get('sender', '')
            recipient = request.form.get('recipient', '')
            subject = request.form.get('subject', '')
            body = request.form.get('body', '')
            headers = request.form.get('headers', '')
            
            # Validate
            if not sender or not body:
                flash('Please provide sender and email body', 'warning')
                return render_template('analyze.html')
            
            # Prepare email data
            email_data = {
                'sender': sender,
                'recipient': recipient or 'unknown@example.com',
                'subject': subject or '(no subject)',
                'body': body,
                'headers': headers
            }
            
            # Analyze email
            results = security_engine.analyze_email(email_data)
            
            # Save to database
            email_log = EmailLog(
                sender=sender,
                recipient=recipient or 'unknown@example.com',
                subject=subject or '(no subject)',
                body_preview=body[:500],
                full_body=body,
                headers=headers,
                spf_pass=results.get('spf_pass', False),
                dkim_pass=results.get('dkim_pass', False),
                dmarc_pass=results.get('dmarc_pass', False),
                phishing_score=results['phishing_score'],
                is_phishing=results['is_phishing'],
                confidence=results['confidence'],
                urls_found=json.dumps(results.get('urls_found', [])),
                suspicious_urls=json.dumps(results.get('suspicious_urls', [])),
                malicious_urls=json.dumps(results.get('malicious_urls', [])),
                threat_type=results.get('threat_type'),
                threat_details=results.get('threat_details'),
                severity=results['severity'],
                is_quarantined=results['is_phishing']
            )
            db.session.add(email_log)
            db.session.commit()
            
            # Generate alert if needed
            if results['is_phishing']:
                alert = security_engine.generate_alert(email_log.id, results)
                if alert:
                    db.session.add(alert)
                    db.session.commit()
            
            flash(f'Email analyzed! Phishing Score: {results["phishing_score"]:.1f}%', 
                  'danger' if results['is_phishing'] else 'success')
            
            return render_template('email_detail.html', 
                                 email=email_log,
                                 results=results,
                                 urls_found=json.loads(email_log.urls_found) if email_log.urls_found else [],
                                 suspicious_urls=json.loads(email_log.suspicious_urls) if email_log.suspicious_urls else [],
                                 malicious_urls=json.loads(email_log.malicious_urls) if email_log.malicious_urls else [])
            
        except Exception as e:
            flash(f'Error analyzing email: {str(e)}', 'danger')
            return render_template('analyze.html')
    
    return render_template('analyze.html')

@app.route('/email/<int:email_id>')
def email_detail(email_id):
    """View email details"""
    email = EmailLog.query.get_or_404(email_id)
    
    urls_found = json.loads(email.urls_found) if email.urls_found else []
    suspicious_urls = json.loads(email.suspicious_urls) if email.suspicious_urls else []
    malicious_urls = json.loads(email.malicious_urls) if email.malicious_urls else []
    
    results = {
        'phishing_score': email.phishing_score,
        'is_phishing': email.is_phishing,
        'confidence': email.confidence,
        'spf_pass': email.spf_pass,
        'dkim_pass': email.dkim_pass,
        'dmarc_pass': email.dmarc_pass,
        'urls_found': urls_found,
        'suspicious_urls': suspicious_urls,
        'malicious_urls': malicious_urls,
        'threat_type': email.threat_type,
        'threat_details': email.threat_details,
        'severity': email.severity
    }
    
    return render_template('email_detail.html',
                         email=email,
                         results=results,
                         urls_found=urls_found,
                         suspicious_urls=suspicious_urls,
                         malicious_urls=malicious_urls)

@app.route('/quarantine')
def quarantine():
    """View quarantined emails"""
    quarantined = EmailLog.query.filter_by(is_quarantined=True).order_by(EmailLog.timestamp.desc()).all()
    return render_template('quarantine.html', emails=quarantined)

@app.route('/release/<int:email_id>', methods=['POST'])
def release_email(email_id):
    """Release email from quarantine"""
    email = EmailLog.query.get_or_404(email_id)
    email.is_quarantined = False
    db.session.commit()
    flash('Email released from quarantine', 'success')
    return redirect(url_for('quarantine'))

@app.route('/delete/<int:email_id>', methods=['POST'])
def delete_email(email_id):
    """Delete email"""
    email = EmailLog.query.get_or_404(email_id)
    db.session.delete(email)
    db.session.commit()
    flash('Email deleted', 'info')
    return redirect(url_for('dashboard'))

@app.route('/resolve_alert/<int:alert_id>', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve security alert"""
    alert = SecurityAlert.query.get_or_404(alert_id)
    alert.is_resolved = True
    db.session.commit()
    flash('Alert resolved', 'success')
    return redirect(url_for('dashboard'))

@app.route('/add_threat_intel', methods=['POST'])
def add_threat_intel():
    """Add threat intelligence indicator"""
    indicator = request.form.get('indicator', '').strip()
    indicator_type = request.form.get('indicator_type', 'domain')
    threat_type = request.form.get('threat_type', 'malicious')
    
    if not indicator:
        flash('Please provide an indicator', 'warning')
        return redirect(url_for('dashboard'))
    
    # Check if exists
    existing = ThreatIntelligence.query.filter_by(indicator=indicator).first()
    if existing:
        existing.last_seen = datetime.utcnow()
        existing.is_active = True
    else:
        threat = ThreatIntelligence(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_type=threat_type,
            confidence=80.0,
            source='manual'
        )
        db.session.add(threat)
    
    db.session.commit()
    security_engine._load_threat_intelligence()
    flash('Threat intelligence added successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for email analysis"""
    try:
        data = request.get_json()
        if not data or 'body' not in data:
            return jsonify({'error': 'Email body required'}), 400
        
        results = security_engine.analyze_email(data)
        return jsonify({
            'success': True,
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/check_url', methods=['POST'])
def api_check_url():
    """API endpoint for URL checking"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL required'}), 400
        
        # Check URL
        result = security_engine.analyze_urls([url])
        
        return jsonify({
            'success': True,
            'url': url,
            'suspicious': bool(result['suspicious']),
            'malicious': bool(result['malicious']),
            'details': result
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= ERROR HANDLERS =============

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error='Internal server error'), 500

# ============= CONTEXT PROCESSORS =============

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

# ============= INITIALIZE DATABASE =============

@app.cli.command('init-db')
def init_db():
    db.create_all()
    print('✅ Database initialized successfully!')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    print("""
    📧 Email Security Gateway with Phishing Detection
    ================================================
    🌐 Server running at: http://127.0.0.1:5000
    
    Features:
    - Email header analysis (SPF, DKIM, DMARC)
    - URL scanning and threat detection
    - ML-based phishing classification
    - Real-time alerting
    - Quarantine management
    - Threat intelligence
    """)
    
    app.run(debug=False, host='0.0.0.0', port=5000)