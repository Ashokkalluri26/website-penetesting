from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import requests
from bs4 import BeautifulSoup
import threading
import time
import ssl
import socket
import dns.resolver
from urllib.parse import urlparse
from models import db, User, Scan
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Store scan results
scan_results = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables and admin user
def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

# Initialize database
init_db()

def check_ssl_certificate(url):
    """Check SSL certificate validity"""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'valid': True,
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'expiry': cert['notAfter']
                }
    except:
        return {'valid': False}

def check_dns_security(url):
    """Check DNS security settings"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        results = {}
        
        # Check for SPF record
        try:
            dns.resolver.resolve(domain, 'TXT')
            results['spf'] = True
        except:
            results['spf'] = False
            
        # Check for DMARC record
        try:
            dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            results['dmarc'] = True
        except:
            results['dmarc'] = False
            
        return results
    except:
        return {'spf': False, 'dmarc': False}

def perform_scan(url, scan_id, user_id):
    """Perform comprehensive security scan on the target URL"""
    results = {
        'status': 'running',
        'findings': [],
        'progress': 0,
        'summary': {
            'high': 0,
            'medium': 0,
            'low': 0
        }
    }
    scan_results[scan_id] = results
    
    try:
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # SSL/TLS Check
        ssl_info = check_ssl_certificate(url)
        if not ssl_info['valid']:
            results['findings'].append({
                'severity': 'High',
                'title': 'Invalid SSL Certificate',
                'description': 'The website has an invalid or expired SSL certificate.'
            })
            results['summary']['high'] += 1
        results['progress'] = 20

        # DNS Security Check
        dns_info = check_dns_security(url)
        if not dns_info['spf']:
            results['findings'].append({
                'severity': 'Medium',
                'title': 'Missing SPF Record',
                'description': 'The domain lacks SPF record for email authentication.'
            })
            results['summary']['medium'] += 1
        if not dns_info['dmarc']:
            results['findings'].append({
                'severity': 'Medium',
                'title': 'Missing DMARC Record',
                'description': 'The domain lacks DMARC record for email authentication.'
            })
            results['summary']['medium'] += 1
        results['progress'] = 40

        # HTTP Security Headers Check
        response = requests.get(url, timeout=10)
        headers = response.headers

        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking protection)',
            'X-XSS-Protection': 'Missing X-XSS-Protection header (XSS protection)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header (MIME type protection)',
            'Strict-Transport-Security': 'Missing HSTS header (HTTPS enforcement)',
            'Content-Security-Policy': 'Missing Content-Security-Policy header (XSS and injection protection)',
            'Referrer-Policy': 'Missing Referrer-Policy header (referrer information control)'
        }

        for header, message in security_headers.items():
            if header not in headers:
                severity = 'High' if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else 'Medium'
                results['findings'].append({
                    'severity': severity,
                    'title': f'Missing {header}',
                    'description': message
                })
                results['summary'][severity.lower()] += 1
        results['progress'] = 60

        # Form Security Check
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if not form.get('action', '').startswith('https'):
                results['findings'].append({
                    'severity': 'High',
                    'title': 'Insecure Form Submission',
                    'description': 'Form submission is not using HTTPS.'
                })
                results['summary']['high'] += 1
            if not form.get('method', '').lower() == 'post':
                results['findings'].append({
                    'severity': 'Medium',
                    'title': 'Form Using GET Method',
                    'description': 'Form is using GET method which exposes data in URL.'
                })
                results['summary']['medium'] += 1
        results['progress'] = 80

        # Cookie Security Check
        cookies = response.cookies
        for cookie in cookies:
            if not cookie.secure:
                results['findings'].append({
                    'severity': 'Medium',
                    'title': 'Insecure Cookie',
                    'description': f'Cookie "{cookie.name}" is not marked as secure.'
                })
                results['summary']['medium'] += 1
            if not cookie.has_nonstandard_attr('HttpOnly'):
                results['findings'].append({
                    'severity': 'Medium',
                    'title': 'Cookie Without HttpOnly Flag',
                    'description': f'Cookie "{cookie.name}" is not marked as HttpOnly.'
                })
                results['summary']['medium'] += 1
        results['progress'] = 100

        results['status'] = 'completed'
        
        # Save scan results to database
        with app.app_context():
            scan = Scan(
                url=url,
                findings=results['findings'],
                summary=results['summary'],
                user_id=user_id
            )
            db.session.add(scan)
            db.session.commit()
        
    except Exception as e:
        results['status'] = 'error'
        results['error'] = str(e)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password')
            return redirect(url_for('login'))
            
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'true'
        
        if not username or not email or not password:
            flash('Please fill in all fields')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        # Check if trying to register as admin
        if is_admin:
            existing_admin = User.query.filter_by(is_admin=True).first()
            if existing_admin:
                flash('An admin already exists')
                return redirect(url_for('register'))
            
        try:
            user = User(username=username, email=email, is_admin=is_admin)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            login_user(user)
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration')
            return redirect(url_for('register'))
            
    # Check if admin exists for registration page
    admin_exists = User.query.filter_by(is_admin=True).first() is not None
    return render_template('register.html', admin_exists=admin_exists)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).all()
    return render_template('dashboard.html', scans=scans)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    scans = Scan.query.order_by(Scan.timestamp.desc()).all()
    return render_template('admin.html', users=users, scans=scans)

@app.route('/admin/user/<int:user_id>')
@login_required
def view_user_dashboard(user_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.timestamp.desc()).all()
    return render_template('user_dashboard.html', user=user, scans=scans)

@app.route('/api/user/<int:user_id>/make-admin', methods=['POST'])
@login_required
def make_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Check if there's already an admin
    existing_admin = User.query.filter_by(is_admin=True).first()
    if existing_admin and existing_admin.id != user_id:
        return jsonify({'error': 'Only one admin can exist at a time'}), 400
    
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/user/<int:user_id>/remove-admin', methods=['POST'])
@login_required
def remove_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot remove your own admin privileges'}), 400
    
    user.is_admin = False
    db.session.commit()
    return jsonify({'success': True})

@app.route('/start-scan', methods=['POST'])
@login_required
def start_scan():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    scan_id = str(int(time.time()))
    thread = threading.Thread(target=perform_scan, args=(url, scan_id, current_user.id))
    thread.start()
    
    return jsonify({'scan_id': scan_id})

@app.route('/scan-status/<scan_id>')
@login_required
def scan_status(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify(scan_results[scan_id])

@app.route('/user_management')
@login_required
def user_management():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('user_management.html', users=users)

@app.route('/api/user/<int:user_id>', methods=['GET'])
@login_required
def get_user_details(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    return jsonify({
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else None,
        'scans': [{
            'url': scan.url,
            'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': scan.findings
        } for scan in user.scans]
    })

@app.route('/api/user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'error': 'Cannot delete admin user'}), 400
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 