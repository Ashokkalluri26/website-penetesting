# Web Application Penetration Testing Tool

A Flask-based web application for performing security scans and penetration testing on web applications.

## Features

- User authentication and authorization
- Admin dashboard for user management
- Comprehensive security scanning including:
  - SSL/TLS certificate validation
  - DNS security checks
  - HTTP security headers analysis
  - Form security assessment
  - Cookie security verification
- Real-time scan progress tracking
- Detailed security reports

## Setup

1. Clone the repository:
```bash
git clone <your-repository-url>
cd webapplicationpenetesting
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
flask run
```

5. Access the application at `http://localhost:5000`

## Default Admin Credentials

- Username: admin
- Password: admin123

## Security Note

Please change the default admin credentials after first login for security purposes. 