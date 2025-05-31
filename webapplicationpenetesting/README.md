# Web Security Scanner

A user-friendly web application for performing basic security scans on websites. This tool helps identify common security vulnerabilities and provides a beautiful, animated interface for viewing results.

## Features

- Modern, responsive UI with animations
- Real-time scan progress updates
- Color-coded severity levels for findings
- Basic security checks including:
  - HTTPS usage
  - Security headers
  - Form security
  - XSS protection

## Setup

1. Install Python 3.7 or higher
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

1. Start the Flask server:
   ```bash
   python app.py
   ```
2. Open your web browser and navigate to `http://localhost:5000`
3. Enter a URL to scan and click "Start Scan"
4. View the results in real-time as the scan progresses

## Security Note

This tool is designed for educational and testing purposes only. Always obtain proper authorization before scanning any website.

## License

MIT License 