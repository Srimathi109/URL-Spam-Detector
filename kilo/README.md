# URL Spam Detector

An AI-powered web application that detects spam, phishing, and malicious URLs to protect users from potential threats.

## Features

- **Real-time URL Analysis**: Instantly checks URLs for suspicious patterns
- **Risk Scoring**: Assigns a risk score (0-100) based on multiple indicators
- **Threat Detection**: Identifies:
  - IP-based URLs
  - Suspicious TLDs
  - Phishing keywords
  - Homograph attacks
  - URL obfuscation techniques
  - Excessive subdomains
  - URL shorteners
- **Visual Alerts**: Color-coded warnings (Safe, Caution, Suspicious, Dangerous)
- **User-Friendly Interface**: Clean, modern web UI

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser and navigate to:
```
http://localhost:5000
```

3. Enter a URL to check and click "Check"

## How It Works

The detector analyzes URLs based on multiple security indicators:

- **Domain Analysis**: Checks for IP addresses, suspicious TLDs, and excessive subdomains
- **Pattern Matching**: Identifies phishing keywords and suspicious patterns
- **Obfuscation Detection**: Finds hidden redirects and URL shorteners
- **Character Analysis**: Detects homograph attacks using lookalike characters
- **Risk Calculation**: Combines all factors into a comprehensive risk score

## Risk Levels

- **SAFE** (0-19): No significant threats detected
- **LOW** (20-39): Minor concerns, proceed with caution
- **MEDIUM** (40-69): Multiple suspicious indicators
- **HIGH** (70+): Likely malicious, do not visit

## Example URLs to Test

Safe:
- https://github.com
- https://stackoverflow.com

Suspicious:
- http://192.168.1.1/login
- https://paypal-verify-account.tk
- https://bit.ly/suspicious

## Future Enhancements

- Integration with URL reputation APIs (VirusTotal, Google Safe Browsing)
- Machine learning model for improved detection
- Browser extension
- URL history and reporting
- Real-time threat intelligence feeds

## License

MIT License
