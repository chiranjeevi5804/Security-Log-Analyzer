
# Security Log Analyzer

## Project Overview

Security Log Analyzer is a Python-based cybersecurity web application designed to analyze login records and identify suspicious login activities.

The application processes uploaded log files, detects repeated failed login attempts, validates IP addresses and timestamps, and generates a security report with risk levels and recommendations.

## Features

- Upload and analyze TXT log files.
- Validate IP addresses and timestamps.
- Identify successful and failed login attempts.
- Detect suspicious IP addresses.
- Classify security risks as Low, Medium, or High.
- Calculate login activity percentages.
- Identify the most targeted IP address.
- Visualize login activity using interactive charts.
- Display hourly login activity.
- Generate and download security reports.
- Validate uploaded files and handle errors.

## Technologies Used

- Python
- Flask
- HTML
- CSS
- JavaScript
- Chart.js

## Project Structure

```text
Cyber/
│
├── app.py
├── main.py
├── sample_logs.txt
├── safe_logs.txt
├── invalid_logs.txt
├── invalid_ip_logs.txt
├── invalid_timestamp_logs.txt
├── low_risk.txt
├── medium_risk.txt
├── high_risk.txt
│
├── templates/
│   └── index.html
│
└── static/
    └── style.css
```

## Installation and Setup

### 1. Install Python

Download and install Python from:

https://www.python.org/

### 2. Install Flask

Open the terminal in the project folder and run:

```bash
pip install flask
```

### 3. Run the Application

Execute:

```bash
python app.py
```

### 4. Open in Browser

Visit:

```text
http://127.0.0.1:5000
```

## Sample Log Format

Each log record should follow this format:

```text
IP_ADDRESS EVENT TIMESTAMP
```

Example:

```text
192.168.1.10 LOGIN_SUCCESS 10:30:15
192.168.1.15 LOGIN_FAILED 10:31:20
192.168.1.15 LOGIN_FAILED 10:31:25
192.168.1.15 LOGIN_FAILED 10:31:30
```

## Risk Classification

| Risk Level | Condition |
|---|---|
| Low Risk | No suspicious IP detected |
| Medium Risk | At least 3 failed attempts from an IP |
| High Risk | At least 5 failed attempts from an IP |

## Output

The application displays:
- Login statistics
- Suspicious IP addresses
- Security risk level
- Login activity charts
- Security recommendations

It also provides a downloadable security report.

## Future Enhancements

- Real-time log monitoring.
- Email alerts for suspicious activities.
- Database integration.
- Advanced threat detection.

## Author

Security Log Analyzer – Cybersecurity Project
