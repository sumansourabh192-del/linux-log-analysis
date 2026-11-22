
# Linux Log Analysis

A Python-based cybersecurity project that analyzes Linux SSH authentication logs to identify failed login attempts, successful logins, and potentially suspicious IP addresses.

## Features

- Parses SSH authentication logs using Python Regular Expressions.
- Counts failed and successful login attempts.
- Identifies usernames targeted by failed login attempts.
- Groups failed attempts by IP address.
- Detects suspicious IP addresses using a configurable threshold.
- Generates TXT and CSV analysis reports.
- Validates threshold input.

## Technologies Used

- Python 3
- Linux (Ubuntu)
- Regular Expressions
- CSV Module
- Git and GitHub

## Project Structure

```text
linux-log-analysis/
├── data/
│   └── sample_auth.log
├── reports/
│   ├── analysis_report.txt
│   └── analysis_report.csv
├── src/
│   └── analyzer.py
├── .gitignore
└── README.md
```

## How to Run

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
cd linux-log-analysis
```

Run with the default threshold of 3:

```bash
python3 src/analyzer.py
```

Run with a custom threshold:

```bash
python3 src/analyzer.py 5
```

## Sample Results

Using the included synthetic sample log:

- Failed login attempts: 3
- Successful login attempts: 2
- Suspicious IP: 192.168.1.50
- Detection threshold: 3

## Generated Reports

The program generates:

- `reports/analysis_report.txt`
- `reports/analysis_report.csv`

## Learning Outcomes

- Linux authentication log analysis
- Python scripting and file handling
- Regular expression pattern matching
- Basic security event monitoring
- Suspicious login detection

## Disclaimer

This project uses synthetic sample authentication logs for educational and testing purposes. An IP flagged by this tool is not proof of a real attack.
