  Repository Structure

UNIQUE-Scanner/
│
├── .github/
│   └── workflows/
│       └── python-package.yml  # CI/CD pipeline
│
├── wordlists/                  # Directory for wordlists
│   ├── common_paths.txt        # Common web paths
│   └── payloads.txt            # Injection payloads
│
├── reports/                    # Scan outputs (gitignored)
│
├── unique.py                   # Main scanner script
├── requirements.txt            # Python dependencies
├── LICENSE                     # MIT/GPL license
├── README.md                   # Project documentation
└── .gitignore                  # Ignore reports/ and sensitive files


Key Features Overview
A. Core Scanning Capabilities

    OWASP Top 10 Coverage

        A01: Broken Access Control

        A02: Cryptographic Failures

        A03: Injection (SQLi/XSS)

        A05: Security Misconfiguration

        A06: Vulnerable Components

        A07: Authentication Failures

        A10: SSRF

    Advanced Detection

        DOM-based XSS

        Open Redirects

        CORS Misconfigurations

        Cloud Metadata Exposure

        RCE Detection
