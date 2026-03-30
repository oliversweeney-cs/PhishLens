# PhishLens

A self-hosted phishing email analyzer built with Python and Flask. Designed for SOC analysts and cybersecurity students who need to analyze `.eml` files locally without uploading sensitive emails to third-party services.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Why PhishLens?

Tools like [PhishTool](https://phishtool.com/) are excellent for email analysis, but they require uploading emails to an external service. In a SOC environment, forwarding real phishing emails externally can expose internal infrastructure details, employee names, and sensitive data. PhishLens keeps everything on your local machine.

## Features

- **Drag-and-drop upload** — Drop `.eml` files into the browser for instant analysis
- **Header analysis** — From, To, Subject, Date, Reply-To, Message-ID, Return-Path with mismatch detection
- **Email authentication** — SPF, DKIM, and DMARC results with visual pass/fail/neutral indicators and contextual explanations
- **Sender mismatch flagging** — Highlights discrepancies between the `From` address and `Return-Path` / `Reply-To` fields
- **Body viewer** — Four tabs: Rendered HTML, raw HTML source, Plaintext, and full email source with line numbers
- **URL extraction** — All URLs pulled from the email body, ready for further analysis in tools like VirusTotal or URLScan
- **Attachment metadata** — Filename, file type, size, and MD5/SHA256 hashes for each attachment
- **Received hop timeline** — PhishTool-style vertical timeline showing the email's path through mail servers with delay calculations

## Screenshots

<!-- Add your own screenshots here -->
<!-- ![Upload Page](screenshots/upload.png) -->
<!-- ![Analysis View](screenshots/analysis.png) -->

## Installation

### Prerequisites

- Python 3.10+
- pip

### Setup

```bash
# Clone the repository
git clone https://github.com/oliversweeney-cs/PhishLens.git
cd PhishLens

# Install dependencies
pip install flask

# Run the application
python3 app.py
```

Then open `http://127.0.0.1:8888` in your browser.

## Usage

1. Navigate to the upload page
2. Drag and drop an `.eml` file (or click to browse)
3. Review the analysis dashboard:
   - Check authentication results (SPF, DKIM, DMARC) for failures or neutral results
   - Look for sender mismatches between `From`, `Return-Path`, and `Reply-To`
   - Inspect extracted URLs before clicking anything
   - Check attachment hashes against threat intelligence platforms
   - Review the hop timeline for suspicious routing or delays

## Project Structure

```
PhishLens/
├── app.py                  # Flask backend — .eml parsing and analysis engine
├── templates/
│   ├── index.html          # Drag-and-drop upload page
│   └── analyze.html        # Analysis dashboard
├── uploads/                # Temporary storage for uploaded .eml files
└── README.md
```

## Limitations

- **No external API integrations** — URL and hash lookups (VirusTotal, AbuseIPDB, etc.) are not built in. PhishLens extracts the data; you feed it to your preferred tools manually.
- **No DKIM signature verification** — PhishLens reads the authentication results from email headers. It does not perform cryptographic DKIM verification independently.
- **Single-user** — No authentication, user management, or case tracking. It is a local analysis tool, not a platform.

## Roadmap

- [ ] Optional VirusTotal API integration for URL and hash lookups
- [ ] Export analysis results as JSON or PDF report
- [ ] Dark/light theme toggle
- [ ] Support for `.msg` file format parsing

## Built With

- [Python](https://www.python.org/) — Core language
- [Flask](https://flask.palletsprojects.com/) — Web framework
- Python `email` stdlib — `.eml` file parsing

## Context

This project was built as part of my cybersecurity study journey while working through the [MYDFIR SOC Analyst Accelerator](https://www.skool.com/mydfir) program. The goal was to create a practical, local-first tool that mirrors the workflow of commercial phishing analysis platforms, while keeping sensitive email data off third-party servers.

## License

MIT License — see [LICENSE](LICENSE) for details.
