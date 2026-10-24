# AI-Based Firewall Monitoring Dashboard with VirusTotal

## Overview

This project is an educational security dashboard that integrates
with the VirusTotal API v3.

It provides a web interface for submitting files and URLs for
security analysis and searching VirusTotal Intelligence.

## Features

- Dark cybersecurity dashboard
- File submission and analysis
- URL submission and analysis
- VirusTotal Intelligence search
- Scan statistics
- Recent activity
- Session-based scan history
- Backend health indicator
- Responsive layout

## Technologies

- HTML
- CSS
- JavaScript
- Node.js
- Express.js
- VirusTotal API v3

## Requirements

- Node.js 18.17 or newer
- npm
- Internet access
- VirusTotal API key

## Installation

### Step 1: Install dependencies

Open a terminal inside the project folder.

Run:

    npm install

### Step 2: Configure the API key

Copy example.env to .env.

Windows PowerShell:

    Copy-Item example.env .env

Linux or macOS:

    cp example.env .env

Edit .env and configure:

    VIRUSTOTAL_API_KEY=your_actual_api_key
    PORT=3000

### Step 3: Start the application

Run:

    npm start

### Step 4: Open the dashboard

Visit:

    http://localhost:3000

Keep the server running while using the dashboard.

## API Endpoints

### Health check

GET /api/health

Reports whether the server has an API key configured.

### File submission

POST /api/scan/file

Uploads a file to VirusTotal.

### URL submission

POST /api/scan/url

Submits a URL for analysis.

### Intelligence search

GET /api/search?q=domain:example.com

Searches VirusTotal Intelligence. Appropriate API permissions
are required.

## Security Notes

- Keep the API key in .env.
- Never put the API key in frontend JavaScript.
- Do not upload confidential files without authorisation.
- VirusTotal submissions may be shared with its security community.
- The demo supports files up to 32 MB.
- Add authentication and rate limiting before deployment.

## Project Limitations

This is a scanning dashboard, not a complete firewall.

It does not currently:

- Block network traffic.
- Inspect live packets.
- Create a VPN connection.
- Run a machine-learning threat detector.
- Persist history in a database.
- Automatically retrieve all completed scan reports.

## Future Enhancements

1. Add completed analysis report retrieval.
2. Store scan history in a database.
3. Integrate firewall logs.
4. Add an AI-based anomaly detector.
5. Integrate VPN status monitoring.
6. Add authentication and alerting.
