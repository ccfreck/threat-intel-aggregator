# Threat Intel Aggregator

A Python CLI tool that aggregates threat intelligence for IP addresses from multiple security APIs.

## Features

- Queries **Shodan** (internetdb), **VirusTotal**, and **AbuseIPDB** for IP reputation data
- Consolidates results into a single, readable report
- No API key required for Shodan (free tier)

## Requirements

- Python 3.10+
- `requests`
- `python-dotenv`

## Installation

```bash
git clone https://github.com/yourusername/threat-intel-aggregator.git
cd threat-intel-aggregator
pip install -r requirements.txt
```
Configuration - create a .env file in the project root:
```bash
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```
Usage
```python
python main.py
```
