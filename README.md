# WiFiRisk CLI

WiFiRisk is a Python-based command-line tool for assessing low-cost Wi-Fi repeaters based on security findings, risk level, pricing, and recommendations.

## Developed By

Dulara

## Features

- Interactive CLI console
- ASCII art banner
- List tested Wi-Fi repeaters
- Search devices
- View device details
- View security findings
- Compare two devices
- Recommend devices based on budget
- Calculate security score from findings
- JSON-based local database

## Project Structure

```text
wifi-risk-cli/
├── data/
│   ├── devices.json
│   └── findings.json
├── wifi_risk/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── models/
│   ├── services/
│   └── utils/
├── requirements.txt
└── README.md