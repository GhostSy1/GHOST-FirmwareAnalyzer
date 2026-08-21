# GHOST-FirmwareAnalyzer

Embedded IoT & Router Firmware Security Audit Engine developed by Abdulaziz (Ghost-SY1).

## Overview & Purpose
`GHOST-FirmwareAnalyzer` is an advanced binary analysis utility designed to inspect embedded firmware images, calculate cryptographic hashes, evaluate entropy, and uncover embedded security risks.

## Installation & Setup
```bash
git clone https://github.com/GhostSy1/GHOST-FirmwareAnalyzer.git
cd GHOST-FirmwareAnalyzer
python3 -m pip install -r requirements.txt
```

## Usage
```bash
python3 main.py --firmware router_fw.bin --json fw_report.json
```
