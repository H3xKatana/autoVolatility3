# Volatility Memory Forensics Automation Script

## Overview

This Python script provides an automated solution for performing memory forensics analysis using Volatility 3. It supports different scan types and offers flexible configuration for analyzing memory dump files.


## Prerequisites

- Python 3.7+
- Volatility 3 installed
- Memory dump file

## Installation

1. Clone the repository:
```bash
git clone github.com/H3xKatana/autoVolatility3/
cd autoVolatility3
```

2. Ensure Volatility 3 is installed
```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
python3 -m venv venv && . venv/bin/activate
pip install -e .[dev]
```

## Usage

### Basic Usage
```bash
python3 autovol3.py -f /path/to/memory/dump.dmp
```

### Advanced Options

#### Scan Types
- Minimal: Basic system information
- Normal (Default): Comprehensive system analysis
- Full: Extensive forensic investigation

```bash
# Minimal scan
python3 autovol3.py -f memory.dmp -s minimal

# Full scan
python3 autovol3.py -f memory.dmp -s full
```

#### Custom Output Directory
```bash
python3 autovol3.py -f memory.dmp -o /custom/output/path
```

#### Custom Volatility Path
```bash
python3 autovol3.py -f memory.dmp --volatility-path /custom/vol.py
```

## Scan Type Details

### Minimal Scan
- System Information
- Process List
- Process Tree
- Command Lines

### Normal Scan
- All Minimal Scan Plugins
- Process Extensions
- Module Listing
- Network Connections
- Malware Detection
- DLL Listing

### Full Scan
- All Normal Scan Plugins
- File Scanning
- Socket Connections
- Security Identifiers
- Registry Analysis
- Scheduled Tasks

## Output

- Analysis results are saved in timestamped directories
- Separate files for each Volatility plugin
- Error logs for plugins with issues



## To do 
- adding support for other operating systems 
- making the script run parallels

