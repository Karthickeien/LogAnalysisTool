# LogAnalysisTool

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/Security-Monitoring-red.svg)
![Type](https://img.shields.io/badge/Type-Log%20Analysis-orange.svg)
## Compatibility
![OS](https://img.shields.io/badge/OS-Linux%20|%20Windows%20|%20MacOS-lightgrey.svg)
![IDE](https://img.shields.io/badge/IDE-VS%20Code%20|%20PyCharm%20|%20Any-blue.svg)
![Framework](https://img.shields.io/badge/Framework-Standard%20Library-purple.svg)

## Project Overview
This Log Analysis Tool is a Python script designed to analyze web server log files and identify patterns, potential security threats, and usage statistics. The tool processes log files to extract key information about IP addresses, endpoint access patterns, and suspicious activities.

## Features
- IP Address Request Analysis: Tracks and counts requests from each unique IP address
- Endpoint Access Tracking: Identifies the most frequently accessed endpoints
- Security Monitoring: Detects potential brute force attacks by monitoring failed login attempts
- CSV Report Generation: Exports analysis results in a structured CSV format

## Requirements
- Python 3.6+
- No external dependencies required (uses standard library only)

## Installation
1. Clone this repository or download the script files
2. Ensure you have Python 3.6 or higher installed
3. Place your log file in the same directory as the script

## Usage
```bash
python log_analyzer.py
```

The script will:
1. Read the log file (`sample.log` by default)
2. Analyze the contents
3. Display results in the terminal
4. Generate a CSV report (`log_analysis_results.csv`)

## Configuration
You can modify the following parameters in the script:
- `login_attempt_threshold`: Number of failed login attempts before flagging an IP (default: 10)
- `log_file`: Input log file path (default: 'sample.log')
- `output_file`: Output CSV file path (default: 'log_analysis_results.csv')

## Output Format
### Terminal Output
```
Requests per IP Address:
IP Address           Request Count
192.168.1.1          234
203.0.113.5          187
...

Most Frequently Accessed Endpoint:
/home (Accessed 403 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.1.100        56
203.0.113.34         12
```

### CSV Output Structure
The CSV file contains three sections:
1. Requests per IP
2. Most Accessed Endpoint
3. Suspicious Activity

## Implementation Details
- Uses regex patterns for efficient log parsing
- Implements OOP principles for maintainable code
- Includes type hints for better code clarity
- Error handling for malformed log entries
- Memory-efficient processing for large log files




## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Keywords
`log analysis` `security monitoring` `python` `data analysis` `cybersecurity` `server logs` `brute force detection` `IP tracking` `web security` `monitoring tools` `threat detection` `log parsing` `security tools` `python security` `log analyzer`
