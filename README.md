# Apache Log Analyzer - Bot Detection Tool

A robust Python script that analyzes Apache access logs to distinguish between legitimate human traffic and malicious bots/scanners. The tool supports multiple Apache log formats and provides intelligent classification based on behavior patterns.

## Features

- **Multi-Format Support**: Works with standard, combined, and custom Apache log formats
- **Intelligent Bot Detection**: Uses multiple factors to classify traffic:
  - User-Agent pattern analysis
  - HTTP status code patterns
  - Request frequency analysis
  - Binary/malformed request detection
  - Suspicious path scanning detection
  - Error-to-success ratio analysis
- **Flexible Output**: Sort and filter results by various criteria
- **Real-Time Monitoring**: Live log monitoring with immediate alerts
- **Robust Parsing**: Handles malformed requests and binary data (including literal `\x` characters) in logs

## Supported Log Formats

### Standard Apache Format
```
%h %l %u %t "%r" %>s %b
```

### Combined Format
```
%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
```

### Poophole Custom Format
```
%t %h %A:%p %v "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %{Host}i
```

## Installation

```bash
# Clone the repository
git clone https://github.com/peoyli/apache-log-analyzer.git
cd apache-log-analyzer

# Ensure Python 3 is installed
python3 --version

# No dependencies required - uses only Python standard library
```

## Usage

### Batch Analysis with log-analyzer.py

```bash
# Analyze a log file with combined format (default)
python3 log-analyzer.py /var/log/apache2/access.log

# Specify log format explicitly
python3 log-analyzer.py /var/log/apache2/access.log --format combined
python3 log-analyzer.py /var/log/apache2/access.log --format standard
python3 log-analyzer.py /var/log/apache2/access.log --format poophole
```

#### Advanced Sorting and Filtering
```bash
# Sort by bot score (highest first)
python3 log-analyzer.py access.log --sort-by score --sort-order desc

# Show only high-confidence bots
python3 log-analyzer.py access.log --filter-type bot-high

# Filter by minimum bot score
python3 log-analyzer.py access.log --min-score 5

# Sort by number of requests (most active first)
python3 log-analyzer.py access.log --sort-by requests

# Show suspicious activity, sorted by error count
python3 log-analyzer.py access.log --filter-type suspicious --sort-by errors

# Sort by unique endpoints accessed (scanner detection)
python3 log-analyzer.py access.log --sort-by endpoints

# Human traffic only, sorted by successful requests
python3 log-analyzer.py access.log --filter-type human --sort-by success
```

#### Detailed Output
```bash
# Get detailed information for each IP
python3 log-analyzer.py access.log --output detailed

# Combine detailed output with filtering
python3 log-analyzer.py access.log --filter-type bot-high --output detailed
```

### Real-Time Monitoring with log-monitor.py

```bash
# Basic monitoring with default settings
python3 log-monitor.py /var/log/apache2/access.log

# Monitor with specific format and faster checking
python3 log-monitor.py /var/log/apache2/access.log --format poophole --interval 2

# Only alert on high-confidence bots
python3 log-monitor.py /var/log/apache2/access.log --filter-type bot-high --min-score 8

# Show all traffic (not just alerts)
python3 log-monitor.py /var/log/apache2/access.log --show-all

# Monitor with very sensitive settings (alert on any suspicion)
python3 log-monitor.py /var/log/apache2/access.log --min-score 1 --filter-type suspicious

# Only show human traffic (for debugging/analysis)
python3 log-monitor.py /var/log/apache2/access.log --filter-type human --show-all
```

## Output Columns

The analyzer provides the following information for each IP address:

- **IP**: Source IP address
- **Type**: Classification (HUMAN, SUSPICIOUS, BOT-MED, BOT-HIGH)
- **Requests**: Total number of requests
- **Score**: Bot confidence score (0-20+)
- **Errors**: Number of error responses (4xx, 5xx)
- **Success**: Number of successful responses (2xx, 3xx)
- **Endpoints**: Number of unique paths accessed

## Real-Time Monitoring Features

The `log-monitor.py` provides real-time analysis with:

- **Immediate Alerts**: Get notified instantly when suspicious activity is detected
- **Live Filtering**: Apply the same filters as batch analysis in real-time
- **Progress Tracking**: See request counts and alert statistics
- **Error Recovery**: Automatically recovers from parsing errors
- **Visual Indicators**: Emoji-based alerts for quick scanning
- **Customizable Sensitivity**: Adjust alert thresholds on the fly

### Monitor Output Example
```
🚨 ALERT #15 - BOT-HIGH 🚨
📡 IP: 195.178.110.108
📊 Score: 16 | Requests: 45
🌐 Request: GET /wp-admin.php...
📱 User-Agent: Mozilla/5.0 (compatible; AhrefsBot/7.0;...
📟 Status: 404
🔍 Indicators:
   • Binary requests: 3
   • Bot-like UA: Mozilla/5.0 (compatible; AhrefsBot/7.0;...
   • Many 404s: 42
```

## Bot Detection Methodology

### Scoring Factors

The analyzer uses a weighted scoring system:

1. **Binary/Malformed Requests** (+5 points):  
   Detects SSL/TLS handshakes, binary data (including literal `\x` characters), or malformed HTTP requests

2. **Suspicious User-Agents** (+3 points):  
   Matches against known bot, crawler, and scanner signatures

3. **Error Patterns** (+2 points each):  
   - Excessive 404 errors (>10)
   - Excessive 403 errors (>5)
   - High error-to-success ratio
   - No successful requests

4. **Request Frequency** (+2 points):  
   High request rate (>2 requests/second)

5. **Path Analysis** (+2-3 points):  
   - Binary data in paths
   - Suspicious paths (admin, config files, etc.)
   - Scanning patterns (many unique endpoints)

### Classification Thresholds

- **BOT-HIGH**: Score ≥ 8 (High confidence malicious activity)
- **BOT-MED**: Score 5-7 (Medium confidence)
- **SUSPICIOUS**: Score 3-4 (Possible bot activity)
- **HUMAN**: Score 0-2 (Likely legitimate traffic)

## Handling Special Cases

### Literal `\x` Characters in Logs

The tool correctly handles logs containing literal `\x` characters, which are commonly seen with:
- SSL/TLS handshake attempts
- Binary protocol probes
- Malformed request attacks

Examples of handled log entries:
```
147.185.132.106 - - [10/Dec/2024:04:12:35 +0100] "\x16\x03\x01" 400 483 "-" "-"
93.174.93.12 - - [10/Dec/2024:07:13:59 +0100] "\x16\x03\x02\x01o\x01" 400 483 "-" "-"
```

These are automatically flagged as suspicious binary requests.

## Customization

### Adding Suspicious Patterns

Edit the `bot_indicators` section in the script to add custom patterns:

```python
self.bot_indicators = {
    'suspicious_user_agents': [
        # Add your custom patterns here
        'custom-bot',
        'scanner-tool'
    ],
    'suspicious_paths': [
        # Add custom path patterns
        r'/wp-admin',
        r'\.bak$'
    ]
}
```

### Adjusting Scoring Thresholds

Modify the scoring logic in the `analyze_ip` method to adjust sensitivity:

```python
# Example: Make 404 detection more sensitive
if activity['status_codes'][404] > 5:  # Changed from 10 to 5
    score += 2
```

## Troubleshooting

### Common Issues

**Parse Errors**: If you see "Could not parse line" warnings, the script will still function using fallback parsing. These are typically caused by:
- Binary data in requests (SSL handshakes, etc.)
- Malformed HTTP requests
- Custom log formats with variations

**Encoding Issues**: If you encounter encoding errors, the script automatically handles them with error recovery.

**Missing IP Addresses**: Rare parsing issues may result in malformed entries. These are typically edge cases with extremely malformed log entries.

### Log Format Verification

To verify your log format matches the expected pattern, check a sample line:

```bash
# Check first few lines of your log
head -5 /path/to/access.log

# Compare with expected format patterns in the script
```

## Example Output

### Batch Analysis
```
Results (sorted by requests, desc):
IP                   Type         Requests   Score  Errors   Success  Endpoints
--------------------------------------------------------------------------------
195.178.110.108      BOT-HIGH     213        16     208      3        209
185.224.128.115      BOT-MED      45         7      42       1        43
84.17.37.109         HUMAN        12         0      0        12       5
...

Detailed view for BOT-HIGH:
   Binary requests: 5
   Bot-like UA: Mozilla/5.0 (compatible; AhrefsBot/7.0;...
   Many 404s: 195
   No successful requests
   Status: {200: 3, 404: 195, 403: 10, 500: 3}
```

### Real-Time Monitoring
```
🔍 Monitoring /var/log/apache2/access.log for suspicious activity...
   Format: combined, Check interval: 5s
   Filters: min_score=3, filter_type=all, alert_only=True
Press Ctrl+C to stop monitoring
------------------------------------------------------------

🚨 ALERT #1 - BOT-HIGH 🚨
📡 IP: 195.178.110.108
📊 Score: 16 | Requests: 1
🌐 Request: GET /wp-admin.php...
📱 User-Agent: Mozilla/5.0 (compatible; AhrefsBot/7.0;...
📟 Status: 404
🔍 Indicators:
   • Bot-like UA: Mozilla/5.0 (compatible; AhrefsBot/7.0;...
------------------------------------------------------------
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests for:

- Additional log format support
- Improved detection algorithms
- Performance optimizations
- Bug fixes
- Enhanced real-time monitoring features

## License

This project is open source. Feel free to use and modify as needed.

## Disclaimer

This tool is designed for server administrators to help identify potentially malicious traffic. It should be used as part of a comprehensive security strategy, not as the sole means of protection. False positives and negatives are possible - always verify results before taking action.

## AI-Generated Content Disclaimer

**Important Notice**: This tool and its accompanying documentation were created entirely by artificial intelligence (AI). While we've made efforts to ensure accuracy, please be aware of the following:

### How It Was Created

This project was generated using **deepseek-v3.1-671b** through an iterative AI development process:

**Initial Prompt:**
```
create a script that analyzes apache access and error logs, groups by IP, then depending on what the return codes are decides on if that host is a real person trying to access my site or a bot trying to find vulnerabilities.  I use the following types of Apache logs:
standard (default)
apache-provided "combined"
self-crafted "poophole":  "%t %h %A:%p %v \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %{Host}i"
```

**Development Process:**
- Initial code generation with the above prompt
- Follow-up prompts to fix parsing errors (particularly handling literal `\x` characters in logs)
- Additional prompts to add sorting, filtering, and real-time monitoring capabilities
- No manual code editing - all changes were made through AI interaction

**Key Features Added Iteratively:**
- Robust log parsing with literal `\x` character handling
- Advanced sorting and filtering options
- Real-time monitoring capabilities
- Multi-format log support (standard, combined, poophole)

### Development Status
- 🤖 **AI-Created**: This entire project, including all code, documentation, and examples, was generated by AI
- 🧪 **Limited Testing**: The software has not undergone thorough real-world testing across all scenarios
- 🔍 **Verification Needed**: Documentation and code examples should be verified before production use
- ⚠️ **Potential Issues**: There may be undiscovered bugs, security vulnerabilities, or functionality gaps

### Safety Assurance
- ✅ **Read-Only Operation**: This tool only reads log files and does not write to any files, making it safe to run
- ✅ **No System Modifications**: The analyzer does not modify system files, configurations, or log data
- ✅ **No Network Operations**: The tool operates locally and does not make network connections

### Recommendations for Use
1. **Test Thoroughly**: Always test in a safe, isolated environment before deploying
2. **Verify Output**: Manually verify analysis results against known traffic patterns
3. **Code Review**: Have experienced developers review the code before production use
4. **Monitor Carefully**: Pay close attention to system behavior when running the tool
5. **Backup First**: Ensure you have backups before analyzing production log files (recommended strategy, run on a copy of the log file)

### Support Limitations
- This is an experimental AI-generated project
- No guarantee of functionality or security
- Community-supported only - no official maintenance team
- Users assume all responsibility for deployment and use

## Standard Disclaimer

This tool is designed for server administrators to help identify potentially malicious traffic. It should be used as part of a comprehensive security strategy, not as the sole means of protection. False positives and negatives are possible - always verify results before taking action.

**Use at your own risk.** The authors and contributors are not responsible for any damages or issues caused by using this software.
