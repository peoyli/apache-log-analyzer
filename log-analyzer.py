#!/usr/bin/env python3
"""
Apache Log Analyzer - Distinguishes between real users and bots
Supports: standard, combined, and poophole log formats
"""

import re
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime
import ipaddress

class ApacheLogAnalyzer:
    def __init__(self):
        self.ip_activity = defaultdict(lambda: {
            'requests': [],
            'status_codes': Counter(),
            'user_agents': Counter(),
            'endpoints': Counter(),
            'first_seen': None,
            'last_seen': None
        })
        
        # Bot indicators
        self.bot_indicators = {
            'suspicious_user_agents': [
                r'bot', r'crawler', r'spider', r'scanner', r'nmap', r'sqlmap',
                r'nikto', r'wget', r'curl', r'python', r'java', r'go-http-client',
                r'zgrab', r'masscan', r'nessus', r'metasploit', r'acunetix',
                r'burp', r'dirbuster', r'gobuster', r'arachni', r'openvas'
            ],
            'suspicious_paths': [
                r'/(admin|administrator|phpmyadmin|mysql|wp-admin|\.git|\.env|backup)',
                r'\.(php|asp|jsp|py|sh|pl)(\.|$)',
                r'(union|select|insert|update|delete|drop|exec)',
                r'(etc/passwd|proc/self|\.\./\.\./)'
            ],
            'suspicious_status_patterns': [
                (404, 10),  # More than 10 404s
                (403, 5),   # More than 5 403s  
                (500, 3),   # More than 3 500s
            ]
        }
    
    def parse_line(self, line, log_format):
        """Parse a log line based on the specified format"""
        try:
            if log_format == 'combined':
                return self.parse_combined(line)
            elif log_format == 'poophole':
                return self.parse_poophole(line)
            else:  # standard
                return self.parse_standard(line)
        except Exception as e:
            return None
    
    def parse_standard(self, line):
        """Parse standard Apache log format"""
        # Standard: %h %l %u %t \"%r\" %>s %b
        pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) (\S+)" (\d+) (\S+)'
        match = re.match(pattern, line)
        if match:
            ip, timestamp, method, path, protocol, status, size = match.groups()
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'path': path,
                'protocol': protocol,
                'status': int(status),
                'size': size if size != '-' else '0',
                'user_agent': '',
                'referer': ''
            }
        return None
    
    def parse_combined(self, line):
        """Parse combined Apache log format"""
        # Combined: %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
        pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"'
        match = re.match(pattern, line)
        if match:
            ip, timestamp, method, path, protocol, status, size, referer, user_agent = match.groups()
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'path': path,
                'protocol': protocol,
                'status': int(status),
                'size': size if size != '-' else '0',
                'referer': referer,
                'user_agent': user_agent
            }
        return None
    
    def parse_poophole(self, line):
        """Parse poophole custom log format"""
        # poophole: "%t %h %A:%p %v \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %{Host}i"
        pattern = r'^\[([^\]]+)\] (\S+) \S+:\d+ \S+ "(\S+) ([^"]+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)" (\S+)'
        match = re.match(pattern, line)
        if match:
            timestamp, ip, method, path, protocol, status, size, referer, user_agent, host = match.groups()
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'path': path,
                'protocol': protocol,
                'status': int(status),
                'size': size if size != '-' else '0',
                'referer': referer,
                'user_agent': user_agent,
                'host': host
            }
        return None
    
    def process_log_file(self, filename, log_format='combined'):
        """Process a log file and extract IP activity"""
        try:
            with open(filename, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    log_entry = self.parse_line(line, log_format)
                    if log_entry:
                        self.update_ip_activity(log_entry)
                    else:
                        print(f"Warning: Could not parse line {line_num}: {line[:100]}...")
        
        except FileNotFoundError:
            print(f"Error: File {filename} not found")
            return False
        except Exception as e:
            print(f"Error reading file {filename}: {e}")
            return False
        
        return True
    
    def update_ip_activity(self, log_entry):
        """Update activity tracking for an IP address"""
        ip = log_entry['ip']
        activity = self.ip_activity[ip]
        
        # Parse timestamp
        try:
            # Handle different timestamp formats
            timestamp_str = log_entry['timestamp']
            if ':' in timestamp_str.split()[0]:
                # Format: [day/month/year:hour:minute:second zone]
                timestamp_str = timestamp_str.replace(':', ' ', 1)
                dt = datetime.strptime(timestamp_str, '%d/%b/%Y %H:%M:%S %z')
            else:
                dt = datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S %Y')
            
            if activity['first_seen'] is None or dt < activity['first_seen']:
                activity['first_seen'] = dt
            if activity['last_seen'] is None or dt > activity['last_seen']:
                activity['last_seen'] = dt
        except:
            pass
        
        # Update counters
        activity['status_codes'][log_entry['status']] += 1
        activity['user_agents'][log_entry.get('user_agent', '')] += 1
        activity['endpoints'][log_entry['path']] += 1
        activity['requests'].append(log_entry)
    
    def analyze_ip(self, ip):
        """Analyze IP behavior and determine if it's a bot"""
        activity = self.ip_activity[ip]
        total_requests = len(activity['requests'])
        
        if total_requests == 0:
            return 'unknown', {}
        
        bot_score = 0
        indicators = []
        
        # 1. Check user agent patterns
        user_agent = max(activity['user_agents'].items(), key=lambda x: x[1])[0] if activity['user_agents'] else ''
        if user_agent:
            for pattern in self.bot_indicators['suspicious_user_agents']:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    bot_score += 3
                    indicators.append(f"Suspicious User-Agent: {user_agent}")
                    break
        
        # 2. Check status code patterns
        for status, threshold in self.bot_indicators['suspicious_status_patterns']:
            if activity['status_codes'][status] > threshold:
                bot_score += 2
                indicators.append(f"Excessive {status} errors: {activity['status_codes'][status]}")
        
        # 3. Check for scanning patterns (many 404s relative to success)
        success_codes = activity['status_codes'][200] + activity['status_codes'][301] + activity['status_codes'][302]
        error_codes = activity['status_codes'][404] + activity['status_codes'][403]
        
        if error_codes > 0 and success_codes == 0:
            bot_score += 4
            indicators.append("All requests resulted in errors")
        elif error_codes > success_codes * 2 and error_codes > 5:
            bot_score += 3
            indicators.append("High error-to-success ratio")
        
        # 4. Check request rate (very high frequency)
        if activity['first_seen'] and activity['last_seen']:
            time_diff = (activity['last_seen'] - activity['first_seen']).total_seconds()
            if time_diff > 0:
                requests_per_second = total_requests / time_diff
                if requests_per_second > 2:  # More than 2 requests per second
                    bot_score += 3
                    indicators.append(f"High request rate: {requests_per_second:.2f} req/sec")
        
        # 5. Check for suspicious paths
        for endpoint in activity['endpoints']:
            for pattern in self.bot_indicators['suspicious_paths']:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    bot_score += 2
                    indicators.append(f"Suspicious path: {endpoint}")
                    break
        
        # 6. Check for single endpoint scanning
        if len(activity['endpoints']) > 20 and total_requests > 50:
            unique_endpoint_ratio = len(activity['endpoints']) / total_requests
            if unique_endpoint_ratio > 0.8:  # Mostly unique requests
                bot_score += 2
                indicators.append("Scanning pattern: many unique endpoints")
        
        # Determine classification
        if bot_score >= 8:
            classification = "BOT - High confidence"
        elif bot_score >= 5:
            classification = "BOT - Medium confidence"
        elif bot_score >= 3:
            classification = "SUSPICIOUS - Possible bot"
        else:
            classification = "HUMAN - Likely legitimate"
        
        return classification, {
            'bot_score': bot_score,
            'indicators': indicators,
            'total_requests': total_requests,
            'status_codes': dict(activity['status_codes']),
            'unique_endpoints': len(activity['endpoints']),
            'time_range': activity['last_seen'] - activity['first_seen'] if activity['first_seen'] and activity['last_seen'] else None
        }

def main():
    parser = argparse.ArgumentParser(description='Analyze Apache logs to distinguish bots from humans')
    parser.add_argument('logfile', help='Apache log file to analyze')
    parser.add_argument('--format', choices=['standard', 'combined', 'poophole'], 
                       default='combined', help='Log format (default: combined)')
    parser.add_argument('--min-requests', type=int, default=1,
                       help='Minimum requests to consider (default: 1)')
    parser.add_argument('--output', choices=['summary', 'detailed'], default='summary',
                       help='Output format')
    
    args = parser.parse_args()
    
    analyzer = ApacheLogAnalyzer()
    
    print(f"Analyzing {args.logfile} with {args.format} format...")
    
    if not analyzer.process_log_file(args.logfile, args.format):
        sys.exit(1)
    
    print(f"\nAnalysis completed. Found {len(analyzer.ip_activity)} unique IP addresses.")
    
    # Analyze each IP
    results = []
    for ip in analyzer.ip_activity:
        activity = analyzer.ip_activity[ip]
        total_requests = len(activity['requests'])
        
        if total_requests >= args.min_requests:
            classification, details = analyzer.analyze_ip(ip)
            results.append({
                'ip': ip,
                'classification': classification,
                'details': details,
                'total_requests': total_requests
            })
    
    # Sort by total requests (descending)
    results.sort(key=lambda x: x['total_requests'], reverse=True)
    
    # Print results
    print(f"\n{'IP Address':<20} {'Classification':<30} {'Requests':<10} {'Bot Score':<10}")
    print("-" * 80)
    
    for result in results:
        print(f"{result['ip']:<20} {result['classification']:<30} {result['total_requests']:<10} {result['details']['bot_score']:<10}")
        
        if args.output == 'detailed' and result['details']['indicators']:
            print("  Indicators:")
            for indicator in result['details']['indicators']:
                print(f"    - {indicator}")
            print("  Status Codes:", result['details']['status_codes'])
            if result['details']['time_range']:
                print(f"  Time Range: {result['details']['time_range']}")
            print()
    
    # Summary statistics
    classifications = Counter([r['classification'] for r in results])
    print(f"\nSummary Statistics:")
    for classification, count in classifications.items():
        print(f"  {classification}: {count} IPs")
    
    total_analyzed = sum(r['total_requests'] for r in results)
    print(f"Total requests analyzed: {total_analyzed}")

if __name__ == "__main__":
    main()
