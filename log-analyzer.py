#!/usr/bin/env python3
"""
Apache Log Analyzer - Distinguishes between real users and bots
Clean version without problematic escape sequences
"""

import re
import sys
import argparse
from collections import defaultdict, Counter
from datetime import datetime

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
        
        # Bot indicators - using raw strings for patterns
        self.bot_indicators = {
            'suspicious_user_agents': [
                'bot', 'crawler', 'spider', 'scanner', 'nmap', 'sqlmap',
                'nikto', 'wget', 'curl', 'python', 'java', 'go-http-client',
                'zgrab', 'masscan', 'nessus', 'metasploit', 'acunetix',
                'burp', 'dirbuster', 'gobuster', 'arachni', 'openvas'
            ],
            'suspicious_paths': [
                r'/(admin|administrator|phpmyadmin|mysql|wp-admin|\.git|\.env|backup)',
                r'\.(php|asp|jsp|py|sh|pl)(\.|$)',
                r'(union|select|insert|update|delete|drop|exec)',
                r'(etc/passwd|proc/self|\.\./\.\./)'
            ]
        }
    
    def parse_line(self, line, log_format):
        """Parse a log line"""
        try:
            if log_format == 'combined':
                return self.parse_combined(line)
            elif log_format == 'poophole':
                return self.parse_poophole(line)
            else:
                return self.parse_standard(line)
        except Exception:
            return self.parse_fallback(line)
    
    def parse_fallback(self, line):
        """Fallback parser for problematic lines"""
        try:
            # Extract basic fields using simple parsing
            parts = line.split()
            if len(parts) < 7:
                return None
            
            ip = parts[0]
            
            # Find timestamp between brackets
            timestamp_match = re.search(r'\[([^\]]+)\]', line)
            timestamp = timestamp_match.group(1) if timestamp_match else ''
            
            # Find status code
            status = 400
            for part in parts:
                if part.isdigit() and len(part) == 3:
                    status = int(part)
                    break
            
            # Extract request between quotes
            request_match = re.search(r'"([^"]*)"', line)
            request = request_match.group(1) if request_match else 'UNKNOWN'
            
            # Check for binary patterns
            method = 'BINARY' if '\\x' in request else 'UNKNOWN'
            
            # Extract user agent
            quotes = re.findall(r'"([^"]*)"', line)
            user_agent = quotes[-1] if quotes else ''
            referer = quotes[-2] if len(quotes) >= 2 else ''
            
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'path': request,
                'protocol': 'UNKNOWN',
                'status': status,
                'size': '0',
                'referer': referer,
                'user_agent': user_agent,
                'malformed': True
            }
        except:
            return None
    
    def parse_combined(self, line):
        """Parse combined log format"""
        # Flexible pattern for combined format
        pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp, request, status, size, referer, user_agent = match.groups()
            
            # Handle binary requests
            if '\\x' in request:
                method = 'BINARY'
                path = request
                protocol = 'UNKNOWN'
            else:
                method, path, protocol = self.parse_http_request(request)
            
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
                'malformed': False
            }
        
        return self.parse_fallback(line)
    
    def parse_standard(self, line):
        """Parse standard log format"""
        pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\S+)'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp, request, status, size = match.groups()
            
            if '\\x' in request:
                method = 'BINARY'
                path = request
                protocol = 'UNKNOWN'
            else:
                method, path, protocol = self.parse_http_request(request)
            
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'path': path,
                'protocol': protocol,
                'status': int(status),
                'size': size if size != '-' else '0',
                'referer': '',
                'user_agent': '',
                'malformed': False
            }
        
        return self.parse_fallback(line)
    
    def parse_poophole(self, line):
        """Parse poophole custom format"""
        pattern = r'^\[([^\]]+)\]\s+(\S+)\s+\S+:\d+\s+\S+\s+"([^"]*)"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"\s+(\S+)'
        match = re.match(pattern, line)
        
        if match:
            timestamp, ip, request, status, size, referer, user_agent, host = match.groups()
            
            if '\\x' in request:
                method = 'BINARY'
                path = request
                protocol = 'UNKNOWN'
            else:
                method, path, protocol = self.parse_http_request(request)
            
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
                'host': host,
                'malformed': False
            }
        
        return self.parse_fallback(line)
    
    def parse_http_request(self, request):
        """Parse normal HTTP request line"""
        if not request or request == '-':
            return 'UNKNOWN', '/', 'HTTP/1.0'
        
        parts = request.split(' ', 2)
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            return parts[0], parts[1], 'HTTP/1.0'
        elif len(parts) == 1:
            return parts[0], '/', 'HTTP/1.0'
        else:
            return 'MALFORMED', request, 'UNKNOWN'
    
    def process_log_file(self, filename, log_format='combined'):
        """Process the log file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                parsed = 0
                errors = 0
                
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    entry = self.parse_line(line, log_format)
                    if entry:
                        self.update_ip_activity(entry)
                        parsed += 1
                    else:
                        errors += 1
                        if errors <= 5:
                            print(f"Parse error line {line_num}: {line[:80]}...")
                
                print(f"Parsed: {parsed}, Errors: {errors}")
                return True
                
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    def update_ip_activity(self, entry):
        """Update activity for an IP"""
        ip = entry['ip']
        activity = self.ip_activity[ip]
        
        # Parse timestamp
        try:
            ts = entry['timestamp']
            if ts:
                if ':' in ts.split()[0]:
                    ts = ts.replace(':', ' ', 1)
                    dt = datetime.strptime(ts, '%d/%b/%Y %H:%M:%S %z')
                else:
                    dt = datetime.strptime(ts, '%a %b %d %H:%M:%S %Y')
                
                if not activity['first_seen'] or dt < activity['first_seen']:
                    activity['first_seen'] = dt
                if not activity['last_seen'] or dt > activity['last_seen']:
                    activity['last_seen'] = dt
        except:
            pass
        
        activity['status_codes'][entry['status']] += 1
        activity['user_agents'][entry.get('user_agent', '')] += 1
        activity['endpoints'][entry['path']] += 1
        activity['requests'].append(entry)
    
    def analyze_ip(self, ip):
        """Analyze IP behavior"""
        activity = self.ip_activity[ip]
        total = len(activity['requests'])
        
        if total == 0:
            return 'UNKNOWN', {}
        
        score = 0
        indicators = []
        
        # Binary requests are highly suspicious
        binary_count = sum(1 for r in activity['requests'] if r['method'] == 'BINARY' or r.get('malformed'))
        if binary_count > 0:
            score += 5
            indicators.append(f"Binary requests: {binary_count}")
        
        # User agent analysis
        ua = max(activity['user_agents'].items(), key=lambda x: x[1])[0] if activity['user_agents'] else ''
        if ua:
            for pattern in self.bot_indicators['suspicious_user_agents']:
                if pattern.lower() in ua.lower():
                    score += 3
                    indicators.append(f"Bot-like UA: {ua[:40]}...")
                    break
        
        # Status code patterns
        if activity['status_codes'][404] > 10:
            score += 2
            indicators.append(f"Many 404s: {activity['status_codes'][404]}")
        
        if activity['status_codes'][403] > 5:
            score += 2
            indicators.append(f"Many 403s: {activity['status_codes'][403]}")
        
        # Error ratio
        success = activity['status_codes'][200] + activity['status_codes'][301] + activity['status_codes'][302]
        errors = activity['status_codes'][404] + activity['status_codes'][403] + activity['status_codes'][500]
        
        if errors > 0 and success == 0:
            score += 3
            indicators.append("No successful requests")
        elif errors > success * 2 and errors > 5:
            score += 2
            indicators.append("High error rate")
        
        # Request frequency
        if activity['first_seen'] and activity['last_seen']:
            secs = (activity['last_seen'] - activity['first_seen']).total_seconds()
            if secs > 0 and total / secs > 2:
                score += 2
                indicators.append("High frequency")
        
        # Path analysis
        for path in activity['endpoints']:
            if '\\x' in path:
                score += 3
                indicators.append("Binary data in paths")
                break
            
            for pattern in self.bot_indicators['suspicious_paths']:
                if re.search(pattern, path, re.IGNORECASE):
                    score += 2
                    indicators.append(f"Suspicious path: {path[:40]}...")
                    break
        
        # Classification
        if score >= 8:
            cls = "BOT-HIGH"
        elif score >= 5:
            cls = "BOT-MED"
        elif score >= 3:
            cls = "SUSPICIOUS"
        else:
            cls = "HUMAN"
        
        return cls, {
            'score': score,
            'indicators': indicators,
            'requests': total,
            'status_codes': dict(activity['status_codes']),
            'binary_count': binary_count
        }

def main():
    parser = argparse.ArgumentParser(description='Apache log analyzer')
    parser.add_argument('logfile', help='Log file path')
    parser.add_argument('--format', choices=['standard', 'combined', 'poophole'], default='combined')
    parser.add_argument('--min-req', type=int, default=1, help='Minimum requests')
    parser.add_argument('--output', choices=['summary', 'detailed'], default='summary')
    
    args = parser.parse_args()
    
    analyzer = ApacheLogAnalyzer()
    print(f"Analyzing {args.logfile}...")
    
    if not analyzer.process_log_file(args.logfile, args.format):
        sys.exit(1)
    
    results = []
    for ip in analyzer.ip_activity:
        total = len(analyzer.ip_activity[ip]['requests'])
        if total >= args.min_req:
            cls, details = analyzer.analyze_ip(ip)
            results.append((ip, cls, details, total))
    
    results.sort(key=lambda x: x[3], reverse=True)
    
    print(f"\n{'IP':<20} {'Type':<12} {'Requests':<10} Score")
    print('-' * 60)
    
    for ip, cls, details, total in results:
        print(f"{ip:<20} {cls:<12} {total:<10} {details['score']}")
        
        if args.output == 'detailed' and details['indicators']:
            for ind in details['indicators']:
                print(f"   {ind}")
            print(f"   Status: {details['status_codes']}")
            print()

if __name__ == "__main__":
    main()
