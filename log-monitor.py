#!/usr/bin/env python3
"""
Real-time Apache Log Monitor
Updated to handle literal \x characters and support all analyzer options
"""

import time
import os
import re
from datetime import datetime
from collections import defaultdict, Counter

class ApacheLogMonitor:
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
        """Parse a log line with support for literal \x characters"""
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
            parts = line.split()
            if len(parts) < 7:
                return None
            
            ip = parts[0]
            
            timestamp_match = re.search(r'\[([^\]]+)\]', line)
            timestamp = timestamp_match.group(1) if timestamp_match else ''
            
            status = 400
            for part in parts:
                if part.isdigit() and len(part) == 3:
                    status = int(part)
                    break
            
            request_match = re.search(r'"([^"]*)"', line)
            request = request_match.group(1) if request_match else 'UNKNOWN'
            
            method = 'BINARY' if '\\x' in request else 'UNKNOWN'
            
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
        pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp, request, status, size, referer, user_agent = match.groups()
            
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
    
    def update_ip_activity(self, entry):
        """Update activity for an IP"""
        ip = entry['ip']
        activity = self.ip_activity[ip]
        
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
        """Analyze IP behavior - same scoring as main analyzer"""
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
            'binary_count': binary_count,
            'success_count': success,
            'error_count': errors,
            'unique_endpoints': len(activity['endpoints'])
        }

def monitor_log_file(logfile, log_format='combined', check_interval=5, 
                    min_score=0, filter_type='all', alert_only=True):
    """Monitor log file for new entries with filtering options"""
    monitor = ApacheLogMonitor()
    last_size = os.path.getsize(logfile) if os.path.exists(logfile) else 0
    
    print(f"🔍 Monitoring {logfile} for suspicious activity...")
    print(f"   Format: {log_format}, Check interval: {check_interval}s")
    print(f"   Filters: min_score={min_score}, filter_type={filter_type}, alert_only={alert_only}")
    print("Press Ctrl+C to stop monitoring")
    print("-" * 60)
    
    alert_count = 0
    total_processed = 0
    
    try:
        while True:
            current_size = os.path.getsize(logfile)
            
            if current_size > last_size:
                with open(logfile, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_size)
                    new_lines = f.read().splitlines()
                    
                    for line in new_lines:
                        if line.strip():
                            entry = monitor.parse_line(line, log_format)
                            if entry:
                                monitor.update_ip_activity(entry)
                                total_processed += 1
                                
                                # Analyze the IP
                                classification, details = monitor.analyze_ip(entry['ip'])
                                
                                # Apply filters
                                if filter_type != 'all':
                                    if filter_type == 'bot-high' and classification != 'BOT-HIGH':
                                        continue
                                    elif filter_type == 'bot-med' and classification not in ['BOT-HIGH', 'BOT-MED']:
                                        continue
                                    elif filter_type == 'suspicious' and classification not in ['BOT-HIGH', 'BOT-MED', 'SUSPICIOUS']:
                                        continue
                                    elif filter_type == 'human' and classification != 'HUMAN':
                                        continue
                                
                                if details['score'] < min_score:
                                    continue
                                
                                # Check if we should alert (either all or only suspicious+)
                                should_alert = not alert_only or classification in ['SUSPICIOUS', 'BOT-MED', 'BOT-HIGH']
                                
                                if should_alert:
                                    alert_count += 1
                                    print(f"\n🚨 ALERT #{alert_count} - {classification} 🚨")
                                    print(f"📡 IP: {entry['ip']}")
                                    print(f"📊 Score: {details['score']} | Requests: {details['requests']}")
                                    print(f"🌐 Request: {entry['method']} {entry['path'][:80]}...")
                                    print(f"📱 User-Agent: {entry.get('user_agent', 'N/A')[:60]}...")
                                    print(f"📟 Status: {entry['status']}")
                                    
                                    if details['indicators']:
                                        print("🔍 Indicators:")
                                        for indicator in details['indicators'][:3]:  # Show first 3
                                            print(f"   • {indicator}")
                                    
                                    print("-" * 50)
                
                last_size = current_size
            
            # Periodic summary
            if total_processed > 0 and total_processed % 100 == 0:
                print(f"\n📈 Summary: Processed {total_processed} requests, {alert_count} alerts")
            
            time.sleep(check_interval)
            
    except KeyboardInterrupt:
        print(f"\n\n📊 Monitoring stopped.")
        print(f"Final stats: {total_processed} requests processed, {alert_count} alerts triggered")
        print("Thank you for using Apache Log Monitor!")
    except Exception as e:
        print(f"❌ Error monitoring log: {e}")
        print("Attempting to restart monitoring in 10 seconds...")
        time.sleep(10)
        monitor_log_file(logfile, log_format, check_interval, min_score, filter_type, alert_only)

def print_summary(monitor, min_score=0, filter_type='all'):
    """Print a summary of current monitoring results"""
    results = []
    for ip in monitor.ip_activity:
        total = len(monitor.ip_activity[ip]['requests'])
        if total > 0:
            cls, details = monitor.analyze_ip(ip)
            
            if filter_type != 'all':
                if filter_type == 'bot-high' and cls != 'BOT-HIGH':
                    continue
                elif filter_type == 'bot-med' and cls not in ['BOT-HIGH', 'BOT-MED']:
                    continue
                elif filter_type == 'suspicious' and cls not in ['BOT-HIGH', 'BOT-MED', 'SUSPICIOUS']:
                    continue
                elif filter_type == 'human' and cls != 'HUMAN':
                    continue
            
            if details['score'] >= min_score:
                results.append({
                    'ip': ip,
                    'classification': cls,
                    'details': details,
                    'total_requests': total
                })
    
    if results:
        results.sort(key=lambda x: x['details']['score'], reverse=True)
        
        print(f"\n📋 Current Summary ({len(results)} IPs meeting criteria):")
        print(f"{'IP':<20} {'Type':<12} {'Requests':<10} {'Score':<6} {'Errors':<8}")
        print('-' * 60)
        
        for result in results:
            ip = result['ip']
            cls = result['classification']
            details = result['details']
            total = result['total_requests']
            
            print(f"{ip:<20} {cls:<12} {total:<10} {details['score']:<6} {details['error_count']:<8}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-time Apache log monitor')
    parser.add_argument('logfile', help='Log file to monitor')
    parser.add_argument('--format', choices=['standard', 'combined', 'poophole'], 
                       default='combined', help='Log format')
    parser.add_argument('--interval', type=int, default=5, help='Check interval in seconds')
    
    # NEW: All the filtering and alerting options
    parser.add_argument('--min-score', type=int, default=0, help='Minimum bot score to alert')
    parser.add_argument('--filter-type', choices=['all', 'bot-high', 'bot-med', 'suspicious', 'human'], 
                       default='all', help='Filter by classification')
    parser.add_argument('--alert-only', action='store_true', default=True,
                       help='Only show alerts for suspicious activity (default: True)')
    parser.add_argument('--show-all', action='store_false', dest='alert_only',
                       help='Show all traffic (disable alert-only mode)')
    parser.add_argument('--summary-interval', type=int, default=0,
                       help='Print summary every N seconds (0 to disable)')
    
    args = parser.parse_args()
    
    print("Apache Log Monitor - Real-time Bot Detection")
    print("=" * 50)
    
    monitor_log_file(
        logfile=args.logfile,
        log_format=args.format,
        check_interval=args.interval,
        min_score=args.min_score,
        filter_type=args.filter_type,
        alert_only=args.alert_only
    )