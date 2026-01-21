#!/usr/bin/env python3
"""
Mobile Network Traffic Analyzer
Part of Mobile Application Security Assessment Framework

This tool performs real-time network traffic analysis for mobile applications
aligned with OWASP MASVS network security requirements.

Author: Security Assessment Framework
License: Educational Use Only
"""

import json
import time
import argparse
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs
import base64

try:
    from mitmproxy import http, ctx
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    print("[!] mitmproxy not available. Install with: pip install mitmproxy")

class MobileTrafficAnalyzer:
    """
    Mobile Application Network Traffic Analyzer
    """
    
    def __init__(self, output_file: str = None):
        self.output_file = output_file
        self.session_data = {
            'session_id': self._generate_session_id(),
            'start_time': datetime.now().isoformat(),
            'requests': [],
            'security_findings': [],
            'statistics': {
                'total_requests': 0,
                'https_requests': 0,
                'http_requests': 0,
                'unique_hosts': set(),
                'suspicious_requests': 0
            }
        }
        
        # Patterns for sensitive data detection
        self.sensitive_patterns = {
            'password': re.compile(r'(password|pwd|pass)\s*[:=]\s*["\']?([^"\'\s&]+)', re.IGNORECASE),
            'api_key': re.compile(r'(api[_-]?key|apikey|key)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{10,})', re.IGNORECASE),
            'token': re.compile(r'(token|access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9._-]{10,})', re.IGNORECASE),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b')
        }
        
        # Known weak/insecure headers
        self.insecure_headers = {
            'X-Forwarded-For': 'Header may reveal internal network topology',
            'X-Real-IP': 'Header may expose real client IP',
            'Server': 'Header may reveal server information',
            'X-Powered-By': 'Header may reveal technology stack'
        }
        
        # Security headers that should be present
        self.security_headers = {
            'Content-Security-Policy': 'Missing CSP header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-XSS-Protection': 'Missing XSS protection header'
        }
    
    def request(self, flow: 'http.HTTPFlow') -> None:
        """Process HTTP request"""
        if not MITMPROXY_AVAILABLE:
            return
            
        request = flow.request
        self.session_data['statistics']['total_requests'] += 1
        
        # Track protocol usage
        if request.scheme == 'https':
            self.session_data['statistics']['https_requests'] += 1
        else:
            self.session_data['statistics']['http_requests'] += 1
            self._add_finding('HIGH', 
                            f'Unencrypted HTTP request to {request.pretty_host}',
                            'MASVS-NETWORK-1')
        
        # Track unique hosts
        self.session_data['statistics']['unique_hosts'].add(request.pretty_host)
        
        # Analyze request
        request_analysis = self._analyze_request(flow)
        self.session_data['requests'].append(request_analysis)
        
        # Real-time logging
        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
              f"{request.method} {request.scheme}://{request.pretty_host}{request.path}")
    
    def response(self, flow: 'http.HTTPFlow') -> None:
        """Process HTTP response"""
        if not MITMPROXY_AVAILABLE:
            return
            
        response = flow.response
        
        # Update the last request with response data
        if self.session_data['requests']:
            last_request = self.session_data['requests'][-1]
            last_request['response'] = self._analyze_response(flow)
        
        # Analyze response security
        self._analyze_response_security(flow)
    
    def _analyze_request(self, flow: 'http.HTTPFlow') -> Dict[str, Any]:
        """Analyze HTTP request for security issues"""
        request = flow.request
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'method': request.method,
            'url': request.pretty_url,
            'scheme': request.scheme,
            'host': request.pretty_host,
            'path': request.path,
            'headers': dict(request.headers),
            'content_length': len(request.content) if request.content else 0,
            'security_issues': []
        }
        
        # Analyze headers
        self._analyze_request_headers(request, analysis)
        
        # Analyze query parameters
        if request.query:
            analysis['query_params'] = dict(request.query)
            self._analyze_query_parameters(request, analysis)
        
        # Analyze request body
        if request.content:
            self._analyze_request_body(request, analysis)
        
        return analysis
    
    def _analyze_response(self, flow: 'http.HTTPFlow') -> Dict[str, Any]:
        """Analyze HTTP response"""
        response = flow.response
        
        analysis = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_length': len(response.content) if response.content else 0,
            'content_type': response.headers.get('content-type', ''),
            'security_issues': []
        }
        
        # Analyze response body for sensitive data
        if response.content:
            self._analyze_response_body(response, analysis)
        
        return analysis
    
    def _analyze_request_headers(self, request: 'http.HTTPRequest', analysis: Dict[str, Any]):
        """Analyze request headers for security issues"""
        headers = dict(request.headers)
        
        # Check for authentication headers
        auth_headers = ['authorization', 'x-api-key', 'x-auth-token']
        for header in auth_headers:
            if header in [h.lower() for h in headers.keys()]:
                analysis['security_issues'].append({
                    'type': 'INFO',
                    'message': f'Authentication header present: {header}',
                    'masvs_category': 'MASVS-AUTH'
                })
        
        # Check for user agent
        user_agent = headers.get('User-Agent', '')
        if not user_agent:
            analysis['security_issues'].append({
                'type': 'LOW',
                'message': 'No User-Agent header present',
                'masvs_category': 'MASVS-NETWORK'
            })
        elif len(user_agent) < 10:
            analysis['security_issues'].append({
                'type': 'MEDIUM',
                'message': 'Suspiciously short User-Agent header',
                'masvs_category': 'MASVS-NETWORK'
            })
        
        # Check for insecure headers
        for header_name, description in self.insecure_headers.items():
            if header_name in headers:
                analysis['security_issues'].append({
                    'type': 'MEDIUM',
                    'message': f'{description}: {header_name}',
                    'masvs_category': 'MASVS-NETWORK'
                })
    
    def _analyze_query_parameters(self, request: 'http.HTTPRequest', analysis: Dict[str, Any]):
        """Analyze query parameters for sensitive data"""
        query_params = dict(request.query)
        
        for param_name, param_value in query_params.items():
            # Check for sensitive parameter names
            if any(sensitive in param_name.lower() 
                   for sensitive in ['password', 'token', 'key', 'secret', 'auth']):
                analysis['security_issues'].append({
                    'type': 'HIGH',
                    'message': f'Sensitive parameter in URL: {param_name}',
                    'masvs_category': 'MASVS-NETWORK-1'
                })
            
            # Check for sensitive data in parameter values
            for pattern_name, pattern in self.sensitive_patterns.items():
                if pattern.search(str(param_value)):
                    analysis['security_issues'].append({
                        'type': 'HIGH',
                        'message': f'Potential {pattern_name} in query parameter: {param_name}',
                        'masvs_category': 'MASVS-NETWORK-1'
                    })
    
    def _analyze_request_body(self, request: 'http.HTTPRequest', analysis: Dict[str, Any]):
        """Analyze request body for sensitive data"""
        try:
            if request.content:
                content_str = request.content.decode('utf-8', errors='ignore')
                
                # Check content type
                content_type = request.headers.get('content-type', '').lower()
                
                if 'application/json' in content_type:
                    self._analyze_json_content(content_str, analysis, 'request')
                elif 'application/x-www-form-urlencoded' in content_type:
                    self._analyze_form_content(content_str, analysis, 'request')
                else:
                    self._analyze_generic_content(content_str, analysis, 'request')
                
        except Exception as e:
            analysis['security_issues'].append({
                'type': 'ERROR',
                'message': f'Failed to analyze request body: {str(e)}',
                'masvs_category': 'MASVS-NETWORK'
            })
    
    def _analyze_response_body(self, response: 'http.HTTPResponse', analysis: Dict[str, Any]):
        """Analyze response body for sensitive data leakage"""
        try:
            if response.content:
                content_str = response.content.decode('utf-8', errors='ignore')
                
                # Check for sensitive data patterns
                for pattern_name, pattern in self.sensitive_patterns.items():
                    matches = pattern.findall(content_str)
                    if matches:
                        analysis['security_issues'].append({
                            'type': 'HIGH',
                            'message': f'Potential {pattern_name} exposed in response',
                            'masvs_category': 'MASVS-NETWORK-1'
                        })
                
                # Check for error messages that might leak information
                error_patterns = [
                    r'stack trace',
                    r'exception',
                    r'sql error',
                    r'database error',
                    r'internal server error',
                    r'debug',
                    r'localhost'
                ]
                
                for error_pattern in error_patterns:
                    if re.search(error_pattern, content_str, re.IGNORECASE):
                        analysis['security_issues'].append({
                            'type': 'MEDIUM',
                            'message': f'Potential information disclosure: {error_pattern}',
                            'masvs_category': 'MASVS-PLATFORM'
                        })
                
        except Exception as e:
            analysis['security_issues'].append({
                'type': 'ERROR',
                'message': f'Failed to analyze response body: {str(e)}',
                'masvs_category': 'MASVS-NETWORK'
            })
    
    def _analyze_response_security(self, flow: 'http.HTTPFlow'):
        """Analyze response for security headers"""
        response = flow.response
        headers = dict(response.headers)
        
        # Check for missing security headers
        for header_name, description in self.security_headers.items():
            if header_name not in headers:
                self._add_finding('MEDIUM', 
                                f'{description} for {flow.request.pretty_host}',
                                'MASVS-NETWORK-2')
        
        # Check HSTS configuration
        hsts_header = headers.get('Strict-Transport-Security', '')
        if hsts_header:
            if 'max-age=' not in hsts_header:
                self._add_finding('MEDIUM', 
                                'HSTS header missing max-age directive',
                                'MASVS-NETWORK-2')
            elif int(re.search(r'max-age=(\d+)', hsts_header).group(1) if re.search(r'max-age=(\d+)', hsts_header) else '0') < 31536000:
                self._add_finding('LOW', 
                                'HSTS max-age is less than 1 year',
                                'MASVS-NETWORK-2')
        
        # Check Content-Type header
        content_type = headers.get('content-type', '')
        if not content_type and response.content:
            self._add_finding('LOW', 
                            'Response missing Content-Type header',
                            'MASVS-NETWORK-2')
    
    def _analyze_json_content(self, content: str, analysis: Dict[str, Any], request_type: str):
        """Analyze JSON content for sensitive data"""
        try:
            data = json.loads(content)
            self._analyze_dict_data(data, analysis, request_type)
        except json.JSONDecodeError:
            analysis['security_issues'].append({
                'type': 'LOW',
                'message': f'Invalid JSON in {request_type}',
                'masvs_category': 'MASVS-NETWORK'
            })
    
    def _analyze_form_content(self, content: str, analysis: Dict[str, Any], request_type: str):
        """Analyze form-encoded content for sensitive data"""
        try:
            # Parse form data
            form_data = parse_qs(content)
            for key, values in form_data.items():
                for value in values:
                    # Check for sensitive field names
                    if any(sensitive in key.lower() 
                           for sensitive in ['password', 'token', 'key', 'secret']):
                        analysis['security_issues'].append({
                            'type': 'HIGH',
                            'message': f'Sensitive field in {request_type}: {key}',
                            'masvs_category': 'MASVS-NETWORK-1'
                        })
        except Exception as e:
            analysis['security_issues'].append({
                'type': 'ERROR',
                'message': f'Failed to parse form data: {str(e)}',
                'masvs_category': 'MASVS-NETWORK'
            })
    
    def _analyze_dict_data(self, data: Dict[str, Any], analysis: Dict[str, Any], request_type: str):
        """Recursively analyze dictionary data for sensitive information"""
        if isinstance(data, dict):
            for key, value in data.items():
                # Check for sensitive keys
                if any(sensitive in key.lower() 
                       for sensitive in ['password', 'token', 'key', 'secret', 'auth']):
                    analysis['security_issues'].append({
                        'type': 'HIGH',
                        'message': f'Sensitive key in {request_type} JSON: {key}',
                        'masvs_category': 'MASVS-NETWORK-1'
                    })
                
                # Recursively check nested data
                if isinstance(value, (dict, list)):
                    self._analyze_dict_data(value, analysis, request_type)
                elif isinstance(value, str):
                    # Check string values for sensitive patterns
                    for pattern_name, pattern in self.sensitive_patterns.items():
                        if pattern.search(value):
                            analysis['security_issues'].append({
                                'type': 'HIGH',
                                'message': f'Potential {pattern_name} in {request_type} JSON value',
                                'masvs_category': 'MASVS-NETWORK-1'
                            })
                            
        elif isinstance(data, list):
            for item in data:
                self._analyze_dict_data(item, analysis, request_type)
    
    def _analyze_generic_content(self, content: str, analysis: Dict[str, Any], request_type: str):
        """Analyze generic content for sensitive patterns"""
        # Check for sensitive data patterns
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(content)
            if matches:
                analysis['security_issues'].append({
                    'type': 'HIGH',
                    'message': f'Potential {pattern_name} in {request_type} content',
                    'masvs_category': 'MASVS-NETWORK-1'
                })
    
    def _add_finding(self, severity: str, message: str, masvs_category: str = None):
        """Add security finding to session data"""
        finding = {
            'severity': severity,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        
        if masvs_category:
            finding['masvs_category'] = masvs_category
        
        self.session_data['security_findings'].append(finding)
        self.session_data['statistics']['suspicious_requests'] += 1
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    def save_session(self):
        """Save session data to file"""
        # Convert set to list for JSON serialization
        self.session_data['statistics']['unique_hosts'] = list(self.session_data['statistics']['unique_hosts'])
        self.session_data['end_time'] = datetime.now().isoformat()
        
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(self.session_data, f, indent=2)
            print(f"[+] Session data saved to: {self.output_file}")
        
        return self.session_data
    
    def generate_report(self):
        """Generate analysis report"""
        stats = self.session_data['statistics']
        findings = self.session_data['security_findings']
        
        print("\n" + "="*60)
        print("MOBILE NETWORK TRAFFIC ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nSession ID: {self.session_data['session_id']}")
        print(f"Analysis Duration: {self.session_data['start_time']} - {datetime.now().isoformat()}")
        
        print(f"\nTraffic Statistics:")
        print(f"  Total Requests: {stats['total_requests']}")
        print(f"  HTTPS Requests: {stats['https_requests']}")
        print(f"  HTTP Requests: {stats['http_requests']}")
        print(f"  Unique Hosts: {len(stats['unique_hosts'])}")
        print(f"  Suspicious Requests: {stats['suspicious_requests']}")
        
        if stats['total_requests'] > 0:
            https_percentage = (stats['https_requests'] / stats['total_requests']) * 100
            print(f"  HTTPS Usage: {https_percentage:.1f}%")
        
        print(f"\nUnique Hosts Contacted:")
        for host in sorted(stats['unique_hosts']):
            print(f"  - {host}")
        
        print(f"\nSecurity Findings ({len(findings)}):")
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'ERROR': 0}
        
        for finding in findings:
            severity = finding['severity']
            severity_counts[severity] += 1
            print(f"  [{severity}] {finding['message']}")
        
        print(f"\nSeverity Summary:")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"  {severity}: {count}")
        
        # MASVS category analysis
        masvs_categories = {}
        for finding in findings:
            if 'masvs_category' in finding:
                category = finding['masvs_category'].split('-')[0] + '-' + finding['masvs_category'].split('-')[1]
                masvs_categories[category] = masvs_categories.get(category, 0) + 1
        
        if masvs_categories:
            print(f"\nMASVS Category Breakdown:")
            for category, count in sorted(masvs_categories.items()):
                print(f"  {category}: {count} issues")
        
        # Risk assessment
        risk_score = (severity_counts['HIGH'] * 20 + 
                     severity_counts['MEDIUM'] * 10 + 
                     severity_counts['LOW'] * 5)
        
        # Adjust for HTTP usage
        if stats['total_requests'] > 0:
            http_penalty = (stats['http_requests'] / stats['total_requests']) * 30
            risk_score += http_penalty
        
        risk_score = min(risk_score, 100)
        
        print(f"\nNetwork Security Risk Score: {risk_score:.1f}/100")
        
        if risk_score >= 70:
            print("  Risk Level: HIGH")
        elif risk_score >= 40:
            print("  Risk Level: MEDIUM")
        else:
            print("  Risk Level: LOW")


def run_mitm_proxy(analyzer: MobileTrafficAnalyzer, port: int = 8080):
    """Run mitmproxy with the analyzer"""
    if not MITMPROXY_AVAILABLE:
        print("[-] mitmproxy not available. Cannot run proxy.")
        return
    
    options = Options(listen_port=port)
    master = DumpMaster(options)
    
    # Add analyzer as addon
    master.addons.add(analyzer)
    
    try:
        print(f"[+] Starting proxy on port {port}")
        print(f"[+] Configure mobile device to use proxy: 127.0.0.1:{port}")
        print("[+] Press Ctrl+C to stop analysis")
        
        master.run()
    except KeyboardInterrupt:
        print("\n[+] Analysis stopped by user")
    finally:
        analyzer.save_session()
        analyzer.generate_report()


def main():
    parser = argparse.ArgumentParser(description='Mobile Network Traffic Analyzer')
    parser.add_argument('-p', '--port', type=int, default=8080, 
                       help='Proxy port (default: 8080)')
    parser.add_argument('-o', '--output', 
                       help='Output file for session data')
    parser.add_argument('-r', '--report-only', 
                       help='Generate report from existing session file')
    
    args = parser.parse_args()
    
    if args.report_only:
        # Load and generate report from existing session
        try:
            with open(args.report_only, 'r') as f:
                session_data = json.load(f)
            
            analyzer = MobileTrafficAnalyzer()
            analyzer.session_data = session_data
            analyzer.generate_report()
            
        except Exception as e:
            print(f"[-] Failed to load session file: {str(e)}")
            sys.exit(1)
    else:
        # Start live analysis
        analyzer = MobileTrafficAnalyzer(args.output)
        run_mitm_proxy(analyzer, args.port)


if __name__ == "__main__":
    main()