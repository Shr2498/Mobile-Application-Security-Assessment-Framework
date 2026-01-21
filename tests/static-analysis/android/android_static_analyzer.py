#!/usr/bin/env python3
"""
Android Static Analysis Tool
Part of Mobile Application Security Assessment Framework

This tool performs comprehensive static analysis of Android APK files
aligned with OWASP MASVS requirements.

Author: Security Assessment Framework
License: Educational Use Only
"""

import os
import sys
import json
import zipfile
import hashlib
import argparse
from pathlib import Path
from xml.etree import ElementTree as ET

class AndroidStaticAnalyzer:
    """
    Comprehensive Android APK Static Analysis Tool
    """
    
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        self.findings = {
            'basic_info': {},
            'security_findings': [],
            'masvs_compliance': {},
            'risk_score': 0
        }
        self.high_risk_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.CALL_PHONE',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR'
        ]
    
    def analyze(self):
        """
        Perform comprehensive APK analysis
        """
        print(f"[+] Starting static analysis of: {self.apk_path}")
        
        if not self.apk_path.exists():
            print(f"[-] APK file not found: {self.apk_path}")
            return None
        
        # Basic APK information
        self._extract_basic_info()
        
        # Security analysis
        self._analyze_permissions()
        self._analyze_components()
        self._analyze_manifest_security()
        self._analyze_code_patterns()
        self._check_masvs_compliance()
        
        # Calculate risk score
        self._calculate_risk_score()
        
        print(f"[+] Analysis complete. Risk Score: {self.findings['risk_score']}/100")
        return self.findings
    
    def _extract_basic_info(self):
        """Extract basic APK information"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # Get APK size and hash
                self.findings['basic_info']['file_size'] = self.apk_path.stat().st_size
                self.findings['basic_info']['md5_hash'] = self._calculate_hash(self.apk_path, 'md5')
                self.findings['basic_info']['sha256_hash'] = self._calculate_hash(self.apk_path, 'sha256')
                
                # List all files in APK
                file_list = apk.namelist()
                self.findings['basic_info']['total_files'] = len(file_list)
                
                # Check for native libraries
                native_libs = [f for f in file_list if f.startswith('lib/')]
                self.findings['basic_info']['native_libraries'] = len(native_libs)
                
                # Check for specific file types
                self.findings['basic_info']['dex_files'] = len([f for f in file_list if f.endswith('.dex')])
                self.findings['basic_info']['so_files'] = len([f for f in file_list if f.endswith('.so')])
                
        except Exception as e:
            self._add_finding("ERROR", f"Failed to extract basic info: {str(e)}")
    
    def _analyze_permissions(self):
        """Analyze AndroidManifest.xml permissions"""
        try:
            manifest_content = self._extract_manifest()
            if not manifest_content:
                return
            
            root = ET.fromstring(manifest_content)
            
            # Extract permissions
            permissions = []
            for perm in root.findall('.//uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                permissions.append(perm_name)
            
            self.findings['basic_info']['permissions'] = permissions
            self.findings['basic_info']['permission_count'] = len(permissions)
            
            # Check for high-risk permissions
            high_risk_found = []
            for perm in permissions:
                if perm in self.high_risk_permissions:
                    high_risk_found.append(perm)
                    self._add_finding("HIGH", 
                                    f"High-risk permission detected: {perm}",
                                    "MASVS-PLATFORM-1")
            
            if high_risk_found:
                self.findings['basic_info']['high_risk_permissions'] = high_risk_found
            
            # Check for dangerous permission combinations
            if 'android.permission.INTERNET' in permissions and 'android.permission.ACCESS_FINE_LOCATION' in permissions:
                self._add_finding("MEDIUM", 
                                "Dangerous permission combination: INTERNET + FINE_LOCATION",
                                "MASVS-PRIVACY-1")
            
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze permissions: {str(e)}")
    
    def _analyze_components(self):
        """Analyze Android components for security issues"""
        try:
            manifest_content = self._extract_manifest()
            if not manifest_content:
                return
            
            root = ET.fromstring(manifest_content)
            
            # Analyze activities
            exported_activities = []
            for activity in root.findall('.//activity'):
                exported = activity.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                name = activity.get('{http://schemas.android.com/apk/res/android}name', '')
                
                if exported.lower() == 'true':
                    exported_activities.append(name)
                    
                    # Check for intent filters on exported activities
                    intent_filters = activity.findall('.//intent-filter')
                    if intent_filters:
                        self._add_finding("MEDIUM", 
                                        f"Exported activity with intent filter: {name}",
                                        "MASVS-PLATFORM-11")
            
            # Analyze services
            exported_services = []
            for service in root.findall('.//service'):
                exported = service.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                name = service.get('{http://schemas.android.com/apk/res/android}name', '')
                
                if exported.lower() == 'true':
                    exported_services.append(name)
                    self._add_finding("HIGH", 
                                    f"Exported service detected: {name}",
                                    "MASVS-PLATFORM-11")
            
            # Analyze broadcast receivers
            exported_receivers = []
            for receiver in root.findall('.//receiver'):
                exported = receiver.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                name = receiver.get('{http://schemas.android.com/apk/res/android}name', '')
                
                if exported.lower() == 'true':
                    exported_receivers.append(name)
                    self._add_finding("MEDIUM", 
                                    f"Exported broadcast receiver: {name}",
                                    "MASVS-PLATFORM-11")
            
            self.findings['basic_info']['exported_components'] = {
                'activities': exported_activities,
                'services': exported_services,
                'receivers': exported_receivers
            }
            
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze components: {str(e)}")
    
    def _analyze_manifest_security(self):
        """Analyze manifest for security configurations"""
        try:
            manifest_content = self._extract_manifest()
            if not manifest_content:
                return
            
            root = ET.fromstring(manifest_content)
            
            # Check for debug mode
            application = root.find('.//application')
            if application is not None:
                debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
                if debuggable.lower() == 'true':
                    self._add_finding("HIGH", 
                                    "Application is debuggable in production",
                                    "MASVS-CODE-8")
                
                # Check for backup allowance
                backup_allowed = application.get('{http://schemas.android.com/apk/res/android}allowBackup', 'true')
                if backup_allowed.lower() == 'true':
                    self._add_finding("MEDIUM", 
                                    "Application allows backup - potential data leakage",
                                    "MASVS-STORAGE-8")
                
                # Check for network security config
                network_config = application.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
                if not network_config:
                    self._add_finding("MEDIUM", 
                                    "No network security configuration defined",
                                    "MASVS-NETWORK-1")
            
            # Check for exported content providers
            for provider in root.findall('.//provider'):
                exported = provider.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                if exported.lower() == 'true':
                    name = provider.get('{http://schemas.android.com/apk/res/android}name', '')
                    self._add_finding("HIGH", 
                                    f"Exported content provider: {name}",
                                    "MASVS-PLATFORM-11")
            
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze manifest security: {str(e)}")
    
    def _analyze_code_patterns(self):
        """Analyze APK for dangerous code patterns"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # Check for hardcoded strings in DEX files
                dex_files = [f for f in apk.namelist() if f.endswith('.dex')]
                
                for dex_file in dex_files:
                    dex_content = apk.read(dex_file)
                    
                    # Simple string pattern matching
                    dangerous_patterns = [
                        b'password',
                        b'api_key',
                        b'secret',
                        b'token',
                        b'private_key'
                    ]
                    
                    for pattern in dangerous_patterns:
                        if pattern in dex_content:
                            self._add_finding("HIGH", 
                                            f"Potential hardcoded credential pattern found: {pattern.decode()}",
                                            "MASVS-CRYPTO-1")
                
                # Check for unsafe protocols
                unsafe_protocols = [
                    b'http://',
                    b'ftp://',
                    b'telnet://'
                ]
                
                for dex_file in dex_files:
                    dex_content = apk.read(dex_file)
                    for protocol in unsafe_protocols:
                        if protocol in dex_content:
                            self._add_finding("MEDIUM", 
                                            f"Unsafe protocol usage detected: {protocol.decode()}",
                                            "MASVS-NETWORK-1")
                
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze code patterns: {str(e)}")
    
    def _check_masvs_compliance(self):
        """Check MASVS compliance based on findings"""
        masvs_categories = {
            'MASVS-STORAGE': 0,
            'MASVS-CRYPTO': 0,
            'MASVS-AUTH': 0,
            'MASVS-NETWORK': 0,
            'MASVS-PLATFORM': 0,
            'MASVS-CODE': 0,
            'MASVS-RESILIENCE': 0,
            'MASVS-PRIVACY': 0
        }
        
        # Count findings per MASVS category
        for finding in self.findings['security_findings']:
            if 'masvs_category' in finding:
                category = finding['masvs_category'].split('-')[0] + '-' + finding['masvs_category'].split('-')[1]
                if category in masvs_categories:
                    masvs_categories[category] += 1
        
        self.findings['masvs_compliance'] = masvs_categories
    
    def _calculate_risk_score(self):
        """Calculate overall risk score"""
        risk_score = 0
        
        # Base score adjustments
        for finding in self.findings['security_findings']:
            severity = finding['severity']
            if severity == 'HIGH':
                risk_score += 20
            elif severity == 'MEDIUM':
                risk_score += 10
            elif severity == 'LOW':
                risk_score += 5
        
        # Permission-based risk
        high_risk_perms = self.findings['basic_info'].get('high_risk_permissions', [])
        risk_score += len(high_risk_perms) * 5
        
        # Component export risk
        exported_components = self.findings['basic_info'].get('exported_components', {})
        total_exported = sum(len(v) for v in exported_components.values())
        risk_score += total_exported * 3
        
        # Cap at 100
        self.findings['risk_score'] = min(risk_score, 100)
    
    def _extract_manifest(self):
        """Extract AndroidManifest.xml from APK"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                # Try to read AndroidManifest.xml
                manifest_data = apk.read('AndroidManifest.xml')
                
                # Note: In real implementation, you'd need to decode binary XML
                # For now, assuming it's readable or using aapt tool
                return manifest_data
                
        except Exception as e:
            self._add_finding("ERROR", f"Failed to extract manifest: {str(e)}")
            return None
    
    def _calculate_hash(self, file_path, algorithm):
        """Calculate file hash"""
        hash_algo = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_algo.update(chunk)
        return hash_algo.hexdigest()
    
    def _add_finding(self, severity, description, masvs_category=None):
        """Add security finding"""
        finding = {
            'severity': severity,
            'description': description,
            'timestamp': self._get_timestamp()
        }
        
        if masvs_category:
            finding['masvs_category'] = masvs_category
        
        self.findings['security_findings'].append(finding)
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def generate_report(self, output_file=None):
        """Generate analysis report"""
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(self.findings, f, indent=2)
            print(f"[+] Report saved to: {output_file}")
        else:
            print("\n" + "="*60)
            print("ANDROID STATIC ANALYSIS REPORT")
            print("="*60)
            
            # Basic info
            print(f"\nAPK: {self.apk_path}")
            print(f"File Size: {self.findings['basic_info'].get('file_size', 'Unknown')} bytes")
            print(f"MD5: {self.findings['basic_info'].get('md5_hash', 'Unknown')}")
            print(f"SHA256: {self.findings['basic_info'].get('sha256_hash', 'Unknown')}")
            
            # Permissions
            permissions = self.findings['basic_info'].get('permissions', [])
            print(f"\nPermissions ({len(permissions)}):")
            for perm in permissions[:10]:  # Show first 10
                print(f"  - {perm}")
            if len(permissions) > 10:
                print(f"  ... and {len(permissions) - 10} more")
            
            # High-risk permissions
            high_risk = self.findings['basic_info'].get('high_risk_permissions', [])
            if high_risk:
                print(f"\nHigh-Risk Permissions:")
                for perm in high_risk:
                    print(f"  - {perm}")
            
            # Security findings
            findings = self.findings['security_findings']
            print(f"\nSecurity Findings ({len(findings)}):")
            
            severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'ERROR': 0}
            for finding in findings:
                severity = finding['severity']
                severity_counts[severity] += 1
                print(f"  [{severity}] {finding['description']}")
            
            print(f"\nSeverity Summary:")
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"  {severity}: {count}")
            
            # MASVS compliance
            print(f"\nMASVS Compliance Issues:")
            masvs_compliance = self.findings['masvs_compliance']
            for category, count in masvs_compliance.items():
                if count > 0:
                    print(f"  {category}: {count} issues")
            
            print(f"\nOverall Risk Score: {self.findings['risk_score']}/100")
            
            if self.findings['risk_score'] >= 70:
                print("  Risk Level: HIGH")
            elif self.findings['risk_score'] >= 40:
                print("  Risk Level: MEDIUM")
            else:
                print("  Risk Level: LOW")


def main():
    parser = argparse.ArgumentParser(description='Android APK Static Analysis Tool')
    parser.add_argument('apk_path', help='Path to APK file to analyze')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Perform analysis
    analyzer = AndroidStaticAnalyzer(args.apk_path)
    results = analyzer.analyze()
    
    if results:
        analyzer.generate_report(args.output)
    else:
        print("[-] Analysis failed")
        sys.exit(1)


if __name__ == "__main__":
    main()