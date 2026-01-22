#!/usr/bin/env python3
"""
iOS Static Analysis Tool
Part of Mobile Application Security Assessment Framework

This tool performs comprehensive static analysis of iOS IPA files
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
import plistlib
from pathlib import Path
from typing import Dict, List, Any

class iOSStaticAnalyzer:
    """
    Comprehensive iOS IPA Static Analysis Tool
    """
    
    def __init__(self, ipa_path: str):
        self.ipa_path = Path(ipa_path)
        self.findings = {
            'basic_info': {},
            'security_findings': [],
            'masvs_compliance': {},
            'risk_score': 0
        }
        self.sensitive_entitlements = [
            'com.apple.developer.healthkit',
            'com.apple.developer.homekit',
            'com.apple.developer.siri',
            'com.apple.security.application-groups',
            'keychain-access-groups',
            'com.apple.developer.networking.networkextension',
            'com.apple.external-accessory.wireless-configuration'
        ]
        
        self.dangerous_apis = [
            'CC_MD5',
            'CC_SHA1',
            'kSecAttrAccessibleAlways',
            'kSecAttrAccessibleAlwaysThisDeviceOnly',
            'SecRandomCopyBytes',
            'arc4random',
            'NSURLConnection',
            'allowsAnyHTTPSCertificate',
            'setAllowsAnyHTTPSCertificate',
            'canAuthenticateAgainstProtectionSpace',
            'continueWithoutCredentialForAuthenticationChallenge',
            'kCFStreamSSLAllowsExpiredCertificates',
            'kCFStreamSSLAllowsAnyRoot',
            'kCFStreamSSLValidatesCertificateChain',
            'NSURLSessionConfiguration',
            'URLSession:didReceiveChallenge:completionHandler'
        ]
        
        self.weak_crypto_patterns = [
            'DES_',
            'RC4_',
            'MD5',
            'SHA1',
            'ECB',
            'kSecAttrKeyTypeRC',
            'kCCAlgorithmDES',
            'kCCAlgorithmRC4'
        ]
        
        self.file_protection_levels = [
            'NSFileProtectionNone',
            'NSFileProtectionComplete',
            'NSFileProtectionCompleteUnlessOpen',
            'NSFileProtectionCompleteUntilFirstUserAuthentication'
            'NSAllowsArbitraryLoads',
            'sqlite3_exec'
        ]
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform comprehensive IPA analysis
        """
        print(f"[+] Starting iOS static analysis of: {self.ipa_path}")
        
        if not self.ipa_path.exists():
            print(f"[-] IPA file not found: {self.ipa_path}")
            return None
        
        # Basic IPA information
        self._extract_basic_info()
        
        # Security analysis
        self._analyze_plist_configuration()
        self._analyze_entitlements()
        self._analyze_url_schemes()
        self._analyze_network_security()
        self._analyze_binary_security()
        self._check_code_signing()
        self._check_masvs_compliance()
        
        # Calculate risk score
        self._calculate_risk_score()
        
        print(f"[+] Analysis complete. Risk Score: {self.findings['risk_score']}/100")
        return self.findings
    
    def _extract_basic_info(self):
        """Extract basic IPA information"""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                # Get IPA size and hash
                self.findings['basic_info']['file_size'] = self.ipa_path.stat().st_size
                self.findings['basic_info']['md5_hash'] = self._calculate_hash(self.ipa_path, 'md5')
                self.findings['basic_info']['sha256_hash'] = self._calculate_hash(self.ipa_path, 'sha256')
                
                # List all files in IPA
                file_list = ipa.namelist()
                self.findings['basic_info']['total_files'] = len(file_list)
                
                # Find app bundle
                app_bundle = None
                for file_path in file_list:
                    if file_path.endswith('.app/'):
                        app_bundle = file_path
                        break
                
                self.findings['basic_info']['app_bundle'] = app_bundle
                
                # Check for specific file types
                self.findings['basic_info']['plist_files'] = len([f for f in file_list if f.endswith('.plist')])
                self.findings['basic_info']['dylib_files'] = len([f for f in file_list if f.endswith('.dylib')])
                self.findings['basic_info']['framework_files'] = len([f for f in file_list if '.framework/' in f])
                
        except Exception as e:
            self._add_finding("ERROR", f"Failed to extract basic info: {str(e)}")
    
    def _analyze_plist_configuration(self):
        """Analyze Info.plist configuration"""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                # Find Info.plist
                plist_path = None
                for file_path in ipa.namelist():
                    if file_path.endswith('Info.plist'):
                        plist_path = file_path
                        break
                
                if not plist_path:
                    self._add_finding("ERROR", "Info.plist not found in IPA")
                    return
                
                # Read and parse plist
                plist_data = ipa.read(plist_path)
                plist = plistlib.loads(plist_data)
                
                # Extract basic app information
                self.findings['basic_info']['bundle_id'] = plist.get('CFBundleIdentifier', '')
                self.findings['basic_info']['app_version'] = plist.get('CFBundleVersion', '')
                self.findings['basic_info']['display_name'] = plist.get('CFBundleDisplayName', '')
                self.findings['basic_info']['minimum_os'] = plist.get('MinimumOSVersion', '')
                
                # Check for security-relevant configurations
                self._check_ats_configuration(plist)
                self._check_background_modes(plist)
                self._check_permissions(plist)
                
                # Store full plist for further analysis
                self.findings['basic_info']['info_plist'] = plist
                
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze Info.plist: {str(e)}")
    
    def _check_ats_configuration(self, plist: Dict[str, Any]):
        """Check App Transport Security configuration"""
        ats_config = plist.get('NSAppTransportSecurity', {})
        
        if not ats_config:
            self._add_finding("MEDIUM", 
                            "No App Transport Security configuration found",
                            "MASVS-NETWORK-1")
            return
        
        # Check for global ATS bypass
        if ats_config.get('NSAllowsArbitraryLoads', False):
            self._add_finding("HIGH", 
                            "App Transport Security globally disabled",
                            "MASVS-NETWORK-1")
        
        # Check for local network bypass
        if ats_config.get('NSAllowsLocalNetworking', False):
            self._add_finding("MEDIUM", 
                            "ATS allows local networking",
                            "MASVS-NETWORK-1")
        
        # Check domain-specific exceptions
        domain_exceptions = ats_config.get('NSExceptionDomains', {})
        for domain, config in domain_exceptions.items():
            if config.get('NSExceptionAllowsInsecureHTTPLoads', False):
                self._add_finding("HIGH", 
                                f"Insecure HTTP allowed for domain: {domain}",
                                "MASVS-NETWORK-1")
            
            if config.get('NSExceptionMinimumTLSVersion') in ['TLSv1.0', 'TLSv1.1']:
                self._add_finding("HIGH", 
                                f"Weak TLS version allowed for domain: {domain}",
                                "MASVS-NETWORK-1")
    
    def _check_background_modes(self, plist: Dict[str, Any]):
        """Check background execution modes"""
        background_modes = plist.get('UIBackgroundModes', [])
        
        sensitive_modes = [
            'background-processing',
            'background-fetch',
            'location',
            'voip',
            'external-accessory',
            'bluetooth-central'
        ]
        
        for mode in background_modes:
            if mode in sensitive_modes:
                self._add_finding("MEDIUM", 
                                f"Sensitive background mode enabled: {mode}",
                                "MASVS-PLATFORM-1")
    
    def _check_permissions(self, plist: Dict[str, Any]):
        """Check usage description strings for permissions"""
        permission_keys = [
            'NSCameraUsageDescription',
            'NSMicrophoneUsageDescription',
            'NSLocationWhenInUseUsageDescription',
            'NSLocationAlwaysUsageDescription',
            'NSContactsUsageDescription',
            'NSCalendarsUsageDescription',
            'NSRemindersUsageDescription',
            'NSPhotoLibraryUsageDescription',
            'NSHealthShareUsageDescription',
            'NSHealthUpdateUsageDescription',
            'NSMotionUsageDescription',
            'NSBluetoothPeripheralUsageDescription',
            'NSFaceIDUsageDescription'
        ]
        
        requested_permissions = []
        for key in permission_keys:
            if key in plist:
                permission_name = key.replace('Usage', '').replace('NS', '').replace('Description', '')
                requested_permissions.append(permission_name)
                
                # Check if description is meaningful
                description = plist[key]
                if len(description.strip()) < 10:
                    self._add_finding("MEDIUM", 
                                    f"Vague permission description for {permission_name}",
                                    "MASVS-PRIVACY-1")
        
        self.findings['basic_info']['requested_permissions'] = requested_permissions
        
        # Check for sensitive permission combinations
        if 'Camera' in requested_permissions and 'Location' in requested_permissions:
            self._add_finding("HIGH", 
                            "Dangerous permission combination: Camera + Location",
                            "MASVS-PRIVACY-1")
    
    def _analyze_entitlements(self):
        """Analyze entitlements.plist if present"""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                # Look for entitlements
                entitlements_paths = [f for f in ipa.namelist() if 'entitlements' in f.lower()]
                
                if not entitlements_paths:
                    self._add_finding("INFO", "No entitlements file found")
                    return
                
                for ent_path in entitlements_paths:
                    try:
                        ent_data = ipa.read(ent_path)
                        entitlements = plistlib.loads(ent_data)
                        
                        self.findings['basic_info']['entitlements'] = entitlements
                        
                        # Check for sensitive entitlements
                        for sensitive_ent in self.sensitive_entitlements:
                            if sensitive_ent in entitlements:
                                self._add_finding("MEDIUM", 
                                                f"Sensitive entitlement found: {sensitive_ent}",
                                                "MASVS-PLATFORM-1")
                        
                        # Check for debugging entitlements
                        if entitlements.get('get-task-allow', False):
                            self._add_finding("HIGH", 
                                            "Debugging entitlement enabled in production",
                                            "MASVS-CODE-8")
                        
                        # Check keychain access groups
                        keychain_groups = entitlements.get('keychain-access-groups', [])
                        if keychain_groups:
                            self.findings['basic_info']['keychain_groups'] = keychain_groups
                            if '*' in keychain_groups:
                                self._add_finding("HIGH", 
                                                "Wildcard keychain access group",
                                                "MASVS-STORAGE-1")
                    
                    except Exception as e:
                        self._add_finding("ERROR", f"Failed to parse entitlements: {str(e)}")
                        
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze entitlements: {str(e)}")
    
    def _analyze_url_schemes(self):
        """Analyze custom URL schemes"""
        try:
            plist = self.findings['basic_info'].get('info_plist', {})
            url_types = plist.get('CFBundleURLTypes', [])
            
            custom_schemes = []
            for url_type in url_types:
                schemes = url_type.get('CFBundleURLSchemes', [])
                for scheme in schemes:
                    if scheme.lower() not in ['http', 'https', 'ftp', 'mailto']:
                        custom_schemes.append(scheme)
                        
                        # Check for weak URL scheme validation
                        if len(scheme) < 8:  # Simple heuristic
                            self._add_finding("MEDIUM", 
                                            f"Weak URL scheme (short): {scheme}",
                                            "MASVS-PLATFORM-3")
            
            if custom_schemes:
                self.findings['basic_info']['custom_url_schemes'] = custom_schemes
                
                # Check for common scheme names that might be hijackable
                common_weak_schemes = ['app', 'myapp', 'mobile', 'ios']
                for scheme in custom_schemes:
                    if any(weak in scheme.lower() for weak in common_weak_schemes):
                        self._add_finding("HIGH", 
                                        f"Potentially hijackable URL scheme: {scheme}",
                                        "MASVS-PLATFORM-3")
                        
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze URL schemes: {str(e)}")
    
    def _analyze_network_security(self):
        """Analyze network security configuration"""
        try:
            plist = self.findings['basic_info'].get('info_plist', {})
            
            # Check for explicit HTTP domains in plist
            ats_exceptions = plist.get('NSAppTransportSecurity', {}).get('NSExceptionDomains', {})
            
            # Look for hardcoded URLs in binary (simplified check)
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                binary_files = [f for f in ipa.namelist() if not f.endswith('/') 
                               and not f.endswith('.plist') 
                               and not f.endswith('.png')
                               and not f.endswith('.jpg')]
                
                for binary_file in binary_files[:5]:  # Check first 5 binary files
                    try:
                        content = ipa.read(binary_file)
                        
                        # Look for HTTP URLs
                        if b'http://' in content:
                            self._add_finding("MEDIUM", 
                                            f"HTTP URL found in binary: {binary_file}",
                                            "MASVS-NETWORK-1")
                        
                        # Look for weak TLS configurations
                        weak_ssl_configs = [
                            b'kSSLProtocol3',
                            b'kTLSProtocol1',
                            b'kTLSProtocol11'
                        ]
                        
                        for weak_config in weak_ssl_configs:
                            if weak_config in content:
                                self._add_finding("HIGH", 
                                                f"Weak SSL/TLS configuration in {binary_file}",
                                                "MASVS-NETWORK-1")
                                break
                    
                    except:
                        continue  # Skip binary files that can't be read
                        
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze network security: {str(e)}")
    
    def _analyze_binary_security(self):
        """Analyze binary security features"""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                # Find main binary
                main_binary = None
                for file_path in ipa.namelist():
                    if file_path.endswith('.app/') and not '/' in file_path[:-5]:
                        app_name = file_path.split('.app')[0].split('/')[-1]
                        binary_path = file_path + app_name
                        if binary_path in ipa.namelist():
                            main_binary = binary_path
                            break
                
                if not main_binary:
                    self._add_finding("ERROR", "Main binary not found")
                    return
                
                self.findings['basic_info']['main_binary'] = main_binary
                
                # Read binary for analysis
                binary_data = ipa.read(main_binary)
                
                # Check for stack canaries (simplified)
                if b'__stack_chk_fail' in binary_data:
                    self._add_finding("INFO", "Stack canaries detected")
                else:
                    self._add_finding("MEDIUM", 
                                    "No stack canaries detected",
                                    "MASVS-CODE-9")
                
                # Check for PIE (Position Independent Executable)
                # This is a simplified check - real implementation would parse Mach-O headers
                if b'PIE' in binary_data[:1000]:  # Check first 1KB for PIE references
                    self._add_finding("INFO", "PIE (ASLR) enabled")
                
                # Look for debugging symbols
                if b'DWARF' in binary_data or b'.debug_' in binary_data:
                    self._add_finding("MEDIUM", 
                                    "Debug symbols present in binary",
                                    "MASVS-CODE-8")
                
                # Check for dangerous API usage
                for api in self.dangerous_apis:
                    if api.encode() in binary_data:
                        if api in ['CC_MD5', 'CC_SHA1']:
                            self._add_finding("HIGH", 
                                            f"Weak cryptographic function detected: {api}",
                                            "MASVS-CRYPTO-4")
                        elif 'kSecAttrAccessibleAlways' in api:
                            self._add_finding("HIGH", 
                                            f"Insecure keychain accessibility: {api}",
                                            "MASVS-STORAGE-1")
                        else:
                            self._add_finding("MEDIUM", 
                                            f"Potentially dangerous API detected: {api}",
                                            "MASVS-CODE-8")
                
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze binary security: {str(e)}")
    
    def _check_code_signing(self):
        """Check code signing status"""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                # Look for code signature files
                codesign_files = [f for f in ipa.namelist() if '_CodeSignature' in f]
                
                if not codesign_files:
                    self._add_finding("HIGH", 
                                    "No code signature found",
                                    "MASVS-CODE-8")
                else:
                    self._add_finding("INFO", f"Code signature files found: {len(codesign_files)}")
                
                # Check for provisioning profile
                provisioning_profiles = [f for f in ipa.namelist() if f.endswith('.mobileprovision')]
                
                if provisioning_profiles:
                    self.findings['basic_info']['provisioning_profiles'] = provisioning_profiles
                    
                    # Basic provisioning profile analysis
                    for profile_path in provisioning_profiles:
                        try:
                            profile_data = ipa.read(profile_path)
                            if b'aps-environment' in profile_data:
                                if b'development' in profile_data:
                                    self._add_finding("MEDIUM", 
                                                    "Development provisioning profile in production",
                                                    "MASVS-CODE-8")
                        except:
                            continue
                            
        except Exception as e:
            self._add_finding("ERROR", f"Failed to check code signing: {str(e)}")
    
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
        permissions = self.findings['basic_info'].get('requested_permissions', [])
        sensitive_permissions = ['Camera', 'Location', 'Contacts', 'Health']
        sensitive_count = sum(1 for perm in permissions if any(sens in perm for sens in sensitive_permissions))
        risk_score += sensitive_count * 5
        
        # Entitlement-based risk
        entitlements = self.findings['basic_info'].get('entitlements', {})
        sensitive_ent_count = sum(1 for ent in self.sensitive_entitlements if ent in entitlements)
        risk_score += sensitive_ent_count * 8
        
        # Cap at 100
        self.findings['risk_score'] = min(risk_score, 100)
    
    def _calculate_hash(self, file_path: Path, algorithm: str) -> str:
        """Calculate file hash"""
        hash_algo = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_algo.update(chunk)
        return hash_algo.hexdigest()
    
    def _add_finding(self, severity: str, description: str, masvs_category: str = None):
        """Add security finding"""
        finding = {
            'severity': severity,
            'description': description,
            'timestamp': self._get_timestamp()
        }
        
        if masvs_category:
            finding['masvs_category'] = masvs_category
        
        self.findings['security_findings'].append(finding)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def generate_report(self, output_file: str = None):
        """Generate analysis report"""
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(self.findings, f, indent=2, default=str)
            print(f"[+] Report saved to: {output_file}")
        else:
            print("\n" + "="*60)
            print("iOS STATIC ANALYSIS REPORT")
            print("="*60)
            
            # Basic info
            print(f"\nIPA: {self.ipa_path}")
            print(f"Bundle ID: {self.findings['basic_info'].get('bundle_id', 'Unknown')}")
            print(f"Version: {self.findings['basic_info'].get('app_version', 'Unknown')}")
            print(f"Minimum iOS: {self.findings['basic_info'].get('minimum_os', 'Unknown')}")
            print(f"File Size: {self.findings['basic_info'].get('file_size', 'Unknown')} bytes")
            print(f"SHA256: {self.findings['basic_info'].get('sha256_hash', 'Unknown')}")
            
            # Permissions
            permissions = self.findings['basic_info'].get('requested_permissions', [])
            if permissions:
                print(f"\nRequested Permissions ({len(permissions)}):")
                for perm in permissions:
                    print(f"  - {perm}")
            
            # URL Schemes
            url_schemes = self.findings['basic_info'].get('custom_url_schemes', [])
            if url_schemes:
                print(f"\nCustom URL Schemes:")
                for scheme in url_schemes:
                    print(f"  - {scheme}")
            
            # Security findings
            findings = self.findings['security_findings']
            print(f"\nSecurity Findings ({len(findings)}):")
            
            severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0, 'ERROR': 0}
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
    
    def _analyze_data_protection(self):
        """Analyze data protection implementation"""
        try:
            plist = self.findings['basic_info'].get('info_plist', {})
            
            # Check for file protection settings
            if 'NSFileProtectionComplete' not in str(plist):
                self._add_finding("MEDIUM", 
                                "No file protection configuration detected",
                                "MASVS-STORAGE-1")
            
            # Check for keychain access groups
            if plist.get('keychain-access-groups'):
                keychain_groups = plist['keychain-access-groups']
                if isinstance(keychain_groups, list) and len(keychain_groups) > 3:
                    self._add_finding("MEDIUM", 
                                    "Multiple keychain access groups defined",
                                    "MASVS-STORAGE-1")
            
            # Check for Core Data usage
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                file_list = ipa.namelist()
                core_data_files = [f for f in file_list if f.endswith('.xcdatamodel') or f.endswith('.sqlite')]
                
                if core_data_files:
                    self._add_finding("INFO", 
                                    f"Core Data files detected: {len(core_data_files)}",
                                    "MASVS-STORAGE-1")
                    
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze data protection: {str(e)}")
    
    def _analyze_code_signing(self):
        """Analyze code signing and provisioning profile"""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                # Look for provisioning profile
                provisioning_files = [f for f in ipa.namelist() if f.endswith('.mobileprovision')]
                
                if not provisioning_files:
                    self._add_finding("HIGH", 
                                    "No provisioning profile found",
                                    "MASVS-RESILIENCE-1")
                    return
                
                # Analyze provisioning profile (basic check)
                for prov_file in provisioning_files:
                    try:
                        prov_data = ipa.read(prov_file).decode('utf-8', errors='ignore')
                        
                        if 'get-task-allow' in prov_data and '<true/>' in prov_data:
                            self._add_finding("HIGH", 
                                            "Debug provisioning profile detected",
                                            "MASVS-RESILIENCE-1")
                        
                        if 'aps-environment' in prov_data:
                            if 'development' in prov_data:
                                self._add_finding("MEDIUM", 
                                                "Development push notification environment",
                                                "MASVS-PLATFORM-1")
                    except:
                        continue
                        
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze code signing: {str(e)}")
    
    def _analyze_third_party_libraries(self):
        """Analyze third-party libraries and frameworks"""
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                file_list = ipa.namelist()
                
                # Look for common third-party frameworks
                frameworks = [f for f in file_list if '/Frameworks/' in f and f.endswith('.framework/')]
                
                vulnerable_frameworks = {
                    'AFNetworking': 'Potentially outdated networking framework',
                    'Alamofire': 'Swift networking framework - check version',
                    'MagicalRecord': 'Core Data helper - potential data leaks',
                    'FMDB': 'SQLite wrapper - check for SQL injection protection'
                }
                
                for framework in frameworks:
                    framework_name = framework.split('/')[-2].replace('.framework', '')
                    
                    if framework_name in vulnerable_frameworks:
                        self._add_finding("MEDIUM", 
                                        f"Third-party framework detected: {framework_name} - {vulnerable_frameworks[framework_name]}",
                                        "MASVS-CODE-1")
                
                # Check for static libraries
                static_libs = [f for f in file_list if f.endswith('.a')]
                if static_libs:
                    self._add_finding("INFO", 
                                    f"Static libraries detected: {len(static_libs)}",
                                    "MASVS-CODE-1")
                    
        except Exception as e:
            self._add_finding("ERROR", f"Failed to analyze third-party libraries: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='iOS IPA Static Analysis Tool')
    parser.add_argument('ipa_path', help='Path to IPA file to analyze')
    parser.add_argument('-o', '--output', help='Output JSON report file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Perform analysis
    analyzer = iOSStaticAnalyzer(args.ipa_path)
    results = analyzer.analyze()
    
    if results:
        analyzer.generate_report(args.output)
    else:
        print("[-] Analysis failed")
        sys.exit(1)


if __name__ == "__main__":
    main()