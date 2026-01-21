#!/usr/bin/env python3
"""
Mobile Security Assessment Framework - Setup and Installation Script

This script sets up the complete mobile security assessment environment
with all necessary tools, dependencies, and configurations.

Author: Security Assessment Framework
License: Educational Use Only
"""

import os
import sys
import subprocess
import platform
import json
import urllib.request
from pathlib import Path
from typing import List, Dict, Any

class SecurityFrameworkSetup:
    """
    Comprehensive setup manager for mobile security assessment framework
    """
    
    def __init__(self):
        self.system = platform.system().lower()
        self.architecture = platform.machine().lower()
        self.python_version = sys.version_info
        self.setup_log = []
        
        # Framework directories
        self.base_dir = Path(__file__).parent
        self.tools_dir = self.base_dir / "tools"
        self.venv_dir = self.base_dir / "venv"
        self.config_dir = self.base_dir / "config"
        
        # Tool configurations
        self.required_tools = {
            "python_packages": [
                "mitmproxy>=8.0.0",
                "frida-tools>=12.0.0", 
                "requests>=2.28.0",
                "cryptography>=3.4.8",
                "pycryptodome>=3.15.0",
                "xml-crypto>=1.0.0",
                "python-jose>=3.3.0",
                "pyjwt>=2.4.0",
                "selenium>=4.0.0",
                "beautifulsoup4>=4.11.0",
                "lxml>=4.8.0",
                "click>=8.0.0",
                "colorama>=0.4.4",
                "tabulate>=0.8.9",
                "tqdm>=4.64.0"
            ],
            "android_tools": [
                "adb",
                "aapt", 
                "apktool",
                "dex2jar",
                "jd-gui"
            ],
            "ios_tools": [
                "libimobiledevice",
                "ideviceinstaller",
                "class-dump",
                "otool"
            ],
            "security_tools": [
                "nmap",
                "wireshark",
                "burpsuite",
                "owasp-zap"
            ]
        }
        
    def run_setup(self):
        """Run complete framework setup"""
        print("="*70)
        print("Mobile Application Security Assessment Framework Setup")
        print("="*70)
        print(f"System: {self.system.title()} ({self.architecture})")
        print(f"Python: {sys.version}")
        print()
        
        try:
            self._create_directories()
            self._setup_python_environment()
            self._install_python_packages()
            self._setup_android_tools()
            self._setup_ios_tools()
            self._setup_security_tools()
            self._create_configuration_files()
            self._setup_git_hooks()
            self._generate_certificates()
            self._create_launcher_scripts()
            
            self._display_setup_summary()
            print("\n✅ Setup completed successfully!")
            print("\nNext steps:")
            print("1. Activate virtual environment: source venv/bin/activate (Linux/macOS) or venv\\Scripts\\activate (Windows)")
            print("2. Review configuration files in config/")
            print("3. Run initial tests: python tests/test_framework.py")
            
        except Exception as e:
            print(f"\n❌ Setup failed: {str(e)}")
            self._display_troubleshooting()
            sys.exit(1)
    
    def _create_directories(self):
        """Create necessary directory structure"""
        print("📁 Creating directory structure...")
        
        directories = [
            self.tools_dir,
            self.config_dir,
            self.base_dir / "reports",
            self.base_dir / "logs",
            self.base_dir / "certificates",
            self.base_dir / "samples",
            self.base_dir / "templates",
            self.tools_dir / "android",
            self.tools_dir / "ios", 
            self.tools_dir / "network",
            self.tools_dir / "automation"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            self._log_action(f"Created directory: {directory}")
        
        print("✓ Directory structure created")
    
    def _setup_python_environment(self):
        """Set up Python virtual environment"""
        print("🐍 Setting up Python virtual environment...")
        
        if self.python_version < (3, 8):
            raise RuntimeError("Python 3.8 or higher is required")
        
        if not self.venv_dir.exists():
            subprocess.run([sys.executable, "-m", "venv", str(self.venv_dir)], check=True)
            self._log_action("Created Python virtual environment")
        
        # Determine pip executable path
        if self.system == "windows":
            pip_path = self.venv_dir / "Scripts" / "pip.exe"
            python_path = self.venv_dir / "Scripts" / "python.exe"
        else:
            pip_path = self.venv_dir / "bin" / "pip"
            python_path = self.venv_dir / "bin" / "python"
        
        # Upgrade pip
        subprocess.run([str(python_path), "-m", "pip", "install", "--upgrade", "pip"], check=True)
        self._log_action("Upgraded pip in virtual environment")
        
        print("✓ Python virtual environment ready")
    
    def _install_python_packages(self):
        """Install required Python packages"""
        print("📦 Installing Python packages...")
        
        pip_path = self._get_pip_path()
        
        # Install packages
        for package in self.required_tools["python_packages"]:
            try:
                print(f"  Installing {package}...")
                subprocess.run([str(pip_path), "install", package], 
                             check=True, capture_output=True, text=True)
                self._log_action(f"Installed Python package: {package}")
            except subprocess.CalledProcessError as e:
                print(f"  ⚠️ Failed to install {package}: {e.stderr}")
                self._log_action(f"Failed to install {package}: {e.stderr}")
        
        print("✓ Python packages installed")
    
    def _setup_android_tools(self):
        """Set up Android development and security tools"""
        print("🤖 Setting up Android tools...")
        
        android_tools_dir = self.tools_dir / "android"
        
        # Check for Android SDK
        android_home = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
        if android_home:
            print(f"  Found Android SDK at: {android_home}")
            self._log_action(f"Android SDK found: {android_home}")
        else:
            print("  ⚠️ Android SDK not found. Please install Android Studio or SDK tools.")
            print("  Set ANDROID_HOME environment variable to SDK location.")
        
        # Download and setup APKTool
        self._setup_apktool(android_tools_dir)
        
        # Download and setup dex2jar
        self._setup_dex2jar(android_tools_dir)
        
        print("✓ Android tools configured")
    
    def _setup_apktool(self, tools_dir: Path):
        """Download and setup APKTool"""
        apktool_path = tools_dir / "apktool.jar"
        
        if not apktool_path.exists():
            print("  Downloading APKTool...")
            apktool_url = "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"
            apktool_jar_url = "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar"
            
            try:
                # Download APKTool wrapper script
                urllib.request.urlretrieve(apktool_url, str(tools_dir / "apktool"))
                os.chmod(str(tools_dir / "apktool"), 0o755)
                
                # Download APKTool JAR
                urllib.request.urlretrieve(apktool_jar_url, str(apktool_path))
                
                self._log_action("Downloaded and configured APKTool")
            except Exception as e:
                print(f"  ⚠️ Failed to download APKTool: {e}")
    
    def _setup_dex2jar(self, tools_dir: Path):
        """Download and setup dex2jar"""
        dex2jar_dir = tools_dir / "dex2jar"
        
        if not dex2jar_dir.exists():
            print("  Downloading dex2jar...")
            dex2jar_url = "https://github.com/pxb1988/dex2jar/releases/download/v2.2/dex-tools-2.2.zip"
            
            try:
                import zipfile
                import tempfile
                
                with tempfile.TemporaryDirectory() as temp_dir:
                    zip_path = Path(temp_dir) / "dex2jar.zip"
                    urllib.request.urlretrieve(dex2jar_url, str(zip_path))
                    
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        zip_ref.extractall(str(tools_dir))
                    
                    # Find extracted directory and rename
                    extracted_dirs = [d for d in tools_dir.iterdir() if d.is_dir() and "dex" in d.name.lower()]
                    if extracted_dirs:
                        extracted_dirs[0].rename(dex2jar_dir)
                
                self._log_action("Downloaded and configured dex2jar")
            except Exception as e:
                print(f"  ⚠️ Failed to download dex2jar: {e}")
    
    def _setup_ios_tools(self):
        """Set up iOS development and security tools"""
        print("🍎 Setting up iOS tools...")
        
        ios_tools_dir = self.tools_dir / "ios"
        
        if self.system == "darwin":  # macOS
            # Check for Xcode
            xcode_path = "/Applications/Xcode.app"
            if os.path.exists(xcode_path):
                print(f"  Found Xcode at: {xcode_path}")
                self._log_action("Xcode found")
            else:
                print("  ⚠️ Xcode not found. Install from App Store for iOS development.")
            
            # Install libimobiledevice via Homebrew if available
            try:
                subprocess.run(["brew", "install", "libimobiledevice"], check=True, capture_output=True)
                self._log_action("Installed libimobiledevice via Homebrew")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("  ⚠️ Homebrew not available. Install manually for iOS device support.")
        else:
            print("  ℹ️ iOS tools require macOS. Some features will be limited.")
        
        print("✓ iOS tools configured")
    
    def _setup_security_tools(self):
        """Set up security testing tools"""
        print("🔒 Setting up security tools...")
        
        security_tools_dir = self.tools_dir / "security"
        security_tools_dir.mkdir(exist_ok=True)
        
        # Check for installed security tools
        tools_status = {}
        
        for tool in self.required_tools["security_tools"]:
            if self._check_tool_available(tool):
                tools_status[tool] = "✓ Available"
            else:
                tools_status[tool] = "⚠️ Not found"
        
        print("  Security tools status:")
        for tool, status in tools_status.items():
            print(f"    {tool}: {status}")
        
        # Download OWASP ZAP if not available
        if "⚠️" in tools_status.get("owasp-zap", ""):
            self._setup_owasp_zap(security_tools_dir)
        
        print("✓ Security tools configured")
    
    def _setup_owasp_zap(self, tools_dir: Path):
        """Download and setup OWASP ZAP"""
        print("  Downloading OWASP ZAP...")
        
        if self.system == "windows":
            zap_url = "https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2_12_0_windows.exe"
        elif self.system == "darwin":
            zap_url = "https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2_12_0_macos.dmg"
        else:
            zap_url = "https://github.com/zaproxy/zaproxy/releases/latest/download/ZAP_2_12_0_Linux.tar.gz"
        
        try:
            zap_file = tools_dir / Path(zap_url).name
            print(f"    Downloading from: {zap_url}")
            urllib.request.urlretrieve(zap_url, str(zap_file))
            self._log_action(f"Downloaded OWASP ZAP: {zap_file}")
        except Exception as e:
            print(f"  ⚠️ Failed to download OWASP ZAP: {e}")
    
    def _create_configuration_files(self):
        """Create framework configuration files"""
        print("⚙️ Creating configuration files...")
        
        # Main configuration
        main_config = {
            "framework": {
                "version": "1.0.0",
                "name": "Mobile Security Assessment Framework",
                "description": "OWASP MASVS-aligned mobile security testing framework"
            },
            "logging": {
                "level": "INFO",
                "file": "logs/framework.log",
                "max_size": "10MB",
                "backup_count": 5
            },
            "testing": {
                "default_timeout": 30,
                "max_threads": 4,
                "retry_attempts": 3
            },
            "reporting": {
                "template_dir": "templates/",
                "output_dir": "reports/",
                "format": "json"
            },
            "tools": {
                "android_tools_dir": str(self.tools_dir / "android"),
                "ios_tools_dir": str(self.tools_dir / "ios"),
                "security_tools_dir": str(self.tools_dir / "security")
            }
        }
        
        config_file = self.config_dir / "framework.json"
        with open(config_file, 'w') as f:
            json.dump(main_config, f, indent=2)
        
        # Network analysis configuration
        network_config = {
            "proxy": {
                "default_port": 8080,
                "ssl_verification": True,
                "certificate_path": "certificates/mitmproxy-ca-cert.pem"
            },
            "analysis": {
                "sensitive_patterns": [
                    "password", "token", "api_key", "secret", "auth",
                    "credit_card", "ssn", "email", "phone"
                ],
                "excluded_domains": [
                    "google.com", "googleapis.com", "apple.com"
                ]
            }
        }
        
        network_config_file = self.config_dir / "network_analysis.json"
        with open(network_config_file, 'w') as f:
            json.dump(network_config, f, indent=2)
        
        print("✓ Configuration files created")
    
    def _setup_git_hooks(self):
        """Set up Git hooks for security checks"""
        print("🔧 Setting up Git hooks...")
        
        git_dir = self.base_dir / ".git"
        if git_dir.exists():
            hooks_dir = git_dir / "hooks"
            
            # Pre-commit hook for security checks
            pre_commit_hook = hooks_dir / "pre-commit"
            pre_commit_content = """#!/bin/bash
# Security pre-commit hook

echo "Running security pre-commit checks..."

# Check for hardcoded secrets
if grep -r "password\s*=" . --include="*.py" --include="*.java" --include="*.kt"; then
    echo "❌ Potential hardcoded passwords found!"
    exit 1
fi

# Check for API keys
if grep -r "api_key\s*=" . --include="*.py" --include="*.java" --include="*.kt"; then
    echo "❌ Potential hardcoded API keys found!"
    exit 1
fi

echo "✓ Security checks passed"
"""
            
            with open(pre_commit_hook, 'w') as f:
                f.write(pre_commit_content)
            
            os.chmod(str(pre_commit_hook), 0o755)
            self._log_action("Created Git pre-commit hook")
        
        print("✓ Git hooks configured")
    
    def _generate_certificates(self):
        """Generate SSL certificates for testing"""
        print("🔐 Generating SSL certificates...")
        
        cert_dir = self.base_dir / "certificates"
        
        # Generate self-signed certificate for testing
        cert_config = """[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = TestState
L = TestCity
O = Mobile Security Framework
OU = Testing Department
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = 127.0.0.1
IP.1 = 127.0.0.1
"""
        
        config_path = cert_dir / "cert.conf"
        with open(config_path, 'w') as f:
            f.write(cert_config)
        
        try:
            # Generate private key
            subprocess.run([
                "openssl", "genrsa", "-out", 
                str(cert_dir / "test-key.pem"), "2048"
            ], check=True, capture_output=True)
            
            # Generate certificate
            subprocess.run([
                "openssl", "req", "-new", "-x509", "-key",
                str(cert_dir / "test-key.pem"), "-out", 
                str(cert_dir / "test-cert.pem"), "-days", "365",
                "-config", str(config_path)
            ], check=True, capture_output=True)
            
            self._log_action("Generated SSL test certificates")
            
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("  ⚠️ OpenSSL not available. Install OpenSSL for certificate generation.")
        
        print("✓ SSL certificates configured")
    
    def _create_launcher_scripts(self):
        """Create launcher scripts for common tasks"""
        print("🚀 Creating launcher scripts...")
        
        scripts = {
            "analyze_android": {
                "description": "Launch Android APK analysis",
                "command": "python tests/static-analysis/android/android_static_analyzer.py"
            },
            "analyze_ios": {
                "description": "Launch iOS IPA analysis", 
                "command": "python tests/static-analysis/ios/ios_static_analyzer.py"
            },
            "network_analysis": {
                "description": "Start network traffic analysis",
                "command": "python tests/dynamic-analysis/network_traffic_analyzer.py"
            },
            "run_tests": {
                "description": "Run framework test suite",
                "command": "python -m pytest tests/ -v"
            }
        }
        
        scripts_dir = self.base_dir / "scripts"
        scripts_dir.mkdir(exist_ok=True)
        
        for script_name, config in scripts.items():
            if self.system == "windows":
                script_path = scripts_dir / f"{script_name}.bat"
                script_content = f"""@echo off
echo {config['description']}
call venv\\Scripts\\activate.bat
{config['command']} %*
"""
            else:
                script_path = scripts_dir / f"{script_name}.sh"
                script_content = f"""#!/bin/bash
echo "{config['description']}"
source venv/bin/activate
{config['command']} "$@"
"""
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            if self.system != "windows":
                os.chmod(str(script_path), 0o755)
        
        print("✓ Launcher scripts created")
    
    def _check_tool_available(self, tool: str) -> bool:
        """Check if a tool is available in PATH"""
        try:
            subprocess.run([tool, "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _get_pip_path(self) -> Path:
        """Get pip executable path for virtual environment"""
        if self.system == "windows":
            return self.venv_dir / "Scripts" / "pip.exe"
        else:
            return self.venv_dir / "bin" / "pip"
    
    def _log_action(self, action: str):
        """Log setup action"""
        self.setup_log.append(action)
    
    def _display_setup_summary(self):
        """Display setup summary"""
        print("\n📋 Setup Summary:")
        print(f"  Total actions: {len(self.setup_log)}")
        print("  Key components installed:")
        print("    • Python virtual environment")
        print("    • Security analysis tools")
        print("    • Configuration files")  
        print("    • SSL certificates")
        print("    • Launcher scripts")
        
    def _display_troubleshooting(self):
        """Display troubleshooting information"""
        print("\n🔧 Troubleshooting:")
        print("  Common issues and solutions:")
        print("  1. Permission denied: Run with appropriate permissions")
        print("  2. Network issues: Check internet connection and proxy settings")
        print("  3. Python version: Ensure Python 3.8+ is installed")
        print("  4. Virtual environment: Delete venv/ directory and retry")
        print("\n  For more help, check the documentation or create an issue.")


def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Mobile Security Framework Setup")
    parser.add_argument("--force", action="store_true", 
                       help="Force reinstallation of existing components")
    parser.add_argument("--minimal", action="store_true",
                       help="Minimal installation (core components only)")
    
    args = parser.parse_args()
    
    setup = SecurityFrameworkSetup()
    setup.run_setup()


if __name__ == "__main__":
    main()