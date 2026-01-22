#!/usr/bin/env python3
"""
Security Assessment Report Generator
Part of Mobile Application Security Assessment Framework

This tool generates comprehensive security assessment reports
based on static and dynamic analysis results.

Author: Security Assessment Framework
License: Educational Use Only
"""

import os
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

class SecurityReportGenerator:
    """
    Comprehensive Security Assessment Report Generator
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.templates_dir = self.base_dir / "templates"
        
    def generate_executive_report(self, 
                                static_results: Dict[str, Any],
                                dynamic_results: Dict[str, Any] = None,
                                output_path: str = None) -> str:
        """
        Generate executive summary report
        
        Args:
            static_results: Results from static analysis
            dynamic_results: Results from dynamic analysis (optional)
            output_path: Output file path for the report
            
        Returns:
            Generated report content as string
        """
        
        report_data = {
            'assessment_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'static_analysis': static_results,
            'dynamic_analysis': dynamic_results or {},
            'executive_summary': self._generate_executive_summary(static_results, dynamic_results),
            'risk_matrix': self._generate_risk_matrix(static_results, dynamic_results),
            'recommendations': self._generate_recommendations(static_results, dynamic_results)
        }
        
        # Generate HTML report
        html_report = self._generate_html_report(report_data)
        
        # Generate markdown report  
        md_report = self._generate_markdown_report(report_data)
        
        if output_path:
            # Save HTML version
            html_path = Path(output_path).with_suffix('.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_report)
            
            # Save Markdown version
            md_path = Path(output_path).with_suffix('.md')
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(md_report)
                
            print(f"[+] Reports generated:")
            print(f"    HTML: {html_path}")
            print(f"    Markdown: {md_path}")
        
        return md_report
    
    def _generate_executive_summary(self, 
                                  static_results: Dict[str, Any],
                                  dynamic_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate executive summary"""
        
        summary = {
            'overall_risk': 'UNKNOWN',
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'total_issues': 0,
            'masvs_compliance': {},
            'key_findings': []
        }
        
        # Process static analysis results
        if static_results and 'security_findings' in static_results:
            findings = static_results['security_findings']
            
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN').upper()
                if severity == 'CRITICAL':
                    summary['critical_issues'] += 1
                elif severity == 'HIGH':
                    summary['high_issues'] += 1
                elif severity == 'MEDIUM':
                    summary['medium_issues'] += 1
                elif severity == 'LOW':
                    summary['low_issues'] += 1
            
            summary['total_issues'] = (summary['critical_issues'] + 
                                     summary['high_issues'] + 
                                     summary['medium_issues'] + 
                                     summary['low_issues'])
            
            # Determine overall risk
            if summary['critical_issues'] > 0 or summary['high_issues'] >= 3:
                summary['overall_risk'] = 'HIGH'
            elif summary['high_issues'] > 0 or summary['medium_issues'] >= 5:
                summary['overall_risk'] = 'MEDIUM'
            else:
                summary['overall_risk'] = 'LOW'
            
            # Extract MASVS compliance data
            if 'masvs_compliance' in static_results:
                summary['masvs_compliance'] = static_results['masvs_compliance']
        
        # Process dynamic analysis results
        if dynamic_results and 'security_findings' in dynamic_results:
            dynamic_findings = dynamic_results['security_findings']
            
            for finding in dynamic_findings:
                severity = finding.get('severity', 'UNKNOWN').upper()
                if severity == 'CRITICAL':
                    summary['critical_issues'] += 1
                elif severity == 'HIGH':
                    summary['high_issues'] += 1
                elif severity == 'MEDIUM':
                    summary['medium_issues'] += 1
                elif severity == 'LOW':
                    summary['low_issues'] += 1
            
            # Update total and re-evaluate risk
            summary['total_issues'] = (summary['critical_issues'] + 
                                     summary['high_issues'] + 
                                     summary['medium_issues'] + 
                                     summary['low_issues'])
            
            if summary['critical_issues'] > 0 or summary['high_issues'] >= 3:
                summary['overall_risk'] = 'HIGH'
            elif summary['high_issues'] > 0 or summary['medium_issues'] >= 5:
                summary['overall_risk'] = 'MEDIUM'
        
        return summary
    
    def _generate_risk_matrix(self, 
                            static_results: Dict[str, Any],
                            dynamic_results: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Generate risk matrix for findings"""
        
        risk_items = []
        
        # Process static findings
        if static_results and 'security_findings' in static_results:
            for finding in static_results['security_findings']:
                risk_item = {
                    'category': finding.get('masvs_category', 'GENERAL'),
                    'description': finding.get('description', 'Unknown issue'),
                    'severity': finding.get('severity', 'UNKNOWN'),
                    'likelihood': self._assess_likelihood(finding),
                    'impact': self._assess_impact(finding),
                    'source': 'Static Analysis'
                }
                risk_items.append(risk_item)
        
        # Process dynamic findings
        if dynamic_results and 'security_findings' in dynamic_results:
            for finding in dynamic_results['security_findings']:
                risk_item = {
                    'category': finding.get('masvs_category', 'GENERAL'),
                    'description': finding.get('description', 'Unknown issue'),
                    'severity': finding.get('severity', 'UNKNOWN'),
                    'likelihood': self._assess_likelihood(finding),
                    'impact': self._assess_impact(finding),
                    'source': 'Dynamic Analysis'
                }
                risk_items.append(risk_item)
        
        # Sort by severity (Critical > High > Medium > Low)
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        risk_items.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
        
        return risk_items
    
    def _assess_likelihood(self, finding: Dict[str, Any]) -> str:
        """Assess likelihood of exploitation"""
        severity = finding.get('severity', '').upper()
        description = finding.get('description', '').lower()
        
        if 'hardcoded' in description or 'plaintext' in description:
            return 'HIGH'
        elif severity in ['CRITICAL', 'HIGH']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _assess_impact(self, finding: Dict[str, Any]) -> str:
        """Assess business impact"""
        severity = finding.get('severity', '').upper()
        description = finding.get('description', '').lower()
        
        if any(word in description for word in ['data', 'credential', 'token', 'key']):
            return 'HIGH'
        elif severity in ['CRITICAL', 'HIGH']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(self, 
                                static_results: Dict[str, Any],
                                dynamic_results: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Generate remediation recommendations"""
        
        recommendations = []
        
        # Standard MASVS-based recommendations
        masvs_recommendations = {
            'MASVS-STORAGE-1': {
                'title': 'Secure Data Storage',
                'priority': 'HIGH',
                'description': 'Implement secure data storage mechanisms',
                'details': [
                    'Use iOS Keychain for sensitive data storage',
                    'Implement proper file protection levels',
                    'Avoid storing sensitive data in NSUserDefaults',
                    'Use Core Data with encryption for local databases'
                ]
            },
            'MASVS-CRYPTO-1': {
                'title': 'Cryptographic Implementation',
                'priority': 'HIGH',
                'description': 'Use strong cryptographic algorithms and proper implementation',
                'details': [
                    'Replace weak algorithms (MD5, SHA1, DES, RC4)',
                    'Use AES-256 for symmetric encryption',
                    'Implement proper key management',
                    'Use secure random number generation'
                ]
            },
            'MASVS-NETWORK-1': {
                'title': 'Network Security',
                'priority': 'HIGH',
                'description': 'Secure network communications',
                'details': [
                    'Implement certificate pinning',
                    'Use TLS 1.2 or higher',
                    'Validate SSL certificates properly',
                    'Configure App Transport Security (ATS)'
                ]
            },
            'MASVS-AUTH-1': {
                'title': 'Authentication and Authorization',
                'priority': 'MEDIUM',
                'description': 'Implement secure authentication mechanisms',
                'details': [
                    'Use strong authentication mechanisms',
                    'Implement proper session management',
                    'Use biometric authentication where appropriate',
                    'Validate authorization tokens properly'
                ]
            }
        }
        
        # Extract MASVS categories from findings
        masvs_issues = set()
        
        if static_results and 'security_findings' in static_results:
            for finding in static_results['security_findings']:
                masvs_cat = finding.get('masvs_category')
                if masvs_cat:
                    masvs_issues.add(masvs_cat)
        
        if dynamic_results and 'security_findings' in dynamic_results:
            for finding in dynamic_results['security_findings']:
                masvs_cat = finding.get('masvs_category')
                if masvs_cat:
                    masvs_issues.add(masvs_cat)
        
        # Generate recommendations for identified issues
        for masvs_cat in masvs_issues:
            if masvs_cat in masvs_recommendations:
                recommendations.append(masvs_recommendations[masvs_cat])
        
        # Sort by priority
        priority_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 0), reverse=True)
        
        return recommendations
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        
        html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Mobile Application Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .risk-high {{ color: #e74c3c; font-weight: bold; }}
        .risk-medium {{ color: #f39c12; font-weight: bold; }}
        .risk-low {{ color: #27ae60; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .recommendation {{ background: #e8f4f8; padding: 15px; margin: 10px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Mobile Application Security Assessment Report</h1>
        <p>Assessment Date: {assessment_date}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <p><strong>Overall Risk Level:</strong> <span class="risk-{overall_risk_class}">{overall_risk}</span></p>
        <p><strong>Total Issues Found:</strong> {total_issues}</p>
        <ul>
            <li>Critical: {critical_issues}</li>
            <li>High: {high_issues}</li>
            <li>Medium: {medium_issues}</li>
            <li>Low: {low_issues}</li>
        </ul>
    </div>
    
    <h2>🎯 Risk Matrix</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Description</th>
            <th>Severity</th>
            <th>Likelihood</th>
            <th>Impact</th>
            <th>Source</th>
        </tr>
        {risk_matrix_rows}
    </table>
    
    <h2>💡 Recommendations</h2>
    {recommendations_html}
    
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd;">
        <p><em>This report was generated by the Mobile Application Security Assessment Framework</em></p>
    </div>
</body>
</html>
        '''
        
        # Process data for template
        summary = report_data['executive_summary']
        risk_matrix = report_data['risk_matrix']
        recommendations = report_data['recommendations']
        
        # Generate risk matrix rows
        risk_matrix_rows = ""
        for risk in risk_matrix[:20]:  # Limit to top 20 risks
            severity_class = risk['severity'].lower()
            risk_matrix_rows += f'''
            <tr>
                <td>{risk['category']}</td>
                <td>{risk['description']}</td>
                <td><span class="risk-{severity_class}">{risk['severity']}</span></td>
                <td>{risk['likelihood']}</td>
                <td>{risk['impact']}</td>
                <td>{risk['source']}</td>
            </tr>
            '''
        
        # Generate recommendations HTML
        recommendations_html = ""
        for rec in recommendations:
            priority_class = rec['priority'].lower()
            details_html = "<ul>" + "".join([f"<li>{detail}</li>" for detail in rec['details']]) + "</ul>"
            
            recommendations_html += f'''
            <div class="recommendation">
                <h3><span class="risk-{priority_class}">[{rec['priority']}]</span> {rec['title']}</h3>
                <p>{rec['description']}</p>
                {details_html}
            </div>
            '''
        
        # Fill template
        return html_template.format(
            assessment_date=report_data['assessment_date'],
            overall_risk=summary['overall_risk'],
            overall_risk_class=summary['overall_risk'].lower(),
            total_issues=summary['total_issues'],
            critical_issues=summary['critical_issues'],
            high_issues=summary['high_issues'],
            medium_issues=summary['medium_issues'],
            low_issues=summary['low_issues'],
            risk_matrix_rows=risk_matrix_rows,
            recommendations_html=recommendations_html
        )
    
    def _generate_markdown_report(self, report_data: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        
        summary = report_data['executive_summary']
        risk_matrix = report_data['risk_matrix']
        recommendations = report_data['recommendations']
        
        md_content = f"""# 🛡️ Mobile Application Security Assessment Report

**Assessment Date:** {report_data['assessment_date']}

---

## 📊 Executive Summary

**Overall Risk Level:** **{summary['overall_risk']}**

**Total Issues Found:** {summary['total_issues']}

| Severity | Count |
|----------|-------|
| Critical | {summary['critical_issues']} |
| High     | {summary['high_issues']} |
| Medium   | {summary['medium_issues']} |
| Low      | {summary['low_issues']} |

---

## 🎯 Risk Matrix

| Category | Description | Severity | Likelihood | Impact | Source |
|----------|-------------|----------|------------|--------|--------|
"""
        
        # Add risk matrix rows (limit to top 20)
        for risk in risk_matrix[:20]:
            md_content += f"| {risk['category']} | {risk['description']} | **{risk['severity']}** | {risk['likelihood']} | {risk['impact']} | {risk['source']} |\n"
        
        md_content += "\n---\n\n## 💡 Recommendations\n\n"
        
        # Add recommendations
        for rec in recommendations:
            md_content += f"### [{rec['priority']}] {rec['title']}\n\n"
            md_content += f"{rec['description']}\n\n"
            md_content += "**Action Items:**\n"
            for detail in rec['details']:
                md_content += f"- {detail}\n"
            md_content += "\n"
        
        md_content += "---\n\n*This report was generated by the Mobile Application Security Assessment Framework*\n"
        
        return md_content


def main():
    parser = argparse.ArgumentParser(description='Security Assessment Report Generator')
    parser.add_argument('-s', '--static', help='Static analysis results JSON file')
    parser.add_argument('-d', '--dynamic', help='Dynamic analysis results JSON file')
    parser.add_argument('-o', '--output', help='Output report file path')
    
    args = parser.parse_args()
    
    if not args.static and not args.dynamic:
        print("[-] Please provide at least one analysis results file")
        return
    
    # Load results
    static_results = None
    dynamic_results = None
    
    if args.static:
        try:
            with open(args.static, 'r') as f:
                static_results = json.load(f)
            print(f"[+] Loaded static analysis results from {args.static}")
        except Exception as e:
            print(f"[-] Failed to load static results: {e}")
            return
    
    if args.dynamic:
        try:
            with open(args.dynamic, 'r') as f:
                dynamic_results = json.load(f)
            print(f"[+] Loaded dynamic analysis results from {args.dynamic}")
        except Exception as e:
            print(f"[-] Failed to load dynamic results: {e}")
            return
    
    # Generate report
    generator = SecurityReportGenerator()
    output_path = args.output or f"security_assessment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    report = generator.generate_executive_report(
        static_results=static_results,
        dynamic_results=dynamic_results,
        output_path=output_path
    )
    
    print(f"[+] Security assessment report generated successfully!")


if __name__ == '__main__':
    main()