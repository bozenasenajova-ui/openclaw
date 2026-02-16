#!/usr/bin/env python3
"""
SecureClaw Skill Security Auditor

Scans OpenClaw/SecureClaw skills for security vulnerabilities.
"""

import os
import re
import json
import yaml
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    severity: Severity
    title: str
    description: str
    location: str = ""
    line_number: int = 0
    recommendation: str = ""
    cwe: str = ""  # Common Weakness Enumeration

@dataclass
class AuditReport:
    skill_name: str
    skill_path: str
    findings: List[Finding] = field(default_factory=list)
    risk_score: float = 0.0
    passed: bool = False
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self._calculate_risk_score()
    
    def _calculate_risk_score(self):
        """Calculate risk score (0-10)"""
        weights = {
            Severity.CRITICAL: 3.0,
            Severity.HIGH: 2.0,
            Severity.MEDIUM: 1.0,
            Severity.LOW: 0.5,
            Severity.INFO: 0.0
        }
        
        score = sum(weights[f.severity] for f in self.findings)
        self.risk_score = min(10.0, score)
        self.passed = self.risk_score < 3.0

class SkillAuditor:
    """Main security auditor class"""
    
    # Dangerous patterns to detect
    DANGEROUS_PATTERNS = {
        # Credential leaks
        r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']': {
            'severity': Severity.CRITICAL,
            'title': 'Hardcoded API Key',
            'cwe': 'CWE-798',
            'recommendation': 'Use secureclaw credential vault instead'
        },
        r'password\s*=\s*["\'].+["\']': {
            'severity': Severity.CRITICAL,
            'title': 'Hardcoded Password',
            'cwe': 'CWE-798',
            'recommendation': 'Never hardcode passwords'
        },
        r'(aws|github|slack)_secret': {
            'severity': Severity.CRITICAL,
            'title': 'Exposed Secret Token',
            'cwe': 'CWE-798',
            'recommendation': 'Use credential vault'
        },
        
        # Command injection
        r'os\.system\([^)]*input\(': {
            'severity': Severity.CRITICAL,
            'title': 'Command Injection Vulnerability',
            'cwe': 'CWE-78',
            'recommendation': 'Sanitize input before shell execution'
        },
        r'subprocess\.(call|run|Popen)\([^)]*user': {
            'severity': Severity.HIGH,
            'title': 'Potential Command Injection',
            'cwe': 'CWE-78',
            'recommendation': 'Use subprocess with shell=False and array arguments'
        },
        r'eval\(': {
            'severity': Severity.CRITICAL,
            'title': 'Code Injection Risk (eval)',
            'cwe': 'CWE-94',
            'recommendation': 'Never use eval() with untrusted input'
        },
        
        # Network security
        r'requests\.(get|post)\([^)]*verify\s*=\s*False': {
            'severity': Severity.HIGH,
            'title': 'TLS Certificate Validation Disabled',
            'cwe': 'CWE-295',
            'recommendation': 'Always validate TLS certificates'
        },
        r'http://(?!localhost|127\.0\.0\.1)': {
            'severity': Severity.MEDIUM,
            'title': 'Unencrypted HTTP Connection',
            'cwe': 'CWE-319',
            'recommendation': 'Use HTTPS for external connections'
        },
        
        # File security
        r'open\([^)]*[\'"]\/': {
            'severity': Severity.MEDIUM,
            'title': 'Absolute Path Access',
            'cwe': 'CWE-22',
            'recommendation': 'Use relative paths within sandbox'
        },
        r'chmod\s+777': {
            'severity': Severity.HIGH,
            'title': 'Overly Permissive File Permissions',
            'cwe': 'CWE-732',
            'recommendation': 'Use least-privilege permissions'
        },
        
        # Obfuscation (suspicious)
        r'\\x[0-9a-f]{2}': {
            'severity': Severity.MEDIUM,
            'title': 'Hex-Encoded Strings (Potential Obfuscation)',
            'cwe': 'CWE-656',
            'recommendation': 'Avoid obfuscated code'
        },
        r'base64\.b64decode': {
            'severity': Severity.LOW,
            'title': 'Base64 Decoding Detected',
            'cwe': 'CWE-656',
            'recommendation': 'Review decoded content'
        },
        
        # Data exfiltration
        r'requests\.post\([^)]*data\s*=': {
            'severity': Severity.MEDIUM,
            'title': 'Outbound Data POST',
            'cwe': 'CWE-359',
            'recommendation': 'Ensure user data is not exfiltrated'
        },
    }
    
    # Required permission declarations
    REQUIRED_PERMISSIONS = [
        'network:egress',
        'exec:bash',
        'read:files',
        'write:files',
        'credentials:use'
    ]
    
    def __init__(self, skill_path: str):
        self.skill_path = Path(skill_path)
        self.report = AuditReport(
            skill_name=self.skill_path.name,
            skill_path=str(self.skill_path)
        )
    
    def audit(self) -> AuditReport:
        """Run full security audit"""
        print(f"🔍 Auditing: {self.skill_path.name}")
        print("━" * 50)
        
        # 1. Check SKILL.md exists
        self._check_skill_md()
        
        # 2. Parse and validate permissions
        self._validate_permissions()
        
        # 3. Scan code for dangerous patterns
        self._scan_code_patterns()
        
        # 4. Check dependencies
        self._audit_dependencies()
        
        # 5. Check for obfuscation
        self._detect_obfuscation()
        
        # 6. Check network access
        self._check_network_access()
        
        # 7. Generate report
        self._print_report()
        
        return self.report
    
    def _check_skill_md(self):
        """Verify SKILL.md exists and is valid"""
        skill_md = self.skill_path / "SKILL.md"
        
        if not skill_md.exists():
            self.report.add_finding(Finding(
                severity=Severity.HIGH,
                title="Missing SKILL.md",
                description="Skill must have SKILL.md with metadata",
                recommendation="Create SKILL.md with proper frontmatter"
            ))
            return
        
        # Parse frontmatter
        try:
            content = skill_md.read_text()
            if not content.startswith('---'):
                self.report.add_finding(Finding(
                    severity=Severity.MEDIUM,
                    title="Invalid SKILL.md Format",
                    description="SKILL.md must start with YAML frontmatter",
                    location=str(skill_md)
                ))
        except Exception as e:
            self.report.add_finding(Finding(
                severity=Severity.MEDIUM,
                title="Failed to Parse SKILL.md",
                description=str(e),
                location=str(skill_md)
            ))
    
    def _validate_permissions(self):
        """Validate permission declarations"""
        skill_md = self.skill_path / "SKILL.md"
        if not skill_md.exists():
            return
        
        content = skill_md.read_text()
        
        # Check for permission metadata
        if 'permissions:' not in content and 'metadata:' not in content:
            self.report.add_finding(Finding(
                severity=Severity.HIGH,
                title="No Permission Declarations",
                description="Skill does not declare required permissions",
                recommendation="Add permissions section to SKILL.md metadata",
                location=str(skill_md)
            ))
    
    def _scan_code_patterns(self):
        """Scan all code files for dangerous patterns"""
        code_extensions = {'.py', '.js', '.ts', '.sh', '.bash'}
        
        for file_path in self.skill_path.rglob('*'):
            if file_path.suffix not in code_extensions:
                continue
            
            if 'node_modules' in file_path.parts:
                continue
            
            try:
                content = file_path.read_text()
                self._scan_file_content(file_path, content)
            except Exception as e:
                pass  # Binary file or encoding issue
    
    def _scan_file_content(self, file_path: Path, content: str):
        """Scan individual file content"""
        lines = content.split('\n')
        
        for pattern, config in self.DANGEROUS_PATTERNS.items():
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    self.report.add_finding(Finding(
                        severity=config['severity'],
                        title=config['title'],
                        description=f"Pattern found: {pattern}",
                        location=f"{file_path.relative_to(self.skill_path)}:{line_num}",
                        line_number=line_num,
                        recommendation=config['recommendation'],
                        cwe=config.get('cwe', '')
                    ))
    
    def _audit_dependencies(self):
        """Check for vulnerable dependencies"""
        # Check package.json
        package_json = self.skill_path / "package.json"
        if package_json.exists():
            self._audit_npm_dependencies(package_json)
        
        # Check requirements.txt
        requirements = self.skill_path / "requirements.txt"
        if requirements.exists():
            self._audit_python_dependencies(requirements)
    
    def _audit_npm_dependencies(self, package_json: Path):
        """Audit npm dependencies for known CVEs"""
        try:
            # Run npm audit if npm is available
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                cwd=self.skill_path,
                capture_output=True,
                timeout=10
            )
            
            if result.returncode != 0:
                audit_data = json.loads(result.stdout)
                vulnerabilities = audit_data.get('vulnerabilities', {})
                
                for pkg, vuln in vulnerabilities.items():
                    severity_map = {
                        'critical': Severity.CRITICAL,
                        'high': Severity.HIGH,
                        'moderate': Severity.MEDIUM,
                        'low': Severity.LOW
                    }
                    
                    severity = severity_map.get(vuln.get('severity', 'low'), Severity.LOW)
                    
                    self.report.add_finding(Finding(
                        severity=severity,
                        title=f"Vulnerable Dependency: {pkg}",
                        description=f"Known vulnerability in {pkg}",
                        location=str(package_json),
                        recommendation="Update to patched version"
                    ))
        except Exception:
            # npm not available or audit failed
            pass
    
    def _audit_python_dependencies(self, requirements: Path):
        """Audit Python dependencies"""
        try:
            # Use pip-audit if available
            result = subprocess.run(
                ['pip-audit', '-r', str(requirements), '--format', 'json'],
                capture_output=True,
                timeout=10
            )
            
            if result.stdout:
                audit_data = json.loads(result.stdout)
                for vuln in audit_data.get('vulnerabilities', []):
                    self.report.add_finding(Finding(
                        severity=Severity.HIGH,
                        title=f"Vulnerable Python Package: {vuln.get('name')}",
                        description=vuln.get('description', 'Known vulnerability'),
                        location=str(requirements),
                        recommendation="Update to secure version"
                    ))
        except Exception:
            # pip-audit not available
            pass
    
    def _detect_obfuscation(self):
        """Detect code obfuscation techniques"""
        for file_path in self.skill_path.rglob('*.js'):
            if 'node_modules' in file_path.parts:
                continue
            
            try:
                content = file_path.read_text()
                
                # Very long lines (minified/obfuscated)
                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    if len(line) > 500:
                        self.report.add_finding(Finding(
                            severity=Severity.MEDIUM,
                            title="Suspiciously Long Line",
                            description=f"Line length: {len(line)} chars",
                            location=f"{file_path.relative_to(self.skill_path)}:{line_num}",
                            recommendation="Avoid minified/obfuscated code"
                        ))
                        break
                
                # High entropy (random-looking strings)
                entropy = self._calculate_entropy(content)
                if entropy > 4.5:
                    self.report.add_finding(Finding(
                        severity=Severity.LOW,
                        title="High Code Entropy",
                        description=f"Entropy: {entropy:.2f} (possibly obfuscated)",
                        location=str(file_path.relative_to(self.skill_path)),
                        recommendation="Review for obfuscation"
                    ))
            except Exception:
                pass
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.__log__() / 2.302585092994046)  # log2
        
        return entropy
    
    def _check_network_access(self):
        """Check for network access patterns"""
        network_patterns = [
            r'requests\.',
            r'fetch\(',
            r'axios\.',
            r'http\.',
            r'urllib',
            r'net/http'
        ]
        
        has_network = False
        for file_path in self.skill_path.rglob('*'):
            if file_path.suffix not in {'.py', '.js', '.ts'}:
                continue
            
            try:
                content = file_path.read_text()
                for pattern in network_patterns:
                    if re.search(pattern, content):
                        has_network = True
                        break
                if has_network:
                    break
            except Exception:
                pass
        
        if has_network:
            # Check if network permissions declared
            skill_md = self.skill_path / "SKILL.md"
            if skill_md.exists():
                content = skill_md.read_text()
                if 'network:egress' not in content and 'network' not in content:
                    self.report.add_finding(Finding(
                        severity=Severity.HIGH,
                        title="Undeclared Network Access",
                        description="Code uses network but permissions not declared",
                        recommendation="Declare network:egress permission in SKILL.md"
                    ))
    
    def _print_report(self):
        """Print formatted audit report"""
        # Group by severity
        by_severity = {}
        for finding in self.report.findings:
            by_severity.setdefault(finding.severity, []).append(finding)
        
        # Print findings
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        severity_colors = {
            Severity.CRITICAL: '\033[91m',  # Red
            Severity.HIGH: '\033[93m',      # Yellow
            Severity.MEDIUM: '\033[94m',    # Blue
            Severity.LOW: '\033[92m',       # Green
            Severity.INFO: '\033[90m'       # Gray
        }
        reset = '\033[0m'
        
        for severity in severity_order:
            if severity not in by_severity:
                continue
            
            color = severity_colors[severity]
            findings = by_severity[severity]
            
            for finding in findings:
                print(f"{color}[{severity.value}]{reset} {finding.title}")
                if finding.location:
                    print(f"  Location: {finding.location}")
                if finding.description:
                    print(f"  {finding.description}")
                if finding.recommendation:
                    print(f"  💡 {finding.recommendation}")
                if finding.cwe:
                    print(f"  CWE: {finding.cwe}")
                print()
        
        # Print summary
        print("━" * 50)
        print(f"Risk Score: {self.report.risk_score:.1f}/10.0")
        
        if self.report.risk_score >= 7.0:
            print(f"{severity_colors[Severity.CRITICAL]}⛔ CRITICAL RISK - DO NOT INSTALL{reset}")
        elif self.report.risk_score >= 5.0:
            print(f"{severity_colors[Severity.HIGH]}⚠️  HIGH RISK - Review carefully{reset}")
        elif self.report.risk_score >= 3.0:
            print(f"{severity_colors[Severity.MEDIUM]}⚡ MEDIUM RISK - Proceed with caution{reset}")
        else:
            print(f"{severity_colors[Severity.LOW]}✅ LOW RISK - Generally safe{reset}")
        
        print(f"\nTotal Issues: {len(self.report.findings)}")
        print(f"Passed: {'✅ Yes' if self.report.passed else '❌ No'}")

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: skill-auditor.py <skill_path>")
        print("\nExample:")
        print("  skill-auditor.py ./my-skill/")
        sys.exit(1)
    
    skill_path = sys.argv[1]
    
    if not os.path.isdir(skill_path):
        print(f"Error: {skill_path} is not a directory")
        sys.exit(1)
    
    auditor = SkillAuditor(skill_path)
    report = auditor.audit()
    
    # Exit with error code if high risk
    sys.exit(0 if report.passed else 1)

if __name__ == '__main__':
    main()
