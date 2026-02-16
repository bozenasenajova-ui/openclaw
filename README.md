# 🛡️ SecureClaw - Security-First Personal AI Assistant

![SecureClaw Banner](assets/banner.png)

**"Personal AI Assistant - Security First, Vibes Second"**

SecureClaw is a hardened fork of OpenClaw that prioritizes security, privacy, and user safety while maintaining the powerful automation capabilities of a personal AI assistant.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-green.svg)](SECURITY.md)
[![Docker: Required](https://img.shields.io/badge/Docker-Required-blue.svg)](docs/installation.md)

## 🎯 Why SecureClaw?

OpenClaw is powerful but has critical security vulnerabilities:
- 7.1% of marketplace skills contain malware
- 135,000+ exposed instances vulnerable to RCE
- Skills can exfiltrate credentials
- Indirect prompt injection attacks
- "Vibe-coded" with minimal security review

**SecureClaw fixes this** with a security-first architecture.

## 🔒 Key Security Improvements

### 1. **Mandatory Skill Sandboxing**
- Every skill runs in isolated Docker containers
- No network/filesystem access by default
- Granular permission system (request → approve → audit)
- Kill switches for misbehaving skills

### 2. **Skill Marketplace Security**
- Automated security scanning for all submissions
- Code signing and verified publishers
- Community reputation system
- Mandatory human review for "verified" badge
- Dependency vulnerability scanning

### 3. **Zero-Trust Architecture**
- Skills are untrusted by default
- Principle of least privilege enforced
- All operations require explicit user consent
- Comprehensive audit logging

### 4. **Credential Protection**
- Encrypted credential storage (age encryption)
- Secrets never passed to AI models
- Credential rotation support
- Automatic detection of leaked API keys

### 5. **Network Isolation**
- Skills can't access localhost by default
- Egress filtering and allowlisting
- No access to internal network ranges
- VPN-aware routing

### 6. **Secure Defaults**
- Authentication required (no "open" mode)
- Rate limiting built-in
- HTTPS/TLS mandatory
- CSRF protection

## 🏗️ Architecture

```
User → SecureClaw Gateway → Permission Manager → Sandboxed Skill
                                                ↓
                                         Audit Logger
                                                ↓
                                         Security Monitor
```

### Core Components

1. **Permission Manager**
   - Capability-based security model
   - Dynamic permission requests
   - User approval UI
   - Permission revocation

2. **Skill Sandbox**
   - gVisor/Firecracker isolation
   - Resource limits (CPU, memory, disk)
   - Network policies
   - Syscall filtering

3. **Security Scanner**
   - Static code analysis
   - Dependency auditing
   - Credential leak detection
   - SBOM generation

4. **Audit System**
   - Immutable logs
   - Anomaly detection
   - Alert system
   - Forensics support

## 📦 Installation

### Prerequisites
- Docker & Docker Compose
- Node.js 22+
- age (encryption tool)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/secureclaw.git
cd secureclaw

# Run security-hardened installation
./scripts/secure-install.sh

# Start with hardened defaults
docker compose up -d

# Access web UI (requires authentication)
open https://localhost:8443
```

### First-Time Setup Wizard

```bash
secureclaw init --secure
```

This wizard will:
- Generate encryption keys
- Set up authentication
- Configure firewall rules
- Install verified skills only
- Create backup strategy

## 🛡️ Security Features in Detail

### Skill Permission System

Skills must declare all capabilities upfront:

```yaml
---
name: example-skill
permissions:
  required:
    - read:files:~/Documents
    - network:egress:api.example.com
  optional:
    - exec:bash
    - read:env:API_KEY
---
```

Users see a clear permission dialog:

```
┌─────────────────────────────────────┐
│ "example-skill" requests:           │
│                                     │
│ ✓ Read files in ~/Documents        │
│ ✓ Network access to api.example.com│
│ ⚠ Execute bash commands             │
│ ⚠ Access API_KEY environment var   │
│                                     │
│ [Approve] [Deny] [View Code]       │
└─────────────────────────────────────┘
```

### Automated Security Scanning

Every skill submission runs through:

1. **Static Analysis**
   - Dangerous function calls
   - Obfuscated code detection
   - Hardcoded credentials
   - Suspicious network patterns

2. **Dependency Audit**
   - Known CVEs in npm/pip packages
   - Malicious package detection
   - License compliance

3. **Behavior Analysis**
   - Sandbox execution with monitoring
   - Network traffic inspection
   - File access patterns
   - Resource usage

### Credential Management

```bash
# Store credentials securely (age-encrypted)
secureclaw creds set OPENAI_API_KEY

# Credentials never visible to skills or AI
# Injected only at execution time via secure vault
```

### Audit Logging

All security events logged:

```json
{
  "timestamp": "2026-02-14T10:30:00Z",
  "skill": "suspicious-skill",
  "action": "network.egress",
  "target": "malicious-domain.com",
  "status": "blocked",
  "reason": "domain_not_allowlisted",
  "user": "alice"
}
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Security Model](docs/security-model.md)
- [Skill Development Guide](docs/skill-development.md)
- [Permission System](docs/permissions.md)
- [Threat Model](docs/threat-model.md)
- [Incident Response](docs/incident-response.md)
- [Security Checklist](docs/security-checklist.md)

## 🔧 Core Differences from OpenClaw

| Feature | OpenClaw | SecureClaw |
|---------|----------|------------|
| Skill Execution | Host process | Isolated containers |
| Default Access | Permissive | Deny-all |
| Credential Storage | Plaintext env vars | Encrypted vault |
| Network Access | Unrestricted | Allowlist-only |
| Skill Review | Community-only | Mandatory security review |
| Authentication | Optional | Required |
| Audit Logging | Limited | Comprehensive |
| Supply Chain | Unverified deps | SBOM + CVE scanning |

## 🛠️ Tools Included

### 1. Skill Security Auditor

```bash
secureclaw audit skill ./my-skill/
```

Output:
```
🔍 Scanning: my-skill
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[HIGH] Credential leak detected (line 42)
[MEDIUM] Unrestricted network access
[LOW] Missing permission declarations
[INFO] Using 3 dependencies with known CVEs

Risk Score: 7.5/10 (HIGH RISK)
Recommendation: Do not install
```

### 2. Permission Analyzer

```bash
secureclaw permissions analyze ./skill/
```

Shows what a skill *actually* does vs what it claims.

### 3. Credential Scanner

```bash
secureclaw scan-credentials ./
```

Finds API keys, tokens, passwords in code.

### 4. Sandbox Tester

```bash
secureclaw test-sandbox ./skill/ --network-capture
```

Runs skill in sandbox and reports all behaviors.

## 🤝 Contributing

We welcome security-focused contributions! Please read:

- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

### Reporting Security Issues

**DO NOT open public issues for security vulnerabilities.**

Email: security@secureclaw.dev
PGP Key: [Download](assets/pgp-key.asc)

## 📊 Current Status

- ✅ Core permission system implemented
- ✅ Skill sandboxing with gVisor
- ✅ Security scanner CLI
- ✅ Credential vault
- ⏳ Marketplace security review process (in progress)
- ⏳ Web UI for permission management (in progress)
- ⏳ Mobile apps with biometric auth (planned)

## 🏆 Security Hall of Fame

Contributors who found critical vulnerabilities:

- [Will be listed here]

## 📜 License

MIT License - see [LICENSE](LICENSE)

## 🙏 Acknowledgments

- OpenClaw team for the original project
- Security researchers who identified vulnerabilities
- gVisor team for container sandboxing
- age encryption project

## ⚠️ Disclaimer

SecureClaw significantly improves security over OpenClaw, but no system is 100% secure. Use at your own risk. Always review skills before installation, even verified ones.

---

**Built with 🔒 by security-conscious developers who actually read the code.**

**"We don't vibe-code security. We paranoid-code it."**
