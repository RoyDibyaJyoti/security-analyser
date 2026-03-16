# 🛡️ Security Analyzer Pro

AI-Powered Phishing Detection & OWASP Vulnerability Scanner

## ⚠️ Important Notice

> **Educational Use Only**: This tool is designed for learning and authorized security testing. 
> Always obtain explicit written permission before scanning any system you do not own. 
> Unauthorized security testing may violate computer crime laws in your jurisdiction.

## ✨ Features

### 🔍 Phishing Detection
- AI-powered email content analysis
- URL reputation & pattern checking
- Header analysis for spoofing detection
- Risk scoring with confidence metrics
- Actionable remediation recommendations

### 🐛 OWASP Top 10 Scanner
- SQL Injection detection (A03)
- Cross-Site Scripting checks (A03)
- Broken Authentication testing (A07)
- Access Control validation (A01)
- Security Misconfiguration checks (A05)
- SSRF behavior detection (A10)
- Configurable scan depth (basic/standard/deep)

### 🎯 Unified Platform
- Modern, responsive web interface
- Real-time scan progress tracking
- Comprehensive reporting with export options
- RESTful API for automation
- Docker support for easy deployment

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
# Clone repository
git clone <your-repo>
cd security-analyzer

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start with Docker Compose
docker-compose up -d

# Access the application
open http://localhost:8000# security-analyser
