# RedStrike.AI 🎯

> Enterprise-grade AI-powered web penetration testing platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![RedStrike Dashboard](docs/dashboard-preview.png)

## 🚀 Overview

RedStrike.AI is an **autonomous penetration testing platform** that combines AI agents with industry-standard security tools. Simply describe your target in natural language, and let the AI orchestrate a comprehensive security assessment.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🤖 **Multi-Agent System** | Orchestrator + 6 specialized agents (Recon, Discovery, Scanner, Fuzzer, Verifier, Reporter) |
| 🔧 **30+ Security Tools** | Nmap, Nuclei, SQLmap, Dalfox, ffuf, Katana, and more running in Kali Linux |
| 💬 **Natural Language Input** | Describe your test in plain English - AI handles the rest |
| 📊 **Real-time Dashboard** | Live WebSocket updates with findings, sitemap, and HTTP history |
| 📚 **Knowledge Base** | Extensible Markdown skills that enhance agent capabilities |
| 🔐 **Role-based Auth** | Admin/Tester roles with JWT authentication |
| 📈 **Report Generation** | Markdown reports with reproduction steps and PoC code |
| ⏸️ **Resumable Scans** | Pause and resume long-running assessments |

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Tools Included](#-tools-included)
- [Knowledge Base](#-knowledge-base)
- [Roadmap / TODO](#-roadmap--todo)
- [Contributing](#-contributing)
- [Security Notice](#-security-notice)

---

## 🏁 Quick Start

### Prerequisites

- **Docker & Docker Compose** (v2.0+)
- **Ollama** (for local models) OR API keys for OpenAI/Anthropic
- 8GB+ RAM recommended

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/RedStrike.AI.git
cd RedStrike.AI

# Copy environment file
cp .env.example .env

# Edit .env with your configuration
nano .env

# Build and start all services
docker-compose build
docker-compose up -d

# View logs to see your admin password
docker-compose logs -f app
```

### First Login

1. Open `http://localhost:9000` in your browser
2. Login with:
   - **Email:** `admin@redstrike.ai`
   - **Password:** Check the terminal logs for the auto-generated secure password

> ⚠️ On first run, a secure random password is generated if ADMIN_PASSWORD is set to `changeme123`

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           WEB DASHBOARD (Port 9000)                         │
│                       HTML/CSS/JS with Real-time Updates                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │ REST + WebSocket
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FASTAPI APPLICATION                                 │
│   ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌─────────────────┐  │
│   │  Auth   │ │ Projects │ │ Findings │ │ Endpoints │ │    WebSocket    │  │
│   └─────────┘ └──────────┘ └──────────┘ └───────────┘ └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       AGENT LAYER (smolagents + LiteLLM)                    │
│                                                                             │
│  ┌──────────────┐    ┌───────────────────────────────────────────────────┐ │
│  │ Orchestrator │───▶│  Recon → Discovery → Scanner → Fuzzer → Verifier │ │
│  └──────────────┘    └───────────────────────────────────────────────────┘ │
│         │                              │                                    │
│         ▼                              ▼                                    │
│  ┌──────────────┐              ┌──────────────┐                            │
│  │   Reporter   │              │   Skills KB  │                            │
│  └──────────────┘              └──────────────┘                            │
└─────────────────────────────────────────────────────────────────────────────┘
         │                               │
         ▼                               ▼
┌─────────────────┐            ┌──────────────────┐           ┌───────────────┐
│   PostgreSQL    │            │     Skills/      │           │  Kali Linux   │
│  (Projects,     │            │   (Markdown      │           │  Container    │
│   Findings,     │            │    Knowledge)    │           │  (30+ Tools)  │
│   History)      │            │                  │           │               │
└─────────────────┘            └──────────────────┘           └───────────────┘
```

### Container Architecture

| Container | Purpose | Port |
|-----------|---------|------|
| `redstrike-app` | FastAPI application + Dashboard | 9000 |
| `redstrike-db` | PostgreSQL database | 5432 |
| `redstrike-kali` | Kali Linux with security tools | - |

---

## ⚙️ Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql+asyncpg://redstrike:redstrike@db:5432/redstrike

# JWT Settings
JWT_SECRET_KEY=your-super-secret-key-change-in-production
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# LLM Configuration (choose one)
# Option 1: Ollama (local)
LITELLM_MODEL=ollama/llama3.2
OLLAMA_API_BASE=http://localhost:11434

# Option 2: OpenAI
LITELLM_MODEL=openai/gpt-4
OPENAI_API_KEY=sk-...

# Option 3: Anthropic
LITELLM_MODEL=anthropic/claude-3-sonnet-20240229
ANTHROPIC_API_KEY=sk-ant-...

# Admin User
ADMIN_EMAIL=admin@redstrike.ai
ADMIN_PASSWORD=changeme123  # Auto-generates secure password on first run
```

### Supported Models

| Provider | Example Models |
|----------|---------------|
| Ollama | `ollama/llama3.2`, `ollama/mistral`, `ollama/codellama` |
| OpenAI | `openai/gpt-4o`, `openai/gpt-4-turbo`, `openai/gpt-3.5-turbo` |
| Anthropic | `anthropic/claude-3-opus`, `anthropic/claude-3-sonnet` |
| Google | `gemini/gemini-pro` |

---

## 📖 Usage

### Creating a Project

1. **Login** to the dashboard at `http://localhost:9000`
2. Click **"New Project"**
3. Enter a **natural language prompt** describing your target:

```
Perform a comprehensive security assessment of https://testphp.vulnweb.com/

Scope: 
- Test only vulnweb.com domain
- Exclude /logout and /password-reset paths

Focus on:
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Authentication bypass
- Information disclosure

Rate limit: Maximum 10 requests per second
```

4. Click **"Create & Start Scan"**
5. Monitor progress in real-time via the dashboard

### Dashboard Views

| View | Description |
|------|-------------|
| **Projects** | List all projects with status |
| **Scan** | Real-time agent activity and phase progress |
| **Findings** | Discovered vulnerabilities with severity |
| **Site View** | Sitemap with endpoint annotations |
| **HTTP History** | Raw request/response viewer |

---

## 📡 API Reference

### Authentication

```bash
# Login
curl -X POST http://localhost:9000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@redstrike.ai", "password": "your-password"}'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}
```

### Projects

```bash
# Create Project
curl -X POST http://localhost:9000/api/projects/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Project",
    "target_url": "https://example.com",
    "prompt": "Test for XSS and SQLi vulnerabilities"
  }'

# Start Scan
curl -X POST http://localhost:9000/api/projects/1/start \
  -H "Authorization: Bearer <token>"

# Get Findings
curl http://localhost:9000/api/projects/1/findings \
  -H "Authorization: Bearer <token>"

# Export Report
curl http://localhost:9000/api/projects/1/export \
  -H "Authorization: Bearer <token>" > report.csv
```

### Full API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate user |
| `/api/auth/register` | POST | Register new user (admin only) |
| `/api/auth/me` | GET | Get current user info |
| `/api/projects/` | GET | List all projects |
| `/api/projects/` | POST | Create new project |
| `/api/projects/{id}` | GET | Get project details |
| `/api/projects/{id}/start` | POST | Start scan |
| `/api/projects/{id}/pause` | POST | Pause scan |
| `/api/projects/{id}/findings` | GET | List findings |
| `/api/projects/{id}/endpoints` | GET | List discovered endpoints |
| `/api/projects/{id}/sitemap` | GET | Get sitemap tree |
| `/api/projects/{id}/history` | GET | Get HTTP history |
| `/api/projects/{id}/export` | GET | Export as CSV |
| `/ws/projects/{id}` | WebSocket | Real-time updates |

---

## 🔧 Tools Included

### Kali Linux Container

| Category | Tools |
|----------|-------|
| **Reconnaissance** | subfinder, httpx, nmap, whatweb, wafw00f, amass |
| **Content Discovery** | ffuf, gobuster, feroxbuster, katana, waybackurls |
| **Vulnerability Scanning** | nuclei, nikto |
| **Web Fuzzing** | sqlmap, dalfox, arjun, paramspider |
| **Wordlists** | SecLists (common, directories, passwords, fuzzing) |

### How Tools Execute

1. Agent decides which tool to use based on the task
2. Tool command is sent to the Kali container via Docker SDK
3. Output is parsed and structured by the agent
4. Findings are saved to the database

---

## 📚 Knowledge Base

Enhance agent capabilities with custom skill files:

```
skills/
├── reconnaissance/
│   ├── subdomain_enum.md
│   └── port_scanning.md
├── vulnerabilities/
│   ├── xss_testing.md
│   ├── sqli_testing.md
│   ├── ssrf_testing.md
│   └── idor_testing.md
└── exploitation/
    └── poc_templates.md
```

### Skill File Format

```markdown
# XSS Testing

## Description
Cross-Site Scripting (XSS) testing methodology...

## Techniques
1. Reflected XSS - Test search forms, URL parameters
2. Stored XSS - Test comments, profiles, messages
3. DOM XSS - Analyze JavaScript sinks and sources

## Payloads
- `<script>alert(1)</script>`
- `"><img src=x onerror=alert(1)>`
- `javascript:alert(1)`

## Tools
- dalfox -u URL -p param
- Use browser DevTools for DOM analysis
```

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Development Setup

```bash
# Local development (without Docker for app)
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start database and Kali container
docker-compose up -d db kali

# Run FastAPI in development mode
uvicorn app.main:app --reload --port 9000
```

---

## 📝 Roadmap / TODO

The following features are planned for future releases:

### 🔴 High Priority

| Task | Description | Status |
|------|-------------|--------|
| **Alembic Migrations** | Set up database migrations for schema versioning | ⏳ Pending |
| **Proxy Integration** | Run mitmproxy as separate process, connect callbacks to ScanService for HTTP history | ⏳ Pending |
| **Agent Output Parsing** | Improve parsing of agent outputs to create structured Finding and Endpoint records | ⏳ Pending |
| **Error Handling** | Add comprehensive error handling for agent failures and tool execution errors | ⏳ Pending |

### 🟡 Medium Priority

| Task | Description | Status |
|------|-------------|--------|
| **Test Coverage** | Add unit tests for agents, tools, and API endpoints using pytest | ⏳ Pending |
| **Rate Limiting** | Implement actual rate limiting enforcement based on project config | ⏳ Pending |
| **Scope Validation** | Enhanced scope checking before tool execution | ⏳ Pending |
| **Token Refresh** | Implement JWT token refresh flow in frontend | ⏳ Pending |
| **Docker Image Optimization** | Multi-stage builds, smaller Kali image with only needed tools | ⏳ Pending |

### 🟢 Nice to Have

| Task | Description | Status |
|------|-------------|--------|
| **More Skill Files** | Add skills for OWASP Top 10, framework-specific testing (Django, Flask, Spring) | ⏳ Pending |
| **PDF Report Export** | Generate PDF reports in addition to Markdown/CSV | ⏳ Pending |
| **Scheduled Scans** | Allow scheduling scans for specific times | ⏳ Pending |
| **Team Collaboration** | Multiple users working on same project with comments | ⏳ Pending |
| **Vulnerability Templates** | Pre-defined templates for common vulnerability types | ⏳ Pending |
| **Custom Tool Integration** | Allow adding custom tools without modifying code | ⏳ Pending |
| **Notification System** | Email/Slack notifications for findings | ⏳ Pending |
| **Dashboard Charts** | Severity distribution, vulnerability trends over time | ⏳ Pending |

### 🔧 Technical Debt

| Task | Description | Status |
|------|-------------|--------|
| **CodeAgent Sandboxing** | Run smolagents CodeAgent generated Python in Docker sandbox | ⏳ Pending |
| **Logging Improvements** | Structured JSON logging, log aggregation support | ⏳ Pending |
| **API Pagination** | Add pagination to list endpoints (findings, endpoints, history) | ⏳ Pending |
| **Caching** | Add Redis caching for frequently accessed data | ⏳ Pending |
| **Health Checks** | Add Docker health checks and `/health` endpoint | ⏳ Pending |
| **CI/CD Pipeline** | GitHub Actions for testing, linting, and Docker builds | ⏳ Pending |

### 📋 Known Issues

| Issue | Description | Workaround |
|-------|-------------|------------|
| **Ollama in Docker** | Ollama running on host requires `host.docker.internal` URL | Auto-replaced in code |
| **smolagents API changes** | Library API evolves frequently | Pin version in requirements |
| **Long scans timeout** | Very long scans may hit timeouts | Pause and resume |

---

## ⚠️ Security Notice

> **WARNING**: This tool is designed for **authorized security testing only**.

- ✅ Only test systems you have **explicit permission** to test
- ✅ Respect **scope boundaries** defined in your engagement
- ✅ Follow **responsible disclosure** practices
- ✅ Comply with all applicable **laws and regulations**

**The developers are not responsible for misuse of this tool.**

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [smolagents](https://github.com/huggingface/smolagents) - AI Agent framework
- [LiteLLM](https://github.com/BerriAI/litellm) - Universal LLM API
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Kali Linux](https://www.kali.org/) - Security tools platform
- [SecLists](https://github.com/danielmiessler/SecLists) - Security wordlists

---

<p align="center">
  Built with ❤️ for the security community
</p>
