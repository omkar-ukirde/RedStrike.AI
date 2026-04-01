# RedStrike.AI 🎯

> Autonomous AI-powered web penetration testing platform built on **LangGraph Deep Agents**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-Deep_Agents-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![RedStrike Dashboard](docs/dashboard-preview.png)

## 🚀 Overview

RedStrike.AI is an **autonomous penetration testing platform** built on the **LangGraph Deep Agents** architecture. It uses a hierarchical multi-agent system — an orchestrator coordinating 12 specialized skill-aware subagents — to perform comprehensive security assessments. Simply describe your target in natural language, and the deep agent graph orchestrates reconnaissance, discovery, vulnerability testing, two-step verification, and reporting — all executing tools inside an isolated Kali Linux Docker container.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🧠 **LangGraph Deep Agents** | `StateGraph` with orchestrator + 12 specialized `create_react_agent` subagents, conditional routing, and `pre_model_hook` context management |
| 🎯 **OWASP Top 10 Coverage** | Dedicated subagents for injection, broken auth, misconfig, insecure design, vulnerable components, SSRF, and more |
| 📚 **Skill-Aware Agents** | 46 SKILL.md files across 11 categories with **progressive disclosure** (summary → instructions → references) per the Agent Skills specification |
| 🔧 **30+ Security Tools** | Nmap, Nuclei, SQLmap, Dalfox, ffuf, Katana, and more — all running in Kali Docker via LangChain tool wrappers |
| 🐳 **Secure Docker Execution** | All tools execute isolated in a Kali Linux container via the Docker SDK |
| 🔀 **Per-Agent LLM Routing** | Configure different models per agent via `config/llm_config.yaml` — supports Ollama, OpenAI, Anthropic, Groq, Google, Azure, Together, vLLM |
| 💬 **Natural Language Input** | Describe your test in plain English — AI parses scope, auth, rate limits, and test types |
| 📊 **Real-time Dashboard** | Live WebSocket updates with scan progress, findings, sitemap, and HTTP history |
| ✅ **Two-Step Verification** | All findings verified by a dedicated Verifier subagent with PoC generation before reporting |
| ⏯️ **Scan Lifecycle Control** | Start, pause, resume, cancel scans with async progress tracking and state persistence |
| 📈 **Report Generation** | Markdown reports with reproduction steps, Python PoC code, and CSV export |

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Deep Agent Architecture](#-deep-agent-architecture)
- [Scan Lifecycle](#-scan-lifecycle)
- [Agent Breakdown](#-agent-breakdown)
- [Skill System](#-skill-system--knowledge-base)
- [LLM Configuration](#-llm-configuration)
- [API Reference](#-api-reference)
- [Tools Included](#-tools-included)
- [Configuration](#-configuration)
- [Roadmap / TODO](#-roadmap--todo)
- [Contributing](#-contributing)
- [Security Notice](#-security-notice)

---

## 🏁 Quick Start

### Prerequisites

- **Docker & Docker Compose** (v2.0+)
- **Ollama** (for local models) OR API keys for OpenAI/Anthropic/Groq/Google
- 8GB+ RAM recommended

### Installation

```bash
# Clone the repository
git clone https://github.com/omkar-ukirde/RedStrike.AI.git
cd RedStrike.AI

# Copy environment file
cp .env.example .env

# Edit .env with your configuration
nano .env

# (Optional) Configure per-agent models
nano config/llm_config.yaml

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

## 🧠 Deep Agent Architecture

RedStrike.AI is built on the **LangGraph Deep Agents** specification — a hierarchical multi-agent system where each agent is a `create_react_agent` instance with its own model, tools, skill context, and context window management.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            WEB DASHBOARD (Port 9000)                            │
│                        HTML/CSS/JS with Real-time WebSocket                     │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ REST + WebSocket
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                          FASTAPI APPLICATION LAYER                               │
│  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐ ┌───────────┐ ┌────────┐  │
│  │  Auth   │ │ Projects │ │ Findings │ │ Endpoints │ │ WebSocket │ │ Health │  │
│  └─────────┘ └──────────┘ └──────────┘ └───────────┘ └───────────┘ └────────┘  │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                 LANGGRAPH DEEP AGENTS (StateGraph + Conditional Routing)         │
│                                                                                  │
│  ┌────────────────┐                                                              │
│  │  Orchestrator  │──── parse_prompt() ──── create_attack_plan()                │
│  │  (ReAct Agent) │                                                              │
│  └───────┬────────┘                                                              │
│          │ StateGraph conditional routing                                         │
│          ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────┐  │
│  │             12 SKILL-AWARE SUBAGENTS (create_react_agent)                   │  │
│  │                                                                             │  │
│  │  RECON          DISCOVERY         TESTING              VERIFY & REPORT     │  │
│  │  ┌───────────┐  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐   │  │
│  │  │ Network   │  │ Endpoint     │  │ Injection Tester │  │  Verifier    │   │  │
│  │  │ Recon     │→ │ Discovery    │→ │ Auth Tester      │→ │  (Two-Step)  │   │  │
│  │  │ Web Recon │  │ Param        │  │ Config Tester    │  │  Reporter    │   │  │
│  │  │           │  │ Discovery    │  │ Logic Tester     │  │              │   │  │
│  │  │           │  │ Code Analyzer│  │ Vuln Scanner     │  │              │   │  │
│  │  └───────────┘  └──────────────┘  └──────────────────┘  └──────────────┘   │  │
│  │                                                                             │  │
│  │  Each subagent has: model (LLM Router) + tools + skills + context manager  │  │
│  └─────────────────────────────────────────────────────────────────────────────┘  │
│          │                              │                          │              │
│          ▼                              ▼                          ▼              │
│  ┌──────────────┐            ┌─────────────────┐        ┌─────────────────┐     │
│  │  LLM Router  │            │   Skill Loader  │        │ LangChain Tools │     │
│  │  (8 Providers │            │  (Progressive   │        │ (StructuredTool │     │
│  │   per-agent)  │            │   Disclosure)   │        │  → Docker SDK)  │     │
│  └──────────────┘            └─────────────────┘        └────────┬────────┘     │
└──────────────────────────────────────────────────────────────────┬───────────────┘
                                                                   │
          ┌────────────────────┬───────────────────────┬───────────┘
          ▼                    ▼                         ▼
┌─────────────────┐  ┌──────────────────┐     ┌───────────────────┐
│   PostgreSQL    │  │     Skills/      │     │   Kali Linux      │
│  (Users,        │  │  (46 SKILL.md    │     │   Container       │
│   Projects,     │  │   + 113 refs     │     │  (30+ Tools)      │
│   Scans,        │  │   across 11      │     │  subfinder, nmap, │
│   Findings,     │  │   categories)    │     │  nuclei, sqlmap,  │
│   Endpoints,    │  │                  │     │  ffuf, dalfox,    │
│   HTTP History) │  │                  │     │  katana, nikto... │
└─────────────────┘  └──────────────────┘     └───────────────────┘
```

### Key Deep Agent Concepts Used

| Concept | Implementation |
|---------|---------------|
| **StateGraph** | `ScanState` TypedDict flows through all agents via `langgraph.graph.StateGraph` |
| **Conditional Routing** | Phase transitions based on scan config — skip unused phases dynamically |
| **ReAct Agents** | Each subagent is a `create_react_agent` with LangChain `StructuredTool` bindings |
| **pre_model_hook** | Context window management — trims messages while preserving system prompts |
| **Skill-Aware Prompts** | System prompts enriched with skill knowledge via progressive disclosure |
| **State Persistence** | `ScanState` snapshots stored in DB for pause/resume capability |

### Container Architecture

| Container | Purpose | Port |
|-----------|---------|------|
| `redstrike-app` | FastAPI + Deep Agent graph + Dashboard | 9000 |
| `redstrike-db` | PostgreSQL database | 5432 |
| `redstrike-kali` | Kali Linux with 30+ security tools | — |

---

## ⏯️ Scan Lifecycle

```
Create Project ──→ Parse Prompt ──→ Attack Plan ──→ Start Scan
      │                                                  │
      │            ┌──────────────────────────────────────┘
      │            ▼
      │     ┌─────────────┐    ┌──────────────┐    ┌──────────────┐
      │     │    Recon     │ →  │  Discovery   │ →  │   Testing    │
      │     │ (network +   │    │ (endpoints + │    │ (injection,  │
      │     │  web recon)  │    │  parameters) │    │  auth, etc.) │
      │     └─────────────┘    └──────────────┘    └──────┬───────┘
      │                                                    │
      │            ┌───────────────────────────────────────┘
      │            ▼
      │     ┌─────────────┐    ┌──────────────┐
      │     │ Verification │ →  │   Reporter   │ →  Complete ✓
      │     │ (Two-step    │    │ (Markdown +   │
      │     │  PoC gen)    │    │  CSV export)  │
      │     └─────────────┘    └──────────────┘
      │
      ├──→ Pause (state saved to DB) ──→ Resume
      ├──→ Cancel (stops execution)
      └──→ Delete Logs (keeps findings)
```

The scan service (`ScanService`) manages execution via FastAPI `BackgroundTasks`. Progress is tracked in-memory and broadcast to connected WebSocket clients in real-time. If WebSocket disconnects, the frontend can poll `GET /api/projects/{id}/status` as a fallback.

---

## 🤖 Agent Breakdown

Each subagent is created via `create_skill_aware_subagent()` — a factory that builds a `create_react_agent` with skill-enriched prompts, LangChain tools, and a `pre_model_hook` for context window management.

| # | Subagent | Phase | Skill Categories | Tools | Description |
|---|----------|-------|-------------------|-------|-------------|
| 1 | `network_recon` | Recon | `network/reconnaissance`, `reconnaissance` | subfinder, nmap, httpx | Port scanning, service detection, subdomain enumeration |
| 2 | `web_recon` | Recon | `network/reconnaissance`, `web/a05-*`, `configuration` | whatweb, wafw00f | Technology detection, WAF, security headers |
| 3 | `code_analyzer` | Recon | `web/a03-injection`, `web/a08-*` | — | SAST / code review (whitebox only) |
| 4 | `endpoint_discovery` | Discovery | `reconnaissance` | ffuf, katana, gobuster | Crawling, directory brute-forcing |
| 5 | `param_discovery` | Discovery | `reconnaissance` | arjun, paramspider | Hidden parameters, API endpoints |
| 6 | `injection_tester` | Testing | `web/a03-injection`, `web/xss`, `web/a10-ssrf`, `injection` | sqlmap, dalfox, curl | XSS, SQLi, SSRF, XXE, RCE, SSTI |
| 7 | `auth_tester` | Testing | `web/a07-auth-failures`, `web/a01-*`, `authentication` | curl | IDOR, auth bypass, session, JWT |
| 8 | `config_tester` | Testing | `web/a05-security-misconfiguration`, `configuration` | curl | Headers, SSL, misconfigs, secrets |
| 9 | `logic_tester` | Testing | `web/a04-insecure-design`, `logic` | curl | Business logic flaws, race conditions |
| 10 | `vuln_scanner` | Testing | `web/a06-vulnerable-components`, `vulnerabilities` | nuclei, nikto | CVE scanning, nuclei templates |
| 11 | `verifier` | Verify | `exploitation` | curl, sqlmap, dalfox | Two-step verification + Python PoC generation |
| 12 | `reporter` | Report | — | — | Markdown report generation with findings summary |

### Graph Flow (Conditional Routing)

```
Orchestrator
     │
     ├── [recon enabled?] ──→ network_recon → web_recon
     │                                            │
     │                          [code_url?] ──→ code_analyzer ─┐
     │                                                         │
     ├── [discovery enabled?] ──→ endpoint_discovery → param_discovery
     │                                                         │
     ├── [testing enabled?] ──→ injection → auth → config → logic → vuln_scanner
     │                                                                    │
     │                              [findings?] ──→ verifier ─────────────┤
     │                                                                    │
     └──────────────────────────────────── reporter ──→ END
```

Phases are skipped dynamically based on the `ScanConfig` toggles the user selects.

---

## 📚 Skill System & Knowledge Base

RedStrike uses the **Agent Skills specification** (`agentskills.io` format) with **progressive disclosure** — loading knowledge at three levels:

| Level | Content | Size | When Loaded |
|-------|---------|------|-------------|
| **1. Summary** | Name + description + tags | ~100 tokens | Agent startup |
| **2. Instructions** | Full `SKILL.md` body | <5000 tokens | Agent activated |
| **3. References** | Detailed technique files in `references/` | On demand | Agent requests detail |

### Skill Structure

```
skills/                                   # 46 SKILL.md files + 113 reference files
├── active-directory/                     # AD attack skills
├── authentication/                       # IDOR, JWT attacks
│   ├── idor/SKILL.md
│   └── jwt/SKILL.md
├── configuration/                        # CORS, headers
│   ├── cors/SKILL.md
│   └── headers/SKILL.md
├── exploitation/                         # PoC templates
├── injection/                            # XSS, SQLi, SSRF, SSTI, XXE, RCE, LFI
│   ├── xss/SKILL.md
│   ├── sqli/SKILL.md
│   ├── ssrf/SKILL.md
│   ├── ssti/SKILL.md
│   ├── xxe/SKILL.md
│   ├── rce/SKILL.md
│   └── lfi/SKILL.md
├── logic/                                # Race conditions, business logic
├── mobile/                               # Android, iOS pentesting
│   ├── android/SKILL.md + references/
│   └── ios/SKILL.md + references/
├── network/                              # Network service pentesting
│   ├── reconnaissance/SKILL.md + references/
│   ├── databases/SKILL.md + references/  # MySQL, Postgres, MongoDB, Redis...
│   ├── containers/SKILL.md + references/ # Docker, Kubernetes
│   ├── email/SKILL.md + references/
│   ├── file-services/SKILL.md + refs/
│   ├── wireless/SKILL.md + references/
│   └── industrial-iot/SKILL.md + refs/
├── reconnaissance/                       # Subdomain enum, port scanning
├── vulnerabilities/                      # XSS, SQLi, SSRF, IDOR testing
└── web/                                  # OWASP Top 10 mapped skills
    ├── a01-broken-access-control/SKILL.md
    ├── a03-injection/SKILL.md + references/
    ├── a04-insecure-design/SKILL.md
    ├── a05-security-misconfiguration/SKILL.md + references/
    ├── a06-vulnerable-components/SKILL.md + references/
    ├── a07-auth-failures/SKILL.md + references/  # JWT, OAuth, session, 2FA, password reset
    ├── a08-data-integrity-failures/SKILL.md + references/
    ├── a10-ssrf/SKILL.md + references/
    ├── api-security/SKILL.md + references/
    ├── file-attacks/SKILL.md + references/
    └── xss/SKILL.md + references/
```

### SKILL.md Format

```markdown
---
name: xss
description: Cross-Site Scripting testing methodology
version: 1.0.0
tags: [injection, client-side, A03:2021]
allowed-tools: dalfox curl
compatibility: ">=1.0.0"
---

# XSS Testing Methodology

## Types
1. Reflected XSS
2. Stored XSS
3. DOM XSS

## Payloads
...
```

Each subagent automatically loads its mapped skill categories (see [Agent Breakdown](#-agent-breakdown)) via the `SkillLoader` service, which supports `.md`, `.yaml`, `.json`, and `.txt` formats.

---

## ⚙️ LLM Configuration

RedStrike uses a **per-agent LLM routing** system. Each of the 12 subagents can use a different provider and model, configured via `config/llm_config.yaml`.

### Supported Providers

| Provider | Example Models | Config Key | Auth |
|----------|---------------|------------|------|
| Ollama | `qwen2.5:7b`, `mistral:7b`, `llama3.1` | `ollama` | None (local) |
| OpenAI | `gpt-4o`, `gpt-4-turbo` | `openai` | `OPENAI_API_KEY` |
| Anthropic | `claude-3-opus`, `claude-3-sonnet` | `anthropic` | `ANTHROPIC_API_KEY` |
| Groq | `llama-3.1-70b-versatile`, `mixtral-8x7b` | `groq` | `GROQ_API_KEY` |
| Google | `gemini-1.5-pro`, `gemini-1.5-flash` | `google` | `GOOGLE_API_KEY` |
| Azure | `gpt-4`, `gpt-35-turbo` | `azure` | `AZURE_OPENAI_API_KEY` |
| Together | `meta-llama/Llama-3-70b-chat-hf` | `together` | `TOGETHER_API_KEY` |
| vLLM | Any self-hosted model | `vllm` | None (local) |

### Per-Agent Configuration Example

```yaml
# config/llm_config.yaml

default:
  provider: "ollama"
  model: "qwen2.5:7b"
  api_base: "http://localhost:11434"
  temperature: 0.1
  max_tokens: 4096

agents:
  # Strong reasoning for orchestration
  orchestrator:
    provider: "ollama"
    model: "qwen2.5:14b"

  # Security-focused code model for injection testing
  injection_tester:
    provider: "ollama"
    model: "qwen2.5-coder:14b"

  # Strong code generation for PoC
  verifier:
    provider: "ollama"
    model: "qwen2.5-coder:20b"
    max_tokens: 8192

  # Use cloud model for orchestrator (example)
  # orchestrator:
  #   provider: "openai"
  #   model: "gpt-4o"
  #   api_key: "${OPENAI_API_KEY}"
```

Key API keys are resolved from environment variables using `${VAR}` syntax. Models are cached per-agent and reuse connections.

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

### Full API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate user |
| `/api/auth/register` | POST | Register new user (admin only) |
| `/api/auth/me` | GET | Get current user info |
| `/api/projects/` | GET | List all projects |
| `/api/projects/` | POST | Create new project (parses prompt with AI) |
| `/api/projects/{id}` | GET | Get project details |
| `/api/projects/{id}` | PATCH | Update project (name, model) |
| `/api/projects/{id}` | DELETE | Delete project |
| `/api/projects/{id}/start` | POST | Start or resume scan |
| `/api/projects/{id}/pause` | POST | Pause running scan |
| `/api/projects/{id}/cancel` | POST | Cancel running scan |
| `/api/projects/{id}/status` | GET | Get scan progress (async polling) |
| `/api/projects/{id}/findings` | GET | List findings |
| `/api/projects/{id}/findings/{fid}` | GET | Get finding details |
| `/api/projects/{id}/findings/{fid}` | PATCH | Update finding (verify/false-positive) |
| `/api/projects/{id}/endpoints` | GET | List discovered endpoints |
| `/api/projects/{id}/sitemap` | GET | Get sitemap tree |
| `/api/projects/{id}/history` | GET | Get HTTP history |
| `/api/projects/{id}/logs` | DELETE | Delete scan logs (keeps findings) |
| `/api/projects/{id}/export` | GET | Export findings as CSV |
| `/api/health` | GET | Health check |
| `/api/config` | GET | Public configuration |
| `/ws/projects/{id}` | WebSocket | Real-time updates (auth via `?token=`) |

### WebSocket Events

| Event Type | Direction | Description |
|------------|-----------|-------------|
| `scan_update` | Server → Client | Phase progress (phase, status, message) |
| `new_finding` | Server → Client | New vulnerability discovered |
| `new_endpoint` | Server → Client | New endpoint discovered |
| `scan_complete` | Server → Client | Scan finished with summary |
| `ping` / `pong` | Bidirectional | Keep-alive |

---

## 🔧 Tools Included

### Security Tools (Kali Linux Container)

| Category | Tools |
|----------|-------|
| **Reconnaissance** | subfinder, httpx, nmap, whatweb, wafw00f, amass, dnsrecon |
| **Content Discovery** | ffuf, gobuster, feroxbuster, katana, waybackurls |
| **Vulnerability Scanning** | nuclei (with templates), nikto |
| **Injection Testing** | sqlmap, dalfox |
| **Parameter Discovery** | arjun, paramspider |
| **Wordlists** | SecLists (common, directories, passwords, fuzzing) |
| **Utilities** | curl, wget, git, jq, python3 |

### LangChain Tool Wrappers

All tools are wrapped as `StructuredTool` instances with Pydantic input schemas for type-safe execution:

| Tool Name | Underlying Tool | Category |
|-----------|----------------|----------|
| `subfinder` | Subfinder | Recon |
| `nmap_scan` | Nmap | Recon |
| `detect_technologies` | WhatWeb | Recon |
| `detect_waf` | wafw00f | Recon |
| `directory_bruteforce` | ffuf | Discovery |
| `crawl_website` | Katana | Discovery |
| `test_sqli` | sqlmap | Injection |
| `test_xss` | Dalfox | Injection |
| `nuclei_scan` | Nuclei | Scanner |
| `nikto_scan` | Nikto | Scanner |
| `http_request` | curl | HTTP |

### How Tools Execute

```
Agent decides tool → LangChain StructuredTool → DockerExecutor → Kali Container
                                                      │
                                   Docker SDK exec_run() via /var/run/docker.sock
                                                      │
                                              stdout/stderr parsed → JSON result
```

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

4. Click **"Create Project"** — the AI parses your prompt into scope, auth, rate limits
5. Review the extracted configuration
6. Click **"▶ Start Scan"** to begin
7. Monitor real-time progress via WebSocket updates
8. Use **"⏸ Pause"** or **"✕ Cancel"** to control the scan
9. View findings, sitemap, and HTTP history in the dashboard
10. **Export** results as CSV or view the generated Markdown report

### Dashboard Views

| View | Description |
|------|-------------|
| **Projects** | All projects with status badges and findings count |
| **Scan Log** | Real-time agent activity with phase progress bar |
| **Findings** | Discovered vulnerabilities with severity, type, verification status |
| **Site Map** | Sitemap tree with endpoint annotations |
| **HTTP History** | Raw request/response viewer |
| **Settings** | Default model configuration |

---

## 🔐 Environment Configuration

```bash
# Database
DATABASE_URL=postgresql+asyncpg://redstrike:redstrike@db:5432/redstrike

# JWT Settings
JWT_SECRET_KEY=your-super-secret-key-change-in-production
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# LLM (fallback — per-agent config is in config/llm_config.yaml)
LITELLM_MODEL=ollama/llama3.2
OLLAMA_API_BASE=http://localhost:11434

# Optional: Cloud provider API keys
# OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
# GROQ_API_KEY=gsk-...
# GOOGLE_API_KEY=...

# Docker Settings
KALI_CONTAINER_NAME=redstrike-kali
DOCKER_NETWORK=redstrike-network

# Proxy Settings
PROXY_PORT=8080
PROXY_ENABLED=true

# Admin User (created on first run)
ADMIN_EMAIL=admin@redstrike.ai
ADMIN_PASSWORD=changeme123  # Auto-generates secure password if unchanged
```

---

## 📝 Roadmap / TODO

### 🔴 High Priority

| Task | Description | Status |
|------|-------------|--------|
| **Alembic Migrations** | Set up database migrations for schema versioning | ⏳ Pending |
| **Proxy Integration** | Run mitmproxy as separate process for HTTP history capture | ⏳ Pending |
| **Agent Output Parsing** | Improve parsing of agent outputs to create structured Finding and Endpoint records | ⏳ Pending |
| **Error Handling** | Comprehensive error handling for agent failures and tool execution errors | ⏳ Pending |
| **Frontend Overhaul** | Modernize dashboard to match backend capabilities (scan control, charts, HTTP history) | ⏳ Pending |

### 🟡 Medium Priority

| Task | Description | Status |
|------|-------------|--------|
| **Test Coverage** | Unit tests for agents, tools, and API endpoints using pytest | ⏳ Pending |
| **Rate Limiting** | Implement actual rate limiting enforcement based on project config | ⏳ Pending |
| **Scope Validation** | Enhanced scope checking before tool execution | ⏳ Pending |
| **Token Refresh** | JWT token refresh flow in frontend | ⏳ Pending |
| **Docker Image Optimization** | Multi-stage builds, smaller Kali image with only needed tools | ⏳ Pending |

### 🟢 Nice to Have

| Task | Description | Status |
|------|-------------|--------|
| **More Skill Files** | Skills for framework-specific testing (Django, Flask, Spring) | ⏳ Pending |
| **PDF Report Export** | Generate PDF reports in addition to Markdown/CSV | ⏳ Pending |
| **Scheduled Scans** | Allow scheduling scans for specific times | ⏳ Pending |
| **Team Collaboration** | Multiple users working on same project with comments | ⏳ Pending |
| **Custom Tool Integration** | Allow adding custom tools without modifying code | ⏳ Pending |
| **Notification System** | Email/Slack notifications for findings | ⏳ Pending |
| **Dashboard Charts** | Severity distribution, vulnerability trends over time | ⏳ Pending |

### ✅ Completed

| Task | Description |
|------|-------------|
| **Health Checks** | `/api/health` endpoint implemented |
| **LangGraph Migration** | Migrated from smolagents to LangGraph Deep Agents |
| **Per-Agent LLM Config** | `config/llm_config.yaml` with 8-provider routing |
| **Skill System v2** | Progressive disclosure, hierarchical categories, 46 skills |
| **Scan Control** | Pause, resume, cancel, delete logs |
| **Async Status Polling** | `GET /api/projects/{id}/status` endpoint |

### 📋 Known Issues

| Issue | Description | Workaround |
|-------|-------------|------------|
| **Ollama in Docker** | Ollama on host requires `host.docker.internal` URL | Auto-replaced in code |
| **Long scans timeout** | Very long scans may hit timeouts | Pause and resume |

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

### Project Structure

```
RedStrike.AI/
├── app/
│   ├── agents/                 # LangGraph Deep Agents
│   │   ├── graph.py            # StateGraph definition + conditional routing
│   │   ├── orchestrator.py     # Orchestrator agent (prompt parsing, planning)
│   │   ├── state.py            # ScanState TypedDict schema
│   │   ├── skill_subagent.py   # Skill-aware subagent factory
│   │   └── subagents/          # 12 specialized subagent modules
│   ├── api/                    # FastAPI route handlers
│   │   ├── auth.py, projects.py, findings.py, endpoints.py, websocket.py
│   ├── core/                   # Config, database, security
│   ├── models/                 # SQLAlchemy models + LLM router
│   ├── services/               # ScanService, SkillLoader
│   ├── tools/                  # LangChain tool wrappers + DockerExecutor
│   ├── proxy/                  # mitmproxy interceptor
│   └── main.py                 # FastAPI app entry point
├── config/
│   └── llm_config.yaml         # Per-agent LLM configuration
├── docker/
│   ├── Dockerfile.app          # Python FastAPI container
│   └── Dockerfile.kali         # Kali Linux + 30+ tools
├── frontend/                   # Vanilla HTML/CSS/JS dashboard
├── skills/                     # 11 categories, 46 skills, 113 references
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

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

- [LangGraph](https://github.com/langchain-ai/langgraph) - Deep Agents multi-agent orchestration
- [LangChain](https://github.com/langchain-ai/langchain) - LLM application framework
- [FastAPI](https://fastapi.tiangolo.com/) - Modern async web framework
- [Kali Linux](https://www.kali.org/) - Security tools platform
- [SecLists](https://github.com/danielmiessler/SecLists) - Security wordlists
- [Agent Skills](https://agentskills.io/) - Skill file specification

---

<p align="center">
  Built with ❤️ for the security community
</p>
