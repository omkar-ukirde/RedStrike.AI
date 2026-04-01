# RedStrike.AI — System Architecture

> Detailed architecture document for RedStrike.AI, an autonomous penetration testing platform built on the **LangGraph Deep Agents** framework.

**Version:** 1.0.0  
**Last Updated:** April 2026  
**Author:** Omkar Ukirde

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Technology Stack](#2-technology-stack)
3. [Deployment Topology](#3-deployment-topology)
4. [LangGraph Deep Agent Architecture](#4-langgraph-deep-agent-architecture)
5. [StateGraph & Conditional Routing](#5-stategraph--conditional-routing)
6. [Subagent Breakdown](#6-subagent-breakdown)
7. [Skill System (Progressive Disclosure)](#7-skill-system-progressive-disclosure)
8. [LLM Router (Multi-Provider)](#8-llm-router-multi-provider)
9. [Tool Execution Pipeline](#9-tool-execution-pipeline)
10. [Database Schema](#10-database-schema)
11. [API Layer](#11-api-layer)
12. [Real-time Communication](#12-real-time-communication)
13. [Scan Lifecycle & Data Flow](#13-scan-lifecycle--data-flow)
14. [Security Design](#14-security-design)
15. [Frontend Architecture](#15-frontend-architecture)
16. [Key Design Decisions](#16-key-design-decisions)

---

## 1. System Overview

RedStrike.AI is a **3-container microservice** application that automates web penetration testing using AI agents. A user provides a natural language prompt ("Test example.com for SQL injection and XSS"), and the system:

1. **Parses** the prompt to extract target URL, scope, authentication, and rate limits
2. **Plans** an attack strategy across 5 testing phases
3. **Executes** 30+ security tools in an isolated Kali Linux container
4. **Verifies** findings with a two-step verification process and PoC generation
5. **Reports** results with reproduction steps and Python exploit code

```mermaid
graph TB
    User["👤 User<br/>(Browser)"] -->|REST + WebSocket| App["🖥️ FastAPI App<br/>(Port 9000)"]
    App -->|SQL| DB["🗄️ PostgreSQL<br/>(Port 5432)"]
    App -->|Docker SDK<br/>exec_run()| Kali["🐉 Kali Linux<br/>(30+ Tools)"]
    App -->|HTTP| LLM["🧠 LLM Provider<br/>(Ollama/OpenAI/...)"]
    App -->|File I/O| Skills["📚 Skills<br/>(46 SKILL.md files)"]

    style App fill:#e74c3c,color:#fff
    style DB fill:#3498db,color:#fff
    style Kali fill:#2ecc71,color:#fff
    style LLM fill:#9b59b6,color:#fff
    style Skills fill:#f39c12,color:#fff
```

---

## 2. Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Web Framework** | FastAPI 0.115+ | Async REST API + WebSocket + static file serving |
| **Agent Framework** | LangGraph 0.2+ | Deep Agents — `StateGraph`, `create_react_agent`, conditional routing |
| **LLM Integration** | LangChain Core 0.3+ | Tool bindings, message types, chat model abstractions |
| **LLM Providers** | LangChain-Ollama/OpenAI/Anthropic/Groq/Google | Provider-specific ChatModel implementations |
| **Database** | PostgreSQL 16 + SQLAlchemy 2.0 (async) | Persistent storage with `asyncpg` driver |
| **Auth** | python-jose + passlib (bcrypt) | JWT-based authentication |
| **Tool Execution** | Docker SDK (Python) | Execute commands in Kali container via `docker.sock` |
| **Proxy** | mitmproxy 10.2+ | HTTP request/response interception (planned) |
| **Frontend** | Vanilla HTML/CSS/JS | Single-page dashboard served as static files |
| **Containerization** | Docker Compose | 3-container orchestration |

### Python Dependencies (Key)

```
langgraph>=0.2.0          # Deep Agent orchestration
langchain-core>=0.3.0     # LLM abstractions
langchain-ollama>=0.2.0   # Ollama provider
langchain-openai>=0.2.0   # OpenAI/Azure/vLLM/Together
langchain-anthropic>=0.2.0
langchain-groq>=0.2.0
langchain-google-genai>=2.0.0
fastapi>=0.115.2
sqlalchemy[asyncio]>=2.0.25
docker>=7.0.0
litellm>=1.55.0
```

---

## 3. Deployment Topology

```mermaid
graph LR
    subgraph Docker["Docker Compose Network (redstrike-network)"]
        subgraph AppContainer["redstrike-app"]
            FastAPI["FastAPI<br/>:9000"]
            AgentGraph["LangGraph<br/>Deep Agents"]
            SkillLoader["Skill Loader"]
            DockerExec["Docker Executor"]
        end

        subgraph DBContainer["redstrike-db"]
            Postgres["PostgreSQL 16<br/>:5432"]
        end

        subgraph KaliContainer["redstrike-kali"]
            Tools["nmap, nuclei,<br/>sqlmap, ffuf,<br/>dalfox, katana,<br/>nikto, subfinder..."]
            SecLists["SecLists<br/>Wordlists"]
        end
    end

    Host["Host Machine"] -->|:9000| FastAPI
    Host -->|:5432| Postgres
    FastAPI -->|asyncpg| Postgres
    DockerExec -->|docker.sock<br/>exec_run()| KaliContainer
    AgentGraph -->|HTTP| LLM["LLM Provider<br/>(localhost:11434<br/>or cloud API)"]

    style AppContainer fill:#e74c3c,color:#fff
    style DBContainer fill:#3498db,color:#fff
    style KaliContainer fill:#27ae60,color:#fff
```

### Volume Mounts

| Container | Mount | Purpose |
|-----------|-------|---------|
| `redstrike-app` | `.:/app` | Application code (hot-reload) |
| `redstrike-app` | `./skills:/app/skills` | Skill files |
| `redstrike-app` | `/var/run/docker.sock` | Docker SDK access to Kali container |
| `redstrike-db` | `postgres_data:/var/lib/postgresql/data` | Persistent database storage |
| `redstrike-kali` | `kali_data:/data` | Tool output storage |
| `redstrike-kali` | `./skills:/skills:ro` | Read-only skill files |

---

## 4. LangGraph Deep Agent Architecture

RedStrike uses the **LangGraph Deep Agents** pattern — a hierarchical multi-agent system where:

- The **Orchestrator** is the entry point that plans and coordinates
- **12 Subagents** are specialized `create_react_agent` instances
- A **StateGraph** manages state flow and conditional phase transitions
- **pre_model_hook** handles context window management
- **Skills** are injected into system prompts using progressive disclosure

```mermaid
graph TD
    Entry["Entry Point"] --> Orch["🎯 Orchestrator<br/>(parse prompt, create plan)"]

    Orch -->|"recon enabled"| NR["🔭 Network Recon"]
    Orch -->|"skip to discovery"| ED["📂 Endpoint Discovery"]
    Orch -->|"skip to testing"| IT["💉 Injection Tester"]

    NR --> WR["🌐 Web Recon"]
    WR -->|"code_url?"| CA["📝 Code Analyzer"]
    WR -->|"discovery"| ED
    WR -->|"skip to testing"| IT
    WR -->|"skip to report"| RP["📄 Reporter"]

    CA --> ED
    ED --> PD["🔍 Param Discovery"]
    PD -->|"testing"| IT
    PD -->|"skip to report"| RP

    IT --> AT["🔐 Auth Tester"]
    AT --> CT["⚙️ Config Tester"]
    CT --> LT["🧩 Logic Tester"]
    LT --> VS["🛡️ Vuln Scanner"]
    VS -->|"findings exist"| VF["✅ Verifier<br/>(Two-Step PoC)"]
    VS -->|"no findings"| RP

    VF --> RP
    RP --> End["END"]

    style Orch fill:#e74c3c,color:#fff
    style NR fill:#3498db,color:#fff
    style WR fill:#3498db,color:#fff
    style CA fill:#3498db,color:#fff
    style ED fill:#2ecc71,color:#fff
    style PD fill:#2ecc71,color:#fff
    style IT fill:#e67e22,color:#fff
    style AT fill:#e67e22,color:#fff
    style CT fill:#e67e22,color:#fff
    style LT fill:#e67e22,color:#fff
    style VS fill:#e67e22,color:#fff
    style VF fill:#9b59b6,color:#fff
    style RP fill:#1abc9c,color:#fff
```

### Why Deep Agents?

| Traditional Approach | Deep Agents Approach (RedStrike) |
|---------------------|----------------------------------|
| Single monolithic agent with all tools | Orchestrator delegates to specialized subagents |
| One shared context window | Each subagent has its own context with `pre_model_hook` trimming |
| All knowledge loaded at once | Progressive disclosure loads skills on demand |
| One model for everything | Per-agent LLM routing — right model for the right task |
| No state persistence | `ScanState` TypedDict enables pause/resume |

---

## 5. StateGraph & Conditional Routing

### ScanState Schema

The `ScanState` TypedDict is the central data structure flowing through all agents:

```mermaid
classDiagram
    class ScanState {
        +list messages            «Annotated[add_messages]»
        +TargetConfig target
        +ScanConfig scan_config
        +str current_phase
        +list~str~ phase_history
        +ReconResults recon_results
        +DiscoveryResults discovery_results
        +list~Finding~ potential_findings
        +list~Finding~ verified_findings
        +list~Finding~ false_positives
        +str final_report
        +list~dict~ errors
    }

    class TargetConfig {
        +str url
        +dict scope
        +dict credentials
        +str code_url
        +dict rate_limit
    }

    class ScanConfig {
        +str scan_mode
        +bool network_recon
        +bool web_recon
        +bool code_analysis
        +bool endpoint_discovery
        +bool param_discovery
        +bool injection_testing
        +bool auth_testing
        +bool config_testing
        +bool logic_testing
        +bool vuln_scanning
    }

    class Finding {
        +str id
        +str title
        +str severity
        +str vulnerability_type
        +str affected_url
        +str affected_parameter
        +str description
        +str evidence
        +str verification_status
        +list~str~ poc_steps
        +str poc_code
        +str owasp_category
    }

    ScanState --> TargetConfig
    ScanState --> ScanConfig
    ScanState --> Finding
```

### Conditional Routing Logic

The graph uses **conditional edges** to skip phases dynamically:

```python
# From orchestrator — choose first phase
orchestrator → [recon?] → network_recon
             → [discovery?] → endpoint_discovery
             → [testing?] → injection_tester

# From web_recon — choose next phase
web_recon → [code_url?] → code_analyzer
          → [discovery?] → endpoint_discovery
          → [testing?] → injection_tester
          → reporter  # skip everything

# From vuln_scanner — verification gate
vuln_scanner → [findings?] → verifier
             → reporter  # no findings to verify
```

Each routing function inspects the `ScanConfig` booleans to determine which phases to run. This means a user can configure a scan to run only reconnaissance, or only injection testing, and the graph adapts.

### Scan Modes

| Mode | Description | Enables |
|------|-------------|---------|
| **Blackbox** | No credentials, no source code | All external testing phases |
| **Greybox** | Credentials provided | Blackbox + authenticated testing |
| **Whitebox** | Credentials + source code URL | Greybox + code_analyzer subagent |

---

## 6. Subagent Breakdown

Each subagent is created by the `create_skill_aware_subagent()` factory:

```python
agent = create_skill_aware_subagent(
    model=get_model_for_agent("injection_tester"),  # Per-agent model
    tools=INJECTION_LANGCHAIN_TOOLS,                # LangChain tools
    skill_categories=["web/a03-injection", "injection"],  # Skill context
    base_prompt=INJECTION_TESTER_PROMPT,            # Role-specific prompt
    max_context_messages=20,                         # Context window limit
)
```

### Subagent Details

| Subagent | Model (Default) | Tools | Skills | Output |
|----------|----------------|-------|--------|--------|
| `network_recon` | mistral:7b | subfinder, nmap, httpx | network/reconnaissance | Subdomains, ports, services |
| `web_recon` | mistral:7b | whatweb, wafw00f | network/recon, web/a05, configuration | Technologies, WAF, headers |
| `code_analyzer` | qwen2.5-coder:14b | — | web/a03-injection, web/a08 | Code vulnerabilities (whitebox) |
| `endpoint_discovery` | mistral:7b | ffuf, katana, gobuster | reconnaissance | Directories, endpoints, URLs |
| `param_discovery` | mistral:7b | arjun, paramspider | reconnaissance | Hidden params, API endpoints |
| `injection_tester` | qwen2.5-coder:14b | sqlmap, dalfox, curl | web/a03, web/xss, injection | XSS, SQLi, SSRF, XXE, RCE, SSTI |
| `auth_tester` | qwen2.5:7b | curl | web/a07, web/a01, authentication | IDOR, auth bypass, JWT, sessions |
| `config_tester` | qwen2.5:7b | curl | web/a05, configuration | Misconfigs, headers, SSL |
| `logic_tester` | qwen2.5:7b | curl | web/a04, logic | Business logic, race conditions |
| `vuln_scanner` | mistral:7b | nuclei, nikto | web/a06, vulnerabilities | CVEs, known vulns |
| `verifier` | qwen2.5-coder:20b | curl, sqlmap, dalfox | exploitation | Verified findings + PoC code |
| `reporter` | qwen2.5:7b | — | — | Markdown report |

### Context Window Management

Each subagent uses a `pre_model_hook` to prevent context overflow:

```mermaid
graph LR
    A["All Messages<br/>(potentially 100+)"] --> B["pre_model_hook"]
    B --> C["System Messages<br/>(always kept)"]
    B --> D["Most Recent N<br/>Other Messages"]
    C --> E["Trimmed Context<br/>(max 20 messages)"]
    D --> E
    E --> F["LLM Call"]
```

This is critical because security tool outputs can be very large (nmap scans, nuclei results). The hook ensures the agent never exceeds its context window while preserving the system prompt with skill knowledge.

---

## 7. Skill System (Progressive Disclosure)

The skill system follows the **Agent Skills specification** (agentskills.io) with 3-level progressive disclosure:

```mermaid
graph TD
    subgraph Level1["Level 1: Summary (~100 tokens)"]
        S1["name: xss<br/>description: XSS testing...<br/>tags: [injection, A03:2021]<br/>allowed-tools: dalfox curl"]
    end

    subgraph Level2["Level 2: Instructions (<5000 tokens)"]
        S2["Full SKILL.md body<br/>Methodologies, payloads,<br/>techniques, checklists"]
    end

    subgraph Level3["Level 3: References (on demand)"]
        S3["references/xss.md<br/>references/clickjacking.md<br/>Detailed payloads,<br/>exploitation guides"]
    end

    Level1 -->|"Agent activated"| Level2
    Level2 -->|"Agent needs detail"| Level3

    style Level1 fill:#2ecc71,color:#fff
    style Level2 fill:#f39c12,color:#fff
    style Level3 fill:#e74c3c,color:#fff
```

### Skill Loading Flow

```mermaid
sequenceDiagram
    participant SA as Subagent Factory
    participant SL as SkillLoader
    participant FS as File System

    SA->>SL: get_skill_summaries(["web/a03-injection"])
    SL->>FS: Find SKILL.md in skills/web/a03-injection/
    FS-->>SL: SKILL.md content
    SL->>SL: Parse YAML frontmatter
    SL-->>SA: {name, description, tags} (~100 tokens)

    SA->>SL: get_progressive_context(categories)
    SL->>FS: Read full SKILL.md body
    FS-->>SL: Full content
    SL->>SL: Check include_references?
    SL->>FS: Read references/*.md (if enabled)
    FS-->>SL: Reference content
    SL-->>SA: Enhanced system prompt with skills

    SA->>SA: create_react_agent(model, tools, prompt=enhanced)
```

### Skill Inventory

| Category | Skills | References | Coverage |
|----------|--------|------------|----------|
| `web/` | 11 SKILL.md | 25+ refs | OWASP A01–A10, XSS, API, File Attacks |
| `network/` | 8 SKILL.md | 30+ refs | Databases, containers, email, wireless, ICS/IoT |
| `injection/` | 7 SKILL.md | — | XSS, SQLi, SSRF, SSTI, XXE, RCE, LFI |
| `authentication/` | 2 SKILL.md | — | IDOR, JWT attacks |
| `configuration/` | 2 SKILL.md | — | CORS, security headers |
| `mobile/` | 3 SKILL.md | 3 refs | Android, iOS pentesting |
| `active-directory/` | varies | varies | AD attack techniques |
| `exploitation/` | 1 file | — | PoC templates |
| `logic/` | 1 SKILL.md | — | Race conditions |
| `reconnaissance/` | 1 file | — | Subdomain enumeration |
| `vulnerabilities/` | 4 files | — | XSS, SQLi, SSRF, IDOR testing guides |
| **Total** | **46 SKILL.md** | **113 references** | — |

---

## 8. LLM Router (Multi-Provider)

The `LLMRouter` class provides **per-agent model routing** — each of the 12 subagents can use a different LLM provider and model.

```mermaid
graph TD
    subgraph Agents["Agent Requests"]
        O["Orchestrator<br/>needs: strong reasoning"]
        IT["Injection Tester<br/>needs: code understanding"]
        V["Verifier<br/>needs: code generation"]
        R["Recon Agents<br/>needs: general"]
    end

    subgraph Router["LLM Router"]
        Config["config/llm_config.yaml"]
        Cache["Model Cache<br/>(per-agent)"]
        Factory["Model Factory"]
    end

    subgraph Providers["8 Supported Providers"]
        Ollama["Ollama<br/>(local)"]
        OpenAI["OpenAI"]
        Anthropic["Anthropic"]
        Groq["Groq"]
        Google["Google"]
        Azure["Azure"]
        Together["Together"]
        vLLM["vLLM<br/>(self-hosted)"]
    end

    O -->|"get_model('orchestrator')"| Config
    IT -->|"get_model('injection_tester')"| Config
    V -->|"get_model('verifier')"| Config
    R -->|"get_model('network_recon')"| Config

    Config --> Cache
    Cache -->|"cache miss"| Factory
    Factory --> Ollama
    Factory --> OpenAI
    Factory --> Anthropic
    Factory --> Groq
    Factory --> Google
    Factory --> Azure
    Factory --> Together
    Factory --> vLLM

    style Router fill:#9b59b6,color:#fff
```

### Configuration Resolution

```
1. Check agents.{agent_type} in llm_config.yaml
2. If not found, use default config
3. Merge agent config with defaults (agent overrides default)
4. Resolve ${ENV_VAR} references in api_key fields
5. Create provider-specific ChatModel (ChatOllama, ChatOpenAI, etc.)
6. Cache model instance for reuse
```

### Recommended Model Selection

| Task Type | Recommended Models | Why |
|-----------|-------------------|-----|
| **Orchestrator** | qwen2.5:14b, gpt-4o, claude-3-sonnet | Needs strong reasoning for planning |
| **Injection/Verifier** | qwen2.5-coder:14b, gpt-4o | Needs code understanding for payload crafting |
| **Recon/Discovery** | mistral:7b, qwen2.5:7b | Simpler tasks, faster models sufficient |
| **Reporter** | qwen2.5:7b | Text generation, any capable model works |

---

## 9. Tool Execution Pipeline

All security tools execute inside the Kali Linux Docker container. The pipeline:

```mermaid
sequenceDiagram
    participant Agent as LangGraph Agent
    participant Tool as LangChain StructuredTool
    participant Exec as DockerExecutor
    participant Kali as Kali Container

    Agent->>Agent: Decide: "I need to scan ports"
    Agent->>Tool: nmap_scan(target="example.com", ports="--top-ports 100")
    Tool->>Tool: Validate input (Pydantic schema)
    Tool->>Exec: execute_tool("nmap", "-sT -sV --top-ports 100 example.com")
    Exec->>Exec: get Docker client via docker.sock
    Exec->>Kali: container.exec_run("nmap -sT -sV --top-ports 100 example.com")
    Kali-->>Exec: stdout + stderr + exit_code
    Exec-->>Tool: {"stdout": "...", "stderr": "...", "success": true}
    Tool->>Tool: Parse output to JSON
    Tool-->>Agent: {"target": "example.com", "output": "PORT STATE...", "success": true}
    Agent->>Agent: Analyze results, decide next action
```

### DockerExecutor Details

- **Connection**: Unix socket `/var/run/docker.sock` mounted into the app container
- **Container lookup**: By name (`KALI_CONTAINER_NAME` env var, default: `redstrike-kali`)
- **Execution**: `container.exec_run(cmd)` — synchronous execution, captures stdout/stderr
- **Timeout**: Configurable per-tool (long-running tools like sqlmap need higher limits)
- **Wordlists**: Mapped to `/wordlists/SecLists/...` paths inside the Kali container

### Tool Categories

```mermaid
graph LR
    subgraph Recon["RECON_LANGCHAIN_TOOLS"]
        T1["subfinder"]
        T2["nmap_scan"]
        T3["detect_technologies"]
        T4["detect_waf"]
    end

    subgraph Discovery["DISCOVERY_LANGCHAIN_TOOLS"]
        T5["directory_bruteforce"]
        T6["crawl_website"]
    end

    subgraph Injection["INJECTION_LANGCHAIN_TOOLS"]
        T7["test_sqli"]
        T8["test_xss"]
        T9["http_request"]
    end

    subgraph Scanner["SCANNER_LANGCHAIN_TOOLS"]
        T10["nuclei_scan"]
        T11["nikto_scan"]
    end

    style Recon fill:#3498db,color:#fff
    style Discovery fill:#2ecc71,color:#fff
    style Injection fill:#e74c3c,color:#fff
    style Scanner fill:#f39c12,color:#fff
```

---

## 10. Database Schema

```mermaid
erDiagram
    User {
        int id PK
        string email UK
        string hashed_password
        enum role "admin|user"
        datetime created_at
    }

    Project {
        int id PK
        string name
        text description
        string target_url
        text prompt
        json scope_config
        json auth_config
        json rate_limit_config
        string model_name
        enum status "pending|running|paused|completed|failed"
        json state_snapshot
        int owner_id FK
        datetime created_at
        datetime updated_at
        datetime started_at
        datetime completed_at
    }

    Scan {
        int id PK
        int project_id FK
        enum agent_type "orchestrator|recon|discovery|scanner|fuzzer|verifier"
        string agent_name
        enum status "pending|running|completed|failed"
        text error
        datetime started_at
        datetime completed_at
    }

    Finding {
        int id PK
        int project_id FK
        int scan_id FK
        int endpoint_id FK
        string title
        enum severity "critical|high|medium|low|info"
        enum vulnerability_type "xss|sqli|ssrf|idor|lfi|rce|..."
        string affected_url
        string affected_parameter
        text description
        text reproduction_steps
        text poc_code
        text request_evidence
        text response_evidence
        json raw_evidence
        bool verified
        bool false_positive
        string discovered_by
        string cvss_score
        string cve_id
        datetime created_at
        datetime verified_at
    }

    Endpoint {
        int id PK
        int project_id FK
        string url
        string method
        int status_code
        string content_type
        json parameters
        json headers
        enum discovery_method "crawl|bruteforce|manual|..."
        datetime discovered_at
    }

    HTTPHistory {
        int id PK
        int project_id FK
        string method
        string url
        int status_code
        text request_headers
        text request_body
        text response_headers
        text response_body
        float response_time
        datetime timestamp
    }

    User ||--o{ Project : "owns"
    Project ||--o{ Scan : "has"
    Project ||--o{ Finding : "has"
    Project ||--o{ Endpoint : "has"
    Project ||--o{ HTTPHistory : "has"
    Scan ||--o{ Finding : "discovers"
    Endpoint ||--o{ Finding : "has"
```

### Key Design Notes

- **`state_snapshot`** (JSON): Stores the LangGraph `ScanState` for pause/resume. When a scan is paused, the current phase index and plan are serialized here.
- **`scope_config`** (JSON): Stores allowed domains, excluded paths, extracted from the user's natural language prompt by the orchestrator.
- **Cascade deletes**: Deleting a project cascades to scans, findings, endpoints, and HTTP history.
- **Finding verification**: Two booleans — `verified` (confirmed by verifier agent) and `false_positive` (manually marked by user).

---

## 11. API Layer

### Architecture

```mermaid
graph TD
    subgraph Routes["FastAPI Routers"]
        Auth["/api/auth/*<br/>login, register, me"]
        Projects["/api/projects/*<br/>CRUD + scan control"]
        Findings["/api/projects/{id}/findings/*<br/>list, detail, update"]
        Endpoints["/api/projects/{id}/endpoints/*<br/>list, sitemap, history"]
        WS["/ws/projects/{id}<br/>WebSocket"]
        Health["/api/health<br/>/api/config"]
    end

    subgraph Middleware["Middleware"]
        CORS["CORS<br/>(allow all origins)"]
        StaticFiles["StaticFiles<br/>(frontend/)"]
    end

    subgraph Auth_Layer["Authentication"]
        JWT["JWT Token<br/>(HS256, 30min expiry)"]
        Deps["get_current_user<br/>dependency"]
    end

    subgraph Services["Services"]
        ScanSvc["ScanService<br/>(BackgroundTasks)"]
        SkillSvc["SkillLoader<br/>(singleton)"]
    end

    Routes --> Auth_Layer
    Auth_Layer --> Services
    Services --> DB["PostgreSQL"]
    Services --> AgentGraph["LangGraph"]

    style Routes fill:#3498db,color:#fff
    style Auth_Layer fill:#e74c3c,color:#fff
    style Services fill:#2ecc71,color:#fff
```

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client
    participant API as FastAPI
    participant Security as Security Module
    participant DB as PostgreSQL

    Client->>API: POST /api/auth/login {email, password}
    API->>DB: SELECT user WHERE email=...
    DB-->>API: User record
    API->>Security: verify_password(plain, hashed)
    Security-->>API: True
    API->>Security: create_access_token(user_id, role)
    Security-->>API: JWT token (HS256, 30min)
    API-->>Client: {"access_token": "eyJ...", "token_type": "bearer"}

    Client->>API: GET /api/projects/ [Authorization: Bearer eyJ...]
    API->>Security: decode_token(token)
    Security-->>API: {sub: user_id, role: admin}
    API->>DB: SELECT projects WHERE owner_id=user_id
    DB-->>API: Projects list
    API-->>Client: [projects...]
```

---

## 12. Real-time Communication

### WebSocket Architecture

```mermaid
graph LR
    subgraph Backend
        ScanSvc["ScanService"] -->|broadcast| CM["ConnectionManager"]
        CM -->|per-project| WS1["WS Client 1"]
        CM -->|per-project| WS2["WS Client 2"]
    end

    subgraph Frontend
        WS1 --> Dashboard1["Dashboard Tab 1"]
        WS2 --> Dashboard2["Dashboard Tab 2"]
    end
```

The `ConnectionManager` maintains a `Dict[int, Set[WebSocket]]` — mapping project IDs to connected WebSocket clients. Events are broadcast to all clients watching a specific project.

### Event Types

| Event | Payload | Trigger |
|-------|---------|---------|
| `scan_update` | `{phase, status, message, data}` | Phase start/complete/error |
| `new_finding` | `{id, title, severity}` | Finding saved to database |
| `new_endpoint` | `{url, method, status_code}` | Endpoint discovered |
| `scan_complete` | `{findings, endpoints, duration}` | All phases complete |
| `ping`/`pong` | — | Keep-alive |

### Fallback: Async Polling

If WebSocket disconnects, the frontend can poll `GET /api/projects/{id}/status`:

```json
{
  "project_id": 1,
  "project_status": "running",
  "scan_progress": {
    "phase": "injection_testing",
    "phase_index": 3,
    "total_phases": 5,
    "status": "running",
    "message": "Running injection_testing...",
    "progress_percent": 60,
    "started_at": "2026-04-01T10:00:00",
    "updated_at": "2026-04-01T10:05:30"
  }
}
```

---

## 13. Scan Lifecycle & Data Flow

### End-to-End Data Flow

```mermaid
sequenceDiagram
    participant User
    participant API as FastAPI
    participant Orch as Orchestrator
    participant Graph as StateGraph
    participant Sub as Subagents
    participant Kali as Kali Container
    participant DB as PostgreSQL
    participant WS as WebSocket

    User->>API: POST /api/projects/ {name, prompt}
    API->>Orch: parse_prompt(prompt)
    Orch->>Orch: LLM extracts target, scope, auth, rate_limit
    Orch-->>API: {target_url, scope, auth, rate_limit}
    API->>DB: INSERT project
    API-->>User: Project created (status: pending)

    User->>API: POST /api/projects/{id}/start
    API->>API: BackgroundTasks.add_task(scan_service.run_scan)
    API-->>User: {"message": "Scan started"}

    Note over API,WS: Background execution begins

    API->>Orch: create_attack_plan(config)
    Orch-->>API: [recon, discovery, scanning, fuzzing, verification]
    API->>WS: broadcast("planning", "Creating attack plan...")

    loop For each phase in plan
        API->>DB: INSERT scan record
        API->>WS: broadcast("phase_name", "Starting...")
        API->>Sub: run_subagent(agent_type, state)
        Sub->>Kali: execute_tool(tool, args)
        Kali-->>Sub: stdout/stderr
        Sub-->>API: {findings, endpoints}
        API->>DB: INSERT findings, endpoints
        API->>WS: broadcast(new_finding / new_endpoint)
        API->>DB: UPDATE scan status
    end

    API->>DB: UPDATE project status = completed
    API->>WS: broadcast("scan_complete", summary)
```

### Pause/Resume Flow

```mermaid
sequenceDiagram
    participant User
    participant API
    participant ScanSvc as ScanService
    participant DB

    User->>API: POST /projects/{id}/pause
    API->>DB: UPDATE project SET status='paused'
    Note over ScanSvc: Next phase check sees status=PAUSED
    ScanSvc->>DB: SAVE state_snapshot (current phase index + plan)
    ScanSvc->>API: Return (scan loop exits)

    User->>API: POST /projects/{id}/start (resume)
    API->>DB: UPDATE project SET status='running'
    API->>ScanSvc: run_scan(project_id)
    ScanSvc->>DB: LOAD state_snapshot
    Note over ScanSvc: Resume from saved phase index
```

---

## 14. Security Design

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Unauthorized access** | JWT authentication on all API endpoints, WebSocket auth via token query param |
| **Tool escape** | All tools execute in isolated Kali Docker container, not on host |
| **Scope violation** | Orchestrator extracts scope from prompt, agents check scope before tool execution |
| **Credential exposure** | Admin password auto-generated on first run, JWT secret configurable |
| **Data leakage** | Projects owned per-user, all queries filter by `owner_id` |
| **Docker socket access** | Only the app container has docker.sock access (required for tool execution) |

### Authentication & Authorization

- **JWT tokens**: HS256 algorithm, 30-minute access token, 7-day refresh token
- **User roles**: `admin` and `user` (admin can register new users)
- **Per-user isolation**: All project/finding queries filtered by `owner_id`
- **Password hashing**: bcrypt via passlib

### Container Isolation

```
Host OS
└── Docker Network (redstrike-network, bridge mode)
    ├── redstrike-app    — Only has docker.sock + DB access
    ├── redstrike-db     — Only accessible within Docker network
    └── redstrike-kali   — Privileged (needed for nmap), but:
                           • No port mapping to host
                           • No docker.sock access
                           • Read-only skills mount
                           • Only accessed via exec_run()
```

---

## 15. Frontend Architecture

The current frontend is a **vanilla HTML/CSS/JS single-page application** served as static files by FastAPI.

```
frontend/
├── index.html        # Single HTML file with all views
├── css/
│   └── styles.css    # Dark theme styles
└── js/
    ├── api.js        # REST API client (fetch wrapper + JWT)
    ├── websocket.js  # WebSocket client (auto-reconnect)
    └── app.js        # View routing, event handlers, DOM manipulation
```

### View Architecture

| View | Route | Data Source |
|------|-------|-------------|
| Login | `#login` | `POST /api/auth/login` |
| Projects | `#projects` | `GET /api/projects/` |
| Project Detail | `#project/{id}` | `GET /api/projects/{id}` + WebSocket |
| Site View | `#site-view` | `GET /api/projects/{id}/sitemap` |
| Findings | `#findings` | `GET /api/projects/{id}/findings` |
| Settings | `#settings` | `GET /api/config` |

> **Note**: The frontend is planned for a major overhaul to better surface backend capabilities (scan control, charts, HTTP history, per-agent config).

---

## 16. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **LangGraph over smolagents** | Deep Agents pattern provides better separation of concerns, per-agent context management, and conditional routing |
| **Per-agent LLM routing** | Different tasks need different model strengths — use a strong coder for injection testing, a fast model for recon |
| **Skills as SKILL.md files** | Follows the agentskills.io standard, easy for non-developers to contribute knowledge |
| **Progressive disclosure** | Prevents context window overflow — only load detailed knowledge when the agent needs it |
| **Docker-based tool execution** | Isolates all security tools from the host, reproducible environment, no host dependencies |
| **PostgreSQL over SQLite** | Multi-user support, concurrent access, production-ready |
| **Vanilla frontend** | Simple to serve (FastAPI StaticFiles), no build step, easy to iterate — migration to React/Vite planned |
| **WebSocket + polling** | WebSocket for real-time experience, polling as fallback for reliability |
| **Two-step verification** | Reduces false positives — all findings go through a dedicated verifier agent before being reported as confirmed |
| **State persistence in DB** | Enables pause/resume — the scan state snapshot is saved as JSON in the project record |

---

<p align="center">
  <strong>RedStrike.AI</strong> — Built with LangGraph Deep Agents 🧠
</p>
