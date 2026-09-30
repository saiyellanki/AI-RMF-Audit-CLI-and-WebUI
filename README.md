AI-RMF-Audit-CLI
Automated CLI for Interrogating Agentic AI &amp; LLM Endpoints against ISO/IEC 4

Static GRC checklists don't catch prompt injections or privilege escalation in production agents—live technical telemetry does.

ai-rmf-audit-cli bridges the gap between compliance frameworks and API reality. Built specifically for 2LoD Risk and 3LoD IT Audit teams, this command-line utility executes automated, adversarial security evaluations against production AI endpoints to measure prompt boundary isolation, tool-use permissions, and context retention limits.

Architecture & Telemetry Pipeline

┌─────────────────────────┐      ┌──────────────────────────┐      ┌──────────────────────────┐
│    ai-rmf-audit-cli     │ ───► │   Adversarial Payload    │ ───► │ Target AI Endpoint /     │
│ (Engine & Test Suites)  │      │   Interrogator & Canary  │      │ Agentic API (MCP/REST)   │
└─────────────────────────┘      └──────────────────────────┘      └────────────┬─────────────┘
                                                                                │
                                                                                ▼
┌─────────────────────────┐      ┌──────────────────────────┐      ┌──────────────────────────┐
│   ISO 42001 / NIST AI   │ ◄─── │ SHA-256 Telemetry Logger │ ◄─── │ Model Response & Context │
│    RMF Mapping Engine   │      │   & Execution Metrics    │      │       Inspection         │
└────────────┬────────────┘      └──────────────────────────┘      └──────────────────────────┘
             │
             ▼
┌───────────────────────────────────────────────────────────┐
│   Machine-Readable Audit Evidence (audit_telemetry.json)  │
└───────────────────────────────────────────────────────────┘

Core Audit Modules
Module	Target Risk / Vector	Standard / Regulatory Mapping
System Prompt Canary Isolation	
Detects unauthorized system prompt leakage and context window exposure during adversarial jailbreaks via cryptographic canary hashes.

NIST MANAGE 2.4

ISO 42001 A.8.4

Indirect Prompt Injection	
Evaluates whether upstream data ingestion pipelines (RAG vector DBs, web search tools) leak untrusted instruction overrides into the execution context.

OWASP LLM01

Context Retention & Memory Hygiene	
Measures context retention lifetimes to verify that model endpoints purge session state in compliance with data minimization requirements.

EU AI Act Art. 10

Signed Audit Evidence	
Produces cryptographically signed, timestamped JSON execution logs ready for ingestion into Workiva IRM, ServiceNow GRC, or SIEM pipelines.

ISO 42001 A.9.2

Quickstart (Prerequisites)
  Python 3.11+
  Target LLM or Agentic API endpoint URL
  API Key / Access Token for the target environment

Installation 
  # Clone the repository
  git clone https://github.com/saiyellanki/ai-rmf-audit-cli.git
  cd ai-rmf-audit-cli
  
  # Install dependencies
  pip install -r requirements.txt

Contributing & Security
Contributions, feature requests, and security policy suggestions are welcome! Please feel free to open an issue or submit a pull request.

License
Distributed under the MIT License. See LICENSE for details.
