# a WIP of Some Cybersecurity Tools

Documentation site source: [`docs/`](docs/) (configured for GitHub Pages publishing from `main` `/docs`).

Categories:
- 🔵 Blue
- 🔴 Red
- 🟢 Green
- 🟣 Purple
- 🔎 Detection Engineering
- 🪪 Identity
- 🔑 Password
- ✉ Email
- 🔏 Privacy
- 🕸️ Web
- 💻 Endpoint
- ⛳ Vulnerability
- 👩‍💻 Open Source
- 🕹️ Games
- 📝 Reports
- 🛣️ Network

------------

## Blue

🪪 Identity
- Breached?
  1. Check if pawned https://haveibeenpwned.com/

- MFA Tokens
  1. Just use a good one (Google, Duo, Microsoft, etc). https://www.cisa.gov/MFA

🔑 Password
- Manager
  1. Keypass https://keepass.info/
  2. Bitwarden https://bitwarden.com (open source, end-to-end encrypted; prefer signed native CLI binaries over npm, since @bitwarden/cli 2026.4.0 was malicious, CVE-2026-42994)

  others cloud-based (more prone to security issues)

✉ Email
- Email Header Analysis
  1. https://mxtoolbox.com/EmailHeaders.aspx
  2. https://mha.azurewebsites.net/

- Phishing Simulation
  1. Gophish: https://getgophish.com/

🛣️ Network
- Network Sniffing
  1. Wireshark https://www.wireshark.org/
  2. TCP Dump (https://www.geeksforgeeks.org/tcpdump-command-in-linux-with-examples/)

🔏 Privacy
- Navigation
  1. TOR https://www.torproject.org/

- Get stuff off search
  1. Recommendations from CISA: https://www.cisa.gov/publication/stuff-off-search

- Operating System (more from this list: https://www.techradar.com/news/best-linux-distro-privacy-security)
  1. Qubes OS https://www.qubes-os.org/
  2. Tails https://tails.net/

- Device debloat / anti-telemetry
  1. CleanYourTV https://cleanyour.tv/ (open-source Android/Google TV debloat and launcher for personal home devices; review package lists, secure ADB afterward, and avoid third-party APK mirrors)

🕸️ Web
- URL Scan
  1. https://urlscan.io/

- Web application firewall and runtime security
  1. WAFio 2.0 https://wafio.cloud/blog/wafio-2-released-rust-waf-agent-open-source (most components are now source-available under GPL licenses, including the [Rust reverse-proxy agent](https://github.com/Wafio/wafio-agent-waf); v2 removes OWASP CRS in favor of WAFio's semantic engines, so treat published performance figures as vendor-run and tune in log mode before blocking)

💻 Endpoint
- Endpoint EDR
  1. Microsoft Defender https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-endpoint

⛳ Vulnerability
- Vulnerability Scanner
  1. OpenVaS : https://openvas.org/

- Exploited Vulnerabilities
  1. CISA Known Exp. Vuln: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

👩‍💻 Open Source
- Free tools
  1. SANS faculty free tools - more than 150 tools developed by SANS instructors: https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/bltd8ba96a0fce78883/Free_Faculty_Tools.pdf

- Application security (SAST)
  1. ElectroNG https://blog.doyensec.com/2026/10/27/electrong-oss.html (Electron app scanner, Apache-2.0; detections last substantially updated in 2024, may be noisy on recent Electron)
  2. GitHub code scanning for AI applications https://github.blog/changelog/2026-10-28-code-scanning-for-ai-applications-in-public-preview/ (public-preview pull-request checks for indirect prompt injection, sensitive-data exposure, and excessive agency; requires GitHub Advanced Security)
  3. CodeCheck by CommBank https://github.com/Commonwealth-Bank-of-Australia/CodeCheck (MIT; Claude Code and Codex plugin for AI-assisted static security review; one-time unsupported release—run in an isolated environment, review every finding, and account for code sent to the model provider)
  4. Semgrep Community Edition https://github.com/semgrep/semgrep (LGPL-2.1 engine; local pattern and taint analysis across many languages; rule packs and proprietary Pro/platform components have separate terms, and CE cross-file/function limits must be understood)
  5. Claude Code Security Review https://github.com/anthropics/claude-code-security-review (MIT GitHub Action and prompt for contextual, diff-aware review; invokes Claude Code and can comment on pull requests or upload artifacts; not a replacement for tests or human AppSec)

- Software composition analysis (SCA)
  1. OSV-Scanner https://github.com/google/osv-scanner (Apache-2.0; scans dependency manifests, lockfiles, supported artifacts, and container packages against OSV advisories; results depend on extraction, version mapping, and advisory coverage and do not prove exploitability)

- CI/CD security
  1. zizmor https://github.com/zizmorcore/zizmor (MIT Rust static analyzer for GitHub Actions, Dependabot, and pre-commit configuration; a clean report does not prove referenced actions are benign)

- AI agent security
  1. NVIDIA SkillSpector https://github.com/NVIDIA/SkillSpector (Apache-2.0 scanner for agent skills and MCP tools; static analysis with optional LLM review and SARIF output)
  2. Cisco Project Quarry https://github.com/cisco-ai-defense/project-quarry (Apache-2.0 detection language and runtime for agent messages, tool use, and multi-step behavior; alpha)
  3. NVIDIA SkillEvaluator https://github.com/NVIDIA/SkillEvaluator (Apache-2.0 quality, security, compatibility, and runtime evaluation for agent skills; advisory and model-based results do not prove a skill safe)
  4. Cloudflare security-audit-skill https://github.com/cloudflare/security-audit-skill (MIT coding-agent audit workflow with JavaScript validators and Markdown skill files; not a standalone scanner, and no independent effectiveness benchmark is established here)
  5. Strands Box https://github.com/strands-agents/box (Apache-2.0 preview sandbox with default-deny policy controls for files, commands, network, and MCP calls; its [Nov 2026 update](https://strandsagents.com/blog/strands-box-cli/) adds Claude Code, Codex, and Kiro CLI profiles; routed credentials stay outside the agent, but project secrets remain readable if policy permits them)
  6. Nox https://github.com/Nox-HQ/nox (Apache-2.0 polyglot scanner for AI applications, MCP configurations, dependencies, IaC, secrets, and CI workflows; [v1.70.0](https://github.com/Nox-HQ/nox/releases/tag/v1.70.0) adds hidden-instruction checks for MCP tool descriptions and GitHub Actions cache-poisoning and pwn-request checks; validate findings and remediation locally)

- Secrets hygiene
  1. omerta https://github.com/shcherbak-ai/omerta (MIT; checks whether values from untracked env files appear in staged changes, tracked files, or git history)
  2. GitHub secret scanning on demand https://github.blog/changelog/2026-11-17-secret-scanning-on-demand-for-developers-and-agents/ (public preview for Copilot security review; opt-in, scans current changes rather than repository history, and may consume Secret Protection AI credits)
  3. Gitleaks https://github.com/gitleaks/gitleaks (MIT CLI; pattern/entropy-based offline secret detection for Git history, directories, and stdin with configurable rules, baselines, redaction, and SARIF/JSON output; the separate Gitleaks Action may have different terms)

- Cloud security assessment
  1. CISA ScubaGear and ScubaGoggles https://www.cisa.gov/news-events/news/cisa-publishes-significant-updates-scubagear-and-scubagoggles (M365 and Google Workspace secure-configuration baseline assessment tools; v2.0/v1.1.0)

- Linux runtime protection
  1. Shirudo https://github.com/shirudo-dev/shirudo (BSD-2-Clause pre-release eBPF security platform from OpenAI and Cisco for signed live mitigations and TPM-measured verification; production targets currently require its kernel patches, signed-loader ABI, and TPM 2.0, and vendor demonstrations are not independent validation)

- Linux DFIR
  1. Iwatobi https://github.com/Yamato-Security/iwatobi (AGPL-3.0 native Sigma scanner and timeline generator for Linux text logs; first release Oct 2026, validate in your environment)

- Deception
  1. ReD-Pot Community Edition https://github.com/RedSideSecurity/ReD-Pot (MIT internal-network decoys, honeytokens, and attack-path console; Community Edition is limited to three decoys and supports fresh installs only)

📝 Reports
- Monthly News and reports
  1. In this repo and on this blog: https://medium.com/@andrecamillo

------------

## Red

🪪 Identity
- Social Media finder
  1. Sherlock https://github.com/sherlock-project/sherlock

🔑 Password
- Dictionaries for auditing
  1. Rockyou2021 https://gitlab.com/5amu/rockyou2021

✉ Email
- Email writer 😯
  1. ChatGPT https://chatgpt.com/

🔏 Privacy
- Navigation
  1. TOR https://www.torproject.org/

- Operating System (more from this list: https://www.techradar.com/news/best-linux-distro-privacy-security)
  1. Qubes OS https://www.qubes-os.org/
  2. Tails https://tails.net/

🕸️ Web
- Web testing
  1. Burp Suite https://portswigger.net/burp
  2. Nmap https://nmap.org/
  3. Nuclei https://github.com/projectdiscovery/nuclei (MIT template-driven active scanner for HTTP/API, TCP, DNS, TLS, and other protocols; templates and cloud may have distinct terms; authorized targets only, and the README's "zero false positives" statement is a vendor claim)
  4. Reverse API Engineer (rae) https://github.com/kalil0321/reverse-api-engineer (MIT Python CLI; HIGH RISK: captured HAR data, including cookies or tokens, is sent to the configured LLM; it drives a real Chrome profile by default and uses playwright-stealth evasion—use only on systems you own or are authorized to assess, in an isolated VM, with ToS and legal review; Portuguese Cauhi guide: https://cauhi.com/pt-br/learn/reverse-api-engineer)

- AI pentesting agents (authorized targets only)
  1. Strix https://github.com/usestrix/strix (run in an isolated VM; avoid 1.0.0–1.0.2, CVE-2026-15519)
  2. Shannon https://github.com/KeygraphHQ/shannon (AGPL-3.0; executes real exploits—use only against non-production apps you own or have explicit written authorization to test)

- Secret validation (authorized incident response only)
  1. TruffleHog https://github.com/trufflesecurity/trufflehog (AGPL-3.0 v3; older versions differ and the enterprise product is separate; can verify credentials against live service APIs and analyze permissions—never test credentials found in public code without explicit authorization)

- LLM red-teaming (authorized systems only)
  1. NVIDIA garak https://github.com/NVIDIA/garak (Apache-2.0 tool code; models, datasets, and providers have separate terms; modular probes and detectors test LLM applications, but outcomes are probe- and detector-dependent and do not certify model safety)

- Directory assessment (authorized environments only)
  1. BloodHound Community Edition https://github.com/SpecterOps/BloodHound (v9.10 adds an extension marketplace and AD CS ESC11/ESC16 analysis; protect collected relationship data and use matching collectors)

🕹️ Games
- Simulation
  1. Hacking Simulator: https://store.steampowered.com/app/1754840/Hacker_Simulator/

- Open World
  1. Watch Dog Series: https://www.ubisoft.com/en-us/game/watch-dogs/watch-dogs

------------

## Green

👩‍💻 Open Source
- Threat intelligence and community sharing
  1. MISP https://www.misp-project.org/ (2.5.52 is a major security release requiring Python 3.11+; Modules 3.1.5 adds DFIR, threat-hunting, KQL/YARA, and STIX 2.1 integrations—validate imported mappings and provenance)

- OSINT dashboards
  1. Crucix https://github.com/calesthio/Crucix (local research only; no auth by default, bind to 127.0.0.1)

- Agentic attack intelligence and detections
  1. ThreatDefence Agentic Attack Detections https://github.com/ThreatDefence/agentic-attack-detections (MIT multi-format rules and indicators; all rules are experimental and have not been tested against captured real intrusions)

------------

## Purple

💻 Endpoint
- Adversary emulation and detection validation
  1. Atomic Red Team https://github.com/redcanaryco/atomic-red-team
  2. Apache Caldera https://caldera.apache.org/ ([demo in this repo](Demos/README.md))

👩‍💻 Open Source
- Adversary behavior knowledge base
  1. MITRE ATT&CK https://attack.mitre.org/

------------

## Detection Engineering

### KQL
- Language reference and query examples
  1. Kusto Query Language overview https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric
  2. [MDEASM High Vulnerabilities](Vendors/Microsoft/Sentinel/KQL/MDEASM_HighVulnerabilities)
  3. [Local-time conversion](Vendors/Microsoft/Sentinel/KQL/localtime)

### CQL (CrowdStrike)
- Language reference
  1. CrowdStrike Query Language https://library.humio.com/crowdstrike-query-language/cql.html

### Splunk
- Language reference
  1. Search Processing Language (SPL) https://help.splunk.com/en/splunk-enterprise/spl-search-reference

- Published detections
  1. PHP2Shell analytic story (Splunk Threat Research Team) https://research.splunk.com/stories/php2shell/
