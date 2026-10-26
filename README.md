# a WIP of Some Cybersecurity Tools

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

🕸️ Web
- URL Scan
  1. https://urlscan.io/

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

🕹️ Games
- Simulation
  1. Hacking Simulator: https://store.steampowered.com/app/1754840/Hacker_Simulator/

- Open World
  1. Watch Dog Series: https://www.ubisoft.com/en-us/game/watch-dogs/watch-dogs

------------

## Green

👩‍💻 Open Source
- Threat intelligence and community sharing
  1. MISP https://www.misp-project.org/

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
