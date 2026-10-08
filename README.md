# ShdGuard — Passive Defensive Monitor

---

#### 🛡️ SHDGUARD — PASSIVE DEFENSIVE MONITOR

**ShdGuard** is a passive defensive monitoring tool designed to detect suspicious activity on a computer, record evidence, and attribute network incidents to the responsible **attacker IP address**.

It is deliberately defensive.

ShdGuard does **not** attempt to identify the person behind an attack, hack back, install trackers, unmask Tor/VPN users, automatically report attackers, or upload user files.

**Detect. Record. Attribute. Alert. Defend passively.**

---

#### 🎯 CORE CAPABILITIES

ShdGuard monitors for several categories of suspicious activity:

* Known botnet Command & Control (**C2**) IP connections
* New open ports
* External connections into open ports
* Programs running from Windows Temp folders and reaching external networks
* Failed Windows logons
* Attacker IP attribution
* Network owner information
* Abuse contact information
* IP reputation
* Reverse DNS
* Malware hash reputation checks
* Hash-sealed evidence files
* Draft abuse reports
* Optional phone alerts through ntfy

---

#### 🔎 BOTNET C2 DETECTION

ShdGuard checks network activity against the **abuse.ch Feodo botnet C2 list**.

When a connection matches a known C2 address, the incident can be recorded and enriched with available attribution and reputation information.

---

#### 🌐 OPEN PORT MONITORING

ShdGuard establishes a baseline of currently open ports.

It detects:

* Newly opened ports
* External connections entering open ports
* Changes from the established baseline

**Important:** the first normal run learns the computer's current open ports as its baseline.

---

#### 🖥️ SUSPICIOUS PROGRAM MONITORING

ShdGuard watches for programs executing from **Temp directories** that subsequently make network connections.

This provides a lightweight behavioral signal for potentially suspicious activity without requiring an endpoint agent or invasive inspection.

---

#### 🔐 FAILED WINDOWS LOGON MONITORING

On supported Windows configurations, ShdGuard can monitor failed Windows logon events.

The implementation uses **Windows Event ID 4625** parsing.

**Administrator privileges are required for the intended Windows failed-logon monitoring path.**

---

#### 🌍 ATTACKER IP ATTRIBUTION

ShdGuard attributes incidents to the **network-level identity available from public infrastructure data**.

For an attacker IP, available enrichment can include:

* Network owner
* Abuse contact
* RIPE information
* AbuseIPDB reputation
* GreyNoise information
* Reverse DNS
* VirusTotal malware hash lookup where configured

### ⚠️ IMPORTANT

ShdGuard attributes the **attacker IP**, not the individual person.

Public network information generally identifies the network operator, ISP, hosting provider or other infrastructure owner.

Identifying an individual behind an IP address requires appropriate legal, police, CERT or ISP/hosting-provider processes.

---

#### 📁 EVIDENCE & INCIDENT RECORDING

For each incident, ShdGuard can create:

* A hash-sealed evidence file
* A draft abuse report
* Incident information
* Enrichment results where available

The evidence hash allows the integrity of the recorded evidence to be verified.

### 📌 HUMAN REVIEW REQUIRED

ShdGuard creates a **draft abuse report**.

It does **not** automatically submit reports to abuse providers.

The operator reviews the evidence and decides whether and where to submit the report.

---

#### 📱 PHONE ALERTS

Optional phone notifications are supported through **ntfy**.

When configured, ShdGuard can send incident alerts to the configured ntfy topic.

### 🔑 NTFY SECURITY

Use a randomly generated topic of at least **16 characters** and treat the topic as a password.

Phone-side protection is not part of the current ShdGuard PC build.

---

#### 🔐 PRIVACY-FIRST NETWORK DESIGN

ShdGuard is designed to minimize what leaves the monitored computer.

It sends:

* Attacker IP addresses
* File hashes for supported reputation lookups

It does **not** upload the actual files.

### 🚫 NO FILE UPLOADS

VirusTotal integration is **hash-only**.

ShdGuard does not upload the user's files to VirusTotal.

---

#### 🚪 NO LISTENING PORTS

ShdGuard does not open a listening network port.

It does not operate as a network server.

The attacker does not receive a ShdGuard service to interact with.

---

#### 🔒 PASSIVE DEFENSE ONLY

ShdGuard intentionally excludes offensive functionality.

It does **NOT**:

* Hack back
* Attack the suspected source
* Install trackers
* Implant malware
* Attempt unauthorized access
* Unmask Tor users
* Unmask VPN users
* Automatically report attackers
* Upload monitored files
* Identify individuals behind IP addresses

**The project remains strictly passive and defensive.**

---

#### ⚙️ HYBRID OPERATION

ShdGuard uses a hybrid operating model.

```text
LOCAL DETECTION
      ↓
Works offline
      ↓
Incident Recorded
      ↓
Evidence Sealed
      ↓
Optional Online Enrichment
      ↓
Retry / Queue When Required
      ↓
Attribution + Reputation
      ↓
Draft Report / Phone Alert
```

Core detection does not require continuous Internet connectivity.

External enrichment is performed when network access and configured services are available.

---

#### 🔑 OPTIONAL API KEYS

API credentials are supplied through **environment variables only** and are never intended to be stored by the application.

Supported variables include:

```text
SHD_ABUSEIPDB_KEY
SHD_GREYNOISE_KEY
SHD_VT_KEY
SHD_NTFY_TOPIC
```

---

#### 📊 API SERVICE LIMITS

**AbuseIPDB**

* Free-tier checking supported
* Up to 1,000 checks/day according to the project configuration

**GreyNoise**

* Community/service quotas apply
* Results are cached for 24 hours

**VirusTotal**

* Hash lookups only
* Public API rate limits apply
* Project configuration uses a 15-second request gap
* Results are cached
* Public API is not intended for commercial use

**ntfy**

* Optional phone notification service
* Topic should be treated as a secret

---

#### 🛡️ SECURITY AUDIT

The project underwent a security-focused review.

| #  | Security Area              | Result                                                   |
| -- | -------------------------- | -------------------------------------------------------- |
| 1  | Environment variables      | No hardcoded secrets; keys supplied through environment  |
| 2  | Input validation           | Python `ipaddress` plus strict regular expressions       |
| 3  | Authorization              | N/A — local single-user application with no open ports   |
| 4  | Password hashing           | N/A — no passwords stored                                |
| 5  | Log scrubbing              | Secrets never logged; sensitive report fields redacted   |
| 6  | Server-authoritative state | N/A — no payments or remote server state                 |
| 7  | Rate limiting              | VirusTotal request gap, caching and retry controls       |
| 8  | Headers / CORS             | N/A — no HTTP server                                     |
| 9  | Supply chain               | Dependencies from PyPI; hash pinning not yet implemented |
| 10 | Error handling             | Per-cycle exception handling; tracebacks remain local    |
| 11 | AI / agent scope           | N/A — no LLM or autonomous agent                         |

---

#### 🧪 TESTING STATUS

Testing was performed in a **Linux sandbox**.

The following tests passed:

* IP validation
* Windows Event ID 4625 parsing
* Feodo feed parsing
* Real-socket detection of a newly opened port
* Single-alert behavior without duplicate alerts
* Evidence hash verification
* Crash-recovery prompt
* Press Enter exit behavior
* Clean offline failure of enrichment services

### ✅ TEST STATUS

**All implemented Linux-sandbox tests passed.**

---

#### ⚠️ NOT YET TESTED

The following areas were **not tested in the supplied verification environment**:

* Windows Event Log access
* Windows administrator execution path
* Windows `.bat` launcher
* Live API responses
* Live API credentials
* Live ntfy phone push

These should be verified on the intended target environment before relying on them operationally.

---

#### 🔬 RESEARCH / VERIFICATION REQUIRED

Additional verification remains desirable for:

* Windows Event Log access without Administrator privileges
* `wevtutil` output encoding
* VirusTotal v3 response field names
* Live ntfy notification behavior

---

#### 🖥️ RUNNING ON WINDOWS

Run:

```text
ShdRun.bat
```

For failed Windows-logon monitoring, run the application **as Administrator**.

---

#### 🐧 RUNNING ON LINUX / macOS

Run:

```bash
bash ShdRun.sh
```

---

#### 🧪 SELF-TEST MODE

ShdGuard includes a synthetic end-to-end test mode.

Run:

```bash
python ShdGuard.py --selftest
```

This sends a synthetic incident through the application's monitoring pipeline without requiring a real attack.

---

#### 📦 PROJECT FILES

The delivered project includes:

```text
ShdGuard.py
ShdRun.bat
ShdRun.sh
ShdRequirements.txt
README.txt
```

The complete project is also distributed as:

```text
ShdGuard.zip
```

---

#### 🧰 TECHNOLOGY STACK

* Python 3.10+
* `psutil`
* `requests[socks]`
* SQLite/local storage components
* Windows Event Log integration where supported
* abuse.ch Feodo feed
* AbuseIPDB enrichment
* GreyNoise enrichment
* VirusTotal hash lookup
* ntfy notifications

---

#### ⚙️ HARDWARE

No AI model or inference engine is used.

Therefore:

* No GPU is required
* No LLM is required
* No model download is required
* Hardware auto-tuning is not applicable

---

#### 📌 KNOWN LIMITATION — FIRST RUN

On the first normal run, ShdGuard learns the computer's current open ports as the baseline.

This prevents existing legitimate ports from immediately appearing as newly opened incidents.

---

#### 🔐 CREDENTIAL & SECRET HANDLING

API keys are provided through environment variables.

ShdGuard is designed so that:

* Secrets are not hardcoded
* Secrets are not written into normal logs
* API keys are not stored in the project
* File contents are not uploaded for reputation checking

---

#### 🚨 WHAT SHDGUARD CAN TELL YOU

ShdGuard can help answer:

```text
Was suspicious activity detected?
        ↓
What happened?
        ↓
When did it happen?
        ↓
Which IP was involved?
        ↓
Who owns that network?
        ↓
Is the IP associated with known reputation data?
        ↓
Is there supporting evidence?
```

---

#### 🚫 WHAT SHDGUARD CANNOT TELL YOU

ShdGuard cannot reliably answer:

```text
Who is the individual person?
```

An IP address is not automatically an individual's identity.

Identity attribution may require cooperation from:

* ISP
* Hosting provider
* CERT
* Police / law-enforcement authorities
* Other legally authorized organizations

---

#### 🔮 FUTURE EXPANSION

Potential future development includes a **signed event feed** from the monitored PC to a self-hosted ntfy service or dashboard.

The goal would be to allow:

```text
PC Detection
     ↓
Signed Event Feed
     ↓
Self-Hosted Dashboard / ntfy
     ↓
PC + Phone
     ↓
One Shared Incident Timeline
```

Other possible future work includes:

* Windows verification
* Phone-side monitoring
* Bundled offline wheels
* Desktop notifications
* Additional defensive enrichment
* Stronger dependency hash pinning

---

#### 📋 PROJECT STATE

**Project:** ShdGuard
**Version:** 1.0
**Type:** Passive Defensive Monitor
**Status:** Delivered
**Primary platform:** Windows PC
**Additional platform:** Linux/macOS execution
**Phone role:** Alerts only
**Architecture:** Hybrid offline/online
**AI/LLM:** None
**Listening ports:** None
**File uploads:** None
**Hack-back capability:** None
**Automatic reporting:** None

---

#### 🛡️ DESIGN PRINCIPLE

> **Observe first. Preserve evidence. Attribute carefully. Never attack back.**

ShdGuard is intentionally designed as a **passive defensive monitoring system**, keeping the operator in control of investigation, evidence review and any subsequent reporting.

---

#### ⚠️ RESPONSIBLE USE

ShdGuard is intended for monitoring computers and networks that you own or are authorized to administer.

Use of network attribution, reputation services and incident reporting should comply with applicable laws, service terms, organizational policies and authorized security procedures.

