# smart-siem-data

> **Smart SIEM — Correlation Engine & UEBA Module**
> Threat detection platform built as a cross-functional student project at UCAC-ICAM.

This repository contains the **intelligence core** of the Smart SIEM: the event correlation engine and the User and Entity Behavior Analytics (UEBA) module.

---

## What is a SIEM?

A **Security Information and Event Management** system collects logs from every source in an infrastructure (servers, network, applications), normalizes them, correlates events across sources and triggers alerts when a threat pattern is detected.

This project simulates a production-grade SIEM architecture, built by a cross-functional student team in 3 weeks.

---

## What's in this Repository

This repo covers **two intelligence modules** of the full SIEM platform:

### 1. Correlation Engine
Detects threats by analyzing relationships between events across sources and time.

- **Threshold-based rules** — e.g. 5 failed logins in 30 seconds from the same IP
- **Pattern-based rules** — e.g. sequential events matching a known attack chain
- **Configurable time windows** — sliding window analysis per rule
- **Cross-source correlation** — a firewall event linked to an Active Directory authentication
- **MITRE ATT&CK scenarios** — reconnaissance, lateral movement, exfiltration

### 2. UEBA Module (User & Entity Behavior Analytics)
Detects anomalies by comparing current behavior against established baselines.

- **Behavioral profiling** — baseline built per user and machine (login hours, data volumes, access patterns)
- **Dynamic risk scoring** — real-time score computed per entity, updated on each event
- **Anomaly detection** — login outside normal hours, unusual data transfer, abnormal access patterns
- **Behavior-event correlation** — links behavioral anomalies to security events

---

## Full Platform Architecture

This repo is one component of a larger platform:

```
┌─────────────────────────────────────────────────────┐
│                   Smart SIEM Platform                │
├──────────────┬──────────────────┬───────────────────┤
│  Collection  │   Intelligence   │   Visualization   │
│              │                  │                   │
│ Syslog       │ ┌──────────────┐ │ React Dashboard   │
│ (UDP/TCP)    │ │  Correlation │ │ (Analyst / CISO   │
│              │ │   Engine     │ │  / Auditor views) │
│ Linux agents │ ├──────────────┤ │                   │
│              │ │    UEBA      │ │ PDF Reports        │
│ Windows      │ │   Module     │ │                   │
│ agents       │ └──────────────┘ │ Event Timeline     │
├──────────────┴──────────────────┴───────────────────┤
│              Storage & Search                        │
│         Elasticsearch · PostgreSQL                   │
├─────────────────────────────────────────────────────┤
│           Backend: Python / FastAPI                  │
│           Containerization: Docker                   │
└─────────────────────────────────────────────────────┘
```

---

## MITRE ATT&CK Coverage

Correlation rules map to real-world attack techniques:

| Tactic | Example Rule |
|--------|-------------|
| **Reconnaissance** | Port scan detection — multiple ports probed from single IP in short time window |
| **Credential Access** | Brute-force detection — N failed authentications in T seconds across M hosts |
| **Lateral Movement** | Unusual authentication to multiple internal machines within same session |
| **Exfiltration** | Large outbound data transfer to external IP outside business hours |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python |
| Search & Storage | Elasticsearch |
| Relational DB | PostgreSQL |
| Backend API | FastAPI |
| Containerization | Docker |
| Frontend | React |

---

## Log Normalization Schema

Every log entering the system is normalized into:

```json
{
  "timestamp": "2026-03-15T14:32:00Z",
  "source_ip": "192.168.1.45",
  "host": "server-prod-01",
  "log_type": "auth",
  "severity": "critical",
  "raw_message": "Failed password for root from 192.168.1.45 port 22",
  "tags": ["auth_failure", "brute_force_candidate"]
}
```

Tags are assigned automatically based on content analysis.

---

## Alert Levels

```
INFO     → Normal activity, logged for audit
WARNING  → Suspicious pattern, monitor closely
HIGH     → Likely threat, investigation recommended
CRITICAL → Active attack pattern detected, immediate action required
```

---

## SOAR Playbooks

When an alert is triggered, automated playbooks can execute:

- **Block IP** — add to firewall deny list
- **Disable account** — lock the compromised user account
- **Escalation notification** — alert the security team via email / webhook

All actions are logged with timestamp, actor and result.

---

## Built During

**Cross-functional student project — UCAC-ICAM**
Promotion X2028 — 2026

3-week intensive project simulating professional SOC (Security Operations Center) conditions.

---

## Project Scope

| Component | Status |
|-----------|--------|
| Log collection (Syslog UDP/TCP) | ✅ Designed |
| JSON normalisation pipeline | ✅ Implemented |
| Elasticsearch indexing | ✅ Implemented |
| Correlation engine (this repo) | ✅ Implemented |
| UEBA module (this repo) | ✅ Implemented |
| React dashboard | ✅ Implemented |
| Docker deployment | ✅ Configured |
| SOAR playbooks | ✅ Designed |

---

## Related Reading

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Elasticsearch — Log Analysis](https://www.elastic.co/what-is/log-analysis)
- [UEBA — Gartner Definition](https://www.gartner.com/en/information-technology/glossary/user-entity-behavior-analytics-ueba)
