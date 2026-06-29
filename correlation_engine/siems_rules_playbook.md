# SMART SIEM — Inventaire des règles, logs et playbooks
> Document de référence — Format compact pour usage opérationnel

---

## STRUCTURE
```
TYPE D'ATTAQUE → ATTAQUE → LOGS DÉCLENCHEURS → PLAYBOOKS
```

---

## 1. INITIAL ACCESS (TA0001)

### 1.1 SSH Brute Force — `threshold` — T1110
**Règle PG** : `SSH Brute Force Detection`
**Déclencheur** : 5+ `login_failed` depuis même `source_ip` en 60s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `login_failed` |
| dest_port | `22` |
| source_ip | IP attaquante (ex: 185.X.X.X) |
| log_type | `auth` |
| severity | `warning` |
| tags | `brute_force_candidate` |

**Playbook 1** : `block_ip` (AUTO) — Bloque l'IP source immédiatement
**Playbook 2** : `escalate_rssi` (AUTO si CRITICAL) — Crée incident + email RSSI

---

### 1.2 Public Facing App Exploit — `threshold` — T1190
**Règle PG** : `Public Facing App Exploit`
**Déclencheur** : 3+ `http_exploit_attempt` depuis même IP en 60s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `http_exploit_attempt` |
| dest_port | `80` ou `443` |
| log_type | `application` |
| severity | `high` |
| tags | `exploit_candidate` |

**Playbook 1** : `block_ip` (CONFIRM) — Demande validation avant blocage
**Playbook 2** : `notify_soc` (AUTO) — Email SOC immédiat

---

### 1.3 Valid Accounts Abuse — `threshold` — T1078
**Règle PG** : `Firewall Block then AD Auth Attempt` (composite)
**Déclencheur** : `connection_blocked` (firewall) + `login_failed` (AD) même IP / 5min

| Source | event_action | Champs clés |
|--------|-------------|-------------|
| firewall | `connection_blocked` | source_ip, dest_port: 443 |
| active_directory | `login_failed` | source_ip, username, dest_port: 389 |

**Playbook 1** : `block_ip` (CONFIRM) — IP suspecte sur deux sources
**Playbook 2** : `disable_account` (CONFIRM) — Si username identifié

---

## 2. DISCOVERY (TA0007)

### 2.1 Network Port Scan — `threshold` — T1046
**Règle PG** : `Network Port Scan Detection`
**Déclencheur** : 50+ `connection_blocked` depuis même IP en 10s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `connection_blocked` |
| source_ip | IP du scanner |
| dest_port | Port variable (1-65535) |
| log_type | `network` |
| severity | `warning` |
| tags | `scan_candidate` |

**Playbook 1** : `block_ip` (AUTO) — Scan actif = blocage immédiat
**Playbook 2** : `notify_soc` (AUTO) — Notification email

---

## 3. LATERAL MOVEMENT (TA0008)

### 3.1 SSH Lateral Movement — `pattern` — T1021
**Règle PG** : `SSH Lateral Movement Kill-Chain`
**Déclencheur** : séquence `login_success` → `file_read` même IP en 300s

| Étape | event_action | Champs clés |
|-------|-------------|-------------|
| 1/2 | `login_success` | source_ip=hôte compromis, dest_port: 22 |
| 2/2 | `file_read` | source_ip=même, enriched_data.file_path=/etc/shadow |

**Playbook 1** : `isolate_machine` (CONFIRM) — Isolation du pivot
**Playbook 2** : `disable_account` (CONFIRM) — Compte compromis
**Playbook 3** : `escalate_rssi` (AUTO) — Niveau CRITICAL

---

### 3.2 SMB Lateral Movement — `threshold` — T1021.002
**Règle PG** : `SMB Lateral Movement`
**Déclencheur** : 5+ connexions port 445 depuis même IP en 120s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `connection_allowed` ou `smb_access` |
| dest_port | `445` |
| source_ip | Machine pivot |
| log_type | `network` |

**Playbook 1** : `block_ip` (CONFIRM) — Bloquer la machine pivot
**Playbook 2** : `notify_soc` (AUTO)

---

### 3.3 Pass-the-Hash — `pattern` — T1550.002
**Règle PG** : `Pass-the-Hash`
**Déclencheur** : séquence `credential_dump` → `login_success` même IP en 600s

| Étape | event_action | Champs clés |
|-------|-------------|-------------|
| 1/2 | `credential_dump` | source_ip, mitre_technique: T1003 |
| 2/2 | `login_success` | source_ip=même, auth_type: NTLM |

**Playbook 1** : `disable_account` (AUTO) — Compte utilisé avec hash volé
**Playbook 2** : `isolate_machine` (CONFIRM) — Machine source du dump
**Playbook 3** : `escalate_rssi` (AUTO)

---

### 3.4 Kerberoasting — `threshold` — T1558.003
**Règle PG** : `Kerberoasting`
**Déclencheur** : 10+ `kerberos_tgs_request` même IP en 30s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `kerberos_tgs_request` |
| source_ip | Machine attaquante |
| log_type | `auth` |
| severity | `high` |

**Playbook 1** : `block_ip` (AUTO)
**Playbook 2** : `escalate_rssi` (AUTO) — CRITICAL

---

### 3.5 RDP Lateral Movement — `threshold` — T1021.001
**Règle PG** : `RDP Lateral Movement`
**Déclencheur** : 3+ connexions port 3389 depuis même IP en 600s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `rdp_connection` |
| dest_port | `3389` |
| source_ip | IP pivot |
| severity | `high` |

**Playbook 1** : `block_ip` (CONFIRM)
**Playbook 2** : `notify_soc` (AUTO)

---

### 3.6 WMI Remote Execution — `threshold` — T1047
**Règle PG** : `WMI Remote Execution`
**Déclencheur** : 1+ `wmi_exec` depuis IP interne en 300s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `wmi_exec` |
| source_ip | Machine pivot |
| log_type | `system` |
| severity | `high` |

**Playbook 1** : `isolate_machine` (CONFIRM)
**Playbook 2** : `notify_soc` (AUTO)

---

### 3.7 Golden Ticket — `threshold` — T1558.001
**Règle PG** : `Golden Ticket`
**Déclencheur** : 20+ `kerberos_tgt_request` même username en 60s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `kerberos_tgt_request` |
| username | Compte suspect |
| log_type | `auth` |
| severity | `critical` |

**Playbook 1** : `disable_account` (AUTO)
**Playbook 2** : `escalate_rssi` (AUTO)
**Playbook 3** : `reset_krbtgt` (CONFIRM) — Réinitialisation compte KRBTGT

---

### 3.8 PsExec Remote Service — `pattern` — T1021.002
**Règle PG** : `PsExec Remote Service`
**Déclencheur** : séquence `service_created` → `process_started` même IP en 120s

| Étape | event_action | Champs clés |
|-------|-------------|-------------|
| 1/2 | `service_created` | source_ip, log_type: system |
| 2/2 | `process_started` | source_ip=même |

**Playbook 1** : `isolate_machine` (CONFIRM)
**Playbook 2** : `escalate_rssi` (AUTO)

---

### 3.9 Admin Share Access — `threshold` — T1021.002
**Déclencheur** : 1+ `admin_share_access` depuis IP non autorisée en 3600s
**Playbook 1** : `block_ip` (CONFIRM)
**Playbook 2** : `notify_soc` (AUTO)

---

### 3.10 Internal Spearphishing — `pattern` — T1534
**Déclencheur** : séquence `login_success` → `email_sent` même username en 1800s
**Playbook 1** : `disable_account` (CONFIRM)
**Playbook 2** : `notify_soc` (AUTO)

---

## 4. EXFILTRATION (TA0010)

### 4.1 Large Transfer — `threshold` — T1041
**Règle PG** : `Data Exfiltration Large Transfer`
**Déclencheur** : 3+ `large_outbound_transfer` même IP en 3600s

| Champ log | Valeur attendue |
|-----------|----------------|
| event_action | `large_outbound_transfer` |
| dest_ip | IP externe inconnue |
| enriched_data.bytes_sent_mb | > 50 Mo |
| log_type | `network` |

**Playbook 1** : `block_ip` (AUTO) — Couper l'exfiltration
**Playbook 2** : `escalate_rssi` (AUTO)

---

### 4.2 DNS Exfiltration — `threshold` — T1048
**Déclencheur** : 200+ `dns_query` même IP en 60s
**Playbook 1** : `block_ip` (AUTO)
**Playbook 2** : `notify_soc` (AUTO)

---

### 4.3 HTTP POST Exfiltration — `threshold` — T1567
**Déclencheur** : 50+ `http_post` même IP en 300s
**Playbook 1** : `block_ip` (CONFIRM)
**Playbook 2** : `notify_soc` (AUTO)

---

### 4.4 FTP/SFTP Exfiltration — `threshold` — T1048
**Déclencheur** : 1+ connexion port 21 même IP en 3600s
**Playbook 1** : `block_ip` (AUTO)
**Playbook 2** : `escalate_rssi` (AUTO)

---

### 4.5 Cloud Storage Upload — `threshold` — T1567.002
**Déclencheur** : 5+ `cloud_upload` même username en 3600s
**Playbook 1** : `disable_account` (CONFIRM)
**Playbook 2** : `notify_soc` (AUTO)

---

### 4.6 Email Exfiltration — `threshold` — T1048
**Déclencheur** : 20+ `email_sent` même username en 3600s
**Playbook 1** : `disable_account` (CONFIRM)
**Playbook 2** : `notify_soc` (AUTO)

---

### 4.7 Scheduled Exfiltration — `threshold` — T1029
**Déclencheur** : 3+ `outbound_connection` même IP en 300s
**Playbook 1** : `block_ip` (CONFIRM)
**Playbook 2** : `notify_soc` (AUTO)

---

### 4.8 ICMP Tunnel — `threshold` — T1095
**Déclencheur** : 100+ `icmp_flood` même IP en 60s
**Playbook 1** : `block_ip` (AUTO)
**Playbook 2** : `notify_soc` (AUTO)

---

## 5. IMPACT (TA0040)

### 5.1 Data Exfiltration (existant dans init_rules)
**Déclencheur** : 3+ `large_outbound_transfer` en 3600s
**Playbook** : `block_ip` (AUTO) + `escalate_rssi` (AUTO)

---

## PLAYBOOKS — Référence complète

| ID | Nom | Action | Mode | Cibles | Règles liées |
|----|-----|--------|------|--------|-------------|
| PB-01 | block_ip | Bloquer IP dans firewall/PG | AUTO | source_ip | Toutes threshold sur IP |
| PB-02 | disable_account | Désactiver compte PG | CONFIRM | username | Pass-hash, Golden Ticket, Cloud upload |
| PB-03 | isolate_machine | Marquer machine pour isolation | CONFIRM | host | Lateral movement, PsExec |
| PB-04 | escalate_rssi | Email RSSI + créer incident | AUTO | — | Tous CRITICAL |
| PB-05 | notify_soc | Email SOC + webhook Slack | AUTO | — | Tous HIGH+ |
| PB-06 | reset_krbtgt | Alerte reset compte KRBTGT | CONFIRM | — | Golden Ticket uniquement |