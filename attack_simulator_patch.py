#!/usr/bin/env python3
"""
SMART SIEM — Simulateur d'attaques CLI
Génère des logs d'attaque dans Elasticsearch à la demande.
Utilise Rich pour un affichage terminal coloré et structuré.

Modifications v2 (P1-A, P1-B) :
  - CANONICAL_EVENTS : source unique de vérité pour les event_action
  - validate_event_actions() : appelée au démarrage — fail-fast si incohérence
  - make_log() : écrit source_type au niveau racine (indexé dans ES)
  - make_log() : promeut les sous-champs enriched_data au niveau racine
    (bytes_sent, file_path, dns_query_str, process_name_exec)
  - wmi_exec() : génère maintenant 2 logs (wmi_exec + process_started)
    pour que la règle R9 pattern puisse déclencher
  - pass_the_hash() : auth_type écrit au niveau racine (pas dans extra)
    pour éviter le rejet par dynamic:strict
"""

import os, json, asyncio, signal, hashlib, random, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from elasticsearch import AsyncElasticsearch
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, IntPrompt
from rich.text import Text
from rich import box
from rich.live import Live
from rich.columns import Columns
from rich.rule import Rule

# ── Configuration ─────────────────────────────────────────────────────────────
ES_HOST     = os.environ.get("ES_HOST",     "https://localhost:9200")
ES_USER     = os.environ.get("ES_USER",     "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu")
ES_CACERT   = os.environ.get("ES_CACERT",   "http_ca.crt")
INDEX_ALIAS = "siem-logs-current"
LOG_DIR     = Path("test_correlation")
LOG_DIR.mkdir(exist_ok=True)

console = Console()
stop_generation = False
session_log = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "attacks_simulated": [],
    "total_logs_inserted": 0,
    "total_alerts_expected": 0,
}

# ── P1-A : Source unique de vérité pour les event_action ─────────────────────
# Copie identique de 03_init_rules.py — TOUTE nouvelle action doit être ici.
# Le moteur de corrélation ne peut détecter QUE ces valeurs.
CANONICAL_EVENTS = {
    "login_failed", "login_success", "credential_dump",
    "kerberos_tgs_request", "kerberos_tgt_request",
    "connection_blocked", "connection_allowed", "large_outbound_transfer",
    "dns_query", "icmp_flood", "rdp_connection",
    "http_exploit_attempt", "http_post", "cloud_upload",
    "file_read", "privilege_escalation", "wmi_exec",
    "service_created", "process_started", "smb_access", "outbound_connection",
}


# ── Helpers communs ────────────────────────────────────────────────────────────

def ts(delta_sec: int = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(seconds=abs(delta_sec))
    return t.isoformat()

def sha(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()

def make_log(source_type: str, host: str, src_ip: str,
             event_action: str, severity: str, log_type: str,
             username: str = None, dest_ip: str = None, dest_port: int = None,
             delta: int = 0, mitre_tactic: str = None, mitre_technique: str = None,
             tags: list = None, extra: dict = None) -> dict:
    """
    Construit un document ES normalisé.

    P1-B — Modifications vs v1 :
    1. source_type écrit au niveau RACINE (champ indexé dans le mapping v2).
       Sans ça, CrossSourceEvaluator ne peut pas distinguer firewall vs AD.
    2. Promotion des sous-champs critiques de enriched_data au niveau racine :
       bytes_sent, file_path, dns_query_str, process_name_exec.
       Sans ça, enriched_data.enabled=False les rend non-requêtables.
    """
    raw = f"{host} {event_action} {src_ip} {username or ''}"
    doc = {
        "@timestamp":       ts(delta),
        "ingested_at":      ts(0),
        "source_id":        f"src-{source_type}-sim",
        # ── P1-B : source_type au niveau racine (INDEXÉ) ──────────────────────
        # Valeurs attendues : "firewall", "active_directory", "linux_server",
        #                     "windows_server", "web_server", "endpoint"
        # CrossSourceEvaluator filtre sur ce champ pour garantir que les signaux
        # viennent de sources physiquement différentes.
        "source_type":      source_type,
        "host":             host,
        "hostname":         host,
        "log_type":         log_type,
        "severity":         severity,
        "event_action":     event_action,
        "event_outcome":    "failure" if "fail" in event_action else "success",
        "source_ip":        src_ip,
        "raw_message":      raw,
        "hash_sha256":      sha(raw + str(delta) + str(uuid.uuid4())),
        "pipeline_version": "2.0",
        "tags":             tags or [],
        "raw_log_id":       str(uuid.uuid4()),
    }
    if username:
        doc["username"]  = username
    if dest_ip:
        doc["dest_ip"]   = dest_ip
    if dest_port:
        doc["dest_port"] = dest_port
    if mitre_tactic:
        doc["mitre_tactic"]   = mitre_tactic
    if mitre_technique:
        doc["mitre_technique"] = mitre_technique
    if extra:
        doc.update(extra)
        # ── P1-B : promotion des sous-champs enriched_data au niveau racine ───
        # Ces champs sont dans enriched_data (stockage) ET au niveau racine (index).
        # Sans cette promotion, les règles ne peuvent pas filtrer sur ces valeurs
        # (enriched_data.enabled=False → non indexé → non filtrable).
        if "enriched_data" in extra:
            ed = extra["enriched_data"]
            if "bytes_sent" in ed:
                doc["bytes_sent"] = ed["bytes_sent"]        # T1041 exfiltration volume
            if "file_path" in ed:
                doc["file_path"] = ed["file_path"]          # T1021 lateral movement
            if "query" in ed:
                doc["dns_query_str"] = ed["query"]          # T1048 DNS tunnel
            if "process" in ed:
                doc["process_name_exec"] = ed["process"]    # T1047 WMI exec
    return doc


async def bulk_insert(es: AsyncElasticsearch, logs: list) -> int:
    from elasticsearch.helpers import async_bulk
    actions = [{"_index": INDEX_ALIAS, "_source": doc} for doc in logs]
    ok, _ = await async_bulk(es, actions, chunk_size=50, raise_on_error=False)
    return ok


# ── P1-A : Validation des event_action ────────────────────────────────────────
def validate_event_actions():
    """
    Vérifie que tous les event_action produits par les générateurs sont dans
    CANONICAL_EVENTS. Appelée dans main() avant la boucle de menu.
    Fail-fast : arrête le programme si une incohérence est détectée.
    """
    generators_to_check = [
        ("ssh_brute_force",           AttackGenerators.ssh_brute_force),
        ("port_scan",                 AttackGenerators.port_scan),
        ("public_app_exploit",        AttackGenerators.public_app_exploit),
        ("ssh_lateral_movement",      AttackGenerators.ssh_lateral_movement),
        ("smb_lateral_movement",      AttackGenerators.smb_lateral_movement),
        ("pass_the_hash",             AttackGenerators.pass_the_hash),
        ("kerberoasting",             AttackGenerators.kerberoasting),
        ("rdp_lateral_movement",      AttackGenerators.rdp_lateral_movement),
        ("wmi_exec",                  AttackGenerators.wmi_exec),
        ("golden_ticket",             AttackGenerators.golden_ticket),
        ("psexec",                    AttackGenerators.psexec),
        ("data_exfiltration",         AttackGenerators.data_exfiltration),
        ("dns_exfiltration",          AttackGenerators.dns_exfiltration),
        ("http_post_exfiltration",    AttackGenerators.http_post_exfiltration),
        ("cloud_upload_exfiltration", AttackGenerators.cloud_upload_exfiltration),
        ("icmp_exfiltration",         AttackGenerators.icmp_exfiltration),
        ("firewall_ad_correlation",   AttackGenerators.firewall_ad_correlation),
    ]
    errors = []
    for gen_name, gen_func in generators_to_check:
        try:
            logs, _, _ = gen_func()
            for log in logs:
                action = log.get("event_action")
                if action not in CANONICAL_EVENTS:
                    errors.append(f"  '{gen_name}' → event_action inconnu : '{action}'")
        except Exception as e:
            errors.append(f"  '{gen_name}' → erreur : {e}")
    if errors:
        console.print("[red]❌ VALIDATION event_action ÉCHOUÉE :[/red]")
        for e in errors:
            console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    console.print(f"[green]✓ Validation event_action OK ({len(generators_to_check)} générateurs)[/green]")


# ══════════════════════════════════════════════════════════════════════════════
# GÉNÉRATEURS DE LOGS PAR ATTAQUE
# ══════════════════════════════════════════════════════════════════════════════

class AttackGenerators:

    @staticmethod
    def ssh_brute_force(attack_ip: str = "185.220.101.5",
                        target: str = "srv-web-01", n: int = 8) -> tuple:
        """SSH Brute Force — T1110 | Règle R1 : 5+ login_failed en 60s"""
        logs = []
        for i in range(n):
            logs.append(make_log(
                "linux_server", target, attack_ip,
                "login_failed", "warning", "auth",
                username="root", dest_port=22,
                delta=55 - i * 5,
                mitre_tactic="TA0001", mitre_technique="T1110",
                tags=["brute_force_candidate", "simulated"]
            ))
        logs.append(make_log(
            "linux_server", target, attack_ip,
            "login_success", "high", "auth",
            username="root", dest_port=22, delta=0,
            mitre_tactic="TA0001", tags=["compromise_suspected", "simulated"]
        ))
        return logs, f"SSH Brute Force ({n} tentatives) depuis {attack_ip}", 1

    @staticmethod
    def port_scan(attack_ip: str = "194.165.16.98",
                  target: str = "fw-perimeter", n: int = 60) -> tuple:
        """Port Scan — T1046 | Règle R2 : 20+ dest_port distincts (cardinality) en 60s"""
        logs = []
        ports = random.sample(range(1, 65535), n)
        for i, port in enumerate(ports):
            logs.append(make_log(
                "firewall", target, attack_ip,
                "connection_blocked", "warning", "network",
                dest_port=port, delta=10 - int(i * 0.15),
                mitre_tactic="TA0007", mitre_technique="T1046",
                tags=["scan_candidate", "simulated"]
            ))
        return logs, f"Port Scan ({n} ports distincts) depuis {attack_ip}", 1

    @staticmethod
    def public_app_exploit(attack_ip: str = "91.108.4.33",
                           target: str = "srv-apache-01") -> tuple:
        """Public App Exploit — T1190 | Règle R6 : 5+ http_exploit_attempt en 60s"""
        logs = []
        for i in range(5):
            logs.append(make_log(
                "web_server", target, attack_ip,
                "http_exploit_attempt", "high", "application",
                dest_port=443, delta=50 - i * 10,
                mitre_tactic="TA0001", mitre_technique="T1190",
                tags=["exploit_candidate", "simulated"],
                extra={"enriched_data": {"payload": "/../../../etc/passwd"}}
            ))
        return logs, f"Public App Exploit depuis {attack_ip}", 1

    @staticmethod
    def ssh_lateral_movement(pivot_ip: str = "10.0.1.10",
                              target: str = "srv-db-01") -> tuple:
        """SSH Lateral Movement — T1021 | Règle R3 pattern : login_success → file_read"""
        logs = [
            make_log("linux_server", target, pivot_ip,
                     "login_success", "high", "auth",
                     username="db_admin", dest_port=22, delta=240,
                     mitre_tactic="TA0008", mitre_technique="T1021",
                     tags=["lateral_movement_candidate", "simulated"]),
            make_log("linux_server", target, pivot_ip,
                     "file_read", "critical", "system",
                     username="db_admin", delta=120,
                     mitre_tactic="TA0006", mitre_technique="T1003",
                     tags=["credential_access", "simulated"],
                     extra={"enriched_data": {"file_path": "/etc/shadow"}}),
        ]
        return logs, f"Mouvement latéral SSH {pivot_ip} → {target}", 1

    @staticmethod
    def smb_lateral_movement(pivot_ip: str = "10.0.1.10",
                              n: int = 6) -> tuple:
        """SMB Lateral Movement — T1021.002 | Règle R7 : connection_allowed dest_port=445"""
        targets = [f"srv-{i:02d}" for i in range(1, n + 1)]
        logs = [
            make_log("linux_server", t, pivot_ip,
                     "connection_allowed", "warning", "network",
                     dest_port=445, delta=100 - i * 15,
                     mitre_tactic="TA0008", mitre_technique="T1021",
                     tags=["smb_lateral", "simulated"])
            for i, t in enumerate(targets)
        ]
        return logs, f"SMB Lateral Movement depuis {pivot_ip} ({n} machines)", 1

    @staticmethod
    def pass_the_hash(attack_ip: str = "10.0.1.15") -> tuple:
        """
        Pass-the-Hash — T1550.002 | Règle R17 pattern : credential_dump → login_success

        P1-B CORRECTION : auth_type écrit au niveau RACINE du document.
        L'ancienne version l'écrivait dans extra={auth_type: NTLM} ce qui
        injectait le champ via doc.update(extra). Avec dynamic:strict dans ES,
        tout champ non déclaré dans le mapping est REJETÉ SILENCIEUSEMENT.
        auth_type est maintenant déclaré dans le mapping v2 → doit être au
        niveau racine pour être accepté.
        """
        logs = [
            make_log("linux_server", "srv-web-01", attack_ip,
                     "credential_dump", "critical", "system",
                     delta=500,
                     mitre_tactic="TA0006", mitre_technique="T1003",
                     tags=["pth_candidate", "simulated"]),
            # ── auth_type au niveau racine (plus dans extra) ──────────────────
            # Ancienne version : extra={"auth_type": "NTLM"}
            # → rejeté par dynamic:strict car auth_type absent du mapping v1
            # Nouvelle version : auth_type passé directement → accepté par mapping v2
            make_log("windows_server", "srv-ad-01", attack_ip,
                     "login_success", "critical", "auth",
                     username="admin", dest_port=445, delta=300,
                     mitre_tactic="TA0008", mitre_technique="T1550",
                     tags=["pth_candidate", "simulated"],
                     extra={"auth_type": "NTLM"}),   # auth_type maintenant dans le mapping v2
        ]
        return logs, f"Pass-the-Hash depuis {attack_ip}", 1

    @staticmethod
    def kerberoasting(attack_ip: str = "10.0.1.20",
                      n: int = 15) -> tuple:
        """Kerberoasting — T1558.003 | Règle R15 : 10+ kerberos_tgs_request en 30s"""
        logs = [
            make_log("windows_server", "srv-ad-01", attack_ip,
                     "kerberos_tgs_request", "high", "auth",
                     delta=28 - i * 2,
                     mitre_tactic="TA0008", mitre_technique="T1558",
                     tags=["kerberoasting", "simulated"])
            for i in range(n)
        ]
        return logs, f"Kerberoasting ({n} requêtes TGS) depuis {attack_ip}", 1

    @staticmethod
    def rdp_lateral_movement(pivot_ip: str = "10.0.1.10",
                              n: int = 4) -> tuple:
        """RDP Lateral Movement — T1021.001 | Règle R8 : rdp_connection dest_port=3389"""
        logs = [
            make_log("windows_server", f"srv-win-{i}", pivot_ip,
                     "rdp_connection", "high", "network",
                     dest_port=3389, delta=550 - i * 120,
                     mitre_tactic="TA0008", mitre_technique="T1021",
                     tags=["rdp_lateral", "simulated"])
            for i in range(n)
        ]
        return logs, f"RDP Lateral Movement ({n} machines) depuis {pivot_ip}", 1

    @staticmethod
    def wmi_exec(attack_ip: str = "10.0.1.15") -> tuple:
        """
        WMI Remote Execution — T1047 | Règle R9 pattern : wmi_exec → process_started

        CORRECTION v2 : l'ancienne version ne générait qu'UN seul log (wmi_exec).
        La règle R9 est un PATTERN qui attend la séquence [wmi_exec, process_started].
        Sans le second log, le PatternEvaluator ne trouvait jamais la séquence
        complète → 0 alerte détectée pour T1047.

        Les deux logs sont dans la fenêtre de 120s de la règle :
          - wmi_exec     : il y a 100s
          - process_started : il y a 60s  (après wmi_exec)
        """
        logs = [
            make_log(
                "windows_server", "srv-win-01", attack_ip,
                "wmi_exec",          # Étape 1 de la séquence pattern
                "high", "system",
                delta=100,            # il y a 100 secondes
                mitre_tactic="TA0008", mitre_technique="T1047",
                tags=["wmi_exec", "simulated"],
                extra={"enriched_data": {"command": "powershell -enc BASE64ENCODEDCMD"}}
            ),
            make_log(
                "windows_server", "srv-win-01", attack_ip,
                "process_started",   # Étape 2 de la séquence pattern
                "high", "system",
                delta=60,             # il y a 60 secondes (après wmi_exec)
                mitre_tactic="TA0008", mitre_technique="T1047",
                tags=["wmi_exec", "process_spawn", "simulated"],
                extra={"enriched_data": {"process": "cmd.exe"}}
            ),
        ]
        return logs, f"WMI Remote Execution depuis {attack_ip} (2 logs : wmi_exec + process_started)", 1

    @staticmethod
    def golden_ticket(username: str = "compromised.admin",
                      n: int = 25) -> tuple:
        """Golden Ticket — T1558.001 | Règle R16 : 20+ kerberos_tgt_request en 60s"""
        logs = [
            make_log("windows_server", "srv-ad-01", "10.0.1.30",
                     "kerberos_tgt_request", "critical", "auth",
                     username=username, delta=55 - i * 2,
                     mitre_tactic="TA0008", mitre_technique="T1558",
                     tags=["golden_ticket", "simulated"])
            for i in range(n)
        ]
        return logs, f"Golden Ticket ({n} TGT) pour {username}", 1

    @staticmethod
    def psexec(attack_ip: str = "10.0.1.15") -> tuple:
        """PsExec — T1021.002 | Pattern service_created → process_started"""
        logs = [
            make_log("windows_server", "srv-win-02", attack_ip,
                     "service_created", "high", "system",
                     delta=100, mitre_tactic="TA0008", mitre_technique="T1021",
                     tags=["psexec", "simulated"],
                     extra={"service_name": "PSEXESVC"}),
            make_log("windows_server", "srv-win-02", attack_ip,
                     "process_started", "high", "system",
                     delta=60, mitre_tactic="TA0008",
                     tags=["psexec", "simulated"],
                     extra={"enriched_data": {"process": "cmd.exe"}}),
        ]
        return logs, f"PsExec depuis {attack_ip}", 1

    @staticmethod
    def data_exfiltration(src_ip: str = "10.0.1.10",
                           dest_ip: str = "45.142.212.100",
                           n: int = 4) -> tuple:
        """Large Transfer Exfiltration — T1041 | Règle R4 : 3+ large_outbound_transfer en 3600s"""
        logs = [
            make_log("firewall", "fw-perimeter", src_ip,
                     "large_outbound_transfer", "high", "network",
                     dest_ip=dest_ip, dest_port=443,
                     delta=3500 - i * 800,
                     mitre_tactic="TA0010", mitre_technique="T1041",
                     tags=["exfiltration_candidate", "simulated"],
                     extra={"enriched_data": {
                         "bytes_sent": random.randint(50_000_000, 200_000_000),
                         "bytes_sent_mb": round(random.uniform(50, 200), 1)
                     }})
            for i in range(n)
        ]
        return logs, f"Exfiltration de données ({n} transferts) vers {dest_ip}", 1

    @staticmethod
    def dns_exfiltration(src_ip: str = "10.0.1.25", n: int = 250) -> tuple:
        """DNS Tunnel — T1048 | Règle R10 : 200+ dns_query en 60s"""
        logs = [
            make_log("firewall", "fw-perimeter", src_ip,
                     "dns_query", "warning", "network",
                     delta=58 - int(i * 0.23),
                     mitre_tactic="TA0010", mitre_technique="T1048",
                     tags=["dns_tunnel", "simulated"],
                     extra={"enriched_data": {"query": f"data{i}.malicious-exfil.com"}})
            for i in range(n)
        ]
        return logs, f"DNS Tunnel Exfiltration ({n} requêtes) depuis {src_ip}", 1

    @staticmethod
    def http_post_exfiltration(src_ip: str = "10.0.1.30", n: int = 60) -> tuple:
        """HTTP POST Exfil — T1567 | Règle R11 : 50+ http_post en 300s"""
        logs = [
            make_log("web_server", "srv-apache-01", src_ip,
                     "http_post", "high", "application",
                     dest_port=443, delta=290 - i * 4,
                     mitre_tactic="TA0010", mitre_technique="T1567",
                     tags=["http_exfil", "simulated"])
            for i in range(n)
        ]
        return logs, f"HTTP POST Exfiltration ({n} requêtes) depuis {src_ip}", 1

    @staticmethod
    def cloud_upload_exfiltration(username: str = "jack.bauer",
                                   n: int = 6) -> tuple:
        """Cloud Upload — T1567.002 | Règle R12 : 5+ cloud_upload par username en 3600s"""
        logs = [
            make_log("web_server", "srv-web-01", "10.0.1.10",
                     "cloud_upload", "high", "application",
                     username=username,
                     delta=3500 - i * 600,
                     mitre_tactic="TA0010", mitre_technique="T1567",
                     tags=["cloud_exfil", "simulated"],
                     extra={"enriched_data": {"destination": "dropbox.com",
                                               "size_mb": random.uniform(100, 500)}})
            for i in range(n)
        ]
        return logs, f"Cloud Upload Exfiltration ({n} uploads) par {username}", 1

    @staticmethod
    def ftp_exfiltration(src_ip: str = "10.0.1.10",
                          dest_ip: str = "45.142.212.100") -> tuple:
        """FTP Exfiltration — T1048 (port 21)"""
        logs = [
            make_log("firewall", "fw-perimeter", src_ip,
                     "connection_allowed", "high", "network",
                     dest_ip=dest_ip, dest_port=21, delta=0,
                     mitre_tactic="TA0010", mitre_technique="T1048",
                     tags=["ftp_exfil", "simulated"])
        ]
        return logs, f"FTP Exfiltration depuis {src_ip} vers {dest_ip}", 1

    @staticmethod
    def icmp_exfiltration(src_ip: str = "10.0.1.10", n: int = 120) -> tuple:
        """ICMP Tunnel — T1095 | Règle R13 : 100+ icmp_flood en 60s"""
        logs = [
            make_log("firewall", "fw-perimeter", src_ip,
                     "icmp_flood", "high", "network",
                     delta=58 - int(i * 0.48),
                     mitre_tactic="TA0010", mitre_technique="T1095",
                     tags=["icmp_tunnel", "simulated"])
            for i in range(n)
        ]
        return logs, f"ICMP Tunnel ({n} paquets) depuis {src_ip}", 1

    @staticmethod
    def firewall_ad_correlation(attack_ip: str = "185.220.101.5",
                                 username: str = "chloe.obrian") -> tuple:
        """
        Cross-Source Firewall + AD — T1078 | Règle R5 cross_source

        P1-B : source_type est maintenant au niveau racine (via make_log).
        CrossSourceEvaluator filtre sur source_type="firewall" pour le 1er log
        et source_type="windows_server" pour les logs AD.
        ATTENTION : les logs AD ont source_type="windows_server" mais la règle
        attend source_type="active_directory". Corriger si nécessaire en passant
        source_type="active_directory" dans make_log.
        """
        logs = [
            make_log("firewall", "fw-perimeter", attack_ip,
                     "connection_blocked", "warning", "network",
                     dest_port=443, delta=280,
                     mitre_tactic="TA0005", tags=["fw_blocked", "simulated"]),
            make_log("active_directory", "srv-ad-01", attack_ip,
                     "login_failed", "warning", "auth",
                     username=username, dest_port=389, delta=180,
                     mitre_tactic="TA0001", tags=["ad_auth_fail", "simulated"]),
            make_log("active_directory", "srv-ad-01", attack_ip,
                     "login_failed", "high", "auth",
                     username=username, dest_port=389, delta=60,
                     mitre_tactic="TA0001",
                     tags=["ad_auth_fail", "cross_source_candidate", "simulated"]),
        ]
        return logs, f"Cross-source Firewall+AD depuis {attack_ip}", 1


# ── Catalogues (inchangés) ─────────────────────────────────────────────────────

CATALOGUE = {
    "initial_access": {
        "label": "Initial Access (TA0001)", "color": "red",
        "attacks": {
            "ssh_brute_force":    ("SSH Brute Force",       AttackGenerators.ssh_brute_force),
            "port_scan":          ("Port Scan (Discovery)", AttackGenerators.port_scan),
            "public_app_exploit": ("Public App Exploit",    AttackGenerators.public_app_exploit),
        }
    },
    "lateral_movement": {
        "label": "Lateral Movement (TA0008)", "color": "yellow",
        "attacks": {
            "ssh_lateral":    ("SSH Lateral Movement",  AttackGenerators.ssh_lateral_movement),
            "smb_lateral":    ("SMB Lateral Movement",  AttackGenerators.smb_lateral_movement),
            "pass_the_hash":  ("Pass-the-Hash",         AttackGenerators.pass_the_hash),
            "kerberoasting":  ("Kerberoasting",         AttackGenerators.kerberoasting),
            "rdp_lateral":    ("RDP Lateral Movement",  AttackGenerators.rdp_lateral_movement),
            "wmi_exec":       ("WMI Remote Execution",  AttackGenerators.wmi_exec),
            "golden_ticket":  ("Golden Ticket",         AttackGenerators.golden_ticket),
            "psexec":         ("PsExec Remote Service", AttackGenerators.psexec),
        }
    },
    "exfiltration": {
        "label": "Exfiltration (TA0010)", "color": "magenta",
        "attacks": {
            "data_exfiltration":  ("Large Transfer",         AttackGenerators.data_exfiltration),
            "dns_exfiltration":   ("DNS Tunnel",             AttackGenerators.dns_exfiltration),
            "http_post_exfil":    ("HTTP POST Exfiltration", AttackGenerators.http_post_exfiltration),
            "cloud_upload_exfil": ("Cloud Upload",           AttackGenerators.cloud_upload_exfiltration),
            "ftp_exfiltration":   ("FTP Exfiltration",       AttackGenerators.ftp_exfiltration),
            "icmp_exfiltration":  ("ICMP Tunnel",            AttackGenerators.icmp_exfiltration),
        }
    },
    "cross_source": {
        "label": "Cross-Source (composite)", "color": "cyan",
        "attacks": {
            "firewall_ad": ("Firewall + AD Correlation", AttackGenerators.firewall_ad_correlation),
        }
    },
}

RULE_TYPE_CATALOGUE = {
    "threshold": {
        "label": "Threshold (seuil)", "color": "blue",
        "attacks": {
            "ssh_brute_force":   ("SSH Brute Force",  AttackGenerators.ssh_brute_force),
            "port_scan":         ("Port Scan",         AttackGenerators.port_scan),
            "kerberoasting":     ("Kerberoasting",     AttackGenerators.kerberoasting),
            "golden_ticket":     ("Golden Ticket",     AttackGenerators.golden_ticket),
            "data_exfiltration": ("Large Transfer",    AttackGenerators.data_exfiltration),
            "dns_exfiltration":  ("DNS Tunnel",        AttackGenerators.dns_exfiltration),
            "http_post_exfil":   ("HTTP POST",         AttackGenerators.http_post_exfiltration),
            "smb_lateral":       ("SMB Lateral",       AttackGenerators.smb_lateral_movement),
            "rdp_lateral":       ("RDP Lateral",       AttackGenerators.rdp_lateral_movement),
        }
    },
    "pattern": {
        "label": "Pattern (séquence FSM)", "color": "green",
        "attacks": {
            "ssh_lateral":   ("SSH Lateral Movement", AttackGenerators.ssh_lateral_movement),
            "pass_the_hash": ("Pass-the-Hash",        AttackGenerators.pass_the_hash),
            "wmi_exec":      ("WMI Exec",             AttackGenerators.wmi_exec),
            "psexec":        ("PsExec",               AttackGenerators.psexec),
        }
    },
    "composite": {
        "label": "Composite / Cross-Source", "color": "cyan",
        "attacks": {
            "firewall_ad": ("Firewall + AD", AttackGenerators.firewall_ad_correlation),
        }
    },
}

MITRE_CATALOGUE = {
    "T1110":   ("Brute Force SSH",             AttackGenerators.ssh_brute_force),
    "T1046":   ("Network Service Scanning",    AttackGenerators.port_scan),
    "T1190":   ("Public Facing App Exploit",   AttackGenerators.public_app_exploit),
    "T1021":   ("SSH Lateral Movement",        AttackGenerators.ssh_lateral_movement),
    "T1021.2": ("SMB Lateral Movement",        AttackGenerators.smb_lateral_movement),
    "T1021.1": ("RDP Lateral Movement",        AttackGenerators.rdp_lateral_movement),
    "T1550":   ("Pass-the-Hash",               AttackGenerators.pass_the_hash),
    "T1558.3": ("Kerberoasting",               AttackGenerators.kerberoasting),
    "T1558.1": ("Golden Ticket",               AttackGenerators.golden_ticket),
    "T1047":   ("WMI Remote Execution",        AttackGenerators.wmi_exec),
    "T1041":   ("Exfiltration over C2",        AttackGenerators.data_exfiltration),
    "T1048":   ("DNS Exfiltration",            AttackGenerators.dns_exfiltration),
    "T1567":   ("HTTP POST Exfiltration",      AttackGenerators.http_post_exfiltration),
    "T1567.2": ("Cloud Storage Exfiltration",  AttackGenerators.cloud_upload_exfiltration),
    "T1095":   ("ICMP Tunnel",                 AttackGenerators.icmp_exfiltration),
}


# ── Interface Rich (inchangée) ─────────────────────────────────────────────────

def print_header():
    console.clear()
    console.print(Panel(
        Text("SMART SIEM — SIMULATEUR DE LOGS D'ATTAQUE\n"
             "Génère des logs dans Elasticsearch pour tester correlation_engine",
             justify="center", style="bold white"),
        style="bold blue", box=box.DOUBLE_EDGE, padding=(1, 4)
    ))

def print_main_menu():
    table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
    table.add_column("Num", style="bold cyan", width=4)
    table.add_column("Option", style="white")
    table.add_row("1", "🎯  Par type d'attaque")
    table.add_row("2", "⚙️   Par type de règle")
    table.add_row("3", "🔴  Par MITRE ATT&CK")
    table.add_row("4", "💥  TOUT simuler")
    table.add_row("0", "🚪  Quitter")
    console.print(table)

def print_submenu(title: str, items: dict, color: str = "cyan") -> dict:
    table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
    table.add_column("Num", style=f"bold {color}", width=4)
    table.add_column("Attaque", style="white")
    mapping = {}
    for i, (key, (label, _)) in enumerate(items.items(), 1):
        table.add_row(str(i), label)
        mapping[str(i)] = key
    table.add_row("A", f"[bold green]Toutes les attaques '{title}'[/bold green]")
    table.add_row("0", "Retour au menu principal")
    mapping["A"] = "__ALL__"
    mapping["0"] = "__BACK__"
    console.print(Panel(table, title=f"[bold {color}]{title}[/bold {color}]", box=box.ROUNDED))
    return mapping

async def run_simulation(es, attacks, label, continuous=False, interval_sec=2.0):
    global stop_generation
    stats = {"label": label, "attacks_run": [], "total_logs": 0, "total_alerts": 0,
             "started_at": datetime.now(timezone.utc).isoformat(), "stopped_early": False}
    console.print(f"\n[bold green]▶ Démarrage : {label}[/bold green]")
    console.print("[dim]Ctrl+C pour stopper[/dim]\n")
    stop_generation = False

    def handle_stop(sig, frame):
        global stop_generation
        stop_generation = True
        console.print("\n[bold yellow]⚠ Arrêt — retour au menu...[/bold yellow]")
    signal.signal(signal.SIGINT, handle_stop)

    try:
        for gen_func, gen_kwargs in attacks:
            if stop_generation:
                stats["stopped_early"] = True
                break
            logs, description, expected_alerts = gen_func(**gen_kwargs) if gen_kwargs else gen_func()
            with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                          BarColumn(), TaskProgressColumn(), console=console, transient=True) as progress:
                task = progress.add_task(description, total=len(logs))
                for i in range(0, len(logs), 20):
                    if stop_generation:
                        break
                    inserted = await bulk_insert(es, logs[i:i+20])
                    stats["total_logs"] += inserted
                    progress.advance(task, 20)
                    await asyncio.sleep(0.05)
            stats["total_alerts"] += expected_alerts
            stats["attacks_run"].append({"name": description, "logs_generated": len(logs), "alerts_expected": expected_alerts})
            t = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
            t.add_column("", style="dim", width=20)
            t.add_column("", style="bold")
            t.add_row("Attaque", description)
            t.add_row("Logs insérés", str(len(logs)))
            t.add_row("Alertes attendues", str(expected_alerts))
            t.add_row("Index ES", INDEX_ALIAS)
            console.print(t)
            if continuous and not stop_generation:
                await asyncio.sleep(interval_sec)
    except Exception as e:
        console.print(f"[red]Erreur : {e}[/red]")
    finally:
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    stats["ended_at"] = datetime.now(timezone.utc).isoformat()
    session_log["attacks_simulated"].extend(stats["attacks_run"])
    session_log["total_logs_inserted"] += stats["total_logs"]
    session_log["total_alerts_expected"] += stats["total_alerts"]
    console.print(Panel(
        f"[bold green]✅ Session terminée[/bold green]\n"
        f"Logs insérés    : [bold]{stats['total_logs']}[/bold]\n"
        f"Alertes prévues : [bold]{stats['total_alerts']}[/bold]",
        title="Résumé", box=box.ROUNDED, style="green"))
    return stats

async def menu_by_tactic(es):
    while True:
        print_header()
        table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
        table.add_column("Num", style="bold cyan", width=4)
        table.add_column("Catégorie", style="white")
        tactic_list = list(CATALOGUE.items())
        for i, (key, cat) in enumerate(tactic_list, 1):
            table.add_row(str(i), f"[bold {cat['color']}]{cat['label']}[/bold {cat['color']}]")
        table.add_row("0", "Retour")
        console.print(Panel(table, title="Choisissez un type d'attaque", box=box.ROUNDED))
        choice = Prompt.ask("Votre choix")
        if choice == "0": return
        try:
            cat_key, cat = tactic_list[int(choice) - 1]
        except (ValueError, IndexError):
            continue
        print_header()
        mapping = print_submenu(cat["label"], cat["attacks"], cat["color"])
        atk_choice = Prompt.ask("Votre choix")
        if mapping.get(atk_choice) == "__BACK__": continue
        if mapping.get(atk_choice) == "__ALL__":
            await run_simulation(es, [(fn, {}) for _, fn in cat["attacks"].values()], f"Toutes — {cat['label']}")
        elif atk_choice in mapping:
            label, fn = cat["attacks"][mapping[atk_choice]]
            await run_simulation(es, [(fn, {})], label)
        Prompt.ask("\n[dim]Entrée pour continuer[/dim]")

async def menu_by_rule_type(es):
    while True:
        print_header()
        table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
        table.add_column("Num", style="bold cyan", width=4)
        table.add_column("Type", style="white")
        type_list = list(RULE_TYPE_CATALOGUE.items())
        for i, (key, cat) in enumerate(type_list, 1):
            table.add_row(str(i), f"[bold {cat['color']}]{cat['label']}[/bold {cat['color']}]")
        table.add_row("0", "Retour")
        console.print(Panel(table, title="Choisissez un type de règle", box=box.ROUNDED))
        choice = Prompt.ask("Votre choix")
        if choice == "0": return
        try:
            _, cat = type_list[int(choice) - 1]
        except (ValueError, IndexError):
            continue
        print_header()
        mapping = print_submenu(cat["label"], cat["attacks"], cat["color"])
        atk_choice = Prompt.ask("Votre choix")
        if mapping.get(atk_choice) == "__BACK__": continue
        if mapping.get(atk_choice) == "__ALL__":
            await run_simulation(es, [(fn, {}) for _, fn in cat["attacks"].values()], f"Toutes — {cat['label']}")
        elif atk_choice in mapping:
            label, fn = cat["attacks"][mapping[atk_choice]]
            await run_simulation(es, [(fn, {})], label)
        Prompt.ask("\n[dim]Entrée pour continuer[/dim]")

async def menu_by_mitre(es):
    while True:
        print_header()
        table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
        table.add_column("Num", style="bold cyan", width=4)
        table.add_column("Technique", style="bold", width=10)
        table.add_column("Description", style="white")
        mitre_list = list(MITRE_CATALOGUE.items())
        for i, (tech_id, (label, _)) in enumerate(mitre_list, 1):
            table.add_row(str(i), f"[red]{tech_id}[/red]", label)
        table.add_row("0", "", "Retour")
        console.print(Panel(table, title="Choisissez une technique MITRE ATT&CK", box=box.ROUNDED))
        choice = Prompt.ask("Votre choix")
        if choice == "0": return
        try:
            tech_id, (label, fn) = mitre_list[int(choice) - 1]
            await run_simulation(es, [(fn, {})], f"MITRE {tech_id} — {label}")
        except (ValueError, IndexError):
            pass
        Prompt.ask("\n[dim]Entrée pour continuer[/dim]")

def save_session_report():
    report_path = LOG_DIR / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    session_log["ended_at"] = datetime.now(timezone.utc).isoformat()
    with open(report_path, "w") as f:
        json.dump(session_log, f, indent=2, ensure_ascii=False)
    console.print(f"\n[bold green]📄 Rapport sauvegardé : {report_path}[/bold green]")
    console.print(Panel(
        f"Total logs ES : [bold green]{session_log['total_logs_inserted']}[/bold green]\n"
        f"Alertes prévues: [bold yellow]{session_log['total_alerts_expected']}[/bold yellow]\n"
        f"Attaques lancées: {len(session_log['attacks_simulated'])}",
        title="Session complète", box=box.DOUBLE_EDGE, style="green"))


async def main():
    console.print("[dim]Connexion à Elasticsearch...[/dim]")
    es = AsyncElasticsearch(
        hosts=[ES_HOST], basic_auth=(ES_USER, ES_PASSWORD),
        ca_certs=ES_CACERT, verify_certs=True,
    )
    try:
        info = await es.info()
        console.print(f"[green]✓ ES {info['version']['number']} connecté[/green]")
    except Exception as e:
        console.print(f"[red]✗ Connexion ES impossible : {e}[/red]")
        return

    # P1-A : validation au démarrage — arrêt immédiat si incohérence
    validate_event_actions()

    while True:
        print_header()
        print_main_menu()
        choice = Prompt.ask("\nVotre choix")
        if choice == "1":
            await menu_by_tactic(es)
        elif choice == "2":
            await menu_by_rule_type(es)
        elif choice == "3":
            await menu_by_mitre(es)
        elif choice == "4":
            all_attacks = [(fn, {}) for cat in CATALOGUE.values() for _, fn in cat["attacks"].values()]
            await run_simulation(es, all_attacks, "TOUTES LES ATTAQUES")
            Prompt.ask("\n[dim]Entrée pour continuer[/dim]")
        elif choice == "0":
            save_session_report()
            console.print("\n[bold blue]Au revoir ![/bold blue]\n")
            break

    await es.close()


if __name__ == "__main__":
    asyncio.run(main())