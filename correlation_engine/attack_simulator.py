#!/usr/bin/env python3
"""
SMART SIEM — Simulateur d'attaques CLI
Génère des logs d'attaque dans Elasticsearch à la demande.
Utilise Rich pour un affichage terminal coloré et structuré.
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

# Flag d'arrêt pour stopper la génération sans quitter le programme
stop_generation = False

# Session complète pour le rapport final
session_log = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "attacks_simulated": [],
    "total_logs_inserted": 0,
    "total_alerts_expected": 0,
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
    raw = f"{host} {event_action} {src_ip} {username or ''}"
    doc = {
        "@timestamp":      ts(delta),
        "ingested_at":     ts(0),
        "source_id":       f"src-{source_type}-sim",
        "host":            host,
        "hostname":        host,
        "log_type":        log_type,
        "severity":        severity,
        "event_action":    event_action,
        "event_outcome":   "failure" if "fail" in event_action else "success",
        "source_ip":       src_ip,
        "raw_message":     raw,
        "hash_sha256":     sha(raw + str(delta) + str(uuid.uuid4())),
        "pipeline_version": "1.0",
        "tags":            tags or [],
        "raw_log_id":      str(uuid.uuid4()),  # clé pour éviter le bug _id
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
    return doc


async def bulk_insert(es: AsyncElasticsearch, logs: list) -> int:
    from elasticsearch.helpers import async_bulk
    actions = [{"_index": INDEX_ALIAS, "_source": doc} for doc in logs]
    ok, _ = await async_bulk(es, actions, chunk_size=50, raise_on_error=False)
    return ok


# ══════════════════════════════════════════════════════════════════════════════
# GÉNÉRATEURS DE LOGS PAR ATTAQUE
# ══════════════════════════════════════════════════════════════════════════════

class AttackGenerators:
    """
    Chaque méthode génère les logs correspondant à une attaque précise.
    Les logs sont construits pour déclencher les règles de corrélation définies.
    Chaque méthode retourne (liste_de_logs, description, alertes_attendues).
    """

    # ── INITIAL ACCESS ─────────────────────────────────────────────────────────

    @staticmethod
    def ssh_brute_force(attack_ip: str = "185.220.101.5",
                        target: str = "srv-web-01", n: int = 8) -> tuple:
        """
        SSH Brute Force — T1110
        Règle : 5+ login_failed depuis même IP en 60s → HIGH
        On génère n tentatives espacées de 5s dans la fenêtre de 60s.
        """
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
        # Connexion réussie finale = compromission
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
        """
        Port Scan — T1046
        Règle : 50+ connection_blocked depuis même IP en 10s → HIGH
        """
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
        return logs, f"Port Scan ({n} ports) depuis {attack_ip}", 1

    @staticmethod
    def public_app_exploit(attack_ip: str = "91.108.4.33",
                           target: str = "srv-apache-01") -> tuple:
        """Public Facing App Exploit — T1190"""
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

    # ── LATERAL MOVEMENT ───────────────────────────────────────────────────────

    @staticmethod
    def ssh_lateral_movement(pivot_ip: str = "10.0.1.10",
                              target: str = "srv-db-01") -> tuple:
        """
        SSH Lateral Movement — T1021 (pattern)
        Règle pattern : login_success → file_read même IP en 300s → CRITICAL
        """
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
        """SMB Lateral Movement — T1021.002 (threshold port 445)"""
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
        """Pass-the-Hash — T1550.002 (pattern)"""
        logs = [
            make_log("linux_server", "srv-web-01", attack_ip,
                     "credential_dump", "critical", "system",
                     delta=500, mitre_tactic="TA0006", mitre_technique="T1003",
                     tags=["pth_candidate", "simulated"]),
            make_log("windows_server", "srv-ad-01", attack_ip,
                     "login_success", "critical", "auth",
                     username="admin", dest_port=445, delta=300,
                     mitre_tactic="TA0008", mitre_technique="T1550",
                     tags=["pth_candidate", "simulated"],
                     extra={"auth_type": "NTLM"}),
        ]
        return logs, f"Pass-the-Hash depuis {attack_ip}", 1

    @staticmethod
    def kerberoasting(attack_ip: str = "10.0.1.20",
                      n: int = 15) -> tuple:
        """Kerberoasting — T1558.003 (10+ TGS en 30s)"""
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
        """RDP Lateral Movement — T1021.001 (3+ port 3389 en 600s)"""
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
        """WMI Remote Execution — T1047"""
        logs = [
            make_log("windows_server", "srv-win-01", attack_ip,
                     "wmi_exec", "high", "system",
                     delta=0, mitre_tactic="TA0008", mitre_technique="T1047",
                     tags=["wmi_exec", "simulated"],
                     extra={"command": "powershell -enc BASE64ENCODEDCMD"})
        ]
        return logs, f"WMI Remote Execution depuis {attack_ip}", 1

    @staticmethod
    def golden_ticket(username: str = "compromised.admin",
                      n: int = 25) -> tuple:
        """Golden Ticket — T1558.001 (20+ TGT en 60s)"""
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
        """PsExec — T1021.002 (pattern service_created → process_started)"""
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
                     extra={"process": "cmd.exe", "parent": "PSEXESVC.exe"}),
        ]
        return logs, f"PsExec depuis {attack_ip}", 1

    # ── EXFILTRATION ───────────────────────────────────────────────────────────

    @staticmethod
    def data_exfiltration(src_ip: str = "10.0.1.10",
                           dest_ip: str = "45.142.212.100",
                           n: int = 4) -> tuple:
        """Large Transfer Exfiltration — T1041 (3+ transferts en 3600s)"""
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
        """DNS Tunnel Exfiltration — T1048.003 (200+ DNS en 60s)"""
        logs = [
            make_log("firewall", "fw-perimeter", src_ip,
                     "dns_query", "warning", "network",
                     delta=58 - int(i * 0.23),
                     mitre_tactic="TA0010", mitre_technique="T1048",
                     tags=["dns_tunnel", "simulated"],
                     extra={"enriched_data": {
                         "query": f"data{i}.malicious-exfil.com"
                     }})
            for i in range(n)
        ]
        return logs, f"DNS Tunnel Exfiltration ({n} requêtes) depuis {src_ip}", 1

    @staticmethod
    def http_post_exfiltration(src_ip: str = "10.0.1.30", n: int = 60) -> tuple:
        """HTTP POST Exfiltration — T1567 (50+ POST en 300s)"""
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
        """Cloud Storage Exfiltration — T1567.002 (5+ uploads en 3600s)"""
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
        """ICMP Tunnel — T1095 (100+ en 60s)"""
        logs = [
            make_log("firewall", "fw-perimeter", src_ip,
                     "icmp_flood", "high", "network",
                     delta=58 - int(i * 0.48),
                     mitre_tactic="TA0010", mitre_technique="T1095",
                     tags=["icmp_tunnel", "simulated"])
            for i in range(n)
        ]
        return logs, f"ICMP Tunnel ({n} paquets) depuis {src_ip}", 1

    # ── CROSS-SOURCE ───────────────────────────────────────────────────────────

    @staticmethod
    def firewall_ad_correlation(attack_ip: str = "185.220.101.5",
                                 username: str = "chloe.obrian") -> tuple:
        """Cross-Source : Firewall + AD — composite (TA0001 + TA0005)"""
        logs = [
            make_log("firewall", "fw-perimeter", attack_ip,
                     "connection_blocked", "warning", "network",
                     dest_port=443, delta=280,
                     mitre_tactic="TA0005", tags=["fw_blocked", "simulated"]),
            make_log("windows_server", "srv-ad-01", attack_ip,
                     "login_failed", "warning", "auth",
                     username=username, dest_port=389, delta=180,
                     mitre_tactic="TA0001", tags=["ad_auth_fail", "simulated"]),
            make_log("windows_server", "srv-ad-01", attack_ip,
                     "login_failed", "high", "auth",
                     username=username, dest_port=389, delta=60,
                     mitre_tactic="TA0001",
                     tags=["ad_auth_fail", "cross_source_candidate", "simulated"]),
        ]
        return logs, f"Cross-source Firewall+AD depuis {attack_ip}", 1


# ── Catalogue des attaques ─────────────────────────────────────────────────────

CATALOGUE = {
    "initial_access": {
        "label": "Initial Access (TA0001)",
        "color": "red",
        "attacks": {
            "ssh_brute_force":       ("SSH Brute Force",         AttackGenerators.ssh_brute_force),
            "port_scan":             ("Port Scan (Discovery)",   AttackGenerators.port_scan),
            "public_app_exploit":    ("Public App Exploit",      AttackGenerators.public_app_exploit),
        }
    },
    "lateral_movement": {
        "label": "Lateral Movement (TA0008)",
        "color": "yellow",
        "attacks": {
            "ssh_lateral":           ("SSH Lateral Movement",    AttackGenerators.ssh_lateral_movement),
            "smb_lateral":           ("SMB Lateral Movement",    AttackGenerators.smb_lateral_movement),
            "pass_the_hash":         ("Pass-the-Hash",           AttackGenerators.pass_the_hash),
            "kerberoasting":         ("Kerberoasting",           AttackGenerators.kerberoasting),
            "rdp_lateral":           ("RDP Lateral Movement",    AttackGenerators.rdp_lateral_movement),
            "wmi_exec":              ("WMI Remote Execution",    AttackGenerators.wmi_exec),
            "golden_ticket":         ("Golden Ticket",           AttackGenerators.golden_ticket),
            "psexec":                ("PsExec Remote Service",   AttackGenerators.psexec),
        }
    },
    "exfiltration": {
        "label": "Exfiltration (TA0010)",
        "color": "magenta",
        "attacks": {
            "data_exfiltration":     ("Large Transfer",          AttackGenerators.data_exfiltration),
            "dns_exfiltration":      ("DNS Tunnel",              AttackGenerators.dns_exfiltration),
            "http_post_exfil":       ("HTTP POST Exfiltration",  AttackGenerators.http_post_exfiltration),
            "cloud_upload_exfil":    ("Cloud Upload",            AttackGenerators.cloud_upload_exfiltration),
            "ftp_exfiltration":      ("FTP Exfiltration",        AttackGenerators.ftp_exfiltration),
            "icmp_exfiltration":     ("ICMP Tunnel",             AttackGenerators.icmp_exfiltration),
        }
    },
    "cross_source": {
        "label": "Cross-Source (composite)",
        "color": "cyan",
        "attacks": {
            "firewall_ad":           ("Firewall + AD Correlation", AttackGenerators.firewall_ad_correlation),
        }
    },
}

# Catalogue par type de règle
RULE_TYPE_CATALOGUE = {
    "threshold": {
        "label": "Threshold (seuil)", "color": "blue",
        "attacks": {
            "ssh_brute_force":    ("SSH Brute Force",        AttackGenerators.ssh_brute_force),
            "port_scan":          ("Port Scan",              AttackGenerators.port_scan),
            "kerberoasting":      ("Kerberoasting",          AttackGenerators.kerberoasting),
            "golden_ticket":      ("Golden Ticket",          AttackGenerators.golden_ticket),
            "data_exfiltration":  ("Large Transfer",         AttackGenerators.data_exfiltration),
            "dns_exfiltration":   ("DNS Tunnel",             AttackGenerators.dns_exfiltration),
            "http_post_exfil":    ("HTTP POST",              AttackGenerators.http_post_exfiltration),
            "smb_lateral":        ("SMB Lateral",            AttackGenerators.smb_lateral_movement),
            "rdp_lateral":        ("RDP Lateral",            AttackGenerators.rdp_lateral_movement),
        }
    },
    "pattern": {
        "label": "Pattern (séquence FSM)", "color": "green",
        "attacks": {
            "ssh_lateral":        ("SSH Lateral Movement",   AttackGenerators.ssh_lateral_movement),
            "pass_the_hash":      ("Pass-the-Hash",          AttackGenerators.pass_the_hash),
            "psexec":             ("PsExec",                 AttackGenerators.psexec),
        }
    },
    "composite": {
        "label": "Composite / Cross-Source", "color": "cyan",
        "attacks": {
            "firewall_ad":        ("Firewall + AD",          AttackGenerators.firewall_ad_correlation),
        }
    },
}

# Catalogue MITRE ATT&CK
MITRE_CATALOGUE = {
    "T1110":  ("Brute Force SSH",              AttackGenerators.ssh_brute_force),
    "T1046":  ("Network Service Scanning",     AttackGenerators.port_scan),
    "T1190":  ("Public Facing App Exploit",    AttackGenerators.public_app_exploit),
    "T1021":  ("SSH Lateral Movement",         AttackGenerators.ssh_lateral_movement),
    "T1021.2":("SMB Lateral Movement",         AttackGenerators.smb_lateral_movement),
    "T1021.1":("RDP Lateral Movement",         AttackGenerators.rdp_lateral_movement),
    "T1550":  ("Pass-the-Hash",                AttackGenerators.pass_the_hash),
    "T1558.3":("Kerberoasting",                AttackGenerators.kerberoasting),
    "T1558.1":("Golden Ticket",                AttackGenerators.golden_ticket),
    "T1047":  ("WMI Remote Execution",         AttackGenerators.wmi_exec),
    "T1041":  ("Exfiltration over C2",         AttackGenerators.data_exfiltration),
    "T1048":  ("DNS Exfiltration",             AttackGenerators.dns_exfiltration),
    "T1567":  ("HTTP POST Exfiltration",       AttackGenerators.http_post_exfiltration),
    "T1567.2":("Cloud Storage Exfiltration",   AttackGenerators.cloud_upload_exfiltration),
    "T1095":  ("ICMP Tunnel",                  AttackGenerators.icmp_exfiltration),
}


# ── Interface Rich ─────────────────────────────────────────────────────────────

def print_header():
    console.clear()
    console.print(Panel(
        Text("SMART SIEM — SIMULATEUR DE LOGS D'ATTAQUE\n"
             "Génère des logs dans Elasticsearch pour tester correlation_engine",
             justify="center", style="bold white"),
        style="bold blue",
        box=box.DOUBLE_EDGE,
        padding=(1, 4)
    ))


def print_main_menu():
    table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
    table.add_column("Num", style="bold cyan", width=4)
    table.add_column("Option", style="white")
    table.add_row("1", "🎯  Par type d'attaque  (Initial Access, Exfiltration, Lateral Movement...)")
    table.add_row("2", "⚙️   Par type de règle   (Threshold, Pattern, Composite)")
    table.add_row("3", "🔴  Par MITRE ATT&CK     (T1110 Brute Force, T1021 Lateral...)")
    table.add_row("4", "💥  TOUT simuler          (toutes les attaques d'un coup)")
    table.add_row("0", "🚪  Quitter")
    console.print(table)


def print_submenu(title: str, items: dict, color: str = "cyan") -> dict:
    """Affiche un sous-menu et retourne le mapping numéro → clé."""
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
    console.print(Panel(table, title=f"[bold {color}]{title}[/bold {color}]",
                        box=box.ROUNDED))
    return mapping


async def run_simulation(es: AsyncElasticsearch,
                         attacks: list[tuple],
                         label: str,
                         continuous: bool = False,
                         interval_sec: float = 2.0):
    """
    Exécute la simulation d'une liste d'attaques.
    Affiche la progression en temps réel avec Rich.
    Retourne les stats de la session.
    """
    global stop_generation

    stats = {
        "label":         label,
        "attacks_run":   [],
        "total_logs":    0,
        "total_alerts":  0,
        "started_at":    datetime.now(timezone.utc).isoformat(),
        "stopped_early": False,
    }

    console.print(f"\n[bold green]▶ Démarrage : {label}[/bold green]")
    console.print("[dim]Appuyez sur Ctrl+C pour stopper et revenir au menu[/dim]\n")

    stop_generation = False

    def handle_stop(sig, frame):
        global stop_generation
        stop_generation = True
        console.print("\n[bold yellow]⚠ Arrêt demandé — retour au menu...[/bold yellow]")

    signal.signal(signal.SIGINT, handle_stop)

    try:
        for gen_func, gen_kwargs in attacks:
            if stop_generation:
                stats["stopped_early"] = True
                break

            # Génération des logs
            logs, description, expected_alerts = gen_func(**gen_kwargs) \
                if gen_kwargs else gen_func()

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(description, total=len(logs))

                # Insertion par batch de 20
                for i in range(0, len(logs), 20):
                    if stop_generation:
                        break
                    batch = logs[i:i + 20]
                    inserted = await bulk_insert(es, batch)
                    stats["total_logs"] += inserted
                    progress.advance(task, len(batch))
                    await asyncio.sleep(0.05)

            stats["total_alerts"] += expected_alerts
            stats["attacks_run"].append({
                "name":            description,
                "logs_generated":  len(logs),
                "alerts_expected": expected_alerts,
            })

            # Table de résumé de l'attaque
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

    # Résumé final de la session
    stats["ended_at"] = datetime.now(timezone.utc).isoformat()
    session_log["attacks_simulated"].extend(stats["attacks_run"])
    session_log["total_logs_inserted"] += stats["total_logs"]
    session_log["total_alerts_expected"] += stats["total_alerts"]

    panel_content = (
        f"[bold green]✅ Session terminée[/bold green]\n"
        f"Logs insérés    : [bold]{stats['total_logs']}[/bold]\n"
        f"Alertes prévues : [bold]{stats['total_alerts']}[/bold]\n"
        f"{'[yellow]⚠ Arrêt anticipé[/yellow]' if stats['stopped_early'] else ''}"
    )
    console.print(Panel(panel_content, title="Résumé", box=box.ROUNDED,
                        style="green"))
    return stats


async def menu_by_tactic(es: AsyncElasticsearch):
    """Menu principal 1 — par type d'attaque."""
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
        if choice == "0":
            return

        try:
            cat_key, cat = tactic_list[int(choice) - 1]
        except (ValueError, IndexError):
            continue

        # Sous-menu des attaques de cette catégorie
        print_header()
        mapping = print_submenu(cat["label"], cat["attacks"], cat["color"])
        atk_choice = Prompt.ask("Votre choix")

        if mapping.get(atk_choice) == "__BACK__":
            continue

        if mapping.get(atk_choice) == "__ALL__":
            attacks = [(fn, {}) for _, fn in cat["attacks"].values()]
            await run_simulation(es, attacks, f"Toutes — {cat['label']}")
        elif atk_choice in mapping:
            atk_key = mapping[atk_choice]
            label, fn = cat["attacks"][atk_key]
            await run_simulation(es, [(fn, {})], label)

        Prompt.ask("\n[dim]Appuyez sur Entrée pour continuer[/dim]")


async def menu_by_rule_type(es: AsyncElasticsearch):
    """Menu principal 2 — par type de règle."""
    while True:
        print_header()
        table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
        table.add_column("Num", style="bold cyan", width=4)
        table.add_column("Type de règle", style="white")
        type_list = list(RULE_TYPE_CATALOGUE.items())
        for i, (key, cat) in enumerate(type_list, 1):
            table.add_row(str(i), f"[bold {cat['color']}]{cat['label']}[/bold {cat['color']}]")
        table.add_row("0", "Retour")
        console.print(Panel(table, title="Choisissez un type de règle", box=box.ROUNDED))

        choice = Prompt.ask("Votre choix")
        if choice == "0":
            return

        try:
            _, cat = type_list[int(choice) - 1]
        except (ValueError, IndexError):
            continue

        print_header()
        mapping = print_submenu(cat["label"], cat["attacks"], cat["color"])
        atk_choice = Prompt.ask("Votre choix")

        if mapping.get(atk_choice) == "__BACK__":
            continue
        if mapping.get(atk_choice) == "__ALL__":
            attacks = [(fn, {}) for _, fn in cat["attacks"].values()]
            await run_simulation(es, attacks, f"Toutes — {cat['label']}")
        elif atk_choice in mapping:
            label, fn = cat["attacks"][mapping[atk_choice]]
            await run_simulation(es, [(fn, {})], label)

        Prompt.ask("\n[dim]Entrée pour continuer[/dim]")


async def menu_by_mitre(es: AsyncElasticsearch):
    """Menu principal 3 — par technique MITRE ATT&CK."""
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
        console.print(Panel(table, title="Choisissez une technique MITRE ATT&CK",
                            box=box.ROUNDED))

        choice = Prompt.ask("Votre choix")
        if choice == "0":
            return
        try:
            tech_id, (label, fn) = mitre_list[int(choice) - 1]
            await run_simulation(es, [(fn, {})], f"MITRE {tech_id} — {label}")
        except (ValueError, IndexError):
            pass

        Prompt.ask("\n[dim]Entrée pour continuer[/dim]")


def save_session_report():
    """Sauvegarde le rapport de session dans test_correlation/."""
    report_path = LOG_DIR / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    session_log["ended_at"] = datetime.now(timezone.utc).isoformat()
    with open(report_path, "w") as f:
        json.dump(session_log, f, indent=2, ensure_ascii=False)

    console.print(f"\n[bold green]📄 Rapport sauvegardé : {report_path}[/bold green]")

    # Résumé lisible
    console.print(Panel(
        f"[bold]Rapport de session[/bold]\n"
        f"Démarré le    : {session_log['started_at']}\n"
        f"Terminé le    : {session_log['ended_at']}\n"
        f"Total logs ES : [bold green]{session_log['total_logs_inserted']}[/bold green]\n"
        f"Alertes prévues: [bold yellow]{session_log['total_alerts_expected']}[/bold yellow]\n"
        f"Attaques lancées: {len(session_log['attacks_simulated'])}",
        title="Session complète", box=box.DOUBLE_EDGE, style="green"
    ))


async def main():
    console.print("[dim]Connexion à Elasticsearch...[/dim]")
    es = AsyncElasticsearch(
        hosts=[ES_HOST],
        basic_auth=(ES_USER, ES_PASSWORD),
        ca_certs=ES_CACERT,
        verify_certs=True,
    )

    try:
        info = await es.info()
        console.print(f"[green]✓ ES {info['version']['number']} connecté[/green]")
    except Exception as e:
        console.print(f"[red]✗ Connexion ES impossible : {e}[/red]")
        return

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
            all_attacks = [
                (fn, {})
                for cat in CATALOGUE.values()
                for _, fn in cat["attacks"].values()
            ]
            await run_simulation(es, all_attacks, "TOUTES LES ATTAQUES")
            Prompt.ask("\n[dim]Entrée pour continuer[/dim]")
        elif choice == "0":
            save_session_report()
            console.print("\n[bold blue]Au revoir ![/bold blue]\n")
            break

    await es.close()


if __name__ == "__main__":
    asyncio.run(main())