#!/usr/bin/env python3
"""
SMART SIEM — Générateur de logs simulés
Génère 1200 logs couvrant 5 scénarios d'attaque MITRE ATT&CK
+ du trafic normal pour le ratio 70/20/10 (normal/anomalie/attaque)
"""

import os
import random
import hashlib
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch

# ── Connexion ES ──────────────────────────────────────────────────────────────
es = Elasticsearch(
    hosts=["https://localhost:9200"],
    basic_auth=("elastic", os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu")),
    ca_certs="http_ca.crt",
    verify_certs=True,
)
INDEX_ALIAS = "siem-logs-current"  # alias write défini dans 02_elasticsearch_setup.py

# ── Sources simulées ──────────────────────────────────────────────────────────
SOURCES = [
    {"id": "src-linux-01",   "type": "linux_server",     "host": "srv-web-01",    "ip": "10.0.1.10"},
    {"id": "src-linux-02",   "type": "linux_server",     "host": "srv-db-01",     "ip": "10.0.1.20"},
    {"id": "src-windows-01", "type": "windows_server",   "host": "srv-ad-01",     "ip": "10.0.1.30"},
    {"id": "src-firewall-01","type": "firewall",          "host": "fw-perimeter",  "ip": "10.0.0.1"},
    {"id": "src-apache-01",  "type": "web_server",        "host": "srv-apache-01", "ip": "10.0.1.40"},
]

USERS   = ["jack.bauer", "chloe.obrian", "bill.buchanan", "david.palmer", "tony.almeida"]
BAD_IPS = ["185.220.101.5", "91.108.4.33", "194.165.16.98", "45.142.212.100"]
LEGIT_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.10.5.50"]

def now_iso(delta_seconds: int = 0) -> str:
    """Retourne un timestamp ISO 8601 UTC avec un décalage optionnel en secondes."""
    t = datetime.now(timezone.utc) - timedelta(seconds=abs(delta_seconds))
    return t.isoformat()

def make_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()

def base_log(source: dict, event_action: str, severity: str, log_type: str,
             username: str = None, src_ip: str = None, delta: int = 0,
             extra: dict = None) -> dict:
    """Construit un document ES normalisé."""
    raw = f"{source['host']} {event_action} {src_ip or ''} {username or ''}"
    doc = {
        "@timestamp":    now_iso(delta),
        "ingested_at":   now_iso(0),
        "source_id":     source["id"],
        "host":          source["host"],
        "hostname":      source["host"],
        "log_type":      log_type,
        "severity":      severity,
        "event_action":  event_action,
        "event_outcome": "failure" if "fail" in event_action else "success",
        "source_ip":     src_ip or random.choice(LEGIT_IPS),
        "raw_message":   raw,
        "hash_sha256":   make_hash(raw),
        "pipeline_version": "1.0",
        "tags":          [],
    }
    if username:
        doc["username"] = username
    if extra:
        doc.update(extra)
    return doc

# ─────────────────────────────────────────────────────────────────────────────
# SCÉNARIOS D'ATTAQUE
# Chaque fonction génère une séquence de logs pour un scénario précis.
# delta = secondes dans le passé (pour simuler une séquence temporelle)
# ─────────────────────────────────────────────────────────────────────────────

def scenario_brute_force_ssh(attack_ip: str, target_user: str = "root") -> list:
    """
    TA0001 — Initial Access / T1110 — Brute Force SSH
    7 tentatives échouées en 45 secondes depuis la même IP.
    Règle threshold : 5 échecs / 60s / même source_ip → HIGH
    """
    logs = []
    for i in range(7):
        logs.append(base_log(
            source=SOURCES[0],  # srv-web-01
            event_action="login_failed",
            severity="warning",
            log_type="auth",
            username=target_user,
            src_ip=attack_ip,
            delta=45 - i * 6,   # espacés de 6 secondes
            extra={
                "dest_port": 22,
                "mitre_tactic": "TA0001",
                "mitre_technique": "T1110",
                "tags": ["brute_force_candidate"],
            }
        ))
    # Une tentative réussie à la fin (compromission)
    logs.append(base_log(
        source=SOURCES[0],
        event_action="login_success",
        severity="high",
        log_type="auth",
        username=target_user,
        src_ip=attack_ip,
        delta=0,
        extra={"dest_port": 22, "mitre_tactic": "TA0001", "tags": ["compromise_suspected"]}
    ))
    return logs

def scenario_lateral_movement(compromised_host: str, attack_ip: str) -> list:
    """
    TA0008 — Lateral Movement / T1021 — Remote Services
    Séquence : login réussi depuis hôte compromis → accès DB → lecture /etc/shadow
    Règle pattern : login_success depuis IP interne inhabituelle → credential_access
    """
    logs = []
    # 1. Connexion depuis l'hôte compromis vers le serveur DB
    logs.append(base_log(
        source=SOURCES[1],  # srv-db-01
        event_action="login_success",
        severity="high",
        log_type="auth",
        username="db_admin",
        src_ip=compromised_host,
        delta=120,
        extra={"dest_port": 22, "mitre_tactic": "TA0008", "mitre_technique": "T1021",
               "tags": ["lateral_movement_candidate"]}
    ))
    # 2. Accès à un fichier sensible
    logs.append(base_log(
        source=SOURCES[1],
        event_action="file_read",
        severity="critical",
        log_type="system",
        username="db_admin",
        src_ip=compromised_host,
        delta=90,
        extra={
            "mitre_tactic": "TA0006", "mitre_technique": "T1003",
            "tags": ["credential_access"],
            "enriched_data": {"file_path": "/etc/shadow", "file_type": "sensitive"}
        }
    ))
    return logs

def scenario_port_scan(attacker_ip: str) -> list:
    """
    TA0007 — Discovery / T1046 — Network Service Scanning
    60 connexions SYN vers des ports différents en 10 secondes.
    Règle threshold : 50 connexions / 10s / même source_ip → HIGH
    """
    logs = []
    ports = random.sample(range(1, 65535), 60)
    for i, port in enumerate(ports):
        logs.append(base_log(
            source=SOURCES[3],  # firewall
            event_action="connection_blocked",
            severity="info" if i < 50 else "warning",
            log_type="network",
            src_ip=attacker_ip,
            delta=10 - int(i * 0.15),  # 60 events en 10 secondes
            extra={
                "dest_port": port,
                "mitre_tactic": "TA0007", "mitre_technique": "T1046",
                "tags": ["scan_candidate"],
            }
        ))
    return logs

def scenario_data_exfiltration(username: str, attacker_ip: str) -> list:
    """
    TA0010 — Exfiltration / T1041 — Exfiltration Over C2 Channel
    Transfert de données vers une IP externe inconnue.
    Règle threshold : volume_mb > 500 / 1h / même source_ip vers IP externe → CRITICAL
    """
    logs = []
    # Plusieurs gros transferts espacés
    for i in range(5):
        logs.append(base_log(
            source=SOURCES[3],  # firewall
            event_action="large_outbound_transfer",
            severity="high",
            log_type="network",
            username=username,
            src_ip="10.0.1.10",  # interne
            delta=3600 - i * 600,
            extra={
                "dest_ip": attacker_ip,
                "dest_port": 443,
                "mitre_tactic": "TA0010", "mitre_technique": "T1041",
                "tags": ["exfiltration_candidate"],
                "enriched_data": {
                    "bytes_sent": random.randint(50_000_000, 150_000_000),  # 50-150 Mo
                    "bytes_sent_mb": random.uniform(50, 150)
                }
            }
        ))
    return logs

def scenario_cross_source_firewall_ad(attacker_ip: str, username: str) -> list:
    """
    Corrélation inter-sources : firewall + Active Directory
    IP bloquée sur le firewall, puis réessaie sur l'AD → tentative d'évasion.
    Règle cross-source : connection_blocked (firewall) + login_failed (AD) / même IP / 5min → HIGH
    """
    logs = []
    # Blocage sur le firewall
    logs.append(base_log(
        source=SOURCES[3],  # firewall
        event_action="connection_blocked",
        severity="warning",
        log_type="network",
        src_ip=attacker_ip,
        delta=300,
        extra={"dest_port": 443, "tags": ["fw_blocked"], "mitre_tactic": "TA0005"}
    ))
    # Tentative sur l'AD 2 minutes plus tard
    logs.append(base_log(
        source=SOURCES[2],  # Active Directory
        event_action="login_failed",
        severity="warning",
        log_type="auth",
        username=username,
        src_ip=attacker_ip,
        delta=180,
        extra={"dest_port": 389, "tags": ["ad_auth_fail"], "mitre_tactic": "TA0001"}
    ))
    # Deuxième tentative AD
    logs.append(base_log(
        source=SOURCES[2],
        event_action="login_failed",
        severity="high",
        log_type="auth",
        username=username,
        src_ip=attacker_ip,
        delta=120,
        extra={"dest_port": 389, "tags": ["ad_auth_fail", "cross_source_candidate"]}
    ))
    return logs

def scenario_normal_traffic(n: int = 700) -> list:
    """Génère du trafic normal pour le ratio 70/20/10."""
    logs = []
    normal_actions = [
        ("login_success",   "info",    "auth"),
        ("file_read",       "info",    "system"),
        ("http_request",    "info",    "application"),
        ("dns_query",       "info",    "network"),
        ("logout",          "info",    "auth"),
        ("config_read",     "info",    "system"),
        ("backup_started",  "info",    "system"),
    ]
    for _ in range(n):
        action, sev, ltype = random.choice(normal_actions)
        source = random.choice(SOURCES)
        logs.append(base_log(
            source=source,
            event_action=action,
            severity=sev,
            log_type=ltype,
            username=random.choice(USERS),
            src_ip=random.choice(LEGIT_IPS),
            delta=random.randint(0, 86400),  # sur les dernières 24h
        ))
    return logs

# ─────────────────────────────────────────────────────────────────────────────
# MAIN — Génération et indexation
# ─────────────────────────────────────────────────────────────────────────────
def bulk_index(logs: list):
    """Indexation par lots de 100 pour la performance."""
    from elasticsearch.helpers import bulk
    actions = [
        {"_index": INDEX_ALIAS, "_source": doc}
        for doc in logs
    ]
    success, errors = bulk(es, actions, chunk_size=100, raise_on_error=False)
    return success, errors

if __name__ == "__main__":
    print("=== Générateur de logs Smart SIEM ===\n")

    # Vérifier la connexion
    try:
        info = es.info()
        print(f"[OK] Connecté à ES {info['version']['number']}")
    except Exception as e:
        print(f"[ERREUR] {e}")
        exit(1)

    # Vérifier que l'alias existe
    if not es.indices.exists_alias(name=INDEX_ALIAS):
        print(f"[ERREUR] L'alias '{INDEX_ALIAS}' n'existe pas.")
        print("  → Lancer d'abord 02_elasticsearch_setup.py")
        exit(1)

    all_logs = []

    # ── Scénarios d'attaque (30% des logs) ───────────────────────────────────
    print("[1/6] Scénario brute force SSH...")
    # 7 fails + 1 success pour chaque IP
    number_of_logs  = scenario_brute_force_ssh(BAD_IPS[0], "root")
    number_of_logs += scenario_brute_force_ssh(BAD_IPS[1], "admin")
    all_logs += number_of_logs
    print("Logs générés pour brute force SSH :", len(number_of_logs))

    print("[2/6] Scénario mouvement latéral...")
    number_of_logs = scenario_lateral_movement("10.0.1.10", BAD_IPS[0])
    all_logs += number_of_logs
    print("Logs générés pour mouvement latéral :", len(number_of_logs))

    print("[3/6] Scénario scan de ports...")
    number_of_logs = scenario_port_scan(BAD_IPS[2])
    all_logs += number_of_logs
    print("Logs générés pour scan de ports :", len(number_of_logs))

    print("[4/6] Scénario exfiltration de données...")
    number_of_logs = scenario_data_exfiltration(USERS[0], BAD_IPS[3])
    all_logs += number_of_logs
    print("Logs générés pour exfiltration de données :", len(number_of_logs))

    print("[5/6] Scénario corrélation inter-sources (firewall + AD)...")
    number_of_logs = scenario_cross_source_firewall_ad(BAD_IPS[0], USERS[1])
    all_logs += number_of_logs
    print("Logs générés pour corrélation inter-sources :", len(number_of_logs))

    # ── Trafic normal (70% des logs) ─────────────────────────────────────────
    print("[6/6] Trafic normal...")
    number_of_logs = scenario_normal_traffic(n=700)
    all_logs += number_of_logs
    print("Logs générés pour trafic normal :", len(number_of_logs))

    # ── Indexation ────────────────────────────────────────────────────────────
    random.shuffle(all_logs)  # mélanger pour simuler l'ordre réel d'arrivée
    print(f"\n[INDEX] Indexation de {len(all_logs)} logs dans ES...")
    success, errors = bulk_index(all_logs)
    print(f"[OK] {success} logs indexés · {len(errors)} erreurs")

    # ── Vérification ─────────────────────────────────────────────────────────
    import time
    time.sleep(2)  # laisser ES rafraîchir
    count = es.count(index=INDEX_ALIAS)["count"]
    print(f"\n[RÉSULTAT] Total documents dans ES : {count}")
    print("  → Si count >= 1000 : Livrable S1 validé sur le critère données")
    print("\n=== Génération terminée ===")
