#!/usr/bin/env python3
"""
SMART SIEM — Initialisation des playbooks dans PostgreSQL
Insère les 6 playbooks standards liés aux règles de corrélation.
"""
import os, json, asyncio, asyncpg

PG_DSN = os.environ.get("PG_DSN",
    "postgresql://postgres:felicia@localhost:5432/nafeh")

PLAYBOOKS = [
    {
        "name": "block_ip",
        "description": (
            "Bloque une adresse IP suspecte. "
            "Ajoute l'IP dans la table playbook_executions avec action=block_ip. "
            "En production : appel API firewall ou règle iptables. "
            "Lié aux règles : SSH Brute Force, Port Scan, Exfiltrations, Kerberoasting."
        ),
        "action_type":   "block_ip",
        "execution_mode": "AUTO",
        "parameters":    json.dumps({
            "duration_hours": 24,
            "target_field":   "source_ip",
            "method":         "database_blocklist",
            "notify_email":   "soc@ctu-siem.int"
        }),
        "target_type":   "ip_address",
        "confirmation_timeout_seconds": 300,
        "rollback_supported": True,
        "rollback_parameters": json.dumps({"action": "unblock_ip"}),
    },
    {
        "name": "disable_account",
        "description": (
            "Désactive un compte utilisateur compromis en mettant is_active=FALSE dans PG. "
            "Mode CONFIRM car désactiver un compte légitime par erreur est très impactant. "
            "Lié aux règles : Pass-the-Hash, Golden Ticket, Cloud Upload, Email Exfiltration."
        ),
        "action_type":   "disable_account",
        "execution_mode": "CONFIRM",
        "parameters":    json.dumps({
            "target_field": "username",
            "set_field":    "is_active",
            "set_value":    False,
            "notify_email": "soc@ctu-siem.int",
            "notify_user_manager": True
        }),
        "target_type":   "user_account",
        "confirmation_timeout_seconds": 300,
        "rollback_supported": True,
        "rollback_parameters": json.dumps({"action": "enable_account"}),
    },
    {
        "name": "isolate_machine",
        "description": (
            "Marque une machine pour isolation réseau et alerte l'équipe infrastructure. "
            "En production : appel API NAC ou VLAN quarantine. "
            "Mode CONFIRM : isoler une machine de production sans vérification = incident majeur. "
            "Lié aux règles : SSH Lateral Movement, PsExec, WMI Execution, Pass-the-Hash."
        ),
        "action_type":   "isolate_machine",
        "execution_mode": "CONFIRM",
        "parameters":    json.dumps({
            "target_field":    "host",
            "quarantine_vlan": "VLAN-QUARANTINE-100",
            "notify_email":    "infra@ctu-siem.int",
            "collect_evidence": True
        }),
        "target_type":   "machine",
        "confirmation_timeout_seconds": 600,
        "rollback_supported": True,
        "rollback_parameters": json.dumps({"action": "restore_network_access"}),
    },
    {
        "name": "escalate_rssi",
        "description": (
            "Crée un incident dans la table incidents ET envoie un email au RSSI. "
            "Mode AUTO : les alertes CRITICAL doivent remonter immédiatement. "
            "Lié à : toutes les règles de niveau CRITICAL "
            "(SSH Lateral Movement, Golden Ticket, Kerberoasting, Data Exfiltration)."
        ),
        "action_type":   "notify_escalation",
        "execution_mode": "AUTO",
        "parameters":    json.dumps({
            "recipient":      "rssi@ctu-siem.int",
            "create_incident": True,
            "priority":       "P1",
            "sla_minutes":    30
        }),
        "target_type":   None,
        "confirmation_timeout_seconds": 300,
        "rollback_supported": False,
        "rollback_parameters": None,
    },
    {
        "name": "notify_soc",
        "description": (
            "Envoie une notification email + webhook Slack à l'équipe SOC. "
            "Mode AUTO : notification immédiate sans bloquer d'action. "
            "Lié à : toutes les règles de niveau HIGH et au-dessus. "
            "N'effectue aucune action technique — information uniquement."
        ),
        "action_type":   "notify_escalation",
        "execution_mode": "AUTO",
        "parameters":    json.dumps({
            "recipient":      "soc@ctu-siem.int",
            "slack_webhook":  True,
            "create_incident": False,
            "priority":       "P2"
        }),
        "target_type":   None,
        "confirmation_timeout_seconds": 300,
        "rollback_supported": False,
        "rollback_parameters": None,
    },
    {
        "name": "reset_krbtgt",
        "description": (
            "Alerte critique pour la réinitialisation du compte KRBTGT (Active Directory). "
            "Un Golden Ticket exploite le hash KRBTGT — le seul remède est de le changer DEUX fois. "
            "Mode CONFIRM : opération AD critique qui requiert une validation manuelle senior. "
            "Lié uniquement à la règle : Golden Ticket (T1558.001)."
        ),
        "action_type":   "custom",
        "execution_mode": "CONFIRM",
        "parameters":    json.dumps({
            "action":       "reset_krbtgt_password",
            "reset_twice":  True,
            "notify_email": "ad-admin@ctu-siem.int",
            "documentation_url": "https://docs.microsoft.com/security/krbtgt-reset",
            "sla_hours":    4
        }),
        "target_type":   "user_account",
        "confirmation_timeout_seconds": 3600,
        "rollback_supported": False,
        "rollback_parameters": None,
    },
]

# Mapping playbook → règles associées (pour les lier via FK playbook_id)
PLAYBOOK_TO_RULES = {
    "block_ip": [
        "SSH Brute Force Detection",
        "Network Port Scan Detection",
        "Data Exfiltration Pattern",
        "Kerberoasting",
        "Data Exfiltration Large Transfer",
        "DNS Exfiltration",
        "FTP/SFTP Exfiltration",
        "ICMP Tunnel Exfiltration",
        "Scheduled Exfiltration",
        "SMB Lateral Movement",
        "RDP Lateral Movement",
    ],
    "disable_account": [
        "Pass-the-Hash",
        "Golden Ticket",
        "Cloud Storage Exfiltration",
        "Email Exfiltration",
        "Internal Spearphishing",
    ],
    "isolate_machine": [
        "SSH Lateral Movement Kill-Chain",
        "Pass-the-Hash",
        "PsExec Remote Service",
        "WMI Remote Execution",
    ],
    "escalate_rssi": [
        "SSH Lateral Movement Kill-Chain",
        "Pass-the-Hash",
        "Golden Ticket",
        "Kerberoasting",
        "Data Exfiltration Pattern",
        "Data Exfiltration Large Transfer",
        "FTP/SFTP Exfiltration",
    ],
    "notify_soc": [
        "SSH Brute Force Detection",
        "Network Port Scan Detection",
        "Firewall Block then AD Auth Attempt",
        "SMB Lateral Movement",
        "RDP Lateral Movement",
        "WMI Remote Execution",
        "DNS Exfiltration",
        "HTTP POST Exfiltration",
        "Cloud Storage Exfiltration",
        "Email Exfiltration",
        "Scheduled Exfiltration",
        "ICMP Tunnel Exfiltration",
        "Admin Share Access",
    ],
    "reset_krbtgt": ["Golden Ticket"],
}


async def init_playbooks():
    pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=1, max_size=3)

    async with pool.acquire() as conn:
        admin_id = await conn.fetchval(
            "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
        )
    if not admin_id:
        print("[ERREUR] Aucun admin — lancer init_rules_commented.py d'abord")
        await pool.close()
        return

    # Insérer les playbooks
    playbook_ids = {}
    for pb in PLAYBOOKS:
        async with pool.acquire() as conn:
            exists = await conn.fetchval(
                "SELECT id FROM playbooks WHERE name = $1", pb["name"]
            )
        if exists:
            print(f"[SKIP] {pb['name']}")
            playbook_ids[pb["name"]] = str(exists)
            continue

        async with pool.acquire() as conn:
            pb_id = await conn.fetchval(
                """
                INSERT INTO playbooks (
                    name, description, action_type, execution_mode,
                    parameters, target_type, confirmation_timeout_seconds,
                    rollback_supported, rollback_parameters,
                    is_active, created_by
                ) VALUES (
                    $1, $2, $3, $4::exec_mode,
                    $5::jsonb, $6, $7,
                    $8, $9::jsonb,
                    TRUE, $10::uuid
                ) RETURNING id
                """,
                pb["name"], pb["description"], pb["action_type"], pb["execution_mode"],
                pb["parameters"], pb.get("target_type"), pb["confirmation_timeout_seconds"],
                pb["rollback_supported"], pb.get("rollback_parameters"),
                str(admin_id),
            )
        playbook_ids[pb["name"]] = str(pb_id)
        print(f"[OK] Playbook inséré : {pb['name']} (mode={pb['execution_mode']})")

    # Lier les playbooks aux règles de corrélation
    print("\n[LINK] Association playbooks ↔ règles...")
    for pb_name, rule_names in PLAYBOOK_TO_RULES.items():
        pb_id = playbook_ids.get(pb_name)
        if not pb_id:
            continue
        for rule_name in rule_names:
            async with pool.acquire() as conn:
                updated = await conn.execute(
                    "UPDATE correlation_rules SET playbook_id = $1::uuid "
                    "WHERE name = $2 AND playbook_id IS NULL",
                    pb_id, rule_name
                )
            if updated != "UPDATE 0":
                print(f"  {pb_name} → {rule_name}")

    # Résumé final
    async with pool.acquire() as conn:
        total_pb = await conn.fetchval("SELECT COUNT(*) FROM playbooks WHERE is_active=TRUE")
        linked   = await conn.fetchval(
            "SELECT COUNT(*) FROM correlation_rules WHERE playbook_id IS NOT NULL"
        )
    print(f"\n[RÉSULTAT] {total_pb} playbooks · {linked} règles liées à un playbook")
    await pool.close()


if __name__ == "__main__":
    asyncio.run(init_playbooks())