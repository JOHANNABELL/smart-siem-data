#!/usr/bin/env python3
"""
================================================================================
SMART SIEM — Chargeur de règles YAML vers PostgreSQL v2
================================================================================
Nouveautés v2 :
  - Classification automatique par dossier (exfiltration/, lateral_movement/, etc.)
  - group_by et confidence_score : OBLIGATOIREMENT dans le YAML (pas de défaut silencieux)
  - Affichage du catalogue complet par tactique MITRE après insertion
  - Validation stricte des champs requis avant insertion

RÉPONSE AUX QUESTIONS :
─────────────────────────────────────────────────────────────────────────────
Q : "Est-ce que load_yaml_rules classe par catégories dans la BD ?"
R : Non — la BD n'a pas de colonne "catégorie". La classification dans la BD
    se fait via le champ mitre_tactic (TA0010, TA0008...). Le dossier sert
    à organiser TES fichiers sources, pas la BD.

    MAIS : ce script lit le NOM DU DOSSIER parent et s'en sert pour :
    1. Déduire la mitre_tactic si absente du YAML
    2. Afficher un catalogue organisé par dossier/tactique

Q : "group_by, source_id, confidence_score : par défaut ou dans le YAML ?"
R : group_by et confidence_score DOIVENT être dans chaque YAML.
    Ce sont des paramètres métier critiques :
    - group_by=source_ip est FAUX pour les règles Lateral Movement
      (où le username est souvent la meilleure entité de groupement)
    - confidence_score varie selon la fidélité de la règle
    Mettre un défaut silencieux = risque de mauvaises détections.
    Ce script AVERTIT si ces champs manquent et utilise des valeurs
    conservatrices (source_ip, 70) en signalant l'anomalie.
─────────────────────────────────────────────────────────────────────────────
"""

import os, json, asyncio, asyncpg, yaml
from pathlib import Path
from typing import Optional

PG_DSN    = os.environ.get("PG_DSN",
    "postgresql://postgres:felicia@localhost:5432/nafeh")
RULES_DIR = os.environ.get("RULES_DIR", "./rules")

SEP = "─" * 70

# ── Mapping dossier → tactique MITRE (fallback si absent du YAML) ─────────────
# Si le YAML n'a pas de mitre_tactic ET est dans le dossier "exfiltration/"
# → on déduit TA0010
FOLDER_TO_TACTIC = {
    "reconnaissance":      "TA0043",
    "initial_access":      "TA0001",
    "execution":           "TA0002",
    "persistence":         "TA0003",
    "privilege_escalation":"TA0004",
    "defense_evasion":     "TA0005",
    "credential_access":   "TA0006",
    "discovery":           "TA0007",
    "lateral_movement":    "TA0008",
    "collection":          "TA0009",
    "command_control":     "TA0011",
    "exfiltration":        "TA0010",
    "impact":              "TA0040",
}

TACTIC_NAMES = {
    "TA0043": "Reconnaissance",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command & Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
    None:     "Non classifié",
}

TECHNIQUE_TO_TACTIC = {
    # Reconnaissance
    "T1595": "TA0043", "T1592": "TA0043", "T1590": "TA0043",
    "T1046": "TA0007",
    # Initial Access
    "T1190": "TA0001", "T1078": "TA0001", "T1110": "TA0001",
    "T1566": "TA0001", "T1133": "TA0001",
    # Execution
    "T1059": "TA0002", "T1047": "TA0002", "T1053": "TA0002",
    # Persistence
    "T1098": "TA0003", "T1543": "TA0003", "T1546": "TA0003",
    # Privilege Escalation
    "T1548": "TA0004", "T1068": "TA0004", "T1055": "TA0004",
    # Defense Evasion
    "T1070": "TA0005", "T1036": "TA0005", "T1562": "TA0005",
    "T1112": "TA0005",
    # Credential Access
    "T1003": "TA0006", "T1555": "TA0006", "T1558": "TA0006",
    "T1552": "TA0006", "T1557": "TA0006",
    # Discovery
    "T1087": "TA0007", "T1083": "TA0007", "T1018": "TA0007",
    "T1082": "TA0007", "T1049": "TA0007", "T1135": "TA0007",
    # Lateral Movement
    "T1021": "TA0008", "T1534": "TA0008", "T1550": "TA0008",
    "T1080": "TA0008", "T1210": "TA0008",
    # Exfiltration
    "T1020": "TA0010", "T1030": "TA0010", "T1041": "TA0010",
    "T1048": "TA0010", "T1567": "TA0010", "T1029": "TA0010",
    "T1095": "TA0010",
    # Impact
    "T1485": "TA0040", "T1486": "TA0040", "T1490": "TA0040",
    "T1499": "TA0040",
}

ALERT_LEVEL_MAP = {
    "critical": "CRITICAL", "high": "HIGH",
    "medium":   "WARNING",  "warning": "WARNING",
    "low":      "INFO",     "info": "INFO",
}

RULE_TYPE_MAP = {
    "seuil": "threshold", "séquence": "pattern", "sequence": "pattern",
    "comportemental": "behavioral", "composite": "composite",
    "threshold": "threshold", "pattern": "pattern",
    "behavioral": "behavioral", "count": "threshold", "frequency": "threshold",
}

MSG_TO_ACTION = {
    "Failed password":        "login_failed",
    "authentication failure": "login_failed",
    "Invalid user":           "login_failed",
    "Accepted password":      "login_success",
    "Accepted publickey":     "login_success",
    "connection_blocked":     "connection_blocked",
    "outbound_connection":    "outbound_connection",
    "large_outbound_transfer":"large_outbound_transfer",
    "dns_query":              "dns_query",
    "http_post":              "http_post",
    "cloud_upload":           "cloud_upload",
    "email_sent":             "email_sent",
    "icmp_flood":             "icmp_flood",
    "login_failed":           "login_failed",
    "login_success":          "login_success",
    "file_read":              "file_read",
    "credential_dump":        "credential_dump",
    "process_started":        "process_started",
    "service_created":        "service_created",
    "wmi_exec":               "wmi_exec",
    "kerberos_tgs_request":   "kerberos_tgs_request",
    "kerberos_tgt_request":   "kerberos_tgt_request",
    "admin_share_access":     "admin_share_access",
    "ransomware_activity":    "ransomware_activity",
}


def extract_technique_id(mitre_str: Optional[str]) -> Optional[str]:
    import re
    if not mitre_str:
        return None
    match = re.search(r'(T\d{4})(?:\.\d{3})?', str(mitre_str))
    return match.group(1) if match else None


def resolve_tactic(yaml_rule: dict, folder_name: str) -> Optional[str]:
    """
    Résout la tactique MITRE dans cet ordre de priorité :
    1. Champ mitre_tactic du YAML (ex: "TA0010")
    2. Déduction depuis mitre_technique_id (ex: "T1041" → TA0010)
    3. Déduction depuis le dossier parent (ex: "exfiltration/" → TA0010)
    """
    import re
    # Priorité 1 : champ mitre_tactic explicite
    mitre_raw = yaml_rule.get("mitre_tactic", "")
    ta_match = re.search(r'TA\d{4}', str(mitre_raw))
    if ta_match:
        return ta_match.group(0)

    # Priorité 2 : déduction depuis la technique
    tech_id = extract_technique_id(
        yaml_rule.get("mitre_technique_id") or yaml_rule.get("mitre_tactic")
    )
    if tech_id and tech_id in TECHNIQUE_TO_TACTIC:
        return TECHNIQUE_TO_TACTIC[tech_id]

    # Priorité 3 : nom du dossier parent
    folder_lower = folder_name.lower().replace("-", "_").replace(" ", "_")
    if folder_lower in FOLDER_TO_TACTIC:
        return FOLDER_TO_TACTIC[folder_lower]

    return None


def build_conditions(yaml_rule: dict) -> dict:
    """
    Construit le JSON conditions pour la table PG.
    group_by est lu depuis le YAML — PAS de valeur par défaut silencieuse.
    """
    condition  = yaml_rule.get("condition", {})
    rule_type  = RULE_TYPE_MAP.get(str(yaml_rule.get("type","threshold")).lower(), "threshold")
    group_by   = condition.get("group_by")

    # Avertissement explicite si group_by absent
    if not group_by:
        print(f"  [AVERT] group_by absent — défaut 'source_ip' appliqué")
        print(f"          Vérifier si c'est pertinent pour cette règle")
        group_by = "source_ip"

    if rule_type == "threshold":
        value        = condition.get("value", "")
        field        = condition.get("field", "")
        event_action = MSG_TO_ACTION.get(value) or MSG_TO_ACTION.get(field) or value

        return {
            "event_action": event_action,
            "group_by":     group_by,
            "field_filter": {"field": field, "contains": value},
            # dest_port si spécifié (règles SMB, RDP, FTP)
            **({"dest_port": int(value)} if str(value).isdigit() else {})
        }

    elif rule_type == "pattern":
        return {
            "sequence": condition.get("sequence", []),
            "group_by": group_by,
        }

    elif rule_type == "composite":
        return {
            "type":    "cross_source",
            "sources": condition.get("sources", []),
            "events":  condition.get("events", {}),
            "group_by": group_by,
        }

    return {"group_by": group_by}


def validate_yaml(yaml_rule: dict, filename: str) -> list[str]:
    """
    Valide les champs requis. Retourne la liste des avertissements.
    """
    warnings = []
    if not yaml_rule.get("nom") and not yaml_rule.get("name"):
        warnings.append("Champ 'nom' ou 'name' manquant")
    if not yaml_rule.get("description"):
        warnings.append("Champ 'description' manquant")
    if "confidence_score" not in yaml_rule:
        warnings.append("'confidence_score' absent — défaut 70 appliqué")
    cond = yaml_rule.get("condition", {})
    if not cond.get("group_by"):
        warnings.append("'condition.group_by' absent — défaut 'source_ip' appliqué")
    return warnings


async def load_rules_from_directory(pool: asyncpg.Pool, rules_dir: str):
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        print(f"[ERREUR] Dossier introuvable : {rules_dir}")
        return

    async with pool.acquire() as conn:
        admin_id = await conn.fetchval(
            "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
        )
    if not admin_id:
        print("[ERREUR] Aucun admin — lancer init_rules_commented.py d'abord")
        return

    yaml_files = sorted(
        list(rules_path.rglob("*.yaml")) + list(rules_path.rglob("*.yml"))
    )

    print(f"\n[SCAN] {len(yaml_files)} fichiers YAML dans {rules_dir}")
    print(SEP)

    stats = {"total": 0, "inserted": 0, "skipped": 0,
             "inactive": 0, "errors": 0, "warnings": 0}

    for yaml_file in yaml_files:
        stats["total"] += 1
        folder_name = yaml_file.parent.name

        try:
            with open(yaml_file, encoding="utf-8") as f:
                rule = yaml.safe_load(f)

            if not rule:
                continue

            if not rule.get("active", True):
                print(f"  [OFF]  {yaml_file.name}")
                stats["inactive"] += 1
                continue

            # Validation
            warnings = validate_yaml(rule, yaml_file.name)
            if warnings:
                stats["warnings"] += len(warnings)
                for w in warnings:
                    print(f"  [AVERT] {yaml_file.name} → {w}")

            # Résolution des champs
            name          = rule.get("nom") or rule.get("name") or yaml_file.stem
            tech_id       = extract_technique_id(
                rule.get("mitre_technique_id") or rule.get("mitre_tactic")
            )
            tactic_id     = resolve_tactic(rule, folder_name)
            alert_level   = ALERT_LEVEL_MAP.get(
                str(rule.get("niveau_alerte_genere","WARNING")).lower(), "WARNING"
            )
            rule_type     = RULE_TYPE_MAP.get(
                str(rule.get("type","threshold")).lower(), "threshold"
            )
            window_sec    = int(rule.get("fenetre_temporelle_s") or
                                rule.get("time_window_seconds") or 60)
            conf_score    = int(rule.get("confidence_score", 70))
            conditions    = build_conditions(rule)
            threshold_cnt = None
            if rule_type == "threshold":
                threshold_cnt = int(
                    rule.get("condition", {}).get("threshold") or
                    rule.get("threshold_count") or 5
                )

            # Idempotence
            async with pool.acquire() as conn:
                exists = await conn.fetchval(
                    "SELECT id FROM correlation_rules WHERE name = $1", name
                )

            if exists:
                print(f"  [SKIP] {yaml_file.name} (existe déjà)")
                stats["skipped"] += 1
                continue

            # Insertion
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO correlation_rules (
                        name, description, rule_type, conditions,
                        time_window_seconds, threshold_count,
                        sources_required, alert_level, confidence_score,
                        mitre_tactic, mitre_technique,
                        is_active, created_by
                    ) VALUES (
                        $1, $2, $3, $4::jsonb,
                        $5, $6,
                        $7::jsonb, $8::alert_level, $9,
                        $10, $11,
                        TRUE, $12::uuid
                    )
                    """,
                    name,
                    rule.get("description", ""),
                    rule_type,
                    json.dumps(conditions),
                    window_sec,
                    threshold_cnt,
                    None,
                    alert_level,
                    conf_score,
                    tactic_id,
                    tech_id,
                    str(admin_id),
                )

            folder_tag = f"[{folder_name}]"
            print(f"  [OK]  {folder_tag:<22} {alert_level:<8} {yaml_file.name}")
            stats["inserted"] += 1

        except yaml.YAMLError as e:
            print(f"  [ERR YAML] {yaml_file.name} : {e}")
            stats["errors"] += 1
        except Exception as e:
            print(f"  [ERR PG]   {yaml_file.name} : {e}")
            stats["errors"] += 1

    print(SEP)
    print(f"\n[RÉSULTAT]")
    print(f"  Fichiers traités : {stats['total']}")
    print(f"  Insérées         : {stats['inserted']}")
    print(f"  Déjà existantes  : {stats['skipped']}")
    print(f"  Inactives        : {stats['inactive']}")
    print(f"  Avertissements   : {stats['warnings']}")
    print(f"  Erreurs          : {stats['errors']}")


async def show_catalogue(pool: asyncpg.Pool):
    """
    Affiche le catalogue complet des règles organisé par tactique MITRE.
    C'est la réponse à 'est-ce classé par catégories' — la classification
    existe dans la BD via mitre_tactic, pas via un champ 'catégorie'.
    """
    print(f"\n{'=' * 70}")
    print("CATALOGUE DES RÈGLES — Classification par tactique MITRE ATT&CK")
    print('=' * 70)

    async with pool.acquire() as conn:
        rules = await conn.fetch(
            """
            SELECT name, rule_type, alert_level,
                   mitre_tactic, mitre_technique, confidence_score
            FROM correlation_rules
            WHERE is_active = TRUE
            ORDER BY mitre_tactic NULLS LAST, alert_level DESC, name
            """
        )

    by_tactic: dict = {}
    for r in rules:
        t = r["mitre_tactic"]
        by_tactic.setdefault(t, []).append(r)

    total = 0
    for tactic, trules in sorted(by_tactic.items(), key=lambda x: x[0] or "ZZ"):
        tactic_name = TACTIC_NAMES.get(tactic, tactic or "Non classifié")
        print(f"\n  ▶ {tactic or '------'} — {tactic_name} ({len(trules)} règle(s))")
        for r in trules:
            crit_icon = {"CRITICAL":"🔴","HIGH":"🟠","WARNING":"🟡","INFO":"⚪"}.get(r["alert_level"],"•")
            print(f"    {crit_icon} [{r['alert_level']:<8}] {r['name']:<50} "
                  f"({r['mitre_technique'] or '—'}) conf:{r['confidence_score']}%")
        total += len(trules)

    print(f"\n  Total : {total} règles actives")


async def main():
    print("=" * 70)
    print("CHARGEUR DE RÈGLES YAML v2 — Smart SIEM")
    print("=" * 70)
    pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=1, max_size=5)
    try:
        await load_rules_from_directory(pool, RULES_DIR)
        await show_catalogue(pool)
    finally:
        await pool.close()

if __name__ == "__main__":
    asyncio.run(main())