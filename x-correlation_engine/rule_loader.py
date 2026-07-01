"""
correlation_engine/rule_loader.py
───────────────────────────────────
Rôle unique : charger les règles actives depuis PostgreSQL et les convertir
              en objets CorrelationRule.

Ce module est le seul qui parle à PostgreSQL pour les règles.
Aucun évaluateur ne doit accéder à PG directement.
"""
import json
import logging
from typing import Optional

import asyncpg

from .models import CorrelationRule

log = logging.getLogger("rule_loader")


async def load_active_rules(pool: asyncpg.Pool) -> list[CorrelationRule]:
    """
    Charge toutes les règles actives depuis PostgreSQL.

    Requête triée par alert_level DESC : les règles CRITICAL sont évaluées
    en premier, ce qui garantit que si une attaque grave est en cours,
    son alerte est créée avant celles des niveaux inférieurs.

    Retourne une liste vide en cas d'erreur (le worker continue).
    """
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                    id, name, rule_type, conditions::text,
                    time_window_seconds, threshold_count,
                    sources_required::text, alert_level::text,
                    confidence_score, mitre_tactic, mitre_technique, playbook_id
                FROM correlation_rules
                WHERE is_active = TRUE
                ORDER BY
                    CASE alert_level::text
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH'     THEN 2
                        WHEN 'WARNING'  THEN 3
                        ELSE 4
                    END
                """
            )
    except Exception as e:
        log.error(f"Erreur chargement des règles depuis PG : {e}")
        return []

    rules = []
    for row in rows:
        try:
            rule = _row_to_rule(row)
            if rule:
                rules.append(rule)
        except Exception as e:
            log.warning(f"Règle ignorée (conversion échouée) : {row['name']} — {e}")

    log.info(f"[RULES] {len(rules)} règles actives chargées")
    return rules


def _row_to_rule(row) -> Optional[CorrelationRule]:
    """
    Convertit une Row asyncpg en CorrelationRule.

    Retourne None si la règle a un type inconnu ou des conditions invalides.
    Cela évite qu'une règle mal formée fasse planter tout le cycle.
    """
    rule_type = row["rule_type"]

    # Types valides selon la contrainte chk_rule_type dans le schéma PG
    VALID_TYPES = {"threshold", "pattern", "behavioral", "composite"}
    if rule_type not in VALID_TYPES:
        log.warning(f"Type de règle inconnu ignoré : '{rule_type}' (règle: {row['name']})")
        return None

    # Désérialisation des champs JSONB stockés en texte par asyncpg
    try:
        conditions = json.loads(row["conditions"]) if row["conditions"] else {}
    except json.JSONDecodeError as e:
        log.warning(f"Conditions JSON invalides pour '{row['name']}' : {e}")
        return None

    sources_required = None
    if row["sources_required"]:
        try:
            sources_required = json.loads(row["sources_required"])
        except json.JSONDecodeError:
            pass

    return CorrelationRule(
        id=str(row["id"]),
        name=row["name"],
        rule_type=rule_type,
        conditions=conditions,
        time_window_seconds=row["time_window_seconds"] or 60,
        threshold_count=row["threshold_count"],
        sources_required=sources_required,
        alert_level=row["alert_level"],
        confidence_score=row["confidence_score"] or 75,
        mitre_tactic=row["mitre_tactic"],
        mitre_technique=row["mitre_technique"],
        playbook_id=str(row["playbook_id"]) if row["playbook_id"] else None,
    )