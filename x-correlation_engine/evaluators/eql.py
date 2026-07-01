"""
correlation_engine/evaluators/eql.py
──────────────────────────────────────
Rôle unique : détecter les kill-chains séquentielles via l'API EQL native d'Elasticsearch.

Pourquoi EQL plutôt que le FSM Python ?
  EQL (Event Query Language) est le langage natif d'ES pour les séquences d'événements.
  L'API /eql/search fait le travail côté serveur — aucun document n'est rapatrié
  en Python, juste les séquences qui matchent.

  Avantages vs FSM Python :
  1. Performance : 0 document transféré si aucun match (vs 1000 docs en FSM)
  2. Précision : maxspan garantit que les événements sont dans la bonne fenêtre
  3. Preuves enrichies : ES retourne tous les events de la séquence avec leur _source

Source : https://www.elastic.co/docs/reference/query-languages/eql
"""
import logging
from datetime import datetime, timedelta, timezone

from elasticsearch import AsyncElasticsearch

from ..models import CorrelationRule, AlertCandidate
from ..config import ES_INDEX

log = logging.getLogger("evaluator.eql")


def _build_eql_query(rule: CorrelationRule) -> tuple[str, dict]:
    """
    Construit la requête EQL depuis les conditions de la règle.

    Format EQL pour une séquence SSH Lateral Movement :
      sequence by source_ip with maxspan=300s
        [any where event_action == "ssh_auth_success"]
        [any where event_action == "file_read"]

    Le mot-clé 'any' signifie "n'importe quelle catégorie d'événement".
    Pour les logs SIEM où event.category n'est pas toujours défini,
    'any' est plus robuste que 'authentication' ou 'file'.

    Retourne (eql_string, request_body).
    """
    conditions = rule.conditions
    sequence   = conditions.get("sequence", [])
    group_by   = conditions.get("group_by", "source_ip")
    window_sec = rule.time_window_seconds or 300

    # Construire les étapes EQL — une par event_action dans la séquence
    # Chaque étape est entre crochets : [any where event_action == "xxx"]
    steps = "\n  ".join(
        f'[any where event_action == "{action}"]'
        for action in sequence
    )

    # Filtre optionnel (ex: is_internal_src: true pour le Lateral Movement)
    filter_clause = ""
    extra_filter = conditions.get("filter", {})
    if extra_filter:
        filters = " and ".join(
            f'{k} == {repr(v) if isinstance(v, str) else str(v).lower()}'
            for k, v in extra_filter.items()
        )
        steps = "\n  ".join(
            f'[any where event_action == "{action}" and {filters}]'
            for action in sequence
        )

    eql_query = (
        f"sequence by {group_by} with maxspan={window_sec}s\n"
        f"  {steps}"
    )

    # La plage temporelle est envoyée via le paramètre filter dans le body
    now   = datetime.now(timezone.utc)
    since = now - timedelta(seconds=window_sec)

    body = {
        "query": eql_query,
        # Filtre temporel appliqué côté ES avant l'évaluation EQL
        "filter": {
            "range": {"@timestamp": {"gte": since.isoformat()}}
        },
        # Nombre maximum de séquences matchées retournées
        "size": 50,
    }

    return eql_query, body


async def evaluate(rule: CorrelationRule,
                   es: AsyncElasticsearch) -> list[AlertCandidate]:
    """
    Évalue une règle pattern via l'API EQL d'Elasticsearch.

    L'API /eql/search retourne des "sequences" — chaque séquence
    est une liste ordonnée d'événements qui matchent le pattern.
    """
    sequence = rule.conditions.get("sequence", [])
    group_by = rule.conditions.get("group_by", "source_ip")

    # Vérification minimale : une séquence doit avoir au moins 2 étapes
    if len(sequence) < 2:
        log.warning(f"Règle pattern '{rule.name}' avec séquence < 2 étapes — ignorée")
        return []

    eql_str, body = _build_eql_query(rule)

    try:
        # L'API EQL utilise /eql/search (pas /search standard)
        # Le client Python expose cela via es.eql.search()
        resp = await es.eql.search(
            index=ES_INDEX,
            body=body,
        )
    except Exception as e:
        log.error(f"Erreur EQL (règle pattern {rule.name}): {e}")
        return []

    # ── Traitement des séquences retournées ──────────────────────────────────
    # resp["hits"]["sequences"] → liste des séquences détectées
    # Chaque séquence a :
    #   - "join_keys" : valeurs des champs de groupement (ex: ["185.220.101.5"])
    #   - "events"    : liste des événements qui constituent la séquence
    sequences  = resp.get("hits", {}).get("sequences", [])
    candidates = []

    for seq in sequences:
        # La valeur du champ de groupement (ex: l'IP source)
        join_keys = seq.get("join_keys", [])
        entity    = join_keys[0] if join_keys else "unknown"

        # Les événements de la séquence avec leurs preuves
        events = seq.get("events", [])

        # Extraction des preuves depuis les événements ES
        event_ids = [e.get("_id", "") for e in events]
        hosts     = list({e.get("_source", {}).get("host", "") for e in events
                          if e.get("_source", {}).get("host")})
        usernames = list({e.get("_source", {}).get("username", "") for e in events
                          if e.get("_source", {}).get("username")})

        title = (
            f"[{rule.name}] Kill-chain EQL détectée pour {entity}: "
            + " → ".join(sequence)
        )

        candidates.append(AlertCandidate(
            rule_id=rule.id,
            rule_name=rule.name,
            level=rule.alert_level,
            title=title,
            correlated_event_ids=event_ids,
            source_ips=[entity] if group_by == "source_ip" else [],
            affected_hosts=hosts,
            usernames=usernames if group_by == "username" else usernames,
            mitre_tactic=rule.mitre_tactic,
            confidence_score=rule.confidence_score,
        ))

        log.warning(
            f"[EQL HIT] {rule.name} | {group_by}={entity} | "
            f"séquence={' → '.join(sequence)}"
        )

    return candidates