#!/usr/bin/env python3
"""
================================================================================
SMART SIEM — Moteur de corrélation temps réel v2
================================================================================
Version 2 — Modifications P1-A, P1-D, P2-A, P2-B, P2-C, P2-D, P2-E, P2-F :

  P1-A  : CANONICAL_EVENTS ajouté comme source de vérité des event_action.
  P2-A  : ThresholdEvaluator — filtres composites dynamiques (event_action + dest_port
           + tout autre champ dans conditions) et cardinalité (count_type=cardinality).
  P2-B  : PatternEvaluator — filtre is_internal_src (RFC1918) + reset temporel FSM
           (max_step_gap_seconds : réinitialise si deux étapes trop espacées).
  P2-C  : CrossSourceEvaluator — filtre sur source_type pour garantir que les signaux
           viennent de sources physiquement différentes (évite les faux positifs).
  P2-D  : AlertCandidate + events_context (contexte riche des événements corrélés
           stocké en JSONB dans PG → pas de requête ES séparée pour l'analyste).
  P2-E  : LOOKBACK_BUFFER_SEC — buffer de recouvrement pour éviter de rater les
           attaques à cheval entre deux cycles du worker.
  P2-F  : ThresholdEvaluator — exclude_usernames (must_not ES) pour whitelist.

Rétrocompatibilité garantie : les 4 règles fonctionnelles avant v2
(SSH Brute Force, Lateral Movement, Data Exfil, Firewall+AD) continuent de fonctionner.
================================================================================
"""

import os, time, json, logging, asyncio, uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Optional

import asyncpg
from elasticsearch import AsyncElasticsearch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("correlation_engine")

# ── Configuration ─────────────────────────────────────────────────────────────
ES_HOST     = os.environ.get("ES_HOST",     "https://localhost:9200")
ES_USER     = os.environ.get("ES_USER",     "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu")
ES_CACERT   = os.environ.get("ES_CACERT",   "http_ca.crt")
ES_INDEX    = "siem-logs-*"
PG_DSN      = os.environ.get("PG_DSN", "postgresql://postgres:felicia@localhost:5432/nafeh")

WORKER_INTERVAL_SEC = 10

# P2-E : buffer de recouvrement — allonge légèrement la fenêtre ES pour éviter
# de rater une attaque qui se termine dans le creux entre deux cycles.
# La déduplication (300s) empêche les doubles alertes générées par ce buffer.
# NOTE ARCHITECTURE : Ce worker utilise une fenêtre à recoupement (tumbling window
# with overlap), pas une vraie fenêtre glissante (sliding window).
# Pour une vraie fenêtre glissante, migrer vers Apache Flink ou Kafka Streams.
LOOKBACK_BUFFER_SEC = 15

# ── Source unique de vérité pour les event_action ─────────────────────────────
# Copie identique de 03_init_rules.py.
# Si une event_action n'est pas ici, elle ne peut pas être dans une règle.
CANONICAL_EVENTS = {
    "login_failed", "login_success", "credential_dump",
    "kerberos_tgs_request", "kerberos_tgt_request",
    "connection_blocked", "connection_allowed", "large_outbound_transfer",
    "dns_query", "icmp_flood", "rdp_connection",
    "http_exploit_attempt", "http_post", "cloud_upload",
    "file_read", "privilege_escalation", "wmi_exec",
    "service_created", "process_started", "smb_access", "outbound_connection",
}

# ── Structures de données ─────────────────────────────────────────────────────

@dataclass
class CorrelationRule:
    id:                  str
    name:                str
    rule_type:           str
    conditions:          dict
    time_window_seconds: int
    threshold_count:     Optional[int]
    sources_required:    Optional[list]
    alert_level:         str
    confidence_score:    int
    mitre_tactic:        Optional[str]
    mitre_technique:     Optional[str]
    playbook_id:         Optional[str]


@dataclass
class AlertCandidate:
    rule_id:              str
    rule_name:            str
    level:                str
    title:                str
    correlated_event_ids: list
    source_ips:           list
    affected_hosts:       list
    usernames:            list
    mitre_tactic:         Optional[str]
    confidence_score:     int
    # P2-D : contexte riche des événements corrélés — permet à l'analyste
    # de voir timestamp, host, event_action sans requête ES séparée.
    events_context: list = field(default_factory=list)


# =============================================================================
# ÉVALUATEURS
# =============================================================================

class ThresholdEvaluator:
    """
    Détecte les attaques par seuil de répétition.

    P2-A — Deux améliorations majeures vs v1 :

    1. FILTRES COMPOSITES DYNAMIQUES
       La v1 filtrait uniquement sur event_action. La v2 lit TOUS les champs
       dans conditions qui ne sont pas "réservés" et les ajoute comme filtres
       must dans la requête ES. Cela permet des règles comme :
         {"event_action": "connection_allowed", "dest_port": 445}
       La règle SMB (R7) filtre sur l'action ET le port — impossible en v1.

    2. CARDINALITÉ
       La v1 comptait doc_count (occurrences totales). La v2 supporte
       count_type=cardinality avec cardinality_field pour compter les valeurs
       DISTINCTES. Port Scan (R2) doit compter des ports UNIQUES, pas des paquets.

    P2-F — WHITELIST (exclude_usernames)
       Clause must_not ES sur username pour éviter les FP sur les admins.
    """

    # Champs réservés — non injectés comme filtres ES
    RESERVED_KEYS = {
        "event_action", "group_by", "threshold", "count_type",
        "cardinality_field", "filter", "sources", "events",
        "sequence", "exclude_usernames", "max_step_gap_seconds"
    }

    def __init__(self, es: AsyncElasticsearch):
        self.es = es

    async def evaluate(self, rule: CorrelationRule) -> list[AlertCandidate]:
        conditions   = rule.conditions
        event_action = conditions.get("event_action")
        group_by     = conditions.get("group_by", "source_ip")
        min_count    = rule.threshold_count or 5
        window_sec   = rule.time_window_seconds or 60
        count_type   = conditions.get("count_type", "count")
        cardinality_field = conditions.get("cardinality_field", "dest_port")
        exclude_usernames = conditions.get("exclude_usernames", [])

        if not event_action:
            log.warning(f"Règle '{rule.name}' sans event_action — ignorée")
            return []

        now   = datetime.now(timezone.utc)
        # P2-E : fenêtre étendue du buffer de recouvrement
        since = now - timedelta(seconds=window_sec + LOOKBACK_BUFFER_SEC)

        # ── Construction dynamique des clauses must ───────────────────────────
        # P2-A : on lit tous les champs de conditions qui ne sont pas réservés
        # et on les ajoute comme filtres term/terms dans la requête ES.
        must_clauses = [
            {"range": {"@timestamp": {"gte": since.isoformat()}}}
        ]

        # Filtre sur event_action (toujours présent)
        must_clauses.append({"term": {"event_action": event_action}})

        # Filtres composites dynamiques (ex: dest_port=445 pour SMB)
        for field_name, value in conditions.items():
            if field_name not in self.RESERVED_KEYS and value is not None:
                if isinstance(value, list):
                    must_clauses.append({"terms": {field_name: value}})
                else:
                    must_clauses.append({"term": {field_name: value}})

        # P2-F : must_not pour exclure les comptes whitelistés
        must_not_clauses = []
        if exclude_usernames:
            must_not_clauses.append({"terms": {"username": exclude_usernames}})

        # ── Sous-agrégations ──────────────────────────────────────────────────
        # P2-D : top_hits pour récupérer le contexte des 5 premiers événements
        aggs_inner = {
            "hosts":     {"terms": {"field": "host",     "size": 5}},
            "usernames": {"terms": {"field": "username", "size": 5}},
            "event_ids": {"terms": {"field": "raw_log_id", "size": 20}},
            # top_hits : récupère les champs des 5 premiers documents du bucket
            "sample_docs": {
                "top_hits": {
                    "size": 5,
                    "_source": ["@timestamp", "event_action", "host", "source_ip", "username"],
                    "sort":    [{"@timestamp": "desc"}]
                }
            }
        }

        if count_type == "cardinality" and cardinality_field:
            # En mode cardinalité, on ne peut pas utiliser min_doc_count sur
            # la valeur cardinale (ES ne le supporte pas) → filtrage en Python
            aggs_inner["cardinality_value"] = {
                "cardinality": {
                    "field":              cardinality_field,
                    "precision_threshold": 100
                }
            }
            bucket_min_count = 1   # pas de filtre côté ES, on filtre en Python
        else:
            bucket_min_count = min_count  # filtre côté ES (plus efficace)

        query = {
            "query": {"bool": {"must": must_clauses, "must_not": must_not_clauses}},
            "aggs": {
                "by_entity": {
                    "terms": {
                        "field":         group_by,
                        "min_doc_count": bucket_min_count,
                        "size":          50
                    },
                    "aggs": aggs_inner
                }
            },
            "size": 0
        }

        try:
            resp = await self.es.search(index=ES_INDEX, body=query)
        except Exception as e:
            log.error(f"Erreur ES (threshold {rule.name}): {e}")
            return []

        buckets    = resp.get("aggregations", {}).get("by_entity", {}).get("buckets", [])
        candidates = []

        for bucket in buckets:
            entity_value = bucket["key"]

            # Déterminer le compte effectif selon le mode
            if count_type == "cardinality" and cardinality_field:
                effective_count = bucket.get("cardinality_value", {}).get("value", 0)
                if effective_count < min_count:
                    continue
                count_label = f"{effective_count} {cardinality_field}s distincts"
                log.warning(f"[CARDINALITY HIT] {rule.name} | {group_by}={entity_value} | {cardinality_field}={effective_count}")
            else:
                effective_count = bucket["doc_count"]
                if effective_count < min_count:
                    continue
                count_label = f"{effective_count} occurrences"
                log.warning(f"[THRESHOLD HIT] {rule.name} | entité={entity_value} | count={effective_count}")

            event_ids = [b["key"] for b in bucket.get("event_ids", {}).get("buckets", [])]
            hosts     = [b["key"] for b in bucket.get("hosts",     {}).get("buckets", [])]
            usernames = [b["key"] for b in bucket.get("usernames", {}).get("buckets", [])]

            # P2-D : extraire le contexte des événements depuis top_hits
            events_context = []
            for hit in bucket.get("sample_docs", {}).get("hits", {}).get("hits", []):
                s = hit.get("_source", {})
                events_context.append({
                    "id":           hit.get("_id", ""),
                    "timestamp":    s.get("@timestamp"),
                    "event_action": s.get("event_action"),
                    "host":         s.get("host"),
                    "source_ip":    s.get("source_ip"),
                    "username":     s.get("username"),
                })

            title = (
                f"[{rule.name}] {count_label} de '{event_action}' "
                f"depuis {entity_value} en {window_sec}s"
            )
            candidates.append(AlertCandidate(
                rule_id=rule.id, rule_name=rule.name, level=rule.alert_level,
                title=title, correlated_event_ids=event_ids,
                source_ips=[entity_value] if group_by == "source_ip" else [],
                affected_hosts=hosts, usernames=usernames,
                mitre_tactic=rule.mitre_tactic,
                confidence_score=rule.confidence_score,
                events_context=events_context,
            ))

        return candidates


class PatternEvaluator:
    """
    Détecte les kill-chains séquentielles via un FSM (Automate à États Finis).

    P2-B — Deux améliorations vs v1 :

    1. FILTRE is_internal_src
       Si conditions.filter.is_internal_src=true, seuls les logs depuis des IPs
       RFC1918 (plages privées : 10/8, 172.16/12, 192.168/16) sont pris en compte.
       Pour T1021 Lateral Movement : distingue un pivot interne (malveillant)
       d'un accès SSH externe légitime.

    2. RESET TEMPOREL DU FSM (max_step_gap_seconds)
       La v1 ne vérifiait pas l'écart entre deux étapes consécutives.
       Une séquence dont les étapes seraient espacées de 4h59 dans une fenêtre
       de 5h serait détectée alors que c'est peu probable d'être une kill-chain.
       La v2 réinitialise le FSM si l'écart dépasse max_step_gap_seconds.
    """

    def __init__(self, es: AsyncElasticsearch):
        self.es = es

    async def evaluate(self, rule: CorrelationRule) -> list[AlertCandidate]:
        conditions = rule.conditions
        sequence   = conditions.get("sequence", [])
        group_by   = conditions.get("group_by", "source_ip")
        window_sec = rule.time_window_seconds or 300
        extra_filter = conditions.get("filter", {})
        is_internal_src = extra_filter.get("is_internal_src", False)
        max_step_gap = conditions.get(
            "max_step_gap_seconds",
            window_sec // max(len(sequence) - 1, 1)
        )

        if not sequence:
            return []

        now   = datetime.now(timezone.utc)
        since = now - timedelta(seconds=window_sec + LOOKBACK_BUFFER_SEC)
        relevant_actions = list(set(sequence))

        # ── Construction de la requête avec filtre RFC1918 optionnel ──────────
        must_clauses = [
            {"terms": {"event_action": relevant_actions}},
            {"range": {"@timestamp": {"gte": since.isoformat()}}}
        ]

        if is_internal_src:
            # P2-B : filtrer sur les plages IP internes RFC1918
            # Seules les connexions depuis des IPs privées sont considérées
            # pour la détection de mouvement latéral interne.
            must_clauses.append({
                "bool": {
                    "should": [
                        {"range": {"source_ip": {"gte": "10.0.0.0",    "lte": "10.255.255.255"}}},
                        {"range": {"source_ip": {"gte": "172.16.0.0",  "lte": "172.31.255.255"}}},
                        {"range": {"source_ip": {"gte": "192.168.0.0", "lte": "192.168.255.255"}}},
                    ],
                    "minimum_should_match": 1
                }
            })

        query = {
            "query": {"bool": {"must": must_clauses}},
            "sort":  [{"@timestamp": "asc"}],
            "size":  1000,
            "_source": ["@timestamp", "event_action", group_by, "host", "username", "source_ip"]
        }

        try:
            resp = await self.es.search(index=ES_INDEX, body=query)
        except Exception as e:
            log.error(f"Erreur ES (pattern {rule.name}): {e}")
            return []

        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return []

        entity_events: dict = {}
        for hit in hits:
            src    = hit["_source"]
            entity = src.get(group_by, "unknown")
            entity_events.setdefault(entity, []).append({
                "id":           hit["_id"],
                "timestamp":    src.get("@timestamp", ""),
                "event_action": src.get("event_action"),
                "host":         src.get("host"),
                "username":     src.get("username"),
                "source_ip":    src.get("source_ip"),
            })

        candidates = []
        for entity, events in entity_events.items():
            events_sorted = sorted(events, key=lambda e: e["timestamp"])

            # ── FSM avec reset temporel ────────────────────────────────────────
            step_index     = 0
            matched_ids    = []
            matched_hosts  = set()
            matched_events = []   # P2-D : contexte complet des étapes matchées
            last_step_time = None

            for event in events_sorted:
                if step_index >= len(sequence):
                    break

                if event["event_action"] == sequence[step_index]:
                    # P2-B : vérification de l'écart temporel depuis la dernière étape
                    if last_step_time is not None:
                        try:
                            t_curr = datetime.fromisoformat(
                                event["timestamp"].replace("Z", "+00:00"))
                            t_last = datetime.fromisoformat(
                                last_step_time.replace("Z", "+00:00"))
                            gap = (t_curr - t_last).total_seconds()
                            if gap > max_step_gap:
                                # Écart trop long → reset du FSM
                                step_index     = 0
                                matched_ids    = []
                                matched_hosts  = set()
                                matched_events = []
                                last_step_time = None
                                # Réessayer cet événement depuis l'état 0
                                if event["event_action"] == sequence[0]:
                                    matched_ids.append(event["id"])
                                    matched_events.append({k: event[k] for k in
                                        ["id","timestamp","event_action","host","source_ip","username"] if k in event})
                                    if event.get("host"):
                                        matched_hosts.add(event["host"])
                                    last_step_time = event["timestamp"]
                                    step_index = 1
                                continue
                        except Exception:
                            pass  # échec de parsing timestamp → on continue sans vérification

                    matched_ids.append(event["id"])
                    matched_events.append({k: event[k] for k in
                        ["id","timestamp","event_action","host","source_ip","username"] if k in event})
                    if event.get("host"):
                        matched_hosts.add(event["host"])
                    last_step_time = event["timestamp"]
                    step_index += 1

            if step_index == len(sequence):
                title = (
                    f"[{rule.name}] Kill-chain détectée pour {entity}: "
                    + " → ".join(sequence)
                )
                candidates.append(AlertCandidate(
                    rule_id=rule.id, rule_name=rule.name, level=rule.alert_level,
                    title=title, correlated_event_ids=matched_ids,
                    source_ips=[entity] if group_by == "source_ip" else [],
                    affected_hosts=list(matched_hosts),
                    usernames=[entity] if group_by == "username" else [],
                    mitre_tactic=rule.mitre_tactic,
                    confidence_score=rule.confidence_score,
                    events_context=matched_events,   # P2-D
                ))
                log.warning(f"[PATTERN HIT] {rule.name} | entité={entity} | séquence={sequence}")

        return candidates


class CrossSourceEvaluator:
    """
    Détecte les menaces par intersection d'ensembles cross-sources.

    P2-C — Filtre source_type
    La v1 collectait TOUS les logs avec l'event_action attendu, sans distinguer
    la source physique. Un serveur AD qui génère à la fois connection_blocked
    (firewall sur lui-même) et login_failed déclenchait la règle avec une
    seule source physique — faux positif.

    La v2 ajoute un filtre {"term": {"source_type": source_type_key}} pour
    s'assurer que chaque signal provient bien de sa source attendue :
    - connection_blocked ne comptabilisé QUE depuis les logs source_type=firewall
    - login_failed ne comptabilisé QUE depuis source_type=active_directory
    """

    def __init__(self, es: AsyncElasticsearch):
        self.es = es

    async def evaluate(self, rule: CorrelationRule) -> list[AlertCandidate]:
        conditions     = rule.conditions
        sources_needed = conditions.get("sources", [])
        event_per_src  = conditions.get("events", {})
        group_by       = conditions.get("group_by", "source_ip")
        window_sec     = rule.time_window_seconds or 300

        if len(sources_needed) < 2:
            return []

        now   = datetime.now(timezone.utc)
        since = now - timedelta(seconds=window_sec + LOOKBACK_BUFFER_SEC)

        results_by_source: dict = {}
        docs_by_entity:    dict = {}

        for source_type_key in sources_needed:
            expected_action = event_per_src.get(source_type_key, "*")

            # P2-C : filtre sur source_type pour n'accepter que les logs
            # de cette source physique (firewall, active_directory, etc.)
            must_clauses = [
                {"range": {"@timestamp": {"gte": since.isoformat()}}},
                {"term":  {"source_type": source_type_key}},  # ← P2-C
            ]
            if expected_action != "*":
                must_clauses.append({"term": {"event_action": expected_action}})

            query = {
                "query": {"bool": {"must": must_clauses}},
                "aggs": {
                    "by_entity": {
                        "terms": {"field": group_by, "size": 100},
                        "aggs": {
                            "event_ids": {"terms": {"field": "raw_log_id", "size": 10}},
                            # P2-D : contexte pour les alertes cross-source
                            "sample_docs": {
                                "top_hits": {
                                    "size": 3,
                                    "_source": ["@timestamp", "event_action", "host", "source_ip"],
                                    "sort": [{"@timestamp": "desc"}]
                                }
                            }
                        }
                    }
                },
                "size": 0
            }

            try:
                resp    = await self.es.search(index=ES_INDEX, body=query)
                buckets = resp.get("aggregations", {}).get("by_entity", {}).get("buckets", [])
                entities_here = set()
                for bucket in buckets:
                    entity = bucket["key"]
                    entities_here.add(entity)
                    docs_by_entity.setdefault(entity, {"ids": [], "context": []})
                    for id_b in bucket.get("event_ids", {}).get("buckets", []):
                        docs_by_entity[entity]["ids"].append(id_b["key"])
                    for hit in bucket.get("sample_docs", {}).get("hits", {}).get("hits", []):
                        s = hit.get("_source", {})
                        docs_by_entity[entity]["context"].append({
                            "id":           hit.get("_id"),
                            "timestamp":    s.get("@timestamp"),
                            "event_action": s.get("event_action"),
                            "host":         s.get("host"),
                            "source_ip":    s.get("source_ip"),
                            "source_type":  source_type_key,
                        })
                results_by_source[source_type_key] = entities_here
            except Exception as e:
                log.error(f"Erreur ES cross-source ({source_type_key}): {e}")
                results_by_source[source_type_key] = set()

        if not results_by_source:
            return []

        common_entities = set.intersection(*results_by_source.values())
        candidates = []

        for entity in common_entities:
            all_ids = docs_by_entity.get(entity, {}).get("ids", [])
            context = docs_by_entity.get(entity, {}).get("context", [])
            title = (
                f"[{rule.name}] Entité {entity} détectée sur "
                + " et ".join(sources_needed)
            )
            candidates.append(AlertCandidate(
                rule_id=rule.id, rule_name=rule.name, level=rule.alert_level,
                title=title, correlated_event_ids=all_ids,
                source_ips=[entity] if group_by == "source_ip" else [],
                affected_hosts=[], usernames=[entity] if group_by == "username" else [],
                mitre_tactic=rule.mitre_tactic,
                confidence_score=rule.confidence_score,
                events_context=context,   # P2-D
            ))
            log.warning(f"[CROSS-SOURCE HIT] {rule.name} | entité={entity} | sources={sources_needed}")

        return candidates


# =============================================================================
# MOTEUR PRINCIPAL
# =============================================================================

class CorrelationEngine:
    def __init__(self):
        self.es             = None
        self.pg_pool        = None
        self.threshold_eval = None
        self.pattern_eval   = None
        self.crosssrc_eval  = None
        self._alert_cache:  dict = {}
        self._dedup_window_sec   = 300

    async def initialize(self):
        log.info("Initialisation du moteur de corrélation v2...")
        self.es      = AsyncElasticsearch(hosts=[ES_HOST], basic_auth=(ES_USER, ES_PASSWORD), ca_certs=ES_CACERT, verify_certs=True)
        self.pg_pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=2, max_size=10)
        self.threshold_eval = ThresholdEvaluator(self.es)
        self.pattern_eval   = PatternEvaluator(self.es)
        self.crosssrc_eval  = CrossSourceEvaluator(self.es)
        log.info("[OK] Moteur v2 initialisé")

    async def load_active_rules(self) -> list[CorrelationRule]:
        async with self.pg_pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, name, rule_type, conditions, time_window_seconds,
                          threshold_count, sources_required, alert_level::text,
                          confidence_score, mitre_tactic, mitre_technique, playbook_id
                   FROM correlation_rules WHERE is_active = TRUE ORDER BY alert_level DESC"""
            )
        rules = []
        for row in rows:
            cond = json.loads(row["conditions"]) if isinstance(row["conditions"], str) else dict(row["conditions"])
            src  = json.loads(row["sources_required"]) if row["sources_required"] else None
            rules.append(CorrelationRule(
                id=str(row["id"]), name=row["name"], rule_type=row["rule_type"],
                conditions=cond, time_window_seconds=row["time_window_seconds"] or 60,
                threshold_count=row["threshold_count"], sources_required=src,
                alert_level=row["alert_level"], confidence_score=row["confidence_score"],
                mitre_tactic=row["mitre_tactic"], mitre_technique=row["mitre_technique"],
                playbook_id=str(row["playbook_id"]) if row["playbook_id"] else None,
            ))
        log.info(f"[RULES] {len(rules)} règles chargées")
        return rules

    def _dedup_key(self, c: AlertCandidate) -> str:
        entities = c.source_ips + c.usernames
        return f"{c.rule_id}::{(entities[0] if entities else 'unknown')}"

    def _is_duplicate(self, c: AlertCandidate) -> bool:
        last = self._alert_cache.get(self._dedup_key(c))
        return last is not None and (datetime.now(timezone.utc) - last).total_seconds() < self._dedup_window_sec

    def _mark_emitted(self, c: AlertCandidate):
        key = self._dedup_key(c)
        self._alert_cache[key] = datetime.now(timezone.utc)
        if len(self._alert_cache) > 10_000:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._dedup_window_sec)
            self._alert_cache = {k: v for k, v in self._alert_cache.items() if v > cutoff}

    async def insert_alert(self, candidate: AlertCandidate) -> str:
        """
        Insère l'alerte dans PostgreSQL.
        P2-D : colonne correlated_events_context ajoutée pour le contexte riche.
        Nécessite : ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlated_events_context JSONB DEFAULT '[]'::jsonb;
        """
        alert_id = str(uuid.uuid4())
        async with self.pg_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO alerts (
                    id, rule_id, title, level, status,
                    correlated_event_ids, correlated_events_context,
                    source_ips, affected_hosts, usernames,
                    mitre_tactic, confidence_score
                ) VALUES (
                    $1::uuid, $2::uuid, $3, $4::alert_level, 'open'::alert_status,
                    $5::jsonb, $6::jsonb,
                    $7::jsonb, $8::jsonb, $9::jsonb,
                    $10, $11
                )
                """,
                alert_id, candidate.rule_id, candidate.title, candidate.level,
                json.dumps(candidate.correlated_event_ids),
                json.dumps(candidate.events_context),       # P2-D : contexte riche
                json.dumps(candidate.source_ips),
                json.dumps(candidate.affected_hosts),
                json.dumps(candidate.usernames),
                candidate.mitre_tactic,
                candidate.confidence_score,
            )
        log.info(f"[ALERT INSERTED] {alert_id[:8]} | {candidate.level} | {candidate.title[:60]}")
        return alert_id

    async def notify_api(self, alert_id: str):
        import aiohttp
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post("http://localhost:8000/internal/alert-triggered",
                                  json={"alert_id": alert_id},
                                  timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status not in (200, 202):
                        log.debug(f"API retourné {r.status}")
        except Exception as e:
            log.debug(f"Notification API non disponible : {e}")

    async def evaluate_all(self, rules: list[CorrelationRule]) -> int:
        alerts_count = 0
        for rule in rules:
            try:
                if rule.rule_type == "threshold":
                    candidates = await self.threshold_eval.evaluate(rule)
                elif rule.rule_type == "pattern":
                    candidates = await self.pattern_eval.evaluate(rule)
                elif rule.rule_type == "cross_source":
                    candidates = await self.crosssrc_eval.evaluate(rule)
                else:
                    log.warning(f"Type de règle inconnu : {rule.rule_type}")
                    continue

                for candidate in candidates:
                    if self._is_duplicate(candidate):
                        log.debug(f"[DEDUP] {candidate.title[:50]}")
                        continue
                    alert_id = await self.insert_alert(candidate)
                    self._mark_emitted(candidate)
                    await self.notify_api(alert_id)
                    alerts_count += 1
                    async with self.pg_pool.acquire() as conn:
                        await conn.execute(
                            "UPDATE correlation_rules SET trigger_count=trigger_count+1, last_triggered_at=NOW() WHERE id=$1::uuid",
                            rule.id
                        )
            except Exception as e:
                log.error(f"Erreur évaluation {rule.name}: {e}", exc_info=True)
        return alerts_count

    async def run(self):
        log.info(f"[START] Moteur v2 démarré (intervalle={WORKER_INTERVAL_SEC}s, buffer={LOOKBACK_BUFFER_SEC}s)")
        rules_cache     = []
        rules_loaded_at = datetime.min

        while True:
            start = time.monotonic()
            try:
                if (datetime.now() - rules_loaded_at).total_seconds() > 60:
                    rules_cache     = await self.load_active_rules()
                    rules_loaded_at = datetime.now()
                if rules_cache:
                    count = await self.evaluate_all(rules_cache)
                    if count:
                        log.info(f"[CYCLE] {count} alerte(s)")
            except Exception as e:
                log.error(f"Erreur boucle principale: {e}", exc_info=True)
            elapsed    = time.monotonic() - start
            await asyncio.sleep(max(0, WORKER_INTERVAL_SEC - elapsed))

    async def close(self):
        await self.es.close()
        await self.pg_pool.close()


async def main():
    engine = CorrelationEngine()
    await engine.initialize()
    try:
        await engine.run()
    except KeyboardInterrupt:
        log.info("Arrêt (Ctrl+C)")
    finally:
        await engine.close()

if __name__ == "__main__":
    asyncio.run(main())