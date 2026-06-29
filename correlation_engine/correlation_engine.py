#!/usr/bin/env python3
"""
================================================================================
SMART SIEM — Moteur de corrélation temps réel
================================================================================
Rôle        : Analyser en continu les logs dans Elasticsearch pour détecter
              des patterns d'attaque et générer des alertes dans PostgreSQL.

Architecture : Worker Python tournant en boucle permanente.
              Toutes les 10 secondes :
              1. Charge les règles actives depuis PostgreSQL
              2. Interroge Elasticsearch sur les logs récents
              3. Évalue chaque règle sur les données récupérées
              4. Insère les alertes détectées dans PostgreSQL
              5. Notifie FastAPI pour déclencher les notifications

Trois types de règles :
  ThresholdEvaluator   → comptage dans une fenêtre temporelle (brute force)
  PatternEvaluator     → séquence ordonnée d'événements (kill-chain MITRE)
  CrossSourceEvaluator → corrélation entre plusieurs sources (firewall + AD)
================================================================================
"""

# ── Imports bibliothèque standard ─────────────────────────────────────────────

import os
# Variables d'environnement (credentials, configuration)

import time
# time.monotonic() : horloge monotone pour mesurer les durées précisément
# Utilisée pour respecter l'intervalle d'évaluation de 10 secondes

import json
# Sérialisation/désérialisation des conditions JSONB stockées dans PostgreSQL
# Les conditions d'une règle sont stockées en JSON : {"event_action": "login_failed", ...}

import logging
# Système de logs structurés pour le monitoring du worker
# Permet de suivre chaque cycle et chaque alerte générée

import asyncio
# Framework d'I/O asynchrone Python
# POURQUOI async/await ici ?
# Le worker fait beaucoup d'attente réseau (ES, PostgreSQL).
# Avec asyncio, pendant qu'il attend la réponse ES, il peut traiter
# autre chose → bien plus efficace qu'un thread bloquant classique

import uuid
# Génération d'identifiants uniques (UUID v4) pour les alertes
# Cohérent avec le type UUID de PostgreSQL

from datetime import datetime, timedelta, timezone
# datetime : représentation des moments dans le temps
# timedelta : calcul de durées (fenêtres temporelles)
# timezone : garantir UTC dans tous les timestamps

from dataclasses import dataclass, field
# dataclass : décorateur Python qui génère automatiquement __init__, __repr__
# Évite d'écrire manuellement les constructeurs pour CorrelationRule et AlertCandidate

from typing import Optional
# Optional[X] = X ou None — indique qu'un paramètre peut être absent

# ── Imports externes ───────────────────────────────────────────────────────────

import asyncpg
# Client PostgreSQL asynchrone — compatible avec asyncio
# Plus performant que psycopg2 (synchrone) pour un worker en boucle

from elasticsearch import AsyncElasticsearch
# Client Elasticsearch asynchrone — compatible avec asyncio
# La version Async permet de faire plusieurs requêtes ES en parallèle

# ── Configuration du système de logs ─────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    # Format : heure | niveau | nom du logger | message
    # Exemple : 2026-06-22 08:14:32 [WARNING] correlation_engine: [THRESHOLD HIT] SSH...
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
# Création du logger nommé "correlation_engine"
# Nommer les loggers permet de les filtrer dans les outils de monitoring
log = logging.getLogger("correlation_engine")

# ── Variables de configuration ────────────────────────────────────────────────
# Toutes lues depuis l'environnement pour faciliter le déploiement Docker
# La valeur après la virgule est le défaut si la variable n'est pas définie

ES_HOST     = os.environ.get("ES_HOST",     "https://localhost:9200")
ES_USER     = os.environ.get("ES_USER",     "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu")
ES_CACERT   = os.environ.get("ES_CACERT",   "http_ca.crt")

# Pattern qui couvre TOUS les index de logs, peu importe le mois
# "siem-logs-*" matche siem-logs-2026.06, siem-logs-2026.07, etc.
ES_INDEX    = "siem-logs-*"

# Chaîne de connexion PostgreSQL au format DSN (Data Source Name)
PG_DSN      = os.environ.get("PG_DSN",
    "postgresql://postgres:felicia@localhost:5432/nafeh")

# Intervalle entre deux cycles d'évaluation (en secondes)
# 10s est un bon compromis : assez fréquent pour le SLA de 30s, pas trop gourmand en ressources
WORKER_INTERVAL_SEC = 10

# Fenêtre de lookback pour les requêtes ES
# On prend plus large que la plus grande fenêtre de règle pour s'assurer de ne rien manquer
# Exemple : si une règle a une fenêtre de 300s, on cherche dans les 120s passées + buffer
LOOKBACK_SEC        = 120


# ── Structures de données ─────────────────────────────────────────────────────

@dataclass
class CorrelationRule:
    """
    Représentation Python d'une règle chargée depuis PostgreSQL.

    @dataclass génère automatiquement __init__ avec tous ces attributs.
    Sans @dataclass, il faudrait écrire manuellement :
    def __init__(self, id, name, rule_type, ...) : self.id = id, ...
    """
    id:                  str       # UUID de la règle dans PG
    name:                str       # nom lisible (ex: "SSH Brute Force Detection")
    rule_type:           str       # threshold | pattern | cross_source
    conditions:          dict      # paramètres de la règle (event_action, group_by, sequence...)
    time_window_seconds: int       # durée de la fenêtre d'évaluation en secondes
    threshold_count:     Optional[int]   # seuil de déclenchement (pour les règles threshold)
    sources_required:    Optional[list]  # sources nécessaires (pour les règles cross_source)
    alert_level:         str       # INFO | WARNING | HIGH | CRITICAL
    confidence_score:    int       # score de confiance 0-100 (réduit les faux positifs)
    mitre_tactic:        Optional[str]   # ex: "TA0001" pour le reporting MITRE ATT&CK
    mitre_technique:     Optional[str]   # ex: "T1110"
    playbook_id:         Optional[str]   # UUID du playbook à déclencher automatiquement


@dataclass
class AlertCandidate:
    """
    Représentation d'une alerte candidate avant son insertion en base.

    Pourquoi une structure intermédiaire ?
    L'évaluateur produit un AlertCandidate. Le moteur vérifie ensuite
    si c'est un doublon avant d'insérer dans PG. Cette séparation
    évite des insertions inutiles et des alertes répétées.
    """
    rule_id:              str       # ID de la règle qui a déclenché
    rule_name:            str       # nom lisible de la règle
    level:                str       # niveau d'alerte hérité de la règle
    title:                str       # description humaine de l'alerte générée
    correlated_event_ids: list      # IDs ES des documents qui ont déclenché la règle
    source_ips:           list      # IPs impliquées (dénormalisé pour le dashboard)
    affected_hosts:       list      # machines touchées
    usernames:            list      # comptes impliqués
    mitre_tactic:         Optional[str]  # tactique MITRE pour le reporting
    confidence_score:     int       # score de confiance copié de la règle


# =============================================================================
# ÉVALUATEURS DE RÈGLES
# =============================================================================
# Chaque évaluateur est une classe séparée appliquant le principe
# Single Responsibility (une classe = une responsabilité).
# Cela facilite les tests unitaires et l'ajout de nouveaux types de règles.

class ThresholdEvaluator:
    """
    Détecte les attaques par dépassement d'un seuil de répétition.

    Principe mathématique : comptage dans une fenêtre glissante.
    ─────────────────────────────────────────────────────────────
    Pour chaque entité (IP ou username), on compte combien de fois
    un même event_action apparaît dans la fenêtre temporelle.
    Si ce nombre dépasse le threshold_count → alerte.

    Exemples de menaces détectées :
    - Brute force SSH : 5 login_failed depuis la même IP en 60s
    - Scan de ports   : 50 connection_blocked depuis la même IP en 10s
    - Credential Stuffing : 10 login_failed sur des usernames différents en 120s

    Pourquoi une agrégation ES plutôt qu'un GROUP BY Python ?
    ES fait l'agrégation côté serveur → seul le résumé (count par entité)
    est renvoyé au client. Si on récupérait tous les documents et qu'on
    faisait le GROUP BY en Python, on transférerait des Mo de données inutilement.
    """

    def __init__(self, es: AsyncElasticsearch):
        # Stockage du client ES pour les requêtes
        # Injecté depuis CorrelationEngine (Dependency Injection pattern)
        self.es = es

    async def evaluate(self, rule: CorrelationRule) -> list[AlertCandidate]:
        """
        Évalue une règle threshold et retourne les alertes candidates.

        Retourne une liste car plusieurs entités peuvent dépasser le seuil
        simultanément (ex: deux attaquants différents font du brute force en même temps).
        """
        # Extraction des paramètres de la règle depuis le champ JSON "conditions"
        conditions = rule.conditions

        # L'event_action à surveiller (ex: "login_failed", "connection_blocked")
        event_action = conditions.get("event_action")

        # Le champ sur lequel grouper les événements
        # "source_ip"  → une alerte par IP attaquante (brute force, scan)
        # "username"   → une alerte par compte ciblé (credential stuffing)
        group_by = conditions.get("group_by", "source_ip")

        # Nombre minimum d'occurrences pour déclencher l'alerte
        # Récupéré depuis la règle PG, avec une valeur par défaut de 5
        min_count = rule.threshold_count or 5

        # Fenêtre temporelle en secondes
        # Les événements au-delà de cette durée sont ignorés
        window_sec = rule.time_window_seconds or 60

        # Calcul de la borne inférieure de la fenêtre temporelle
        # now = maintenant, since = il y a window_sec secondes
        now   = datetime.now(timezone.utc)
        since = now - timedelta(seconds=window_sec)

        # ── Construction de la requête Elasticsearch ─────────────────────────
        # Structure de la requête DSL (Domain Specific Language) d'Elasticsearch
        query = {
            # "query" : filtre les documents à analyser
            "query": {
                "bool": {
                    # "must" : toutes ces conditions doivent être vraies
                    "must": [
                        # Filtre 1 : seulement les logs avec cet event_action
                        # "term" = correspondance exacte (pas d'analyse de texte)
                        {"term":  {"event_action": event_action}},

                        # Filtre 2 : seulement les logs dans la fenêtre temporelle
                        # "range" sur @timestamp avec borne inférieure (gte = greater than or equal)
                        {"range": {"@timestamp": {"gte": since.isoformat()}}}
                    ]
                }
            },

            # "aggs" : agrégations ES — calculs statistiques côté serveur
            "aggs": {
                # Nom de l'agrégation (au choix, on l'appellera "by_entity")
                "by_entity": {
                    # "terms" : groupe par valeur unique du champ group_by
                    # Équivalent SQL : GROUP BY source_ip ORDER BY COUNT(*) DESC
                    "terms": {
                        "field":         group_by,
                        # min_doc_count : ne retourner que les buckets qui ont
                        # au moins min_count documents → filtre côté ES (plus efficace)
                        "min_doc_count": min_count,
                        # size : nombre maximum de buckets retournés
                        # 50 = on traite au maximum 50 attaquants distincts par cycle
                        "size":          50
                    },
                    # Sous-agrégations : informations additionnelles par bucket
                    "aggs": {
                        # IDs des documents ES (pour les stocker dans correlated_event_ids)
                        "event_ids":  {"terms": {"field": "_id",      "size": 20}},
                        # Machines touchées (pour affected_hosts dans l'alerte)
                        "hosts":      {"terms": {"field": "host",     "size": 5}},
                        # Comptes impliqués (pour usernames dans l'alerte)
                        "usernames":  {"terms": {"field": "username", "size": 5}},
                    }
                }
            },

            # "size": 0 → on ne veut pas les documents eux-mêmes, seulement les agrégations
            # Sans ça, ES retournerait aussi les 10 000 premiers logs → inutile et lent
            "size": 0
        }

        # ── Exécution de la requête ───────────────────────────────────────────
        try:
            # await : on attend la réponse ES sans bloquer les autres coroutines
            resp = await self.es.search(index=ES_INDEX, body=query)
        except Exception as e:
            # En cas d'erreur ES (timeout, index indisponible...) on log et on continue
            # Le moteur ne doit pas s'arrêter si une règle échoue
            log.error(f"Erreur requête ES (règle threshold {rule.name}): {e}")
            return []  # Retourner liste vide = pas d'alerte pour cette règle ce cycle

        # ── Traitement des résultats ──────────────────────────────────────────
        candidates = []

        # Navigation dans la structure de réponse ES :
        # resp → aggregations → by_entity → buckets (liste des entités)
        buckets = resp.get("aggregations", {}).get("by_entity", {}).get("buckets", [])

        for bucket in buckets:
            # "key" = la valeur du champ group_by (ex: "185.220.101.5")
            entity_value = bucket["key"]
            # "doc_count" = nombre d'occurrences de cette entité dans la fenêtre
            doc_count    = bucket["doc_count"]

            # Double vérification du seuil (ES fait déjà le filtre min_doc_count
            # mais on vérifie à nouveau en Python pour être sûr)
            if doc_count < min_count:
                continue

            # Extraction des informations des sous-agrégations
            event_ids = [b["key"] for b in bucket.get("event_ids", {}).get("buckets", [])]
            hosts     = [b["key"] for b in bucket.get("hosts",     {}).get("buckets", [])]
            usernames = [b["key"] for b in bucket.get("usernames", {}).get("buckets", [])]

            # Construction du titre lisible de l'alerte
            # Ce titre apparaîtra dans le dashboard et les emails
            title = (
                f"[{rule.name}] {doc_count} occurrences de '{event_action}' "
                f"depuis {entity_value} en {window_sec}s"
            )

            # Création de l'AlertCandidate
            candidates.append(AlertCandidate(
                rule_id=rule.id,
                rule_name=rule.name,
                level=rule.alert_level,
                title=title,
                correlated_event_ids=event_ids,  # preuves : IDs des logs déclencheurs
                # Si on groupe par source_ip, c'est l'entité = l'IP source
                source_ips=[entity_value] if group_by == "source_ip" else [],
                affected_hosts=hosts,
                usernames=usernames,
                mitre_tactic=rule.mitre_tactic,
                confidence_score=rule.confidence_score,
            ))

            # Log de niveau WARNING pour tracer les détections dans les logs du worker
            log.warning(
                f"[THRESHOLD HIT] {rule.name} | entité={entity_value} | count={doc_count}"
            )

        return candidates  # Liste vide si aucun seuil dépassé


class PatternEvaluator:
    """
    Détecte les attaques séquentielles (kill-chain MITRE ATT&CK).

    Principe mathématique : Automate à États Finis (FSM)
    ─────────────────────────────────────────────────────
    Un FSM est un modèle qui traverse des états en réponse à des entrées.
    Pour détecter une kill-chain :
    - Les ÉTATS sont les étapes de l'attaque
    - Les TRANSITIONS sont les event_actions attendus
    - La FENÊTRE TEMPORELLE est la contrainte de durée

    Exemple : kill-chain de compromission SSH
    État 0 (Idle) → [login_success] → État 1 (Compromis) → [file_read] → État 2 (ALERTE)

    Pourquoi pas une simple requête ES ?
    Parce qu'ES ne peut pas vérifier nativement qu'un event_action A précède
    un event_action B pour la MÊME entité dans un intervalle donné.
    Il faut récupérer les logs et analyser l'ordre en Python.

    Note avancée : EQL (Event Query Language) d'Elasticsearch peut faire du
    pattern matching natif, mais nécessite une licence avancée. Notre implémentation
    Python offre plus de flexibilité pour 3 semaines.
    """

    def __init__(self, es: AsyncElasticsearch):
        self.es = es  # client ES injecté

    async def evaluate(self, rule: CorrelationRule) -> list[AlertCandidate]:
        """Évalue une règle pattern et retourne les kill-chains détectées."""
        conditions = rule.conditions

        # La séquence ordonnée d'event_actions à détecter
        # Exemple : ["login_success", "file_read"]
        # signifie : d'abord login_success, PUIS file_read (dans cet ordre)
        sequence = conditions.get("sequence", [])

        # Entité commune qui doit apparaître dans tous les événements de la séquence
        # "source_ip" → même attaquant (IP) dans tous les événements
        # "username"  → même compte dans tous les événements
        group_by = conditions.get("group_by", "source_ip")

        # Fenêtre temporelle : tous les événements de la séquence doivent
        # se produire dans cet intervalle
        window_sec = rule.time_window_seconds or 300

        # Si la règle n'a pas de séquence définie, elle est invalide → on skip
        if not sequence:
            return []

        # Calcul de la fenêtre temporelle
        now   = datetime.now(timezone.utc)
        since = now - timedelta(seconds=window_sec)

        # ── Requête ES : récupérer tous les logs pertinents ───────────────────
        # On récupère les logs contenant N'IMPORTE LAQUELLE des actions de la séquence
        # list(set(sequence)) supprime les doublons si une action apparaît plusieurs fois
        relevant_actions = list(set(sequence))

        query = {
            "query": {
                "bool": {
                    "must": [
                        # "terms" (pluriel) = OU logique sur une liste de valeurs
                        # équivalent SQL : WHERE event_action IN ('login_success', 'file_read')
                        {"terms": {"event_action": relevant_actions}},
                        # Filtre temporel
                        {"range": {"@timestamp": {"gte": since.isoformat()}}}
                    ]
                }
            },
            # Trier par timestamp ascendant CRUCIAL pour le FSM
            # Si on ne trie pas, on ne peut pas déterminer l'ordre des événements
            "sort": [{"@timestamp": "asc"}],
            # 1000 documents max → si plus, la fenêtre est peut-être trop large
            "size": 1000,
            # _source : on ne récupère que les champs nécessaires (économie de bande passante)
            "_source": ["@timestamp", "event_action", group_by, "host", "username"]
        }

        try:
            resp = await self.es.search(index=ES_INDEX, body=query)
        except Exception as e:
            log.error(f"Erreur requête ES (règle pattern {rule.name}): {e}")
            return []

        # Récupération des documents de la réponse
        # resp["hits"]["hits"] → liste des documents correspondants
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return []  # Aucun log dans la fenêtre → pas d'alerte possible

        # ── Groupement par entité ─────────────────────────────────────────────
        # On construit un dictionnaire : {valeur_entité → [liste des événements]}
        # Exemple : {"185.220.101.5" → [event1, event2, event3]}
        entity_events: dict[str, list] = {}

        for hit in hits:
            src    = hit["_source"]  # contenu du document ES
            entity = src.get(group_by, "unknown")  # valeur de source_ip ou username

            # setdefault : si la clé n'existe pas, l'initialiser avec une liste vide
            entity_events.setdefault(entity, []).append({
                "id":           hit["_id"],                    # ID ES du document
                "timestamp":    src.get("@timestamp"),         # pour le tri
                "event_action": src.get("event_action"),       # action observée
                "host":         src.get("host"),               # machine concernée
                "username":     src.get("username"),           # compte impliqué
            })

        # ── Application du FSM sur chaque entité ─────────────────────────────
        candidates = []

        for entity, events in entity_events.items():
            # Tri par timestamp pour garantir l'ordre chronologique
            # (les données ES sont déjà triées mais on sécurise)
            events_sorted = sorted(events, key=lambda e: e["timestamp"])

            # Initialisation du FSM
            step_index  = 0   # étape courante dans la séquence (commence à 0)
            matched_ids   = []  # IDs ES des événements qui ont progressé le FSM
            matched_hosts = set()  # machines impliquées dans la kill-chain

            # Parcours des événements dans l'ordre chronologique
            for event in events_sorted:
                # Si on a déjà complété toute la séquence, on sort
                if step_index >= len(sequence):
                    break

                # Transition FSM : si l'événement courant correspond
                # à l'étape attendue dans la séquence
                if event["event_action"] == sequence[step_index]:
                    # On enregistre cet événement comme faisant partie de la kill-chain
                    matched_ids.append(event["id"])
                    if event.get("host"):
                        matched_hosts.add(event["host"])
                    # On passe à l'étape suivante de la séquence
                    step_index += 1
                # Si l'événement ne correspond pas à l'étape attendue,
                # on l'ignore (on attend le bon event_action)

            # Vérification : a-t-on traversé TOUTES les étapes de la séquence ?
            # step_index == len(sequence) signifie que le FSM a atteint l'état final
            if step_index == len(sequence):
                title = (
                    f"[{rule.name}] Kill-chain détectée pour {entity}: "
                    + " → ".join(sequence)  # affichage de la séquence avec des flèches
                )
                candidates.append(AlertCandidate(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    level=rule.alert_level,
                    title=title,
                    correlated_event_ids=matched_ids,  # logs déclencheurs de la séquence
                    source_ips=[entity] if group_by == "source_ip" else [],
                    affected_hosts=list(matched_hosts),
                    usernames=[entity] if group_by == "username" else [],
                    mitre_tactic=rule.mitre_tactic,
                    confidence_score=rule.confidence_score,
                ))
                log.warning(f"[PATTERN HIT] {rule.name} | entité={entity} | séquence={sequence}")

        return candidates


class CrossSourceEvaluator:
    """
    Détecte les menaces corrélant des événements sur des sources DIFFÉRENTES.

    Principe mathématique : Intersection d'ensembles
    ──────────────────────────────────────────────────
    On cherche les entités (IPs ou comptes) qui apparaissent
    SIMULTANÉMENT dans plusieurs sources différentes.

    Exemple :
    Source 1 (firewall)        → IPs bloquées : {A, B, C, D}
    Source 2 (active_directory) → IPs tentant auth : {B, D, E, F}
    Intersection               → {B, D} → ces IPs sont suspectes sur les DEUX sources

    Pourquoi c'est puissant ?
    Un attaquant peut contourner un seul contrôle (ex: VPN pour passer le firewall).
    Mais s'il est visible sur PLUSIEURS sources indépendantes → fort signal d'alerte.
    C'est la corrélation inter-sources : le cœur de valeur ajoutée d'un SIEM.
    """

    def __init__(self, es: AsyncElasticsearch):
        self.es = es

    async def evaluate(self, rule: CorrelationRule) -> list[AlertCandidate]:
        """Évalue une règle cross-source et retourne les entités corroborées."""
        conditions = rule.conditions

        # Liste des types de sources qui doivent être impliqués
        # Exemple : ["firewall", "active_directory"]
        sources_needed = conditions.get("sources", [])

        # Dictionnaire : pour chaque source, quel event_action chercher
        # Exemple : {"firewall": "connection_blocked", "active_directory": "login_failed"}
        event_per_src  = conditions.get("events", {})

        # Entité commune entre les sources (IP ou username)
        group_by       = conditions.get("group_by", "source_ip")

        # Fenêtre temporelle dans laquelle les deux sources doivent être actives
        window_sec     = rule.time_window_seconds or 300

        # Règle invalide si moins de 2 sources définies
        if len(sources_needed) < 2:
            return []

        # Calcul de la fenêtre temporelle
        now   = datetime.now(timezone.utc)
        since = now - timedelta(seconds=window_sec)

        # ── Collecte des entités par source ──────────────────────────────────
        # Pour chaque source, on fait une requête ES séparée et on récupère
        # l'ensemble des entités (IPs ou usernames) présentes

        # dict : {type_source → ensemble des valeurs d'entités}
        # Exemple : {"firewall" → {"185.X.X.X", "91.X.X.X"}, "active_directory" → {"185.X.X.X"}}
        results_by_source: dict[str, set] = {}

        # Stockage des IDs de documents par entité (pour les preuves dans l'alerte)
        docs_by_entity: dict[str, dict] = {}

        for source_type in sources_needed:
            # Action attendue pour ce type de source
            expected_action = event_per_src.get(source_type, "*")

            # Construction de la requête pour cette source
            must_clauses = [
                {"range": {"@timestamp": {"gte": since.isoformat()}}},
            ]

            # Filtrer par action si spécifiée
            # "*" signifie "toute action" → pas de filtre sur event_action
            if expected_action != "*":
                must_clauses.append({"term": {"event_action": expected_action}})

            query = {
                "query": {"bool": {"must": must_clauses}},
                "aggs": {
                    "by_entity": {
                        # Agrégation pour récupérer les entités distinctes
                        "terms": {"field": group_by, "size": 100},
                        # Sous-agrégation pour les IDs de preuves
                        "aggs": {"event_ids": {"terms": {"field": "_id", "size": 10}}}
                    }
                },
                "size": 0  # pas de documents, seulement les agrégations
            }

            try:
                resp = await self.es.search(index=ES_INDEX, body=query)
                buckets = resp.get("aggregations", {}).get("by_entity", {}).get("buckets", [])

                # Extraction des entités présentes dans cette source
                entities_in_source = set()
                for bucket in buckets:
                    entity = bucket["key"]
                    entities_in_source.add(entity)
                    # Stockage des IDs de preuves pour cette entité
                    docs_by_entity.setdefault(entity, {"ids": [], "hosts": set()})
                    for id_b in bucket.get("event_ids", {}).get("buckets", []):
                        docs_by_entity[entity]["ids"].append(id_b["key"])

                results_by_source[source_type] = entities_in_source

            except Exception as e:
                log.error(f"Erreur requête ES cross-source ({source_type}): {e}")
                # En cas d'erreur sur une source, on met un ensemble vide
                # L'intersection avec un ensemble vide donnera un ensemble vide → pas d'alerte
                results_by_source[source_type] = set()

        # ── Intersection des ensembles ─────────────────────────────────────────
        # set.intersection(*sets) retourne les éléments communs à TOUS les ensembles
        # Si results_by_source est vide, on retourne une liste vide
        if not results_by_source:
            return []

        # * décompresse le dict.values() en arguments séparés pour intersection()
        common_entities = set.intersection(*results_by_source.values())

        candidates = []
        for entity in common_entities:
            # Une entité présente dans TOUTES les sources → alerte
            title = (
                f"[{rule.name}] Entité {entity} détectée simultanément sur "
                + " et ".join(sources_needed)  # ex: "firewall et active_directory"
            )
            all_ids = docs_by_entity.get(entity, {}).get("ids", [])
            candidates.append(AlertCandidate(
                rule_id=rule.id,
                rule_name=rule.name,
                level=rule.alert_level,
                title=title,
                correlated_event_ids=all_ids,
                source_ips=[entity] if group_by == "source_ip" else [],
                affected_hosts=[],
                usernames=[entity] if group_by == "username" else [],
                mitre_tactic=rule.mitre_tactic,
                confidence_score=rule.confidence_score,
            ))
            log.warning(f"[CROSS-SOURCE HIT] {rule.name} | entité={entity}")

        return candidates


# =============================================================================
# MOTEUR PRINCIPAL
# =============================================================================

class CorrelationEngine:
    """
    Orchestrateur principal du moteur de corrélation.

    Responsabilités :
    1. Gérer les connexions ES et PostgreSQL
    2. Charger les règles actives depuis PostgreSQL
    3. Dispatcher chaque règle vers l'évaluateur approprié
    4. Dédupliquer les alertes (éviter les doublons)
    5. Insérer les alertes dans PostgreSQL
    6. Notifier FastAPI
    7. Gérer le timing de la boucle principale
    """

    def __init__(self):
        # Ces attributs seront initialisés dans initialize()
        # (les connexions DB ne peuvent pas s'ouvrir dans __init__ avec asyncio)
        self.es      = None  # client Elasticsearch async
        self.pg_pool = None  # pool de connexions PostgreSQL async

        # Instances des évaluateurs (créées après la connexion ES)
        self.threshold_eval  = None
        self.pattern_eval    = None
        self.crosssrc_eval   = None

        # Cache de déduplication : mémorise les alertes récentes pour éviter les doublons
        # Clé : "rule_id::entité" (ex: "uuid-brute-force::185.220.101.5")
        # Valeur : datetime de la dernière alerte pour cette combinaison
        self._alert_cache: dict[str, datetime] = {}

        # Durée pendant laquelle une alerte identique est considérée comme doublon
        # 300s = 5 minutes → pas d'alerte répétée pour le même attaquant pendant 5 min
        self._dedup_window_sec = 300

    async def initialize(self):
        """
        Établit les connexions aux bases de données.
        Doit être appelé avant run().

        POURQUOI séparer __init__ et initialize() ?
        asyncio ne supporte pas les coroutines dans __init__ (qui est synchrone).
        Les connexions à ES et PG sont des opérations asynchrones.
        → On les met dans une méthode async séparée.
        """
        log.info("Initialisation du moteur de corrélation...")

        # Création du client Elasticsearch asynchrone
        self.es = AsyncElasticsearch(
            hosts=[ES_HOST],
            basic_auth=(ES_USER, ES_PASSWORD),  # authentification
            ca_certs=ES_CACERT,                 # certificat TLS
            verify_certs=True,                  # vérification obligatoire
        )

        # Création du pool de connexions PostgreSQL
        # Un pool = plusieurs connexions réutilisables (évite d'ouvrir/fermer à chaque requête)
        # min_size=2 : garder au moins 2 connexions ouvertes en permanence
        # max_size=10 : ne jamais ouvrir plus de 10 connexions simultanées
        self.pg_pool = await asyncpg.create_pool(
            dsn=PG_DSN,
            min_size=2,
            max_size=10
        )

        # Création des instances d'évaluateurs
        # On leur passe le client ES (injection de dépendance)
        self.threshold_eval = ThresholdEvaluator(self.es)
        self.pattern_eval   = PatternEvaluator(self.es)
        self.crosssrc_eval  = CrossSourceEvaluator(self.es)

        log.info("[OK] Connexions ES et PG établies")

    async def load_active_rules(self) -> list[CorrelationRule]:
        """
        Charge les règles de corrélation actives depuis PostgreSQL.

        Pourquoi recharger les règles à chaque cycle ?
        Un analyste peut ajouter/modifier/désactiver une règle via l'interface.
        Sans rechargement, le worker utiliserait des règles obsolètes.
        → On recharge toutes les 60 secondes (voir run() pour le cache).
        """
        # "async with" = context manager asynchrone
        # acquire() récupère une connexion du pool (la libère automatiquement à la sortie)
        async with self.pg_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, name, rule_type, conditions, time_window_seconds,
                       threshold_count, sources_required, alert_level::text,
                       confidence_score, mitre_tactic, mitre_technique, playbook_id
                FROM correlation_rules
                WHERE is_active = TRUE
                ORDER BY alert_level DESC
                -- On évalue les règles CRITICAL en premier
                -- Si une attaque est en cours, on veut l'alerte la plus grave rapidement
                """
            )

        # Conversion de chaque ligne PG en objet CorrelationRule Python
        rules = []
        for row in rows:
            rules.append(CorrelationRule(
                id=str(row["id"]),    # UUID → string pour la cohérence
                name=row["name"],
                rule_type=row["rule_type"],
                # conditions est stocké en JSONB dans PG
                # asyncpg peut le retourner comme dict ou string selon la configuration
                conditions=json.loads(row["conditions"])
                           if isinstance(row["conditions"], str)
                           else dict(row["conditions"]),
                time_window_seconds=row["time_window_seconds"] or 60,
                threshold_count=row["threshold_count"],
                sources_required=json.loads(row["sources_required"])
                                 if row["sources_required"] else None,
                alert_level=row["alert_level"],
                confidence_score=row["confidence_score"],
                mitre_tactic=row["mitre_tactic"],
                mitre_technique=row["mitre_technique"],
                playbook_id=str(row["playbook_id"]) if row["playbook_id"] else None,
            ))

        log.info(f"[RULES] {len(rules)} règles actives chargées depuis PostgreSQL")
        return rules

    def _dedup_key(self, candidate: AlertCandidate) -> str:
        """
        Génère une clé unique pour identifier une alerte dans le cache de déduplication.

        Format : "rule_id::entité_principale"
        Exemple : "uuid-brute-force-rule::185.220.101.5"

        Deux alertes avec la même clé = même type d'attaque, même attaquant
        → la deuxième est un doublon si dans la fenêtre de déduplication.
        """
        # On prend la première entité disponible (IP ou username)
        entities = candidate.source_ips + candidate.usernames
        entity   = entities[0] if entities else "unknown"
        # f-string avec :: comme séparateur (ne peut pas être dans un UUID ou une IP)
        return f"{candidate.rule_id}::{entity}"

    def _is_duplicate(self, candidate: AlertCandidate) -> bool:
        """
        Vérifie si une alerte similaire a été émise récemment.

        Retourne True si une alerte avec la même clé a été émise
        dans les _dedup_window_sec dernières secondes.
        """
        key  = self._dedup_key(candidate)         # clé de déduplication
        last = self._alert_cache.get(key)          # timestamp de la dernière alerte similaire

        if last is None:
            return False  # jamais vu → pas un doublon

        # .total_seconds() → durée en secondes depuis la dernière alerte similaire
        elapsed = (datetime.now(timezone.utc) - last).total_seconds()
        # Si l'écart est inférieur à la fenêtre → doublon
        return elapsed < self._dedup_window_sec

    def _mark_emitted(self, candidate: AlertCandidate):
        """
        Enregistre qu'une alerte vient d'être émise dans le cache de déduplication.
        Appelé APRÈS l'insertion réussie dans PG.
        """
        key = self._dedup_key(candidate)
        # Stockage du timestamp actuel pour cette clé
        self._alert_cache[key] = datetime.now(timezone.utc)

        # Nettoyage périodique du cache pour éviter la fuite mémoire
        # Si le cache dépasse 10 000 entrées, on supprime les entrées expirées
        if len(self._alert_cache) > 10_000:
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._dedup_window_sec)
            # Dict comprehension : ne garde que les entrées plus récentes que cutoff
            self._alert_cache = {k: v for k, v in self._alert_cache.items() if v > cutoff}

    async def insert_alert(self, candidate: AlertCandidate) -> str:
        """
        Insère une alerte candidate dans la table alerts de PostgreSQL.
        Retourne l'UUID de l'alerte créée.
        """
        # Génération d'un UUID v4 unique pour cette alerte
        alert_id = str(uuid.uuid4())

        async with self.pg_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO alerts (
                    id, rule_id, title, level, status,
                    correlated_event_ids, source_ips, affected_hosts, usernames,
                    mitre_tactic, confidence_score
                ) VALUES (
                    $1::uuid,         -- id           : UUID généré
                    $2::uuid,         -- rule_id      : FK vers correlation_rules
                    $3,               -- title        : description humaine
                    $4::alert_level,  -- level        : cast vers le type ENUM PG
                    'open'::alert_status,  -- status  : toujours "open" à la création
                    $5::jsonb,        -- correlated_event_ids : preuves (IDs ES)
                    $6::jsonb,        -- source_ips   : IPs impliquées
                    $7::jsonb,        -- affected_hosts : machines touchées
                    $8::jsonb,        -- usernames    : comptes impliqués
                    $9,               -- mitre_tactic : ex: "TA0001"
                    $10               -- confidence_score : 0-100
                )
                """,
                alert_id,
                candidate.rule_id,
                candidate.title,
                candidate.level,
                # json.dumps() : convertit la liste Python en string JSON pour JSONB PG
                json.dumps(candidate.correlated_event_ids),
                json.dumps(candidate.source_ips),
                json.dumps(candidate.affected_hosts),
                json.dumps(candidate.usernames),
                candidate.mitre_tactic,
                candidate.confidence_score,
            )

        log.info(f"[ALERT INSERTED] {alert_id} | {candidate.level} | {candidate.title[:60]}")
        return alert_id

    async def notify_api(self, alert_id: str):
        """
        Notifie l'API FastAPI qu'une nouvelle alerte a été créée.

        Pourquoi notifier FastAPI plutôt que d'envoyer les emails directement ?
        Séparation des responsabilités :
        - Le moteur de corrélation DÉTECTE les menaces
        - FastAPI RÉPOND aux menaces (emails, webhooks, playbooks)
        Cette séparation facilite les tests et l'évolution du code.

        Si FastAPI n'est pas démarré, on log l'erreur mais on continue.
        Le moteur ne doit jamais s'arrêter à cause d'un service externe.
        """
        import aiohttp  # client HTTP asynchrone
        try:
            # Création d'une session HTTP asynchrone
            async with aiohttp.ClientSession() as session:
                # Envoi du POST avec l'ID de l'alerte
                async with session.post(
                    "http://localhost:8000/internal/alert-triggered",
                    json={"alert_id": alert_id},  # corps JSON
                    # Timeout court : si FastAPI ne répond pas en 5s, on passe
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    # 200 ou 202 = succès (202 Accepted = traitement asynchrone en cours)
                    if resp.status not in (200, 202):
                        log.warning(f"API a retourné {resp.status} pour l'alerte {alert_id}")
        except Exception as e:
            # L'API n'est peut-être pas encore démarrée — ce n'est pas fatal
            log.debug(f"Notification API échouée (API peut-être pas démarrée): {e}")

    async def evaluate_all(self, rules: list[CorrelationRule]) -> int:
        """
        Évalue toutes les règles actives sur un cycle.
        Retourne le nombre d'alertes générées ce cycle.
        """
        alerts_count = 0  # compteur pour le log de fin de cycle

        for rule in rules:
            try:
                # Dispatch vers le bon évaluateur selon le type de règle
                # C'est le pattern "Strategy" : comportement différent selon le type
                if rule.rule_type == "threshold":
                    candidates = await self.threshold_eval.evaluate(rule)
                elif rule.rule_type == "pattern":
                    candidates = await self.pattern_eval.evaluate(rule)
                elif rule.rule_type == "cross_source":
                    candidates = await self.crosssrc_eval.evaluate(rule)
                else:
                    # Type inconnu → log et on passe à la règle suivante
                    log.warning(f"Type de règle inconnu : {rule.rule_type} (règle: {rule.name})")
                    continue  # "continue" passe à l'itération suivante du for

                # Traitement de chaque alerte candidate
                for candidate in candidates:
                    # Vérification de déduplication AVANT insertion
                    if self._is_duplicate(candidate):
                        # Doublon : on log en debug (pas visible en INFO) et on skip
                        log.debug(f"[DEDUP] Doublon ignoré : {candidate.title[:50]}")
                        continue

                    # Insertion dans PostgreSQL
                    alert_id = await self.insert_alert(candidate)

                    # Enregistrement dans le cache de déduplication
                    self._mark_emitted(candidate)

                    # Notification asynchrone de FastAPI
                    await self.notify_api(alert_id)

                    alerts_count += 1

                    # Mise à jour des statistiques de la règle dans PG
                    async with self.pg_pool.acquire() as conn:
                        await conn.execute(
                            """UPDATE correlation_rules
                               SET trigger_count      = trigger_count + 1,
                                   last_triggered_at  = NOW()
                               WHERE id = $1::uuid""",
                            rule.id
                        )

            except Exception as e:
                # En cas d'erreur sur une règle, on log et on CONTINUE avec les autres
                # Le moteur ne doit jamais s'arrêter à cause d'une règle défaillante
                # exc_info=True → inclut la stack trace complète dans le log
                log.error(f"Erreur évaluation règle {rule.name}: {e}", exc_info=True)

        return alerts_count

    async def run(self):
        """
        Boucle principale du worker — tourne indéfiniment.

        ARCHITECTURE DE LA BOUCLE :
        ┌─────────────────────────────────────────────────────┐
        │  Toutes les 60s : recharger les règles depuis PG    │
        │  ┌───────────────────────────────────────────────┐  │
        │  │  Toutes les 10s : évaluer toutes les règles   │  │
        │  │  sur les logs ES des dernières secondes       │  │
        │  └───────────────────────────────────────────────┘  │
        └─────────────────────────────────────────────────────┘
        """
        log.info(f"[START] Moteur démarré (intervalle: {WORKER_INTERVAL_SEC}s)")

        rules_cache     = []         # cache des règles pour éviter une requête PG à chaque cycle
        rules_loaded_at = datetime.min  # datetime.min = il y a très longtemps → force un rechargement au 1er cycle

        while True:  # boucle infinie — le moteur tourne jusqu'à Ctrl+C
            # time.monotonic() est plus précis que datetime.now() pour mesurer des durées
            # N'est pas affecté par les ajustements d'horloge système
            start = time.monotonic()

            try:
                # Rechargement des règles toutes les 60s
                # (datetime.now() - rules_loaded_at).total_seconds() > 60
                if (datetime.now() - rules_loaded_at).total_seconds() > 60:
                    rules_cache     = await self.load_active_rules()
                    rules_loaded_at = datetime.now()

                # Évaluation si des règles existent
                if rules_cache:
                    count = await self.evaluate_all(rules_cache)
                    if count:
                        # Log INFO seulement s'il y a eu des alertes (évite le bruit)
                        log.info(f"[CYCLE] {count} alerte(s) générée(s)")
                    else:
                        # DEBUG = pas affiché par défaut (niveau INFO)
                        log.debug("[CYCLE] Aucune alerte ce cycle")

            except Exception as e:
                # Erreur dans la boucle principale → log et on continue
                # Le moteur ne doit JAMAIS s'arrêter, même en cas d'erreur
                log.error(f"Erreur dans la boucle principale: {e}", exc_info=True)

            # Calcul du temps de sommeil pour respecter l'intervalle
            elapsed    = time.monotonic() - start  # durée de ce cycle
            sleep_time = max(0, WORKER_INTERVAL_SEC - elapsed)  # temps restant
            # max(0, ...) évite un sleep négatif si le cycle a duré plus de 10s

            # await asyncio.sleep() : pause non bloquante
            # Pendant ce sleep, d'autres coroutines asyncio peuvent s'exécuter
            await asyncio.sleep(sleep_time)

    async def close(self):
        """Fermeture propre des connexions — appelée à l'arrêt du processus."""
        await self.es.close()       # fermer le client ES
        await self.pg_pool.close()  # fermer le pool PG (libère toutes les connexions)


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

async def main():
    """Fonction principale asynchrone — point d'entrée de l'application."""
    engine = CorrelationEngine()
    await engine.initialize()  # connexions aux bases de données
    try:
        await engine.run()     # boucle infinie
    except KeyboardInterrupt:
        # Ctrl+C → arrêt propre (pas une erreur)
        log.info("Arrêt du moteur de corrélation (Ctrl+C)")
    finally:
        # "finally" s'exécute TOUJOURS, même en cas d'exception
        # Garantit que les connexions sont fermées proprement
        await engine.close()

if __name__ == "__main__":
    # asyncio.run() démarre la boucle d'événements asyncio
    # et exécute la coroutine main() jusqu'à sa complétion
    asyncio.run(main())