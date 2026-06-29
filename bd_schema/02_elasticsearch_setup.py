# 02_elasticsearch_setup.py
#!/usr/bin/env python3
"""
SMART SIEM — Création des index Elasticsearch
Rôle : stockage, indexation et recherche des logs normalisés
       et des profils comportementaux (UEBA).
Prérequis : pip install elasticsearch==8.* python-dateutil
"""

"""
✅ Elasticsearch security features have been automatically configured!
✅ Authentication is enabled and cluster connections are encrypted.

ℹ️  Password for the elastic user (reset with `bin/elasticsearch-reset-password -u elastic`):
  8-0Il66xvSeGnK=COySu

ℹ️  HTTP CA certificate SHA-256 fingerprint:
  814eae1b7d582184a5ae41006f458ad853a671ca377acb741bcdebdfeb45b763

ℹ️  Configure Kibana to use this cluster:
• Run Kibana and click the configuration link in the terminal when Kibana starts.
• Copy the following enrollment token and paste it into Kibana in your browser (valid for the next 30 minutes):
  eyJ2ZXIiOiI4LjE0LjAiLCJhZHIiOlsiMTcyLjE4LjAuMjo5MjAwIl0sImZnciI6IjgxNGVhZTFiN2Q1ODIxODRhNWFlNDEwMDZmNDU4YWQ4NTNhNjcxY2EzNzdhY2I3NDFiY2RlYmRmZWI0NWI3NjMiLCJrZXkiOiJfMlVXOHA0QjlpNk5CNHZmUWYyUjoyOFQ5aTBucU8wRDZpOWFDTzhqazlRIn0=

ℹ️ Configure other nodes to join this cluster:
• Copy the following enrollment token and start new Elasticsearch nodes with `bin/elasticsearch --enrollment-token <token>` (valid for the next 30 minutes):
  eyJ2ZXIiOiI4LjE0LjAiLCJhZHIiOlsiMTcyLjE4LjAuMjo5MjAwIl0sImZnciI6IjgxNGVhZTFiN2Q1ODIxODRhNWFlNDEwMDZmNDU4YWQ4NTNhNjcxY2EzNzdhY2I3NDFiY2RlYmRmZWI0NWI3NjMiLCJrZXkiOiJBV1VXOHA0QjlpNk5CNHZmUWY2Wjp2aE1yWFEyZTg4TVQ2SU5XY2Jobkp3In0=

  If you're running in Docker, copy the enrollment token and run:
  `docker run -e "ENROLLMENT_TOKEN=<token>" docker.elastic.co/elasticsearch/elasticsearch:9.4.2`
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
docker run -e "ENROLLMENT_TOKEN=eyJ2ZXIiOiI4LjE0LjAiLCJhZHIiOlsiMTcyLjE4LjAuMjo5MjAwIl0sImZnciI6IjgxNGVhZTFiN2Q1ODIxODRhNWFlNDEwMDZmNDU4YWQ4NTNhNjcxY2EzNzdhY2I3NDFiY2RlYmRmZWI0NWI3NjMiLCJrZXkiOiJBV1VXOHA0QjlpNk5CNHZmUWY2Wjp2aE1yWFEyZTg4TVQ2SU5XY2Jobkp3In0=" docker.elastic.co/elasticsearch/elasticsearch:9.4.2
"""
 
import json
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import RequestError
 
# ─── Connexion sécurisée (TLS activé par défaut sur ES 8.x) ──
es = Elasticsearch(
    hosts=["https://localhost:9200"],
    http_auth=("elastic", "8-0Il66xvSeGnK=COySu"),
    ca_certs="http_ca.crt",
    verify_certs=True,
)
 
# ─────────────────────────────────────────────────────────────
# 1. POLITIQUE ILM — Index Lifecycle Management
#    Rôle : rétention automatique configurable des index de logs
#    Phases : hot (données chaudes, derniers jours) →
#             warm (données tièdes, compressées) →
#             cold (données froides, non prioritaires) →
#             delete (suppression)
# ─────────────────────────────────────────────────────────────
ILM_POLICY = {
    "policy": {
        "phases": {
            "hot": {
                # Phase active : données des dernières 24h
                # Rollover automatique si l'index dépasse 5 Go ou 1 jour
                "min_age": "0ms",
                "actions": {
                    "rollover": {
                        "max_primary_shard_size": "5gb",
                        "max_age": "1d"
                    },
                    "set_priority": {"priority": 100}
                }
            },
            "warm": {
                # Phase tiède : 7 jours après rollover
                # Compresse les segments, réduit les shards
                "min_age": "7d",
                "actions": {
                    "shrink": {"number_of_shards": 1},
                    "forcemerge": {"max_num_segments": 1},
                    "set_priority": {"priority": 50}
                }
            },
            "cold": {
                # Phase froide : 30 jours
                # Index en lecture seule, consommation réduite
                "min_age": "30d",
                "actions": {
                    "set_priority": {"priority": 0}
                }
            },
            "delete": {
                # Suppression à 180 jours (configurable via retention_policies PG)
                "min_age": "180d",
                "actions": {"delete": {}}
            }
        }
    }
}
 
def create_ilm_policy():
    es.ilm.put_lifecycle(name="siem-logs-policy", body=ILM_POLICY)
    print("[OK] Politique ILM créée : siem-logs-policy")
 
 
# ─────────────────────────────────────────────────────────────
# 2. INDEX TEMPLATE — log_events
#    Rôle : modèle appliqué automatiquement à tous les index
#           correspondant au pattern "siem-logs-*"
#    Les mappings définissent les types de données et
#    l'indexation de chaque champ.
# ─────────────────────────────────────────────────────────────
LOG_EVENTS_MAPPING = {
    "mappings": {
        "dynamic": "strict",  # Rejette tout champ non déclaré → protection contre les injections
        "properties": {
 
            # ── Champs temporels ──────────────────────────────
            # INDEXÉ en tant que date — permet les agrégations temporelles
            # (date_histogram, date_range) en moins de 3s sur 6 mois
            "@timestamp": {
                "type": "date",
                "format": "strict_date_optional_time||epoch_millis"
            },
 
            # ── Référence vers PostgreSQL ─────────────────────
            "raw_log_id": {
                "type": "keyword",      # keyword = pas d'analyse (exact match uniquement)
                "index": True           # INDEXÉ : permet la recherche par ID brut
            },
            "source_id": {
                "type": "keyword",
                "index": True           # INDEXÉ : filtre par source de logs
            },
 
            # ── IPs réseau ────────────────────────────────────
            # Type "ip" permet les requêtes CIDR (ex: 192.168.0.0/16)
            "source_ip": {
                "type": "ip",
                "index": True           # INDEXÉ : requêtes CIDR et exact match
            },
            "dest_ip": {
                "type": "ip",
                "index": True           # INDEXÉ : détection d'exfiltration
            },
            "dest_port": {
                "type": "integer",
                "index": True           # INDEXÉ : détection de scans de ports
            },
 
            # ── Identification de la source ───────────────────
            "host": {
                "type": "keyword",
                "index": True           # INDEXÉ : corrélation intra-système
            },
            "hostname": {
                "type": "keyword",
                "index": True
            },
 
            # ── Classification fonctionnelle ──────────────────
            "log_type": {
                "type": "keyword",
                "index": True           # INDEXÉ : filtre par catégorie (auth/réseau/système)
            },
            "severity": {
                "type": "keyword",
                "index": True           # INDEXÉ : filtre par criticité (premier filtre dashboard)
            },
            "event_action": {
                "type": "keyword",
                "index": True           # INDEXÉ : règles pattern-based (login_failed, etc.)
            },
            "event_outcome": {
                "type": "keyword",
                "index": True           # INDEXÉ : success | failure
            },
 
            # ── Identité ──────────────────────────────────────
            "username": {
                "type": "keyword",
                "index": True,          # INDEXÉ : corrélation UEBA
                "fields": {
                    "text": {"type": "text"}  # champ text pour recherche floue
                }
            },
            "process_name": {
                "type": "keyword",
                "index": False          # NON INDEXÉ : peu utilisé en filtre
            },
            "process_id": {
                "type": "integer",
                "index": False
            },
 
            # ── Message brut ──────────────────────────────────
            # Double indexation : text (full-text search) + keyword (agrégation exacte)
            "raw_message": {
                "type": "text",
                "index": True,          # INDEXÉ en full-text (tf-idf, BM25)
                "analyzer": "standard",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 1024  # troncature pour les très longs messages
                    }
                }
            },
 
            # ── Intégrité ─────────────────────────────────────
            "hash_sha256": {
                "type": "keyword",
                "index": True,          # INDEXÉ : vérification d'intégrité lors d'audits
                "doc_values": True
            },
 
            # ── Géolocalisation ───────────────────────────────
            "geo": {
                "properties": {
                    "country_code":  {"type": "keyword", "index": True},
                    "country_name":  {"type": "keyword", "index": False},
                    "city_name":     {"type": "keyword", "index": False},
                    "location": {
                        "type": "geo_point"  # INDEXÉ : permet les requêtes géospatiales
                    }
                }
            },
 
            # ── Intelligence de menace ────────────────────────
            "threat": {
                "properties": {
                    "is_known_bad_ip": {"type": "boolean", "index": True},
                    "reputation_score": {"type": "float", "index": True},
                    "threat_category":  {"type": "keyword", "index": True}
                }
            },
 
            # ── MITRE ATT&CK ──────────────────────────────────
            "mitre_tactic":     {"type": "keyword", "index": True},
            "mitre_technique":  {"type": "keyword", "index": True},
 
            # ── Tags ──────────────────────────────────────────
            # Array de mots-clés — chaque tag est indexé
            "tags": {
                "type": "keyword",
                "index": True           # INDEXÉ : filtres dashboard rapides
            },
 
            # ── Données brutes enrichies ──────────────────────
            # NON indexées globalement — accès par sous-champs si besoin
            "enriched_data": {
                "type": "object",
                "enabled": False        # NON INDEXÉ : stockage uniquement
            },
 
            # ── Métadonnées de pipeline ───────────────────────
            "pipeline_version": {"type": "keyword", "index": False},
            "ingested_at":      {"type": "date", "index": True}
        }
    },
    "settings": {
        "number_of_shards":   2,   # 2 shards pour la tolérance et la performance
        "number_of_replicas": 1,   # 1 réplique pour la disponibilité
        "refresh_interval":   "5s",  # rafraîchissement toutes les 5s (quasi temps réel)
        "codec": "best_compression", # compression LZ4 → économise ~30% d'espace
        "index": {
            "lifecycle": {
                "name":       "siem-logs-policy",  # politique ILM associée
                "rollover_alias": "siem-logs-current"   # alias pointant vers l'index actif
            },
            # Tri par défaut — réduit le temps de recherche sur les requêtes chronologiques
            "sort": {
                "field": "@timestamp",
                "order": "desc"
            }
        }
    }
}
 
def create_log_events_template():
    """Crée le template d'index pour tous les index logs-*"""
    template = {
        "index_patterns": ["siem-logs-*"],
        "template": LOG_EVENTS_MAPPING,
        "priority": 300,
        "_meta": {"description": "Smart SIEM — Template pour les logs d'événements normalisés"}
    }
    es.indices.put_index_template(name="siem-logs-template", body=template)
    print("[OK] Template d'index créé : siem-logs-template")
 
 
def create_initial_log_index():
    """Crée le premier index et l'alias de l'index courant"""
    from datetime import datetime
    index_name = f"siem-logs-{datetime.now().strftime('%Y.%m')}"
 
    if not es.indices.exists(index=index_name):
        es.indices.create(
            index=index_name,
            body={
                "aliases": {
                    "siem-logs-current":   {"is_write_index": True},
                    "siem-logs-all":       {}       # alias de recherche sur tous les index
                }
            }
        )
        print(f"[OK] Index créé : {index_name}")
    else:
        print(f"[INFO] Index existe déjà : {index_name}")
 
 
# ─────────────────────────────────────────────────────────────
# 3. INDEX — ueba_profiles
#    Rôle : profils comportementaux des entités (users/machines)
#           Séries temporelles des scores de risque
# ─────────────────────────────────────────────────────────────
UEBA_PROFILES_MAPPING = {
    "mappings": {
        "dynamic": "strict",
        "properties": {
 
            # Identité de l'entité
            "entity_id":       {"type": "keyword", "index": True},
            "entity_type":     {"type": "keyword", "index": True},  # user | machine
 
            # Période de référence du profil
            "profile_period_start": {"type": "date", "index": True},
            "profile_period_end":   {"type": "date", "index": True},
 
            # Comportements normaux modélisés
            "typical_login_hours": {
                "type": "object",
                "enabled": True,
                "properties": {
                    "peak_hours": {
                        "type": "integer",
                        "index": False          # stockage uniquement
                    },
                    "off_hours": {
                        "type": "integer",
                        "index": False
                    },
                    "avg_hour":  {"type": "float", "index": False}
                }
            },
            "typical_source_ips": {
                "type": "ip",
                "index": True               # INDEXÉ : détection de connexion depuis IP inconnue
            },
            "avg_daily_events":       {"type": "float",   "index": True},
            "avg_daily_data_volume_mb": {"type": "float", "index": True},
            "typical_accessed_systems": {"type": "keyword", "index": True},
 
            # Scores de risque
            "risk_score_current": {
                "type": "integer",
                "index": True               # INDEXÉ : tri par risque dans le dashboard RSSI
            },
 
            # Historique des scores — nested pour requêtes sur sous-documents
            "risk_score_history": {
                "type": "nested",
                "properties": {
                    "timestamp":    {"type": "date",    "index": True},
                    "score":        {"type": "integer", "index": True},
                    "trigger":      {"type": "keyword", "index": False}
                }
            },
 
            # Anomalies détectées
            "anomalies_detected": {
                "type": "nested",
                "properties": {
                    "detected_at":  {"type": "date",    "index": True},
                    "type":         {"type": "keyword", "index": True},
                    "description":  {"type": "text",    "index": False},
                    "severity":     {"type": "keyword", "index": True},
                    "delta":        {"type": "float",   "index": False}
                }
            },
 
            "last_updated": {"type": "date", "index": True}
        }
    },
    "settings": {
        "number_of_shards":   1,
        "number_of_replicas": 1,
        "refresh_interval":   "30s"  # moins fréquent — données moins volatiles
    }
}
 
def create_ueba_index():
    if not es.indices.exists(index="ueba-profiles"):
        es.indices.create(index="ueba-profiles", body=UEBA_PROFILES_MAPPING)
        print("[OK] Index créé : ueba-profiles")
    else:
        print("[INFO] Index existe déjà : ueba-profiles")
 
 
# ─────────────────────────────────────────────────────────────
# 4. INDEX — alert_mirror
#    Rôle : copie des alertes dans ES pour la recherche rapide
#           dans les dashboards (complément de la table PG)
# ─────────────────────────────────────────────────────────────
ALERT_MIRROR_MAPPING = {
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "pg_alert_id":   {"type": "keyword", "index": True},
            "@timestamp":    {"type": "date"},
            "level":         {"type": "keyword", "index": True},
            "status":        {"type": "keyword", "index": True},
            "title":         {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "rule_name":     {"type": "keyword", "index": True},
            "mitre_tactic":  {"type": "keyword", "index": True},
            "source_ips":    {"type": "ip",      "index": True},
            "affected_hosts":{"type": "keyword", "index": True},
            "confidence_score": {"type": "integer", "index": True}
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 1}
}
 
def create_alert_mirror_index():
    if not es.indices.exists(index="alert-mirror"):
        es.indices.create(index="alert-mirror", body=ALERT_MIRROR_MAPPING)
        print("[OK] Index créé : alert-mirror")
    else:
        print("[INFO] Index existe déjà : alert-mirror")
 
 
# ─────────────────────────────────────────────────────────────
# 5. RÉCAPITULATIF DES INDEXATIONS ELASTICSEARCH
# ─────────────────────────────────────────────────────────────
def print_index_summary():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║        RÉCAPITULATIF DES INDEXATIONS ELASTICSEARCH               ║
╠══════════════════════════════════════════════════════════════════╣
║  INDEX : logs-YYYY.MM (pattern siem-logs-*)                           ║
║  ─────────────────────────────────────────────────────────────   ║
║  CHAMP             TYPE        INDEXÉ   RAISON                   ║
║  @timestamp        date        OUI ★    Toutes les requêtes tem  ║
║  source_ip         ip          OUI      Filtres, CIDR, corrél.   ║
║  dest_ip           ip          OUI      Exfiltration             ║
║  dest_port         integer     OUI      Scans de ports           ║
║  host              keyword     OUI      Corrélation systèmes     ║
║  log_type          keyword     OUI      Filtre fonctionnel       ║
║  severity          keyword     OUI ★    Premier filtre dashboard ║
║  event_action      keyword     OUI      Règles pattern-based     ║
║  username          keyword     OUI      UEBA, corrélation        ║
║  raw_message       text        OUI      Full-text search         ║
║  hash_sha256       keyword     OUI      Vérification intégrité   ║
║  mitre_tactic      keyword     OUI      Reporting MITRE          ║
║  tags              keyword     OUI      Filtres dashboard        ║
║  raw_log_id        keyword     OUI      Traçabilité (→ PG)       ║
║  geo.location      geo_point   OUI      Requêtes géospatiales    ║
║  geo.country_code  keyword     OUI      Filtres géo              ║
║  threat.*          mixed       OUI      Threat intelligence      ║
║  process_name      keyword     NON      Faible cardinalité       ║
║  enriched_data     object      NON      Stockage uniquement      ║
║                                                                   ║
║  INDEX : ueba-profiles                                           ║
║  entity_id         keyword     OUI      Lookup par entité        ║
║  entity_type       keyword     OUI      user vs machine          ║
║  risk_score_current integer    OUI ★    Tri dashboard RSSI       ║
║  typical_source_ips ip         OUI      Détection IP inconnue    ║
║  risk_score_history nested     OUI      Requêtes historique      ║
║  anomalies_detected nested     OUI      Filtres anomalies        ║
║                                                                   ║
║  ★ = champ critique pour les SLA de performance                  ║
╚══════════════════════════════════════════════════════════════════╝
""")
 
 
# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Initialisation Elasticsearch — Smart SIEM ===\n")
 
    try:
        info = es.info()
        print(f"[OK] Connecté à Elasticsearch {info['version']['number']}\n")
    except Exception as e:
        print(f"[ERREUR] Connexion impossible : {e}")
        exit(1)
    # es.indices.delete(index="siem-logs-*")
    # es.indices.delete(index="logs-2026.06")
    # es.indices.delete(index="alert-mirror")
    # es.indices.delete(index="ueba-profiles")
    create_ilm_policy()
    create_log_events_template()
    create_initial_log_index()
    create_ueba_index()
    create_alert_mirror_index()
    print_index_summary()
 
    print("\n=== Initialisation terminée avec succès ===")
 
