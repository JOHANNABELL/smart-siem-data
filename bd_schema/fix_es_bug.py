#!/usr/bin/env python3
"""
================================================================================
SMART SIEM — Correctif du bug _id fielddata dans Elasticsearch
================================================================================
Problème : BadRequestError 400 — "Fielddata access on the _id field is disallowed"

Cause    : Les agrégations ES de type "terms" sur le champ "_id" sont interdites
           par défaut depuis ES 5.x. Le champ _id est un méta-champ système
           stocké dans une structure interne non compatible avec le fielddata.

Solutions disponibles (dans l'ordre de préférence) :
   A. Activer indices.id_field_data.enabled  (cluster setting — rapide)
   B. Remplacer _id par raw_log_id dans le code (propre mais demande modifs)

Ce script applique la SOLUTION A automatiquement via l'API ES,
puis vérifie que la correction est active.
================================================================================
"""

import os
import sys
import asyncio
from elasticsearch import AsyncElasticsearch

# ── Configuration ─────────────────────────────────────────────────────────────
ES_HOST     = os.environ.get("ES_HOST",     "https://localhost:9200")
ES_USER     = os.environ.get("ES_USER",     "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "8-0Il66xvSeGnK=COySu")
ES_CACERT   = os.environ.get("ES_CACERT",   "http_ca.crt")


async def fix_id_fielddata():
    """
    Active le fielddata sur _id au niveau du cluster.

    POURQUOI "persistent" et pas "transient" ?
    - transient : s'applique jusqu'au prochain redémarrage d'ES (perdu au reboot)
    - persistent : survit aux redémarrages, écrit dans le cluster state
    On utilise persistent pour que la correction ne disparaisse pas
    si le serveur ES redémarre.

    IMPACT MÉMOIRE :
    Activer id_field_data permet à ES de charger les _id en mémoire pour
    les agrégations. Sur de gros volumes (> 100 Mo de logs), cela consomme
    de la RAM. Dans notre cas (projet étudiant, quelques milliers de logs),
    l'impact est négligeable.

    ALTERNATIVE SANS IMPACT MÉMOIRE :
    Utiliser raw_log_id à la place de _id dans toutes les agrégations.
    raw_log_id est un champ applicatif keyword que nous avons défini dans
    le mapping — il supporte nativement les agrégations terms sans fielddata.
    """

    es = AsyncElasticsearch(
        hosts=[ES_HOST],
        basic_auth=(ES_USER, ES_PASSWORD),
        ca_certs=ES_CACERT,
        verify_certs=True,
    )

    print("=" * 60)
    print("CORRECTIF — Bug _id fielddata — Smart SIEM")
    print("=" * 60)

    # ── Étape 1 : Vérifier la connexion ───────────────────────────────────────
    try:
        info = await es.info()
        print(f"\n[OK] Connecté à Elasticsearch {info['version']['number']}")
    except Exception as e:
        print(f"[ERREUR] Connexion impossible : {e}")
        print("  → Vérifier ES_HOST, ES_USER, ES_PASSWORD, ES_CACERT")
        await es.close()
        sys.exit(1)

    # ── Étape 2 : Lire le paramètre actuel ────────────────────────────────────
    try:
        current = await es.cluster.get_settings()
        current_val = (
            current.get("persistent", {})
            .get("indices", {})
            .get("id_field_data", {})
            .get("enabled")
        )
        print(f"\n[INFO] Valeur actuelle de indices.id_field_data.enabled : "
              f"{current_val or 'non défini (défaut = false)'}")
    except Exception as e:
        print(f"[WARN] Impossible de lire les settings actuels : {e}")

    # ── Étape 3 : Appliquer le correctif ──────────────────────────────────────
    print("\n[ACTION] Application du correctif persistent...")
    try:
        response = await es.cluster.put_settings(
            body={
                "persistent": {
                    # Active le fielddata sur le champ méta _id
                    # Permet les agrégations "terms" sur _id dans les requêtes ES
                    "indices.id_field_data.enabled": True
                }
            }
        )

        if response.get("acknowledged"):
            print("[OK] Paramètre appliqué avec succès")
            print("     indices.id_field_data.enabled = true (persistent)")
        else:
            print(f"[WARN] Réponse inattendue : {response}")

    except Exception as e:
        print(f"[ERREUR] Impossible d'appliquer le correctif : {e}")
        print("\n  Causes possibles :")
        print("  1. L'utilisateur 'elastic' n'a pas les droits manage (cluster:admin)")
        print("  2. ES est en mode lecture seule")
        print("  3. Version ES incompatible")
        print("\n  Solution alternative : ajouter dans elasticsearch.yml :")
        print("  indices.id_field_data.enabled: true")
        print("  puis redémarrer ES : sudo systemctl restart elasticsearch")
        await es.close()
        sys.exit(1)

    # ── Étape 4 : Vérification post-correctif ─────────────────────────────────
    print("\n[VERIFY] Vérification du correctif par test d'agrégation réel...")
    try:
        # Test concret : faire une agrégation terms sur _id
        # C'est exactement ce que fait correlation_engine.py
        test_resp = await es.search(
            index="siem-logs-*",
            body={
                "query":  {"match_all": {}},
                "aggs":   {
                    "test_id_agg": {
                        "terms": {
                            "field": "_id",
                            "size":  5
                        }
                    }
                },
                "size": 0
            }
        )

        buckets = (test_resp.get("aggregations", {})
                            .get("test_id_agg", {})
                            .get("buckets", []))

        print(f"[OK] Test agrégation _id réussi — {len(buckets)} buckets retournés")
        print("\n✅ CORRECTIF APPLIQUÉ ET VÉRIFIÉ")
        print("   Le moteur de corrélation peut maintenant utiliser _id dans ses agrégations.")
        print("   Vous pouvez relancer correlation_engine.py")

    except Exception as e:
        if "id_field_data" in str(e):
            print(f"[ERREUR] Le correctif n'a pas été pris en compte : {e}")
            print("\n  → Essayer de redémarrer Elasticsearch et relancer ce script")
        else:
            # Autre erreur (ex: index vide) — le correctif est quand même actif
            print(f"[INFO] Test d'agrégation : {e}")
            print("[OK] Le setting a été appliqué même si l'index est vide")

    # ── Étape 5 : Afficher les settings finaux ────────────────────────────────
    try:
        final = await es.cluster.get_settings()
        val   = (final.get("persistent", {})
                      .get("indices", {})
                      .get("id_field_data", {})
                      .get("enabled"))
        print(f"\n[SETTINGS] indices.id_field_data.enabled (persistent) = {val}")
    except Exception:
        pass

    await es.close()
    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(fix_id_fielddata())