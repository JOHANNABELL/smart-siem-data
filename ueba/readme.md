# UEBA — User and Entity Behavior Analytics
## Smart SIEM — UCAC/ULC-ICAM 2026

---

## Architecture du module

```
ueba/
├── config.py               ← TOUS les paramètres (modifier ici uniquement)
├── dataset_generator.py    ← Génère les 30 jours de données de test
├── feature_engineering.py  ← Extrait les features depuis Elasticsearch
├── baseline.py             ← Construit les profils de référence
├── anomaly_detector.py     ← Isolation Forest + Z-Score → score 0–100
├── ueba_worker.py          ← Orchestrateur (point d'entrée unique)
├── ueba_reports/           ← Rapports JSON générés à chaque run
└── README.md               ← Ce fichier
```

**Règle fondamentale : chaque fichier fait UNE seule chose.**
Ne jamais mettre de logique de détection dans `baseline.py`, ni de logique
de persistance dans `anomaly_detector.py`.

---

## Installation des dépendances

```bash
pip install scikit-learn numpy elasticsearch asyncpg
```

---

## Mode d'emploi complet

### Étape 0 — Configuration (obligatoire)

Ouvrir `config.py` et vérifier/modifier :

```python
# Section 1 : credentials ES et PG
ES_CONFIG["password"] = "votre_mot_de_passe_elasticsearch"
PG_CONFIG["dsn"]      = "postgresql://user:password@host/db"

# Section 5 : utilisateurs à surveiller
ENTITIES_CONFIG["users"] = ["jack.bauer", "chloe.obrian", ...]
```

### Étape 1 — Générer le dataset de test

```bash
cd ueba/
python3 dataset_generator.py
```

Résultat attendu :
```
[Phase 1] Génération du comportement normal...
  jack.bauer           : 2847 logs normaux sur 30 jours
  chloe.obrian         : 4521 logs normaux sur 30 jours
  ...
[Phase 2] Injection des anomalies documentées...
  ANO-001 (jack.bauer) : 6 logs anormaux — Connexion à 2h30 depuis IP inconnue
  ANO-002 (david.palmer): 1 log anormal — Export de 500 Mo
  ...
[Phase 3] Insertion de 15432 logs dans ES...
[RÉSULTAT] 15432/15432 logs insérés
```

### Étape 2 — Lancer le worker UEBA

```bash
python3 ueba_worker.py
```

Résultat attendu :
```
UEBA WORKER — Cycle du 2026-06-29 03:00:00

[USERS] 5 utilisateurs à analyser

  [USER] jack.bauer
    → Extraction des features historiques (30 jours)...
    ✓ 28 jours de données disponibles
    Score: 78/100 [HIGH] — Anomalies: login_hour_mean, unique_source_ips
    🚨 Alerte créée dans PG : uuid-alerte

  [USER] tony.almeida
    Score: 12/100 [NORMAL] — Comportement normal

RÉSUMÉ DU CYCLE UEBA
  Entités traitées    : 5
  Alertes créées      : 4
  Recall estimé       : 80% (4/5 anomalies détectées)
  Objectif            : ≥ 80%
```

### Étape 3 — Vérifier la qualité

```bash
# Vérifier les alertes UEBA dans PostgreSQL
psql -d smart_siem -c "
  SELECT a.title, a.level, a.triggered_at, a.confidence_score
  FROM alerts a
  JOIN correlation_rules r ON r.id = a.rule_id
  WHERE r.rule_type = 'behavioral'
  ORDER BY a.triggered_at DESC;
"

# Vérifier les profils dans Elasticsearch
curl -u elastic:MOT_DE_PASSE \
  --cacert /etc/elasticsearch/certs/http_ca.crt \
  "https://localhost:9200/ueba-profiles/_search?pretty&size=10"
```

### Étape 4 — Calculer les métriques de qualité

```bash
# Recall = anomalies connues détectées / total anomalies injectées
# Le rapport JSON dans ueba_reports/ contient toutes les informations

cat ueba_reports/run_*.json | python3 -c "
import json, sys
report = json.load(sys.stdin)
alerts = report['alerts_created']
expected_anomalous_users = {'jack.bauer', 'david.palmer', 'chloe.obrian', 'bill.buchanan'}
detected = {a['entity'] for a in alerts if a['entity'] in expected_anomalous_users}
normal_alerted = [a for a in alerts if a['entity'] == 'tony.almeida']
print(f'Recall  : {len(detected)}/{len(expected_anomalous_users)} = {len(detected)/len(expected_anomalous_users):.0%}')
print(f'FP Rate : {len(normal_alerted)} faux positifs sur tony.almeida (attendu: 0)')
"
```

---

## Configuration des features — Guide de paramétrage

### Modifier un seuil Z-Score

Dans `config.py`, section `FEATURES_CONFIG` :

```python
"data_volume_mb": {
    "zscore_threshold": 2.5,   # ← réduire pour plus de sensibilité
    # ...
}
```

- `zscore_threshold: 2.0` → détecte les anomalies à 2σ (plus de détections, plus de FP)
- `zscore_threshold: 3.0` → standard industriel (équilibre)
- `zscore_threshold: 3.5` → très strict (moins de FP mais risque de manquer des attaques)

### Modifier les poids des features

La somme des poids DOIT être 1.0.
Augmenter le poids d'une feature = elle contribue plus au score final.

```python
"data_volume_mb": {
    "weight": 0.25,   # augmenter si l'exfiltration est votre priorité
}
```

### Modifier le seuil d'alerte

```python
DETECTION_CONFIG = {
    "alert_threshold": 70,   # ← alerte si score ≥ 70 (défaut)
}
```

### Modifier les heures ouvrées

```python
DETECTION_CONFIG = {
    "business_hours_start": 8,    # ← 8h00 (modifier si horaires différents)
    "business_hours_end":   18,   # ← 18h00
    "business_days": [0,1,2,3,4], # ← lundi–vendredi
}
```

---

## Objectifs de qualité à valider

| Critère | Seuil | Comment vérifier |
|---------|-------|-----------------|
| Recall | ≥ 80% | rapport JSON : alerts_created / anomalies_injectées |
| Faux positifs | 0 pour tony.almeida | alerts WHERE entity='tony.almeida' |
| Explicabilité | ≥ 1 feature citée | anomalous_features non vide dans chaque alerte |
| Score cohérent | david.palmer > 85 (exfiltration) | risk_score dans PG |
| Latence | < 30 secondes par entité | mesurer le temps du worker |

---

## Anomalies injectées dans le dataset (référence pour le Recall)

| ID | Utilisateur | Anomalie | Score attendu | Technique MITRE |
|----|-------------|----------|--------------|-----------------|
| ANO-001 | jack.bauer | Connexion 2h30 IP inconnue | ≥ 75 | T1078 |
| ANO-002 | david.palmer | Export 500 Mo | ≥ 90 | T1041 |
| ANO-003 | chloe.obrian | 15 serveurs en 1h | ≥ 85 | T1021 |
| ANO-004 | bill.buchanan | Compte admin créé à 22h | ≥ 80 | T1098 |
| ANO-005 | jack.bauer | 50 échecs auth internes | ≥ 70 | T1110 |
| — | tony.almeida | Comportement normal | < 30 | — |