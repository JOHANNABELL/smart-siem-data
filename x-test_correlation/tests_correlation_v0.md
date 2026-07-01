# Rapport de Tests — Moteur de Corrélation Smart SIEM
## UCAC/ULC-ICAM — Projet transversal 2026
### Approche académique et professionnelle

---

## 1. Environnement de test

| Composant | Version | Configuration |
|-----------|---------|---------------|
| Elasticsearch | 8.x | TLS activé, indices.id_field_data.enabled=true |
| PostgreSQL | 14+ | Base smart_siem, utilisateur siem_app_user |
| Python | 3.11 | asyncpg, elasticsearch-py 8.17.2, scikit-learn 1.6.1 |
| OS | Ubuntu 22.04 LTS | VPS distant |
| Accès | ngrok (HTTP tunnel) | Accès multi-postes pendant les tests |

**Fichiers impliqués dans les tests :**
- `attack_simulator.py` — simulateur d'attaques (générateur de logs)
- `correlation_engine_commented.py` — moteur de corrélation (détecteur)
- `correlation_monitor.py` — moniteur temps réel
- `verify_correlation.py` — script de diagnostic

---

## 2. Contexte et objectifs

### 2.1 Objectifs des tests
Valider que le moteur de corrélation détecte correctement les 5 types d'attaques définis dans le cahier des charges : brute force, scan de ports, mouvement latéral, exfiltration, et corrélation inter-sources.

### 2.2 Méthode
Injection de logs synthétiques via `attack_simulator.py`, surveillance des alertes créées dans PostgreSQL via `correlation_monitor.py`, analyse des écarts via `verify_correlation.py`.

### 2.3 Critères de succès (exigences du cahier des charges)
- Minimum 5 règles de corrélation actives (EF-09 à EF-12)
- Minimum 2 règles multi-sources (EF-12)
- Minimum 2 tactiques MITRE ATT&CK couvertes (EF-11)
- Alerte CRITICAL notifiée en moins de 30 secondes (ENF-02)

---

## 3. Résultats des tests par technique MITRE ATT&CK

| # | Technique | Attaque | Logs insérés | Alerte générée | Statut |
|---|-----------|---------|-------------|----------------|--------|
| 1 | T1110 | SSH Brute Force | ✅ | ✅ HIGH | **RÉUSSI** |
| 2 | T1046 | Port Scan | ✅ | ❌ | **PARTIEL** |
| 3 | T1190 | Public App Exploit | ❌ | ❌ | **ÉCHEC** |
| 4 | T1021 | SSH Lateral Movement | ✅ | ✅ CRITICAL ×2 | **RÉUSSI** |
| 5 | T1021.2 | SMB Lateral Movement | ✅ | ❌ | **ÉCHEC** |
| 6 | T1021.1 | RDP Lateral Movement | ✅ | ❌ | **ÉCHEC** |
| 7 | T1550 | Pass-the-Hash | ✅ | ❌ | **ÉCHEC** |
| 8 | T1558.3 | Kerberoasting | ✅ | ❌ | **ÉCHEC** |
| 9 | T1558.1 | Golden Ticket | ✅ | ❌ | **ÉCHEC** |
| 10 | T1047 | WMI Remote Execution | ✅ | ❌ | **ÉCHEC** |
| 11 | T1041 | Exfiltration over C2 | ✅ | ✅ CRITICAL | **RÉUSSI** |
| 12 | T1048 | DNS Exfiltration | ✅ | ❌ | **ÉCHEC** |
| 13 | T1567 | HTTP POST Exfiltration | ✅ | ❌ | **ÉCHEC** |
| 14 | T1567.2 | Cloud Storage Exfil | ✅ | ❌ | **ÉCHEC** |
| 15 | T1095 | ICMP Tunnel | ✅ | ❌ | **ÉCHEC** |
| — | composite | Firewall + AD | ✅ (3 logs) | ✅ HIGH | **RÉUSSI** |

**Score global : 4/16 = 25% de détection**

---

## 4. Analyse des causes d'échec

### 4.1 Cause principale — Désalignement `event_action`

**Description technique :** Le `ThresholdEvaluator` interroge Elasticsearch en filtrant sur le champ `event_action`. La valeur cherchée est extraite du champ `conditions.event_action` de la règle dans PostgreSQL. Si ce champ ne correspond pas exactement à la valeur `event_action` produite par `attack_simulator.py`, la requête ES retourne zéro résultat, même si les logs sont bien présents.

**Exemple concret :**
```
Règle PG (venue du YAML)   : conditions.event_action = "Failed password"
Simulateur                  : event_action = "login_failed"
Résultat ES                 : 0 correspondances → pas d'alerte
```

**Règles impactées :** T1046, T1021.2, T1021.1, T1550, T1558.3, T1558.1, T1047, T1048, T1567, T1567.2, T1095

### 4.2 Cause secondaire — Règles YAML mal converties

**Description technique :** Le script `load_yaml_rules_v2.py` fait un mapping `field_filter.value → event_action` via un dictionnaire `MSG_TO_ACTION`. Certaines valeurs du dictionnaire `value` dans les YAML ne sont pas dans ce mapping, ce qui produit un `event_action` incorrect dans PostgreSQL.

**Impact :** Les règles chargées depuis les fichiers YAML du dossier `rules/` ne correspondent pas aux `event_action` générés par le simulateur ni à ceux présents dans les vrais logs.

### 4.3 Cause tertiaire — Logs non insérés (T1190)

**Description technique :** Pour T1190 (Public App Exploit), les logs générés par `attack_simulator.py` n'ont pas été trouvés dans l'index Elasticsearch lors de la recherche par `source_ip`. Cause probable : erreur lors de l'indexation (alias `siem-logs-current` non résolu, ou le script a été interrompu).

### 4.4 Cause quaternaire — ThresholdEvaluator ne lit pas `dest_port`

**Description technique :** Pour SMB (port 445) et RDP (port 3389), les règles YAML stockent la condition sur le port destination, pas sur `event_action`. Le `ThresholdEvaluator` actuel ne lit que `conditions.event_action` dans la requête ES. Le champ `dest_port` dans les conditions est ignoré.

---

## 5. Analyse des tests réussis

### T1110 — SSH Brute Force ✅
**Pourquoi ça marche :** L'`event_action` du simulateur (`login_failed`) correspond exactement à la valeur dans `correlation_rules.conditions`. La règle threshold avec seuil de 5 en 60s est correctement évaluée. L'agrégation ES par `source_ip` retourne les IPs qui dépassent le seuil.

### T1021 — SSH Lateral Movement ✅ (2 alertes)
**Pourquoi ça marche :** Le simulateur génère la séquence exacte `login_success → file_read` qui correspond à la règle pattern. Le `PatternEvaluator` (FSM) traverse les états correctement. Deux alertes créées car deux scénarios de mouvement latéral successifs.

### T1041 — Exfiltration over C2 ✅
**Pourquoi ça marche :** `event_action=large_outbound_transfer` correspond exactement dans le simulateur ET dans la règle PG. La fenêtre de 3600s et le seuil de 3 sont correctement calibrés.

### Cross-source Firewall+AD ✅
**Pourquoi ça marche :** La `CrossSourceEvaluator` fait l'intersection des IPs présentes dans les deux sources. Les événements `connection_blocked` (firewall) et `login_failed` (AD) depuis la même IP dans la fenêtre de 300s déclenchent l'alerte.

---

## 6. Métriques de qualité mesurées

| Métrique | Valeur mesurée | Seuil exigé | Statut |
|----------|---------------|-------------|--------|
| Recall global | 25% (4/16) | — | À améliorer |
| Règles opérationnelles | 4/16 | ≥ 5 | ❌ |
| Règles multi-sources | 1 (cross-source) | ≥ 2 | ❌ |
| Tactiques MITRE couvertes | 3 (TA0001, TA0008, TA0010) | ≥ 2 | ✅ |
| Délai alerte CRITICAL | < 30s (estimé) | < 30s | ✅ |
| Faux positifs observés | 0 | — | ✅ |
| Insertion logs ES | Fiable (bulk API) | — | ✅ |

---

## 7. Constats techniques

### 7.1 Ce qui fonctionne bien
- L'architecture du moteur de corrélation (boucle 10s, rechargement règles 60s) est fonctionnelle
- La déduplication (pas d'alerte dupliquée en 5 minutes) est opérationnelle
- L'insertion dans PostgreSQL et la liaison règle→alerte fonctionnent
- La corrélation cross-source (intersection d'ensembles) est fonctionnelle
- Le FSM pour les règles pattern est fonctionnel

### 7.2 Ce qui nécessite des corrections
- Alignement systématique entre les `event_action` du simulateur et des règles PG
- Extension du `ThresholdEvaluator` pour supporter les filtres sur `dest_port`
- Validation des règles YAML avant insertion (vérifier que `event_action` existe dans ES)
- Augmentation du volume de logs pour les règles à seuil élevé (50 en 10s pour T1046)

---

## 8. Pistes d'amélioration

### 8.1 Court terme (pour le Livrable S2)
1. **Corriger le mapping `event_action`** dans `load_yaml_rules_v2.py` — ajouter toutes les valeurs manquantes dans `MSG_TO_ACTION`
2. **Étendre `ThresholdEvaluator`** pour lire `dest_port` dans les conditions et l'ajouter au filtre ES
3. **Valider les règles au chargement** — vérifier que `event_action` est présent dans ES avant insertion
4. **Ajouter un mode `--dry-run`** au simulateur pour voir les logs générés sans les insérer

### 8.2 Moyen terme (pour le Livrable Final)
5. **Implémenter EQL** (Event Query Language d'Elasticsearch) pour les règles de séquence — plus performant que le FSM Python
6. **Scoring de confiance calibré** — mesurer la corrélation entre confidence_score et taux de vrais positifs
7. **Tests de charge** — 50 000 events/heure (ENF-03) avec mesure de la latence de détection
8. **Résistance aux évasions** — tester les attaques lentes (1 tentative/minute pendant 10 minutes)

### 8.3 Architecture long terme
9. **Migration vers Apache Flink** pour la corrélation en streaming à grande échelle
10. **Intégration des règles Sigma** (standard industriel) via `pySigma` pour la portabilité
11. **Feedback loop** — permettre aux analystes de marquer les faux positifs pour améliorer les seuils automatiquement