# Guide d'installation — Smart SIEM
## UCAC/ULC-ICAM — Projet transversal 2026
### Environnement : Windows 10/11 — Installation locale

---

## Prérequis matériels

| Ressource | Minimum | Recommandé |
|-----------|---------|-----------|
| CPU | 4 cœurs | 8 cœurs |
| RAM | 8 Go | 16 Go |
| Disque | 50 Go SSD | 100 Go SSD |
| OS | Windows 10 64-bit | Windows 11 64-bit |
| Python | 3.11+ | 3.13 |

---

## 1. Installation de Python

Télécharger Python 3.13 depuis https://www.python.org/downloads/

Pendant l'installation, cocher **"Add Python to PATH"**.

Vérifier dans PowerShell :
```powershell
python --version
# Attendu : Python 3.13.x

pip --version
# Attendu : pip 26.x from C:\Program Files\Python313\...
```

**Si pip est cassé** (erreur `No module named 'pip._vendor.rich'`) :
```powershell
# Toujours utiliser le pip de la version système, pas celui de AppData
"C:\Program Files\Python313\python.exe" -m pip install --upgrade pip --force-reinstall
```

---

## 2. Installation de PostgreSQL

Télécharger l'installeur depuis https://www.postgresql.org/download/windows/

Version recommandée : **PostgreSQL 16**

Pendant l'installation :
- Mot de passe superutilisateur : choisir et noter (ex: `postgres2026`)
- Port : `5432` (défaut)
- Locale : laisser par défaut

Après installation, ajouter PostgreSQL au PATH :
```powershell
# Ajouter dans les variables d'environnement système
# Ou lancer manuellement depuis PowerShell :
$env:PATH += ";C:\Program Files\PostgreSQL\16\bin"
```

Vérifier :
```powershell
psql --version
# Attendu : psql (PostgreSQL) 16.x
```

**Créer la base de données :**
```powershell
# Ouvrir PowerShell en tant qu'administrateur
psql -U postgres
```

Dans le shell psql qui s'ouvre :
```sql
CREATE DATABASE smart_siem;
CREATE USER siem_app_user WITH ENCRYPTED PASSWORD 'APP_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE smart_siem TO siem_app_user;
\q
```

**Appliquer le schéma :**
```powershell
# Depuis le dossier du projet
psql -U postgres -d smart_siem -f 01_postgres_schema.sql
psql -U postgres -d smart_siem -f 03_rbac.sql
```

**Vérifier les tables :**
```powershell
psql -U siem_app_user -d smart_siem -c "\dt"
# Attendu : 11 tables (alerts, audit_logs, correlation_rules,
# incidents, log_sources, playbook_executions, playbooks,
# raw_logs, retention_policies, ueba_profiles, users)
```

---

## 3. Installation d'Elasticsearch

Télécharger depuis https://www.elastic.co/downloads/elasticsearch

Choisir : **Windows ZIP** — version 8.x

**Extraction et démarrage :**
```powershell
# Extraire dans C:\elasticsearch
# Naviguer vers le dossier bin
cd C:\elasticsearch\bin

# Démarrer Elasticsearch
.\elasticsearch.bat
```

Au premier démarrage, Elasticsearch affiche dans le terminal :
```
✅ Authentication is enabled and cluster connections are encrypted.

Password for the elastic user : XXXX-XXXXXXXXXXXXXXX

HTTP CA certificate SHA-256 fingerprint : XXXX...

Configure Kibana to use this cluster: [...]
```

**IMPORTANT : noter immédiatement le mot de passe affiché.**
Si manqué, réinitialiser avec :
```powershell
cd C:\elasticsearch\bin
.\elasticsearch-reset-password.bat -u elastic
```

Le certificat CA se trouve dans :
```
C:\elasticsearch\config\certs\http_ca.crt
```

**Vérifier qu'Elasticsearch fonctionne :**
```powershell
# Ouvrir un nouveau PowerShell
curl.exe -u elastic:VOTRE_MOT_DE_PASSE `
    --cacert "C:\elasticsearch\config\certs\http_ca.crt" `
    "https://localhost:9200/_cluster/health?pretty"

# Attendu :
# {
#   "status" : "green",
#   ...
# }
```

**Corriger le bug _id fielddata (obligatoire) :**
```powershell
python fix_es_id_fielddata.py
```

---

## 4. Installation des dépendances Python

```powershell
# Se placer dans le dossier du projet
cd C:\Users\HP\Desktop\UCAC-ICAM\X3\Projet Intégrateur\Data

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
venv\Scripts\activate

# Vérifier que l'environnement est actif (le prompt change)
# (venv) PS C:\...>

# Installer les dépendances
pip install -r requirements.txt

# Vérifier les installations clés
python -c "import elasticsearch, asyncpg, fastapi, sklearn; print('Toutes les dépendances OK')"
```

---

## 5. Configuration des variables d'environnement

**Option A — Variables dans PowerShell (session courante) :**
```powershell
$env:ES_HOST     = "https://localhost:9200"
$env:ES_USER     = "elastic"
$env:ES_PASSWORD = "VOTRE_MOT_DE_PASSE_ELASTICSEARCH"
$env:ES_CACERT   = "C:\elasticsearch\config\certs\http_ca.crt"
$env:PG_DSN      = "postgresql://siem_app_user:APP_PASSWORD@localhost:5432/smart_siem"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_EMAIL    = "admin@ctu-siem.int"
$env:ADMIN_PASSWORD = "Admin@SIEM2026!"
```

**Option B — Fichier `.env` permanent (recommandé) :**

Créer le fichier `C:\Users\HP\Desktop\UCAC-ICAM\X3\Projet Intégrateur\Data\.env` :
```
ES_HOST=https://localhost:9200
ES_USER=elastic
ES_PASSWORD=VOTRE_MOT_DE_PASSE_ELASTICSEARCH
ES_CACERT=C:\elasticsearch\config\certs\http_ca.crt
PG_DSN=postgresql://siem_app_user:APP_PASSWORD@localhost:5432/smart_siem
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@ctu-siem.int
ADMIN_PASSWORD=Admin@SIEM2026!
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=votre_email@gmail.com
SMTP_PASS=votre_mot_de_passe_application
SOC_EMAIL=soc@ctu-siem.int
RSSI_EMAIL=rssi@ctu-siem.int
```

Charger le fichier dans PowerShell :
```powershell
Get-Content .env | ForEach-Object {
    if ($_ -match "^([^=]+)=(.+)$") {
        [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}
```

---

## 6. Initialisation du système — Ordre obligatoire

Ouvrir PowerShell dans le dossier du projet et activer l'environnement virtuel :
```powershell
cd "C:\Users\HP\Desktop\UCAC-ICAM\X3\Projet Intégrateur\Data"
venv\Scripts\activate
```

**Étape 1 — Créer les index Elasticsearch :**
```powershell
python 02_elasticsearch_setup.py
# Attendu :
# [OK] Politique ILM créée : siem-logs-policy
# [OK] Template d'index créé : siem-logs-template
# [OK] Index créé : siem-logs-2026.06
# [OK] Index créé : ueba-profiles
# [OK] Index créé : alert-mirror
```

**Étape 2 — Créer l'admin et les règles initiales :**
```powershell
python init_rules_commented.py
# Attendu :
# [1/2] Vérification / création du compte administrateur...
# COMPTE ADMINISTRATEUR CRÉÉ
#   Identifiant  : admin
#   MFA Secret   : XXXXXXXXXXXX
# [2/2] Insertion des règles de corrélation...
# [OK] Insérée : SSH Brute Force Detection (HIGH)
# ...
# [RÉSULTAT] 5 règles actives dans PostgreSQL
```

**Étape 3 — Créer les playbooks SOAR :**
```powershell
python init_playbooks.py
# Attendu :
# [OK] Playbook inséré : block_ip (mode=AUTO)
# [OK] Playbook inséré : disable_account (mode=CONFIRM)
# ...
# [RÉSULTAT] 6 playbooks · N règles liées à un playbook
```

**Étape 4 — Charger les règles YAML :**
```powershell
$env:RULES_DIR = ".\rules"
python load_yaml_rules_v2.py
# Attendu :
# [SCAN] N fichiers YAML trouvés dans .\rules
# [OK] [exfiltration]  CRITICAL  data_exfiltration_large_transfer.yaml
# ...
```

**Étape 5 — Générer les logs de test :**
```powershell
python log_generator_commented.py
# Attendu :
# [OK] Connecté à Elasticsearch 8.x
# [INDEX] Indexation de 1200 logs dans ES...
# [RÉSULTAT] Total documents dans ES : 1200
```

**Vérification globale :**
```powershell
python verify_correlation.py
# Affiche le diagnostic complet :
# - Règles dans PostgreSQL
# - Logs dans Elasticsearch
# - Désalignements détectés
# - Tests manuels par règle
```

---

## 7. Démarrage des services

Ouvrir **4 fenêtres PowerShell** dans le dossier du projet.
Dans chacune, activer l'environnement virtuel :
```powershell
cd "C:\Users\HP\Desktop\UCAC-ICAM\X3\Projet Intégrateur\Data"
venv\Scripts\activate
```

**Fenêtre 1 — Moteur de corrélation :**
```powershell
python correlation_engine_commented.py
# Attendu toutes les 10s :
# [RULES] 5 règles actives chargées depuis PostgreSQL
# [CYCLE] 0 alerte(s) générée(s)
# Quand une attaque est détectée :
# [THRESHOLD HIT] SSH Brute Force Detection | entité=185.X.X.X | count=8
# [ALERT INSERTED] uuid-alerte | HIGH | [SSH Brute Force...]
```

**Fenêtre 2 — API FastAPI (router d'alertes) :**
```powershell
uvicorn alert_router_commented:app --host 0.0.0.0 --port 8000
# Ouvrir http://localhost:8000/docs pour la documentation Swagger
```

**Fenêtre 3 — Simulateur d'attaques :**
```powershell
python attack_simulator.py
# Menu interactif s'affiche
# Choisir 1 (par type), 2 (Exfiltration), 1 (Toutes)
# Ctrl+C pour stopper la génération sans quitter
```

**Fenêtre 4 — Moniteur temps réel :**
```powershell
python correlation_monitor.py
# Interface Rich qui se rafraîchit toutes les 3 secondes
# Commandes :
#   c + Entrée → filtrer les CRITICAL
#   a + Entrée → afficher tous les niveaux
#   s + Entrée → inverser l'ordre chronologique
#   q + Entrée → quitter
```

---

## 8. Accès depuis d'autres PCs (ngrok)

**Installation de ngrok :**

Télécharger depuis https://ngrok.com/download — version Windows

Créer un compte sur https://ngrok.com et récupérer le token d'authentification.

```powershell
# Extraire ngrok.exe dans le dossier du projet
# S'authentifier
.\ngrok.exe config add-authtoken VOTRE_TOKEN_NGROK

# Exposer l'API FastAPI (8000) pour envoyer des logs depuis d'autres PCs
.\ngrok.exe http 8000

# Les autres PCs se connectent à l'URL affichée :
# Forwarding  https://abc123.ngrok-free.app -> http://localhost:8000
```

---

## 9. Structure des fichiers du projet

```
Projet Intégrateur\Data\
├── 01_postgres_schema.sql
├── 02_elasticsearch_setup.py
├── 03_rbac.sql
├── init_rules_commented.py
├── init_playbooks.py
├── log_generator_commented.py
├── correlation_engine_commented.py
├── alert_router_commented.py
├── attack_simulator.py
├── correlation_monitor.py
├── verify_correlation.py
├── fix_es_id_fielddata.py
├── load_yaml_rules_v2.py
├── requirements.txt
├── .env
├── rules\
│   ├── exfiltration\     ← 8 fichiers YAML
│   └── lateral_movement\ ← 10 fichiers YAML
├── ueba\
│   ├── config.py
│   ├── dataset_generator.py
│   ├── feature_engineering.py
│   ├── baseline.py
│   ├── anomaly_detector.py
│   ├── ueba_worker.py
│   └── README.md
└── test_correlation\     ← Rapports JSON des sessions de test
```

---

## 10. Résolution des problèmes fréquents

| Problème | Cause | Solution |
|----------|-------|----------|
| `BadRequestError: _id fielddata` | ES interdit les agrégations sur `_id` | `python fix_es_id_fielddata.py` |
| `CheckViolationError chk_rule_type` | Valeur `cross_source` interdite dans PG | Remplacer par `composite` dans init_rules |
| `ValueError: password > 72 bytes` | Limite bcrypt | Déjà corrigé dans init_rules_commented.py |
| `ModuleNotFoundError: pip._vendor.rich` | Conflit entre deux versions pip | `"C:\Program Files\Python313\python.exe" -m pip install -r requirements.txt` |
| Elasticsearch ne démarre pas | Port 9200 déjà utilisé | Vérifier avec `netstat -ano \| findstr :9200` |
| `Connection refused port 9200` | ES non démarré | Lancer `C:\elasticsearch\bin\elasticsearch.bat` |
| `psql: command not found` | PostgreSQL pas dans PATH | Ajouter `C:\Program Files\PostgreSQL\16\bin` aux variables d'environnement |
| Alertes non créées | Désalignement event_action | `python verify_correlation.py` — voir étape 3 du rapport |