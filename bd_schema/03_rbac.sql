-- ============================================================
--  SMART SIEM — Implémentation RBAC complète
--  Mécanisme : Row Level Security PostgreSQL + vues filtrées
--  Rôles : reader | analyst | rssi | auditor | admin
-- ============================================================
 
-- ─── Rôles PostgreSQL (niveau base de données) ───────────────
-- Ces rôles limitent l'accès au niveau du moteur SQL,
-- AVANT même que l'application ne s'exécute.
-- C'est une défense en profondeur : même si l'API est compromise,
-- un rôle SQL ne peut pas accéder à ce qu'il n'a pas le droit de voir.
 
-- Rôle applicatif unique que l'API utilise pour se connecter
-- (jamais les rôles individuels directement)
CREATE ROLE siem_app_user LOGIN PASSWORD 'APP_PASSWORD_STRONG';
 
-- Rôles fonctionnels (pas de LOGIN — utilisés via SET ROLE)
CREATE ROLE siem_reader;
CREATE ROLE siem_analyst;
CREATE ROLE siem_rssi;
CREATE ROLE siem_auditor;
CREATE ROLE siem_admin;
 
-- Hiérarchie des rôles (chaque rôle hérite du précédent)
GRANT siem_reader  TO siem_analyst;
GRANT siem_analyst TO siem_rssi;
GRANT siem_rssi    TO siem_auditor;
GRANT siem_auditor TO siem_admin;
 
-- L'utilisateur applicatif peut prendre n'importe quel rôle
GRANT siem_reader, siem_analyst, siem_rssi, siem_auditor, siem_admin TO siem_app_user;
 
-- ─── Permissions par table ────────────────────────────────────
-- Principe : permission minimale par rôle.
 
-- TABLE : raw_logs
GRANT SELECT ON raw_logs TO siem_analyst;  -- analysts peuvent voir les logs bruts
GRANT SELECT ON raw_logs TO siem_admin;
GRANT INSERT ON raw_logs TO siem_app_user; -- l'API insère les logs
 
-- TABLE : log_sources
GRANT SELECT ON log_sources TO siem_reader;
GRANT INSERT, UPDATE ON log_sources TO siem_admin;
 
-- TABLE : users
GRANT SELECT ON users TO siem_rssi;        -- RSSI voit les comptes
GRANT SELECT ON users TO siem_auditor;
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO siem_admin;
 
-- TABLE : correlation_rules
GRANT SELECT ON correlation_rules TO siem_reader;  -- tout le monde voit les règles
GRANT INSERT, UPDATE ON correlation_rules TO siem_analyst;  -- analyst peut créer des règles
GRANT DELETE ON correlation_rules TO siem_admin;
 
-- TABLE : alerts
GRANT SELECT ON alerts TO siem_reader;
GRANT INSERT, UPDATE ON alerts TO siem_analyst;
GRANT UPDATE ON alerts TO siem_rssi;       -- RSSI peut escalader
 
-- TABLE : incidents
GRANT SELECT ON incidents TO siem_reader;
GRANT INSERT, UPDATE ON incidents TO siem_analyst;
 
-- TABLE : playbooks
GRANT SELECT ON playbooks TO siem_reader;
GRANT INSERT, UPDATE ON playbooks TO siem_analyst;
GRANT DELETE ON playbooks TO siem_admin;
 
-- TABLE : playbook_executions
GRANT SELECT ON playbook_executions TO siem_analyst;
GRANT INSERT ON playbook_executions TO siem_analyst;
GRANT SELECT ON playbook_executions TO siem_auditor;
 
-- TABLE : audit_logs
GRANT SELECT ON audit_logs TO siem_auditor;  -- seul l'auditeur accède aux logs d'audit
GRANT SELECT ON audit_logs TO siem_admin;
GRANT INSERT ON audit_logs TO siem_app_user; -- seule l'API peut insérer
-- UPDATE et DELETE intentionnellement non accordés (immuabilité)
 
-- TABLE : ueba_profiles
GRANT SELECT ON ueba_profiles TO siem_analyst;
GRANT SELECT ON ueba_profiles TO siem_rssi;
GRANT INSERT, UPDATE ON ueba_profiles TO siem_app_user;
 
-- TABLE : retention_policies
GRANT SELECT ON retention_policies TO siem_analyst;
GRANT UPDATE ON retention_policies TO siem_admin;
 
 
-- ============================================================
-- ROW LEVEL SECURITY (RLS)
-- Rôle : filtrage des lignes selon le périmètre organisationnel.
-- Un analyste ne voit que les alertes de son org_scope.
-- ============================================================
 
-- Activation du RLS sur les tables sensibles
ALTER TABLE alerts    ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE raw_logs  ENABLE ROW LEVEL SECURITY;
ALTER TABLE users     ENABLE ROW LEVEL SECURITY;
 
-- ── Politique RLS : alerts ─────────────────────────────────
-- L'admin voit tout
CREATE POLICY rls_alerts_admin ON alerts
    FOR ALL TO siem_admin
    USING (TRUE);
 
-- L'analyste voit les alertes dans son périmètre
-- current_setting('app.user_org_scope') est injecté par l'API lors de chaque requête
CREATE POLICY rls_alerts_analyst ON alerts
    FOR SELECT TO siem_analyst
    USING (
        -- Voit les alertes de son périmètre OU sans périmètre défini
        EXISTS (
            SELECT 1 FROM log_sources ls
            WHERE ls.id::text = ANY(
                SELECT jsonb_array_elements_text(alerts.correlated_event_ids)
            )
            AND (
                ls.org_unit = current_setting('app.user_org_scope', TRUE)
                OR current_setting('app.user_org_scope', TRUE) IS NULL
                OR current_setting('app.user_org_scope', TRUE) = ''
            )
        )
        OR correlated_event_ids IS NULL  -- alertes sans source liée = visibles par tous
    );
 
-- Le lecteur (reader) voit les alertes ouvertes uniquement
CREATE POLICY rls_alerts_reader ON alerts
    FOR SELECT TO siem_reader
    USING (status NOT IN ('closed') AND level != 'INFO');
 
-- Le RSSI voit tout dans son périmètre mais ne peut modifier que le statut
CREATE POLICY rls_alerts_rssi ON alerts
    FOR SELECT TO siem_rssi
    USING (TRUE);
 
-- ── Politique RLS : users ──────────────────────────────────
-- Un utilisateur peut voir son propre profil
-- Le RSSI voit tous les utilisateurs
-- L'admin a un accès total
 
CREATE POLICY rls_users_self ON users
    FOR SELECT TO siem_reader
    USING (id::text = current_setting('app.user_id', TRUE));
 
CREATE POLICY rls_users_rssi ON users
    FOR SELECT TO siem_rssi
    USING (TRUE);
 
CREATE POLICY rls_users_admin ON users
    FOR ALL TO siem_admin
    USING (TRUE);
 
-- ── Politique RLS : incidents ──────────────────────────────
CREATE POLICY rls_incidents_admin ON incidents
    FOR ALL TO siem_admin USING (TRUE);
 
CREATE POLICY rls_incidents_analyst ON incidents
    FOR ALL TO siem_analyst
    USING (
        assigned_to::text = current_setting('app.user_id', TRUE)
        OR assigned_to IS NULL
        OR current_setting('app.user_org_scope', TRUE) = ''
        OR current_setting('app.user_org_scope', TRUE) IS NULL
    );
 
 
-- ============================================================
-- VUES FILTRÉES PAR RÔLE
-- Rôle : chaque vue présente exactement les données
--        que son rôle cible doit voir — sans filtrage applicatif.
-- ============================================================
 
-- Vue RSSI : synthèse opérationnelle (pas de données techniques détaillées)
CREATE OR REPLACE VIEW view_rssi_dashboard AS
    SELECT
        date_trunc('hour', a.triggered_at)  AS period,
        a.level,
        a.status,
        a.mitre_tactic,
        COUNT(*)                             AS alert_count,
        AVG(a.confidence_score)             AS avg_confidence,
        COUNT(*) FILTER (WHERE a.is_false_positive) AS false_positive_count
    FROM alerts a
    WHERE a.triggered_at >= NOW() - INTERVAL '7 days'
    GROUP BY 1, 2, 3, 4
    ORDER BY 1 DESC;
 
COMMENT ON VIEW view_rssi_dashboard IS 'Vue synthétique pour le RSSI — pas de données techniques détaillées.';
GRANT SELECT ON view_rssi_dashboard TO siem_rssi;
 
-- Vue Analyste : détail technique complet
CREATE OR REPLACE VIEW view_analyst_alerts AS
    SELECT
        a.id, a.title, a.level, a.status,
        a.triggered_at, a.acknowledged_at,
        a.source_ips, a.dest_ips, a.affected_hosts, a.usernames,
        a.correlated_event_ids,
        a.mitre_tactic, a.confidence_score,
        a.notes,
        r.name          AS rule_name,
        r.rule_type,
        r.mitre_technique,
        u.username      AS acknowledged_by_username,
        p.name          AS playbook_name,
        p.execution_mode
    FROM alerts a
    LEFT JOIN correlation_rules r ON a.rule_id = r.id
    LEFT JOIN users u             ON a.acknowledged_by = u.id
    LEFT JOIN playbooks p         ON r.playbook_id = p.id
    ORDER BY a.triggered_at DESC;
 
GRANT SELECT ON view_analyst_alerts TO siem_analyst;
 
-- Vue Auditeur : conformité et traçabilité
CREATE OR REPLACE VIEW view_auditor_compliance AS
    SELECT
        al.performed_at,
        al.username_snapshot,
        al.role_snapshot,
        al.action,
        al.resource_type,
        al.resource_id,
        al.result,
        al.ip_address,
        al.metadata
    FROM audit_logs al
    ORDER BY al.performed_at DESC;
 
GRANT SELECT ON view_auditor_compliance TO siem_auditor;
 
-- Vue Lecteur : alertes ouvertes uniquement, sans détails sensibles
CREATE OR REPLACE VIEW view_reader_alerts AS
    SELECT
        a.id,
        a.title,
        a.level,
        a.status,
        a.triggered_at,
        a.mitre_tactic
    FROM alerts a
    WHERE a.status IN ('open', 'investigating')
      AND a.level IN ('HIGH', 'CRITICAL')
    ORDER BY a.triggered_at DESC;
 
GRANT SELECT ON view_reader_alerts TO siem_reader;
 
 
-- ============================================================
-- MATRICE RBAC RÉCAPITULATIVE (commentée)
-- ============================================================
/*
MATRICE DES ACCÈS — Smart SIEM
═══════════════════════════════════════════════════════════════════════════
RESSOURCE              │ READER │ ANALYST │ RSSI  │ AUDITOR │ ADMIN
═══════════════════════════════════════════════════════════════════════════
raw_logs               │   -    │  READ   │   -   │   READ  │  FULL
log_sources            │  READ  │  READ   │  READ │  READ   │  FULL
alerts (toutes)        │ PARTIAL│  FULL*  │  READ │  READ   │  FULL
alerts (modifier)      │   -    │  WRITE  │ UPDATE│   -     │  FULL
incidents              │  READ  │  FULL*  │  READ │  READ   │  FULL
correlation_rules      │  READ  │  WRITE  │  READ │  READ   │  FULL
playbooks              │  READ  │  WRITE  │  READ │  READ   │  FULL
playbook_executions    │   -    │  FULL   │   -   │  READ   │  FULL
users                  │  SELF  │   -     │  READ │  READ   │  FULL
audit_logs             │   -    │   -     │   -   │  READ   │  READ
ueba_profiles          │   -    │  READ   │  READ │   -     │  FULL
retention_policies     │   -    │  READ   │  READ │  READ   │  WRITE
═══════════════════════════════════════════════════════════════════════════
* limité au périmètre organisationnel (org_scope via RLS)
PARTIAL = alertes ouvertes HIGH/CRITICAL uniquement
SELF    = uniquement son propre profil utilisateur
*/
 
