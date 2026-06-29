#!/usr/bin/env python3
"""
SMART SIEM — Middleware RBAC FastAPI
Rôle : vérification des droits à chaque requête API,
       injection du contexte utilisateur pour le RLS PostgreSQL,
       et journalisation automatique dans audit_logs.
"""
 
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from enum import Enum
from functools import wraps
from typing import Optional
import asyncpg
 
 
# ─── Définition des rôles et permissions ──────────────────
class Role(str, Enum):
    READER   = "reader"
    ANALYST  = "analyst"
    RSSI     = "rssi"
    AUDITOR  = "auditor"
    ADMIN    = "admin"
 
# Hiérarchie des rôles (chaque rôle inclut les droits des rôles inférieurs)
ROLE_HIERARCHY = {
    Role.READER:  0,
    Role.ANALYST: 1,
    Role.RSSI:    2,
    Role.AUDITOR: 3,
    Role.ADMIN:   4,
}
 
# Matrice des permissions par ressource et action
# Structure : {resource: {action: [roles autorisés]}}
PERMISSIONS: dict[str, dict[str, list[Role]]] = {
    "alerts": {
        "read":   [Role.READER, Role.ANALYST, Role.RSSI, Role.AUDITOR, Role.ADMIN],
        "write":  [Role.ANALYST, Role.ADMIN],
        "delete": [Role.ADMIN],
        "escalate": [Role.ANALYST, Role.RSSI, Role.ADMIN],
    },
    "incidents": {
        "read":   [Role.READER, Role.ANALYST, Role.RSSI, Role.AUDITOR, Role.ADMIN],
        "write":  [Role.ANALYST, Role.ADMIN],
        "assign": [Role.ANALYST, Role.RSSI, Role.ADMIN],
        "resolve":[Role.ANALYST, Role.RSSI, Role.ADMIN],
    },
    "correlation_rules": {
        "read":   [Role.READER, Role.ANALYST, Role.RSSI, Role.AUDITOR, Role.ADMIN],
        "write":  [Role.ANALYST, Role.ADMIN],
        "delete": [Role.ADMIN],
        "toggle": [Role.ANALYST, Role.ADMIN],
    },
    "playbooks": {
        "read":    [Role.READER, Role.ANALYST, Role.RSSI, Role.AUDITOR, Role.ADMIN],
        "write":   [Role.ANALYST, Role.ADMIN],
        "execute": [Role.ANALYST, Role.ADMIN],
        "delete":  [Role.ADMIN],
    },
    "users": {
        "read_self": [Role.READER, Role.ANALYST, Role.RSSI, Role.AUDITOR, Role.ADMIN],
        "read_all":  [Role.RSSI, Role.AUDITOR, Role.ADMIN],
        "write":     [Role.ADMIN],
        "delete":    [Role.ADMIN],
        "change_role": [Role.ADMIN],
    },
    "audit_logs": {
        "read":   [Role.AUDITOR, Role.ADMIN],
    },
    "raw_logs": {
        "read":   [Role.ANALYST, Role.AUDITOR, Role.ADMIN],
    },
    "reports": {
        "generate": [Role.ANALYST, Role.RSSI, Role.AUDITOR, Role.ADMIN],
        "export":   [Role.ANALYST, Role.RSSI, Role.AUDITOR, Role.ADMIN],
    },
    "retention_policies": {
        "read":   [Role.ANALYST, Role.RSSI, Role.AUDITOR, Role.ADMIN],
        "write":  [Role.ADMIN],
    },
    "ueba": {
        "read":   [Role.ANALYST, Role.RSSI, Role.ADMIN],
    },
    "system_config": {
        "read":   [Role.ADMIN],
        "write":  [Role.ADMIN],
    }
}
 
 
# ─── Modèle utilisateur (issu du JWT) ─────────────────────
class CurrentUser:
    def __init__(self, user_id: str, username: str, role: Role,
                 org_scope: Optional[str] = None):
        self.user_id   = user_id
        self.username  = username
        self.role      = role
        self.org_scope = org_scope
 
    def can(self, resource: str, action: str) -> bool:
        """Vérifie si l'utilisateur peut effectuer l'action sur la ressource."""
        allowed_roles = PERMISSIONS.get(resource, {}).get(action, [])
        return self.role in allowed_roles
 
    def has_minimum_role(self, minimum_role: Role) -> bool:
        """Vérifie si l'utilisateur a au moins le rôle minimum requis."""
        return ROLE_HIERARCHY.get(self.role, -1) >= ROLE_HIERARCHY.get(minimum_role, 999)
 
 
# ─── Extraction et validation du JWT ──────────────────────
JWT_SECRET    = "VOTRE_SECRET_JWT_256_BITS"  # à charger depuis les variables d'env
JWT_ALGORITHM = "HS256"
security      = HTTPBearer()
 
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> CurrentUser:
    """
    Dépendance FastAPI : extrait et valide le JWT,
    retourne l'utilisateur courant.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return CurrentUser(
            user_id   = payload["sub"],
            username  = payload["username"],
            role      = Role(payload["role"]),
            org_scope = payload.get("org_scope")
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")
    except ValueError:
        raise HTTPException(status_code=401, detail="Rôle inconnu dans le token")
 
 
# ─── Décorateur de permission ──────────────────────────────
def require_permission(resource: str, action: str):
    """
    Décorateur pour protéger les routes FastAPI.
    Usage : @require_permission("alerts", "write")
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: CurrentUser = Depends(get_current_user), **kwargs):
            if not current_user.can(resource, action):
                raise HTTPException(
                    status_code=403,
                    detail=f"Accès refusé. Rôle '{current_user.role}' insuffisant pour {action} sur {resource}."
                )
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator
 
 
# ─── Middleware : injection du contexte RLS ───────────────
class RBACMiddleware:
    """
    Middleware qui injecte le contexte utilisateur dans PostgreSQL
    pour activer le Row Level Security.
    """
    async def inject_pg_context(self, conn: asyncpg.Connection, user: CurrentUser):
        """
        Inject les variables de session PostgreSQL utilisées par les politiques RLS.
        Appelé avant chaque requête SQL.
        """
        await conn.execute(
            "SELECT set_config('app.user_id', $1, TRUE)",      # TRUE = local à la transaction
            user.user_id
        )
        await conn.execute(
            "SELECT set_config('app.user_org_scope', $1, TRUE)",
            user.org_scope or ""
        )
        await conn.execute(
            "SELECT set_config('app.user_role', $1, TRUE)",
            user.role.value
        )
        # Activer le rôle SQL correspondant
        await conn.execute(f"SET LOCAL ROLE siem_{user.role.value}")
 
 
# ─── Middleware : journalisation automatique ──────────────
class AuditMiddleware:
    """
    Journalise automatiquement chaque action significative dans audit_logs.
    Appelé après chaque requête réussie sur les ressources sensibles.
    """
    AUDITABLE_ROUTES = {
        "POST /api/v1/users":            ("user_created",       "user"),
        "DELETE /api/v1/users/{id}":     ("user_deleted",       "user"),
        "PATCH /api/v1/users/{id}/role": ("role_changed",       "user"),
        "POST /api/v1/auth/login":       ("user_login",         None),
        "POST /api/v1/auth/logout":      ("user_logout",        None),
        "PATCH /api/v1/alerts/{id}":     ("alert_acknowledged", "alert"),
        "POST /api/v1/incidents":        ("incident_created",   "incident"),
        "PATCH /api/v1/incidents/{id}/resolve": ("incident_resolved", "incident"),
        "POST /api/v1/rules":            ("rule_created",       "rule"),
        "PUT /api/v1/rules/{id}":        ("rule_modified",      "rule"),
        "DELETE /api/v1/rules/{id}":     ("rule_deleted",       "rule"),
        "POST /api/v1/playbooks/{id}/execute": ("playbook_executed", "playbook"),
        "GET /api/v1/logs/export":       ("log_exported",       None),
        "POST /api/v1/reports/generate": ("report_generated",   None),
    }
 
    async def log_action(
        self,
        conn: asyncpg.Connection,
        user: CurrentUser,
        action: str,
        resource_type: Optional[str],
        resource_id: Optional[str],
        result: str,
        request: Request,
        metadata: dict = None
    ):
        await conn.execute(
            """
            INSERT INTO audit_logs
                (user_id, username_snapshot, role_snapshot, action,
                 resource_type, resource_id, ip_address, user_agent, result, metadata)
            VALUES ($1, $2, $3, $4::audit_action, $5, $6, $7::inet, $8, $9::action_result, $10)
            """,
            user.user_id,
            user.username,
            user.role.value,
            action,
            resource_type,
            resource_id,
            request.client.host if request.client else None,
            request.headers.get("user-agent"),
            result,
            (metadata or {})
        )
 
 
# ─── Exemple d'utilisation sur les routes FastAPI ─────────
app = FastAPI()
 
@app.get("/api/v1/alerts")
@require_permission("alerts", "read")
async def list_alerts(
    current_user: CurrentUser = Depends(get_current_user)
):
    """
    Liste les alertes selon le rôle de l'utilisateur.
    Le RLS PostgreSQL filtre automatiquement selon l'org_scope.
    """
    # Le filtrage par org_scope est fait automatiquement par le RLS PostgreSQL
    # grâce à l'injection du contexte dans inject_pg_context()
    return {"message": f"Alertes pour {current_user.username} (rôle: {current_user.role})"}
 
 
@app.post("/api/v1/playbooks/{playbook_id}/execute")
@require_permission("playbooks", "execute")
async def execute_playbook(
    playbook_id: str,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Seuls les Analystes et Admins peuvent exécuter des playbooks."""
    return {"message": f"Playbook {playbook_id} déclenché par {current_user.username}"}
 
 
@app.get("/api/v1/audit-logs")
@require_permission("audit_logs", "read")
async def get_audit_logs(
    current_user: CurrentUser = Depends(get_current_user)
):
    """Seuls les Auditeurs et Admins ont accès aux logs d'audit."""
    return {"message": "Logs d'audit"}
 
 
@app.delete("/api/v1/users/{user_id}")
@require_permission("users", "delete")
async def delete_user(
    user_id: str,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Seul l'Admin peut supprimer un utilisateur."""
    return {"message": f"Utilisateur {user_id} supprimé par {current_user.username}"}
 
